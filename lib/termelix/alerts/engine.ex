defmodule Termelix.Alerts.Engine do
  @moduledoc """
  The threshold alert engine — the port of `hosts/metrics/alert-engine.ts`'s `evaluateMetrics`
  path. Split into a **pure decision core** and a thin **I/O orchestration** so the crossing
  logic is unit-testable without a database or network.

    * **`decide/5`** is pure: given the enabled rules, a host id, a `ServerMetrics` map, the
      carried engine state, and `now` (ms), it returns `{new_state, fires}` — the rules that
      should fire this tick and the updated breach/cooldown bookkeeping. It reproduces Node's
      logic exactly: a rule fires only after the value has stayed at/above its threshold for
      `thresholdDurationSeconds`, and never again within `cooldownMinutes` of its last firing.
    * **`evaluate_metrics/3`** does the I/O: loads the host's enabled rules, runs `decide/5`,
      and for each fire writes an `alert_firings` row (pruning firings older than 30 days) and
      fans the payload out to the rule's enabled notification channels.

  Engine state (`%{breach: map, cooldown: map}`, keyed `"<ruleId>:<hostId>"`) lives in the
  caller, which threads it across ticks exactly as the Node singleton kept its
  `breachStartMap`/`cooldownMap`. Only the `*_threshold` trigger types are handled; host
  up/down, health-check, and user-login triggers are DEFERRED (their Node evaluators are
  status/event-driven, not part of the metrics tick).
  """
  require Logger

  alias Termelix.Alerts
  alias Termelix.Alerts.Notifier

  @threshold_triggers ~w(cpu_threshold memory_threshold disk_threshold)
  @default_cooldown_minutes 15
  @critical_at 95
  @firing_retention_days 30

  @type state :: %{
          breach: %{optional(String.t()) => integer()},
          cooldown: %{optional(String.t()) => integer()}
        }
  @type fire :: %{rule: map(), value: number(), message: String.t(), severity: String.t()}

  @doc "Empty engine state (no active breaches, no cooldowns)."
  @spec initial_state() :: state()
  def initial_state, do: %{breach: %{}, cooldown: %{}}

  @doc """
  Pure threshold evaluation. Returns `{new_state, fires}` where `fires` is the list of rules
  that crossed and cleared duration + cooldown this tick (in rule order). Non-threshold rules
  and rules with a missing value/threshold are skipped.
  """
  @spec decide([map()], integer(), map(), state(), integer()) :: {state(), [fire()]}
  def decide(rules, host_id, metrics, state, now) do
    rules
    |> Enum.filter(&threshold_rule?/1)
    |> Enum.reduce({state, []}, fn rule, {state, fires} ->
      value = current_value(rule, metrics)
      threshold = rule.thresholdValue
      key = "#{rule.id}:#{host_id}"

      cond do
        is_nil(value) or is_nil(threshold) ->
          {state, fires}

        value >= threshold ->
          breach_start = Map.get(state.breach, key, now)
          state = put_in(state.breach[key], breach_start)
          duration_ms = (rule.thresholdDurationSeconds || 0) * 1000

          if now - breach_start >= duration_ms and not cooling_down?(rule, key, state, now) do
            state = put_in(state.cooldown[key], now)
            {state, [build_fire(rule, value) | fires]}
          else
            {state, fires}
          end

        true ->
          {%{state | breach: Map.delete(state.breach, key)}, fires}
      end
    end)
    |> then(fn {state, fires} -> {state, Enum.reverse(fires)} end)
  end

  @doc """
  Evaluate a host's enabled rules against `metrics`, carrying `state` across ticks. Writes a
  firing row and dispatches notifications for every crossing, and returns the updated state.
  I/O failures for a single rule are logged and swallowed (the tick stays resilient).
  """
  @spec evaluate_metrics(integer(), map(), state()) :: state()
  def evaluate_metrics(host_id, metrics, state) do
    rules = Alerts.list_enabled_rules_for_host(host_id)
    {new_state, fires} = decide(rules, host_id, metrics, state, now_ms())
    Enum.each(fires, &fire_alert(&1, host_id))
    new_state
  end

  # --- firing side effects ----------------------------------------------------

  defp fire_alert(%{rule: rule, value: value, message: message, severity: severity}, host_id) do
    host_name = Alerts.host_display_name(host_id) || "Host ##{host_id}"

    Alerts.create_firing(%{
      userId: rule.userId,
      ruleId: rule.id,
      hostId: host_id,
      hostName: host_name,
      value: value,
      message: message,
      severity: severity
    })

    Alerts.prune_firings_older_than(rule.userId, @firing_retention_days)

    payload = build_payload(rule, host_id, host_name, value, message, severity)

    rule.id
    |> Alerts.list_enabled_channels_for_rule()
    |> Enum.each(&Notifier.send_notification(&1, payload))

    :ok
  rescue
    error ->
      Logger.warning("Alert firing failed for rule #{inspect(rule.id)}: #{inspect(error)}")
      :ok
  end

  defp build_payload(rule, host_id, host_name, value, message, severity) do
    %{
      hostName: host_name,
      hostId: host_id,
      triggerType: rule.triggerType,
      value: value,
      threshold: rule.thresholdValue,
      message: message,
      severity: severity,
      timestamp: iso_now(),
      ruleId: rule.id,
      ruleName: rule.name
    }
  end

  # --- pure helpers -----------------------------------------------------------

  defp threshold_rule?(rule), do: rule.triggerType in @threshold_triggers

  defp current_value(%{triggerType: "cpu_threshold"}, metrics),
    do: get_in(metrics, [:cpu, :percent])

  defp current_value(%{triggerType: "memory_threshold"}, metrics),
    do: get_in(metrics, [:memory, :percent])

  defp current_value(%{triggerType: "disk_threshold"}, metrics),
    do: get_in(metrics, [:disk, :percent])

  defp current_value(_rule, _metrics), do: nil

  defp cooling_down?(rule, key, state, now) do
    case Map.get(state.cooldown, key) do
      nil -> false
      last -> now - last < (rule.cooldownMinutes || @default_cooldown_minutes) * 60 * 1000
    end
  end

  defp build_fire(rule, value) do
    %{
      rule: rule,
      value: value,
      message: threshold_message(rule, value),
      severity: severity(value)
    }
  end

  # "CPU usage at 96.3% (threshold: 80%)" — Node's `${type}` toUpperCase + toFixed(1) + `${threshold}`.
  defp threshold_message(rule, value) do
    label = rule.triggerType |> String.replace("_threshold", "") |> String.upcase()
    "#{label} usage at #{fixed1(value)}% (threshold: #{js_num(rule.thresholdValue)}%)"
  end

  defp severity(value) when value >= @critical_at, do: "critical"
  defp severity(_value), do: "warning"

  defp fixed1(value), do: :erlang.float_to_binary(value * 1.0, decimals: 1)

  # Render a number the way JS string interpolation would (drop a whole float's `.0`).
  defp js_num(n) when is_integer(n), do: Integer.to_string(n)

  defp js_num(n) when is_float(n) do
    t = trunc(n)
    if n == t, do: Integer.to_string(t), else: Float.to_string(n)
  end

  defp js_num(other), do: to_string(other)

  defp now_ms, do: System.system_time(:millisecond)

  defp iso_now, do: DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()
end
