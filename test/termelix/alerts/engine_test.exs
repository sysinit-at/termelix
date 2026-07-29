defmodule Termelix.Alerts.EngineTest do
  @moduledoc """
  The threshold alert engine. `decide/5` is exercised purely (fixture rules + metrics + explicit
  `now`), proving the breach-duration and cooldown gates and the message/severity shaping match
  Node's `evaluateMetrics`. `evaluate_metrics/3` is then run end-to-end against real rows (a
  DEK-free user + host inserted for the enforced FKs) to prove a crossing writes an
  `alert_firings` row and that cooldown state carried across ticks suppresses a re-fire.
  """
  use Termelix.DataCase, async: true

  alias Termelix.Alerts
  alias Termelix.Alerts.Engine
  alias Termelix.Schema.{AlertRule, User, Host}

  @host_id 5

  # --- pure decide/5 ----------------------------------------------------------

  describe "decide/5 (pure)" do
    test "a value at/above threshold with no duration fires immediately" do
      rule = threshold_rule(id: 1, type: "cpu_threshold", threshold: 80.0, duration: 0)

      {state, [fire]} =
        Engine.decide([rule], @host_id, metrics(cpu: 96), Engine.initial_state(), 1_000)

      assert fire.severity == "critical"
      assert fire.message == "CPU usage at 96.0% (threshold: 80%)"
      assert Map.has_key?(state.cooldown, "1:#{@host_id}")
    end

    test "below 95 is a warning, not critical" do
      rule = threshold_rule(id: 1, type: "memory_threshold", threshold: 80.0, duration: 0)

      {_state, [fire]} =
        Engine.decide([rule], @host_id, metrics(memory: 90), Engine.initial_state(), 1_000)

      assert fire.severity == "warning"
      assert fire.message == "MEMORY usage at 90.0% (threshold: 80%)"
    end

    test "the threshold duration must elapse before the first fire" do
      rule = threshold_rule(id: 1, type: "cpu_threshold", threshold: 80.0, duration: 60)

      # First tick: breaching but 0s < 60s → no fire, breach start recorded.
      {state1, []} =
        Engine.decide([rule], @host_id, metrics(cpu: 90), Engine.initial_state(), 1_000)

      assert state1.breach["1:#{@host_id}"] == 1_000

      # 60s later: duration satisfied, cooldown empty → fires.
      {_state2, [fire]} = Engine.decide([rule], @host_id, metrics(cpu: 90), state1, 61_000)
      assert fire.message == "CPU usage at 90.0% (threshold: 80%)"
    end

    test "cooldown suppresses re-firing until it elapses" do
      rule = threshold_rule(id: 1, type: "cpu_threshold", threshold: 80.0, duration: 0)

      {state1, [_]} =
        Engine.decide([rule], @host_id, metrics(cpu: 90), Engine.initial_state(), 1_000)

      # Within the 15-minute cooldown → no re-fire.
      {state2, []} = Engine.decide([rule], @host_id, metrics(cpu: 90), state1, 1_000 + 5 * 60_000)

      # Exactly at the cooldown boundary → fires again.
      {_state3, [_]} =
        Engine.decide([rule], @host_id, metrics(cpu: 90), state2, 1_000 + 15 * 60_000)
    end

    test "dropping below the threshold clears the breach timer" do
      rule = threshold_rule(id: 1, type: "disk_threshold", threshold: 80.0, duration: 60)
      state = %{breach: %{"1:#{@host_id}" => 1_000}, cooldown: %{}}

      {new_state, []} = Engine.decide([rule], @host_id, metrics(disk: 50), state, 9_000)

      assert new_state.breach == %{}
    end

    test "a missing metric value or threshold is skipped" do
      no_value = threshold_rule(id: 1, type: "cpu_threshold", threshold: 80.0, duration: 0)
      no_threshold = threshold_rule(id: 2, type: "disk_threshold", threshold: nil, duration: 0)

      assert {_, []} =
               Engine.decide([no_value], @host_id, metrics(cpu: nil), Engine.initial_state(), 1)

      assert {_, []} =
               Engine.decide(
                 [no_threshold],
                 @host_id,
                 metrics(disk: 99),
                 Engine.initial_state(),
                 1
               )
    end

    test "non-threshold trigger types are ignored" do
      rule = threshold_rule(id: 1, type: "host_offline", threshold: 80.0, duration: 0)

      assert {_, []} =
               Engine.decide([rule], @host_id, metrics(cpu: 99), Engine.initial_state(), 1)
    end

    test "fires are returned in rule order" do
      cpu = threshold_rule(id: 1, type: "cpu_threshold", threshold: 10.0, duration: 0)
      mem = threshold_rule(id: 2, type: "memory_threshold", threshold: 10.0, duration: 0)

      {_state, fires} =
        Engine.decide(
          [cpu, mem],
          @host_id,
          metrics(cpu: 50, memory: 60),
          Engine.initial_state(),
          1
        )

      assert Enum.map(fires, & &1.rule.id) == [1, 2]
    end
  end

  # --- evaluate_metrics/3 (I/O) -----------------------------------------------

  describe "evaluate_metrics/3" do
    setup do
      user = make_user("alice")
      host = make_host(user, "web-1")
      %{user: user, host: host}
    end

    test "a crossing records a firing and cooldown suppresses the next tick", %{
      user: user,
      host: host
    } do
      {:ok, _rule, _} =
        Alerts.create_alert_rule(%{
          userId: user.id,
          hostId: host.id,
          name: "cpu high",
          enabled: true,
          triggerType: "cpu_threshold",
          thresholdValue: 80,
          thresholdDurationSeconds: 0,
          cooldownMinutes: 15,
          channels: [],
          now: iso_now()
        })

      metrics = %{cpu: %{percent: 96}, memory: %{percent: 10}, disk: %{percent: 10}}
      state = Engine.evaluate_metrics(host.id, metrics, Engine.initial_state())

      {[{firing, rule_name}], 1} =
        Alerts.list_alert_firings(%{userId: user.id, limit: 50, offset: 0})

      assert firing.hostName == "web-1"
      assert firing.severity == "critical"
      assert firing.value == 96.0
      assert firing.message == "CPU usage at 96.0% (threshold: 80%)"
      assert firing.acknowledged == false
      assert rule_name == "cpu high"
      assert map_size(state.cooldown) == 1

      # Re-evaluating with the carried state (still within cooldown) writes no new firing.
      Engine.evaluate_metrics(host.id, metrics, state)
      {_rows, total} = Alerts.list_alert_firings(%{userId: user.id, limit: 50, offset: 0})
      assert total == 1
    end

    test "a global (hostId nil) rule applies to any host", %{user: user, host: host} do
      {:ok, _rule, _} =
        Alerts.create_alert_rule(%{
          userId: user.id,
          hostId: nil,
          name: "disk any",
          enabled: true,
          triggerType: "disk_threshold",
          thresholdValue: 50,
          thresholdDurationSeconds: 0,
          cooldownMinutes: 15,
          channels: [],
          now: iso_now()
        })

      Engine.evaluate_metrics(
        host.id,
        %{cpu: %{percent: 1}, memory: %{percent: 1}, disk: %{percent: 88}},
        Engine.initial_state()
      )

      {_rows, total} = Alerts.list_alert_firings(%{userId: user.id, limit: 50, offset: 0})
      assert total == 1
    end
  end

  # --- fixtures ---------------------------------------------------------------

  defp threshold_rule(opts) do
    %AlertRule{
      id: Keyword.fetch!(opts, :id),
      userId: "u1",
      name: "rule-#{Keyword.fetch!(opts, :id)}",
      triggerType: Keyword.fetch!(opts, :type),
      thresholdValue: Keyword.fetch!(opts, :threshold),
      thresholdDurationSeconds: Keyword.fetch!(opts, :duration),
      cooldownMinutes: 15
    }
  end

  defp metrics(fields) do
    %{
      cpu: %{percent: Keyword.get(fields, :cpu)},
      memory: %{percent: Keyword.get(fields, :memory)},
      disk: %{percent: Keyword.get(fields, :disk)}
    }
  end

  defp make_user(username) do
    Repo.insert!(%User{
      id: Termelix.Id.generate(),
      username: username,
      passwordHash: "x",
      isAdmin: false,
      isOidc: false,
      totpEnabled: false,
      donationModalDismissed: false,
      registeredAt: DateTime.utc_now() |> DateTime.to_iso8601()
    })
  end

  defp make_host(user, name) do
    Repo.insert!(
      Ecto.Changeset.change(%Host{}, %{
        userId: user.id,
        name: name,
        ip: "10.0.0.1",
        port: 22,
        username: "root",
        authType: "password"
      })
    )
  end

  defp iso_now, do: DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()
end
