defmodule Termelix.ErrorReporting do
  @moduledoc """
  Opt-in gate for Sentry error reporting.

  Reporting is **off by default**: even with a `SENTRY_DSN` configured, every event is
  dropped by `before_send/1` (wired via `config :sentry, :before_send`) until an admin has
  opted in. The choice is one persisted setting (`#{inspect("sentry_error_reporting")}` in
  `Termelix.Settings`) with three states: absent — nobody has decided yet (the SPA prompts
  the first admin who logs in), `"true"` — opted in, `"false"` — explicitly opted out. The
  admin settings panel can flip it in both directions at runtime; no restart is needed
  because the gate is evaluated per event.

  `before_send/1` runs inside Sentry's capture path — including during early boot or a
  crashing supervision tree — so the setting read must never raise: any failure (Repo not
  started, table missing) counts as "not enabled" and the event is dropped.
  """

  @setting_key "sentry_error_reporting"

  @doc """
  The current opt-in state: `%{enabled, decided, available}`. `available` is whether a
  Sentry DSN is configured at all — without one there is nothing to opt in to, so the SPA
  neither prompts nor offers the toggle (the stored decision is kept for when a DSN
  appears).
  """
  @spec status() :: %{enabled: boolean(), decided: boolean(), available: boolean()}
  def status do
    base =
      case safe_get() do
        "true" -> %{enabled: true, decided: true}
        "false" -> %{enabled: false, decided: true}
        _ -> %{enabled: false, decided: false}
      end

    Map.put(base, :available, available?())
  end

  @doc "Whether a Sentry DSN is configured (reporting can actually go somewhere)."
  @spec available?() :: boolean()
  def available? do
    case Application.get_env(:sentry, :dsn) do
      dsn when is_binary(dsn) -> String.trim(dsn) != ""
      _ -> false
    end
  end

  @doc "Whether events may currently be sent."
  @spec enabled?() :: boolean()
  def enabled?, do: safe_get() == "true"

  @doc """
  Persist an explicit opt-in/opt-out decision **atomically with its audit record**: the
  previous state is read, the setting written, and the consent audit row inserted in one
  transaction. A failed audit write rolls the whole change back — no applied consent
  change can go unaudited — and reading the previous state inside the same transaction
  makes each row's previous/new pair race-free (SQLite serializes writers).

  `user` is the acting admin (`id`/`username`); `request_meta` may carry `:ip_address` and
  `:user_agent`. Returns `{:ok, status()}` or `{:error, reason}` with nothing changed.
  """
  @spec record_decision(map(), boolean(), map()) ::
          {:ok, %{enabled: boolean(), decided: boolean(), available: boolean()}}
          | {:error, term()}
  def record_decision(user, enabled, request_meta \\ %{}) when is_boolean(enabled) do
    action = if enabled, do: "error_reporting_enable", else: "error_reporting_disable"

    result =
      Termelix.Repo.transaction(fn ->
        previous = status()
        set_enabled(enabled)

        Termelix.Audit.record_strict!(%{
          userId: user.id,
          username: user.username || user.id,
          action: action,
          resourceType: "settings",
          resourceId: @setting_key,
          resourceName: "Sentry error reporting",
          details:
            Jason.encode!(%{
              enabled: enabled,
              previous: Map.take(previous, [:enabled, :decided])
            }),
          ipAddress: request_meta[:ip_address],
          userAgent: request_meta[:user_agent],
          success: true
        })

        status()
      end)

    with {:ok, _status} <- result do
      # The in-transaction invalidation leaves a window where a concurrent reader
      # re-caches the pre-commit value; invalidating again AFTER the commit closes it —
      # otherwise the gate could keep honoring the old consent state indefinitely.
      Termelix.Settings.invalidate_cache(@setting_key)
      result
    end
  rescue
    # Repo.transaction re-raises after rolling back; the change did not happen.
    error -> {:error, error}
  end

  @doc """
  Low-level setter used by `record_decision/3` (and unit tests). Product code must go
  through `record_decision/3` so the change is audited.
  """
  @spec set_enabled(boolean()) :: :ok
  def set_enabled(enabled) when is_boolean(enabled) do
    Termelix.Settings.put_value(@setting_key, to_string(enabled))
    :ok
  end

  @doc """
  Sentry `before_send` callback: pass the event through when reporting is enabled, drop it
  (return nil) otherwise.
  """
  @spec before_send(Sentry.Event.t()) :: Sentry.Event.t() | nil
  def before_send(event) do
    if enabled?(), do: event, else: nil
  end

  # A gate failure must never take down (or recurse into) the capture path.
  defp safe_get do
    Termelix.Settings.get_value(@setting_key)
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end
end
