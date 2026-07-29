defmodule Termelix.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  # Placeholder written over the secret-bearing parts of a crash report. See
  # `scrub_crash_report/2`.
  @redacted "[redacted]"

  @impl true
  def start(_type, _args) do
    # Forward crash reports and error-level logs to Sentry (no-op without a DSN).
    # `:capture_metadata` is an allowlist — it is the 13.3.0 name of the old `:metadata`
    # option (deps/sentry/lib/sentry/logger_handler.ex:321-323). The handler has no option
    # for the crashed process's state and last message (the option schema is
    # logger_handler.ex:15-144), so those are stripped by a `:logger` filter instead.
    :logger.add_handler(:sentry_handler, Sentry.LoggerHandler, %{
      config: %{capture_metadata: [:file, :line]},
      filters: [scrub_crash_report: {&__MODULE__.scrub_crash_report/2, []}]
    })

    # The settings-cache version counter must exist before anything concurrent runs —
    # created here (single-threaded boot) and pinned in :persistent_term for the node's
    # lifetime, it survives every supervisor restart (see Termelix.Settings.Cache).
    Termelix.Settings.Cache.ensure_counter()

    children = [
      # First child on purpose: its runtime gauges are best-effort and tolerate the
      # registries below not existing yet (see TermelixWeb.Telemetry.dispatch_runtime_stats/0).
      TermelixWeb.Telemetry,
      core_supervisor(),
      runtime_supervisor()
    ]

    # `:one_for_one` at the top: the two child supervisors enforce their own internal
    # ordering, and rebuilding the core must not drop every live session and tunnel.
    opts = [strategy: :one_for_one, name: Termelix.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    TermelixWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  @doc """
  `:logger` filter for the Sentry handler: redact the crashed process's state and last
  message before the handler turns the report into an event.

  Sentry copies both into the event's `:extra` and, when it cannot parse the report, sends
  the whole formatted message verbatim (deps/sentry/lib/sentry/logger_handler/error_backend.ex:196
  and :251-254). For `Termelix.SSH.Client` that state is the decrypted connect opts
  (ssh/client.ex:84, nil-ed only once connected at :125) and its last message is the user's
  keystrokes (`{:send, data}`, ssh/client.ex:66).

  Handler filters run before `Sentry.LoggerHandler.log/2` and only on that handler's copy
  of the event, so console/file logging still gets the full report.
  """
  def scrub_crash_report(%{msg: {:report, %{elixir_translation: _} = report}} = event, _) do
    # Elixir >= 1.19 leaves the report intact and adds its translation alongside; Sentry
    # reads only that key (error_backend.ex:54-59).
    %{event | msg: {:report, %{report | elixir_translation: redact(report.elixir_translation)}}}
  end

  def scrub_crash_report(%{msg: {:string, chardata}} = event, _) do
    %{event | msg: {:string, redact(chardata)}}
  end

  def scrub_crash_report(event, _), do: event

  # Ordered, mutually dependent boot chain, hence `:rest_for_one`: a SystemCrypto restart
  # re-derives the root key, so the UserKeyManager DEK cache that copied key material from it
  # has to be rebuilt too. The intensity is tight — a core that cannot come up should surface
  # as an application exit for the release supervisor, not thrash.
  #
  # The chain is deliberately NARROW. `:rest_for_one` restarts everything *after* the child
  # that died, so every member added here is one more thing a routine SQLite hiccup takes with
  # it. `Termelix.EtsOwner` in particular does NOT belong: it depends on none of these, and
  # putting it last meant a single `Termelix.Repo` crash wiped the login/registration/TOTP
  # rate-limit budgets and the TOTP anti-replay markers it exists to hold across requests —
  # resetting a brute-force attacker's counter and making a captured TOTP code replayable
  # inside its window. It lives in the runtime tail instead; its only real ordering
  # requirement ("before the endpoint") is satisfied there.
  defp core_supervisor do
    children = [
      # Root key material must be available before the key manager and any request.
      Termelix.Crypto.SystemCrypto,
      Termelix.Repo,
      {Ecto.Migrator,
       repos: Application.fetch_env!(:termelix, :ecto_repos), skip: skip_migrations?()},
      # Per-user DEK cache/unsealer; depends on SystemCrypto's ENCRYPTION_KEY.
      Termelix.Crypto.UserKeyManager
    ]

    opts = [
      strategy: :rest_for_one,
      max_restarts: 3,
      max_seconds: 30,
      name: Termelix.CoreSupervisor
    ]

    %{
      id: Termelix.CoreSupervisor,
      type: :supervisor,
      start: {Supervisor, :start_link, [children, opts]}
    }
  end

  # Independent runtime services: none is a prerequisite for another, so `:one_for_one`
  # keeps a crash local — a Registry that flaps must not take the endpoint (and with it
  # every `restart: :temporary` terminal session) down with it. Looser intensity than the
  # core, because leaf churn under load is expected rather than fatal.
  #
  # `max_children` on the three DynamicSupervisors is a memory bound, not a product limit:
  # their children are all `restart: :temporary`, so restart intensity never fires and this
  # is the only thing standing between a client that opens sessions in a loop and the node.
  defp runtime_supervisor do
    children = [
      # Owns the process-less rate-limiter + HTTP-cache + file-manager-session ETS tables for
      # the node's lifetime and sweeps their expired rows. First here so the tables exist
      # before the endpoint accepts a request, but isolated by `:one_for_one` so a Repo or
      # migrator restart cannot reset a brute-force counter (see core_supervisor/0).
      Termelix.EtsOwner,
      {Task.Supervisor, name: Termelix.TaskSupervisor},
      {Phoenix.PubSub, name: Termelix.PubSub},
      # Persistent terminal sessions (survive WebSocket disconnects until expiry).
      {Registry, keys: :unique, name: Termelix.Terminal.Registry},
      {DynamicSupervisor,
       name: Termelix.Terminal.SessionSupervisor, strategy: :one_for_one, max_children: 200},
      # SSH tunnels (one supervised GenServer per active tunnel).
      {Registry, keys: :unique, name: Termelix.Tunnels.Registry},
      {DynamicSupervisor,
       name: Termelix.Tunnels.TunnelSupervisor, strategy: :one_for_one, max_children: 100},
      # Pooled data-plane SSH connections (one per unique host+credential set).
      {Registry, keys: :unique, name: Termelix.SSH.ConnRegistry},
      {DynamicSupervisor,
       name: Termelix.SSH.ConnSupervisor, strategy: :one_for_one, max_children: 100},
      # Server-side tmux watchers — one per watched host, started by subscriber interest, NOT
      # one per host that exists. `max_children` bounds how many hosts can be watched at once;
      # past it `ensure_started/2` refuses and the caller falls back to the on-demand poll.
      {Registry, keys: :unique, name: Termelix.Tmux.WatcherRegistry},
      {DynamicSupervisor,
       name: Termelix.Tmux.WatcherSupervisor, strategy: :one_for_one, max_children: 100},
      # Ages out session recordings. The retention setting has shipped since the port and has
      # never done anything — a policy that only exists in a settings screen tells an operator
      # their transcripts are being deleted while the volume fills.
      # Buffers `api_keys.last_used_at` so an agent in a loop does not write per request.
      Termelix.ApiKeys.Usage,
      Termelix.Terminal.RecordingPruner,
      # Periodic node/host resource sampling for the dashboard.
      Termelix.SystemMonitor,
      # Start to serve requests, typically the last entry
      TermelixWeb.Endpoint
    ]

    opts = [
      strategy: :one_for_one,
      max_restarts: 10,
      max_seconds: 60,
      name: Termelix.RuntimeSupervisor
    ]

    %{
      id: Termelix.RuntimeSupervisor,
      type: :supervisor,
      start: {Supervisor, :start_link, [children, opts]}
    }
  end

  # Elixir's Logger translator renders a GenServer/GenEvent terminate as
  #
  #     [[…, "\nLast message", from, ": ", inspect(msg)], "\nState: ", inspect(state) | client]
  #
  # at `:debug`, and as the bare inner list (no state at all) at higher levels — verified on
  # Elixir 1.20/OTP 29, and prod runs at `:info` (config/prod.exs:10). Redact in place rather
  # than dropping elements: Sentry matches this exact shape to group the event under a
  # pid-free message (error_backend.ex:227-319), and a report it cannot parse is reported
  # verbatim instead.
  defp redact([header, "\nState: ", _state | rest]) when is_list(header) do
    [redact_last_message(header), "\nState: ", @redacted | rest]
  end

  defp redact(chardata) when is_list(chardata), do: redact_last_message(chardata)
  defp redact(chardata), do: chardata

  # Walked by hand rather than with Enum: chardata may be an improper list (`["a" | "b"]`),
  # and a filter that raises is dropped by :logger — taking the redaction with it.
  defp redact_last_message([element | rest]) do
    if last_message_marker?(element) do
      [element | redact_tail(rest)]
    else
      [element | redact_last_message(rest)]
    end
  end

  defp redact_last_message(other), do: other

  # The inspected message is the final element after the marker; the elements before it are
  # separators ("(from #PID<…>)", ": ") that Sentry's pattern needs to keep matching.
  defp redact_tail([_last]), do: [@redacted]
  defp redact_tail([element | rest]), do: [element | redact_tail(rest)]
  defp redact_tail(_empty_or_improper), do: [@redacted]

  defp last_message_marker?(element) when is_binary(element),
    do: String.starts_with?(element, "\nLast message")

  defp last_message_marker?(_element), do: false

  defp skip_migrations?() do
    # By default, sqlite migrations are run when using a release
    System.get_env("RELEASE_NAME") == nil
  end
end
