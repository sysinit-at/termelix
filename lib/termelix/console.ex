defmodule Termelix.Console do
  @moduledoc """
  Operator introspection for a release with distribution switched off.

  `bin/termelix rpc` and `bin/termelix remote` both need Erlang distribution, and this release
  runs without it — a deliberate choice, since a distributed node on a self-hosted box is an
  extra listening port and an extra trust boundary for a feature one person uses occasionally.
  The cost is that the ordinary way to ask a running release a question does not work.

  `bin/termelix eval` still does, but it starts a SEPARATE node: it can read the database and
  the config, and it can see nothing about the processes that are actually running. Everything
  in this module is written to be useful from that separate node, and each function says which
  of the two it is answering from — because "no sessions" is a very different statement
  depending on whether you asked the live node or a fresh one.

  Usage:

      docker exec termelix /app/bin/termelix eval 'Termelix.Console.status()'
  """

  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo

  @doc """
  Everything an operator usually wants first, from a fresh `eval` node: what is in the
  database, what the instance settings say, and which subsystems are switched on.

  Deliberately does NOT report live sessions or connections — an `eval` node has none, and
  printing "0 sessions" would be a lie of the most confusing kind.
  """
  @spec status() :: :ok
  def status do
    ensure_started()

    print("Termelix #{version()}", [
      {"database", database_summary()},
      {"settings", settings_summary()},
      {"features", feature_summary()}
    ])
  end

  @doc "What the database holds. Safe from an `eval` node — this is all it can honestly see."
  @spec database_summary() :: keyword()
  def database_summary do
    ensure_started()

    [
      users: count(Termelix.Schema.User),
      hosts: count(Termelix.Schema.Host),
      api_keys: count(Termelix.Schema.ApiKey),
      active_api_keys: count(from(k in Termelix.Schema.ApiKey, where: k.isActive == true)),
      auth_sessions: count(Termelix.Schema.Session),
      recordings: count(Termelix.Schema.SessionRecording),
      audit_rows: count(Termelix.Schema.AuditLog),
      terminal_bindings: count(Termelix.Schema.TerminalBinding)
    ]
  end

  @doc "The instance settings that change behaviour, and what they are set to."
  @spec settings_summary() :: keyword()
  def settings_summary do
    ensure_started()

    [
      ssh_host_key_policy: setting("ssh_host_key_policy", "tofu_warn"),
      session_recording_enabled: setting("session_recording_enabled", "false"),
      session_recording_retention_days: setting("session_recording_retention_days", "30"),
      alerts_egress_allow_private: setting("alerts_egress_allow_private", "false"),
      alerts_allow_plaintext_egress: setting("alerts_allow_plaintext_egress", "false")
    ]
  end

  @doc "Which subsystems this build has, so a deploy can be confirmed without reading a diff."
  @spec feature_summary() :: keyword()
  def feature_summary do
    [
      agent_api: function_exported?(Termelix.Agent, :hosts, 1),
      mcp: Code.ensure_loaded?(TermelixWeb.McpController),
      tmux_watcher: Code.ensure_loaded?(Termelix.Tmux.Watcher),
      recording: Code.ensure_loaded?(Termelix.Terminal.Recorder),
      egress_allowlist: Code.ensure_loaded?(Termelix.Net.Egress)
    ]
  end

  @doc """
  Live process counts — meaningful ONLY inside the running node.

  From an `eval` node every number here is zero, and that is not information. It is exposed for
  a future in-node console (and for tests), and it says so rather than being quietly wrong.
  """
  @spec live_summary() :: keyword()
  def live_summary do
    [
      terminal_sessions: registry_size(Termelix.Terminal.Registry),
      tunnels: registry_size(Termelix.Tunnels.Registry),
      pooled_connections: registry_size(Termelix.SSH.ConnRegistry),
      tmux_watchers: registry_size(Termelix.Tmux.WatcherRegistry),
      note: "zero from an `eval` node — it is a different VM"
    ]
  end

  @doc "Deactivate every API key for a user, from the shell. Prints what it did."
  @spec revoke_keys(String.t()) :: :ok
  def revoke_keys(user_id) do
    ensure_started()
    count = Termelix.ApiKeys.deactivate_all_for_user(user_id)
    IO.puts("deactivated #{count} api key(s) for #{user_id}")
    :ok
  end

  # --- internals --------------------------------------------------------------

  # `bin/termelix eval` does NOT start the application, and starting it naively fails: the
  # release is already listening on the HTTP port, so `TermelixWeb.Endpoint` cannot bind and the
  # whole supervision tree refuses to come up. The first version of this swallowed that and
  # reported `:unavailable` for every count — on the live release, which is the only place it
  # was ever going to run.
  #
  # So the endpoint is switched off for this node before starting. Nothing here serves HTTP;
  # it only needs the Repo and the settings cache.
  defp ensure_started do
    if Process.whereis(Repo) do
      :ok
    else
      Application.load(:termelix)

      config =
        :termelix
        |> Application.get_env(TermelixWeb.Endpoint, [])
        |> Keyword.put(:server, false)

      Application.put_env(:termelix, TermelixWeb.Endpoint, config)
      {:ok, _apps} = Application.ensure_all_started(:termelix)
      :ok
    end
  rescue
    error ->
      # Said out loud. A status readout that silently reports nothing is worse than one that
      # explains why, because the person running it is already trying to work out what is wrong.
      IO.puts("console: could not start the application: #{Exception.message(error)}")
      :error
  end

  defp count(queryable) do
    Repo.aggregate(queryable, :count)
  rescue
    # A table this build does not have, or a Repo that would not start. Reported rather than
    # crashing the whole readout — this is what an operator runs when something is already
    # wrong, and it should still print everything it CAN answer.
    _error -> :unavailable
  end

  defp setting(key, default) do
    Termelix.Settings.get_value(key) || default
  rescue
    _error -> default
  end

  defp registry_size(registry) do
    Registry.count(registry)
  rescue
    _error -> 0
  catch
    _, _ -> 0
  end

  defp version do
    case :application.get_key(:termelix, :vsn) do
      {:ok, vsn} -> to_string(vsn)
      _ -> "unknown"
    end
  end

  defp print(title, sections) do
    IO.puts("\n#{title}")

    Enum.each(sections, fn {name, entries} ->
      IO.puts("\n  #{name}")

      Enum.each(entries, fn {key, value} ->
        IO.puts("    #{String.pad_trailing(to_string(key), 34)} #{inspect(value)}")
      end)
    end)

    IO.puts("")
    :ok
  end
end
