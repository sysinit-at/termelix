defmodule Termelix.Agent do
  @moduledoc """
  The agent verbs as plain functions: authority in, data out, no `%Plug.Conn{}` anywhere.

  This module exists because "both, over one core" has to be true of the *code*, not just of
  the description. The first attempt had `McpController` call `AgentController`'s actions and
  re-wrap what they wrote. That works under `Plug.Test`, whose adapter buffers the response —
  and fails on a real socket, where the bytes are already gone and cannot be unsent. Every MCP
  test passed while the live endpoint returned the bare REST body followed by a crash.

  So the core is a context, and the two controllers are what they should have been from the
  start: thin renderers. A door that needs a different shape reshapes the data, not the
  response.

  Every function takes the `key` and does its OWN authorization. Not because the plugs are
  wrong — the REST door still uses them — but because a second caller with a different
  transport is exactly how an authorization check gets skipped, and the check belongs where
  the verb is, not where one of its doors is.
  """

  alias Termelix.{ApiKeys, Audit, Hosts, RateLimiter, Tmux}
  alias Termelix.Schema.ApiKey
  alias Termelix.Tmux.{Orchestrator, Watcher}

  @type result :: {:ok, map()} | {:error, atom() | tuple()}

  @doc "The hosts this key may act on, and the scopes it holds."
  @spec hosts(ApiKey.t()) :: result()
  def hosts(key) do
    public = ApiKeys.to_public(key)
    allowed = MapSet.new(public.hostIds)

    hosts =
      key.userId
      |> Hosts.list_for_user(decrypt: false)
      |> Enum.filter(&MapSet.member?(allowed, &1.id))
      |> Enum.map(
        &%{id: &1.id, name: &1.name, folder: &1.folder, tmuxMonitor: &1.enableTmuxMonitor}
      )

    {:ok, %{hosts: hosts, scopes: public.scopes}}
  end

  @doc "Every pane on a host, with what it is doing."
  @spec panes(ApiKey.t(), term()) :: result()
  def panes(key, host_id) do
    with {:ok, host} <- authorize(key, host_id, "tmux:read") do
      # The watcher's cache first: an agent polling this in a loop must not become one SSH exec
      # per call. `ageMs` travels with it so the caller can judge the freshness itself.
      Watcher.ensure_started(key.userId, host.id)

      case Watcher.snapshot(key.userId, host.id) do
        {:ok, snapshot} ->
          {:ok, %{hostId: host.id, ageMs: snapshot[:age_ms], panes: flatten(snapshot)}}

        :miss ->
          case Tmux.overview(host, key.userId) do
            {:ok, overview} -> {:ok, %{hostId: host.id, ageMs: 0, panes: flatten(overview)}}
            {:error, reason} -> {:error, reason}
          end
      end
    end
  end

  @doc "Create or attach a named session, and say which pane to work in."
  @spec ensure_session(ApiKey.t(), term(), String.t(), keyword()) :: result()
  def ensure_session(key, host_id, session, opts \\ []) do
    with {:ok, host} <- authorize(key, host_id, "tmux:write"),
         :ok <- budget(key, host) do
      case Orchestrator.ensure_session(host, session, opts) do
        {:ok, result} ->
          audit(
            key,
            host,
            "agent_ensure_session",
            result.session,
            %{created: result.created},
            opts
          )

          {:ok, %{session: result.session, paneId: result.pane, created: result.created}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc "Read a pane's screen, with a verdict about it."
  @spec capture(ApiKey.t(), term(), String.t(), keyword()) :: result()
  def capture(key, host_id, pane, opts \\ []) do
    with {:ok, host} <- authorize(key, host_id, "tmux:read"),
         :ok <- present(pane) do
      case Orchestrator.capture(host, pane, opts) do
        {:ok, result} ->
          {:ok,
           %{paneId: pane, text: result.text, activity: result.activity, lines: result.lines}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc "Type a command into a pane and run it."
  @spec dispatch(ApiKey.t(), term(), String.t(), String.t(), keyword()) :: result()
  def dispatch(key, host_id, pane, command, opts \\ []) do
    with {:ok, host} <- authorize(key, host_id, "tmux:write"),
         :ok <- present(pane),
         :ok <- budget(key, host) do
      case Orchestrator.dispatch(host, pane, to_string(command)) do
        {:ok, result} ->
          # With the command: a machine acted on a machine with nobody watching, and "what did
          # it run" must be answerable from the log alone.
          audit(key, host, "agent_dispatch", pane, %{command: result.command}, opts)
          {:ok, %{paneId: pane}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc "Type text (and optionally Enter) into a pane — the quick-reply verb."
  @spec send_keys(ApiKey.t(), term(), String.t(), [term()], keyword()) :: result()
  def send_keys(key, host_id, pane, keys, opts \\ []) do
    with {:ok, host} <- authorize(key, host_id, "tmux:write"),
         :ok <- present(pane),
         :ok <- budget(key, host),
         {:ok, keys} <- normalize_keys(keys) do
      case Orchestrator.send_keys(host, pane, keys) do
        :ok ->
          # The COUNT, never the text: this is the verb that answers a password prompt.
          audit(key, host, "agent_send_keys", pane, %{keys: length(keys)}, opts)
          {:ok, %{paneId: pane}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Block until a pane reaches a state.

  `{:ok, %{timedOut: true}}` rather than an error when the budget runs out: a wait that ran its
  course is a correct answer to the question asked, and an error would push a caller into a
  retry loop around something that is merely still working.
  """
  @spec wait(ApiKey.t(), term(), String.t(), keyword()) :: result()
  def wait(key, host_id, pane, opts \\ []) do
    with {:ok, host} <- authorize(key, host_id, "tmux:wait"),
         :ok <- present(pane),
         :ok <- claim_wait(key) do
      try do
        do_wait(key, host, pane, opts)
      after
        release_wait(key)
      end
    end
  end

  defp do_wait(key, host, pane, opts) do
    case Orchestrator.wait(key.userId, host.id, pane, opts) do
      {:ok, result} ->
        {:ok, %{paneId: pane, state: result.state, waitedMs: result[:waited_ms], timedOut: false}}

      {:error, :timeout, result} ->
        {:ok, %{paneId: pane, state: result.state, timedOut: true}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  The HTTP status a reason should be reported as.

  One table, so the REST door and the MCP door cannot disagree about whether something was the
  caller's fault.
  """
  @spec status(term()) :: pos_integer()
  def status(:forbidden), do: 403
  def status({:missing_scope, _scope}), do: 403
  def status(:missing_scope), do: 403
  def status(:locked), do: 423
  def status(:rate_limited), do: 429
  def status(:too_many_waits), do: 429
  def status({:ssh, _reason}), do: 502
  def status(reason) when reason in [:invalid_pane, :empty_command, :multiline_command], do: 400

  def status(reason) when reason in [:invalid_session, :invalid_directory, :nothing_to_send],
    do: 400

  def status({:unsupported_key, _key}), do: 400
  def status({:unknown_states, _states}), do: 400
  def status(_reason), do: 500

  @doc "A human-readable message for a reason. Same table, same reason."
  @spec message(term()) :: String.t()
  def message(:forbidden), do: "This key is not scoped to that host"
  def message(:locked), do: "Encrypted data is locked"
  def message(:rate_limited), do: "Too many commands for this host"
  def message(:too_many_waits), do: "Too many concurrent waits"
  def message(:invalid_pane), do: "Invalid pane ID"
  def message(:empty_command), do: "Command is required"
  def message(:multiline_command), do: "Command must be a single line"
  def message(:invalid_session), do: "Invalid session name"
  def message(:invalid_directory), do: "Invalid path"
  def message(:nothing_to_send), do: "Nothing to send"
  def message({:unsupported_key, _key}), do: "Unsupported key or control byte"
  def message({:unknown_states, _states}), do: "Unknown wait state"
  def message({:ssh, _reason}), do: "Could not reach the host"
  def message(:missing_scope), do: "This key lacks the required scope"
  def message({:missing_scope, scope}), do: "This key lacks the #{scope} scope"
  def message(_reason), do: "tmux command failed"

  # --- authorization ----------------------------------------------------------

  # Scope, then host scope, then ownership — and the last two collapse into the SAME error.
  # Distinguishing "not in scope" from "no such host" would let a key enumerate which host ids
  # exist by comparing the answers.
  defp authorize(key, host_id, scope) do
    with {:ok, id} <- host_id(host_id),
         true <- ApiKeys.has_scope?(key, scope) || {:error, {:missing_scope, scope}},
         true <- ApiKeys.allows_host?(key, id) || {:error, :forbidden} do
      case Hosts.fetch_for_connect(id, key.userId) do
        {:ok, host} -> {:ok, host}
        {:error, :locked} -> {:error, :locked}
        {:error, :not_found} -> {:error, :forbidden}
      end
    else
      {:error, _reason} = error -> error
      _ -> {:error, :forbidden}
    end
  end

  defp host_id(id) when is_integer(id), do: {:ok, id}

  defp host_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {int, ""} -> {:ok, int}
      _ -> {:error, :forbidden}
    end
  end

  defp host_id(_id), do: {:error, :forbidden}

  defp budget(key, host) do
    case RateLimiter.check_orchestrate(key.userId, host.id) do
      :ok ->
        RateLimiter.record_orchestrate(key.userId, host.id)
        :ok

      {:error, _retry_after} ->
        {:error, :rate_limited}
    end
  end

  # A wait HOLDS a connection for up to fifteen minutes and is deliberately exempt from the
  # per-host command budget (it costs no SSH of its own, and charging for it would penalise
  # exactly the pattern it exists to encourage). That left it with no bound at all: an agent in
  # a loop — or a buggy one that never reads the reply — can pin one Bandit connection process
  # per call, indefinitely, and nothing in the request path says no. The SSE stream has had a
  # cap since P6 for the same reason; this is the same resource wearing a different name.
  @max_concurrent_waits 8
  @wait_table :termelix_agent_waits

  defp claim_wait(key) do
    ensure_wait_table()

    if :ets.update_counter(@wait_table, key.userId, {2, 1}, {key.userId, 0}) >
         @max_concurrent_waits do
      :ets.update_counter(@wait_table, key.userId, {2, -1}, {key.userId, 0})
      {:error, :too_many_waits}
    else
      :ok
    end
  end

  defp release_wait(key) do
    ensure_wait_table()
    :ets.update_counter(@wait_table, key.userId, {2, -1, 0, 0}, {key.userId, 0})
    :ok
  rescue
    _ -> :ok
  end

  @doc false
  @spec ensure_wait_table() :: :ok
  def ensure_wait_table do
    case :ets.whereis(@wait_table) do
      :undefined ->
        :ets.new(@wait_table, [:named_table, :public, :set, write_concurrency: true])
        :ok

      _tid ->
        :ok
    end
  rescue
    ArgumentError -> :ok
  end

  defp present(pane) when is_binary(pane) and pane != "", do: :ok
  defp present(_pane), do: {:error, :invalid_pane}

  defp normalize_keys(keys) do
    case Enum.reject(keys, &valid_key?/1) do
      [] when keys == [] -> {:error, :nothing_to_send}
      [] -> {:ok, keys}
      _invalid -> {:error, {:unsupported_key, :unknown}}
    end
  end

  defp valid_key?(key) when key in [:enter, :ctrl_c, :escape], do: true
  defp valid_key?({:literal, text}) when is_binary(text), do: true
  defp valid_key?(_key), do: false

  # --- shaping ----------------------------------------------------------------

  # Flat: one row per pane, with its session and window as fields rather than as nesting. An
  # agent asking "what needs me" wants a list it can filter, not a tree to walk.
  defp flatten(snapshot) do
    for session <- Map.get(snapshot, :sessions, []),
        window <- Map.get(session, :windows, []),
        pane <- Map.get(window, :panes, []) do
      %{
        paneId: Map.get(pane, :id),
        session: Map.get(session, :name),
        window: Map.get(window, :name),
        command: Map.get(pane, :topCommand) || Map.get(pane, :command),
        path: Map.get(pane, :path),
        activity: Map.get(pane, :activity),
        evidence: Map.get(pane, :activityEvidence, [])
      }
    end
  end

  # The audit actor is the KEY, not just the user: with several agent keys per person, "the
  # user did it" is not an answer anybody can act on.
  #
  # The caller's IP travels in `opts`. It was lost when this moved out of the controller — the
  # controller had a conn and this does not — and for a credential used by MACHINES, *which*
  # machine used it is close to the only forensic question worth asking. A context that cannot
  # see a conn must be handed what it needs, not quietly do without it.
  defp audit(key, host, action, resource_name, details, opts) do
    Audit.log(%{id: key.userId, username: "key:" <> key.keyPrefix}, action, "host", %{
      resource_id: to_string(host.id),
      resource_name: resource_name,
      details: Jason.encode!(Map.put(details, :apiKey, key.keyPrefix)),
      ip_address: Keyword.get(opts, :client_ip),
      user_agent: Keyword.get(opts, :user_agent, "api-key")
    })
  end
end
