defmodule TermelixWeb.TmuxController do
  @moduledoc """
  Ports the `/tmux_monitor` surface (port 30010) the frontend calls via `tmuxMonitorApi`
  (`src/ui/api/tmux-monitor-api.ts`): the polled **overview**, the per-user **session tags**,
  the **mutating actions** (focus, create session/window, rename, kill session/window/pane,
  split), and the batched **search** / per-pane **metrics**.

  The `Authenticate` plug has run, so the owner is `conn.assigns.current_user_id` — a body
  `userId` is never trusted. Every request runs the Node `requireHost` gate: a valid numeric
  host id, an unlocked user DEK, an owned+resolvable host, and the per-host `enableTmuxMonitor`
  opt-in (hiding the UI is not enough — the API must refuse too). The actual tmux work is
  short-lived one-shot SSH exec via `Termelix.Tmux`. Destructive actions (rename / kill*) land
  in the audit log like other host-level mutations; rename/kill also reconcile saved tags.

  There is no dedicated tmux WebSocket — the "live" view is the polled overview.
  """
  use Phoenix.Controller, formats: [:json]

  import TermelixWeb.ControllerHelpers, only: [client_ip: 1]

  alias Termelix.{Audit, Hosts, RateLimiter, Tmux}
  alias Termelix.Tmux.Orchestrator
  alias Termelix.Crypto.UserKeyManager

  # A tmux pane id as tmux prints it (`%N`).
  @pane_id_re ~r/^%\d+$/
  # New session names: tmux forbids ":" and "."; keep to a conservative printable subset so
  # the name is safe as a tmux target everywhere.
  @session_name_re ~r/^[A-Za-z0-9_@%+=-]{1,64}$/
  # Existing session names come from tmux's own listing, so they are only checked for
  # characters that would change a target's meaning.
  @target_breaking_re ~r/[:.\n]/

  # GET /tmux_monitor/overview — aggregate across all the user's tmux-enabled hosts.
  # DEK must be unlocked to decrypt host secrets for the fan-out probes.
  def overview_all(conn, _params) do
    user_id = conn.assigns.current_user_id

    if UserKeyManager.try_get_user_dek(user_id) == nil do
      error(conn, 401, "User data is locked")
    else
      json(conn, %{hosts: Tmux.overview_all(user_id)})
    end
  end

  # GET /tmux_monitor/:hostId/overview
  def overview(conn, %{"hostId" => host_id_param}) do
    user_id = conn.assigns.current_user_id

    case require_host(conn, host_id_param, user_id) do
      {:error, conn} ->
        conn

      {:ok, host} ->
        case Tmux.overview(host, user_id) do
          {:ok, result} -> json(conn, result)
          {:error, reason} -> send_tmux_error(conn, reason)
        end
    end
  end

  # PUT /tmux_monitor/:hostId/tags  body {sessionName, tags: string[]}
  def set_tags(conn, %{"hostId" => host_id_param} = params) do
    user_id = conn.assigns.current_user_id

    case require_host(conn, host_id_param, user_id) do
      {:error, conn} ->
        conn

      {:ok, host} ->
        session_name = params["sessionName"]

        cond do
          not valid_session_name?(session_name) ->
            error(conn, 400, "Missing session name")

          not valid_tags?(params["tags"]) ->
            error(conn, 400, "Tags must be an array of strings")

          true ->
            {:ok, clean} = Tmux.set_session_tags(user_id, host.id, session_name, params["tags"])
            json(conn, %{sessionName: session_name, tags: clean})
        end
    end
  end

  # --- mutating actions --------------------------------------------------------

  # POST /tmux_monitor/:hostId/focus  body {paneId}
  def focus(conn, %{"hostId" => host_id_param} = params) do
    with_host_and_pane(conn, host_id_param, params["paneId"], fn conn, host, pane_id ->
      case Tmux.focus(host, pane_id) do
        :ok -> json(conn, %{ok: true})
        {:error, reason} -> send_tmux_error(conn, reason)
      end
    end)
  end

  # POST /tmux_monitor/:hostId/sessions  body {name}
  def create_session(conn, %{"hostId" => host_id_param} = params) do
    with_host(conn, host_id_param, fn conn, host ->
      name = String.trim(str(params["name"]))

      if Regex.match?(@session_name_re, name) do
        case Tmux.create_session(host, name) do
          :ok ->
            json(conn, %{ok: true, name: name})

          {:error, reason} ->
            case classify_remote(reason) do
              :duplicate -> error(conn, 409, "A session with this name already exists")
              _ -> send_tmux_error(conn, reason)
            end
        end
      else
        error(conn, 400, "Invalid session name")
      end
    end)
  end

  # POST /tmux_monitor/:hostId/windows  body {sessionName}
  def create_window(conn, %{"hostId" => host_id_param} = params) do
    with_host_and_session(conn, host_id_param, params["sessionName"], fn conn, host, session ->
      case Tmux.create_window(host, session) do
        :ok ->
          json(conn, %{ok: true})

        {:error, reason} ->
          case classify_remote(reason) do
            :session_not_found -> error(conn, 404, "Session not found")
            _ -> send_tmux_error(conn, reason)
          end
      end
    end)
  end

  # POST /tmux_monitor/:hostId/rename  body {sessionName, newName}
  def rename(conn, %{"hostId" => host_id_param} = params) do
    with_host_and_session(conn, host_id_param, params["sessionName"], fn conn, host, session ->
      new_name = String.trim(str(params["newName"]))

      if Regex.match?(@session_name_re, new_name) do
        case Tmux.rename_session(host, session, new_name) do
          :ok ->
            Tmux.rename_session_tags(host.id, session, new_name)
            audit(conn, host, "tmux_session_rename", session, %{newName: new_name})
            json(conn, %{ok: true, name: new_name})

          {:error, reason} ->
            case classify_remote(reason) do
              :session_not_found -> error(conn, 404, "Session not found")
              :duplicate -> error(conn, 409, "A session with this name already exists")
              _ -> send_tmux_error(conn, reason)
            end
        end
      else
        error(conn, 400, "Invalid new session name")
      end
    end)
  end

  # POST /tmux_monitor/:hostId/kill  body {sessionName}
  def kill(conn, %{"hostId" => host_id_param} = params) do
    with_host_and_session(conn, host_id_param, params["sessionName"], fn conn, host, session ->
      case Tmux.kill_session(host, session) do
        :ok ->
          Tmux.delete_session_tags(host.id, session)
          audit(conn, host, "tmux_session_kill", session)
          json(conn, %{ok: true})

        {:error, reason} ->
          case classify_remote(reason) do
            :session_not_found -> error(conn, 404, "Session not found")
            _ -> send_tmux_error(conn, reason)
          end
      end
    end)
  end

  # POST /tmux_monitor/:hostId/kill-window  body {sessionName, windowIndex}
  def kill_window(conn, %{"hostId" => host_id_param} = params) do
    with_host_and_session(conn, host_id_param, params["sessionName"], fn conn, host, session ->
      case params["windowIndex"] do
        index when is_integer(index) and index >= 0 ->
          case Tmux.kill_window(host, session, index) do
            :ok ->
              audit(conn, host, "tmux_window_kill", session, %{windowIndex: index})
              json(conn, %{ok: true})

            {:error, reason} ->
              case classify_remote(reason) do
                kind when kind in [:session_not_found, :window_not_found] ->
                  error(conn, 404, "Window not found")

                _ ->
                  send_tmux_error(conn, reason)
              end
          end

        _ ->
          error(conn, 400, "Invalid window index")
      end
    end)
  end

  # POST /tmux_monitor/:hostId/kill-pane  body {paneId}
  def kill_pane(conn, %{"hostId" => host_id_param} = params) do
    with_host_and_pane(conn, host_id_param, params["paneId"], fn conn, host, pane_id ->
      case Tmux.kill_pane(host, pane_id) do
        :ok ->
          audit(conn, host, "tmux_pane_kill", pane_id)
          json(conn, %{ok: true})

        {:error, reason} ->
          case classify_remote(reason) do
            :pane_not_found -> error(conn, 404, "Pane not found")
            _ -> send_tmux_error(conn, reason)
          end
      end
    end)
  end

  # POST /tmux_monitor/:hostId/split  body {paneId, direction: "h" | "v"}
  def split(conn, %{"hostId" => host_id_param} = params) do
    with_host_and_pane(conn, host_id_param, params["paneId"], fn conn, host, pane_id ->
      case params["direction"] do
        direction when direction in ["h", "v"] ->
          case Tmux.split_pane(host, pane_id, direction) do
            :ok -> json(conn, %{ok: true})
            {:error, reason} -> send_tmux_error(conn, reason)
          end

        _ ->
          error(conn, 400, "Invalid split direction")
      end
    end)
  end

  # --- search / metrics --------------------------------------------------------

  # GET /tmux_monitor/:hostId/search?q=
  def search(conn, %{"hostId" => host_id_param} = params) do
    with_host(conn, host_id_param, fn conn, host ->
      query = String.trim(str(params["q"]))

      if query == "" do
        error(conn, 400, "Missing search query")
      else
        case Tmux.search(host, query) do
          {:ok, result} -> json(conn, Map.put(result, :query, query))
          {:error, reason} -> send_tmux_error(conn, reason)
        end
      end
    end)
  end

  # GET /tmux_monitor/:hostId/metrics
  def metrics(conn, %{"hostId" => host_id_param}) do
    with_host(conn, host_id_param, fn conn, host ->
      case Tmux.pane_metrics(host) do
        {:ok, panes} -> json(conn, %{panes: panes})
        {:error, reason} -> send_tmux_error(conn, reason)
      end
    end)
  end

  # --- orchestration verbs (P7) -----------------------------------------------

  # POST /tmux_monitor/:hostId/dispatch   body {paneId, command}
  #
  # Types a command into a live pane and presses Enter. Audited unconditionally and with the
  # command recorded: this is the one route where the server acts on a machine on someone's
  # behalf without a human at the keyboard, and "what did it run" must be answerable afterwards
  # from the audit log alone.
  def dispatch(conn, %{"hostId" => host_id_param} = params) do
    with_orchestration(conn, host_id_param, params["paneId"], fn conn, host, pane ->
      case Orchestrator.dispatch(host, pane, to_string(params["command"] || "")) do
        {:ok, result} ->
          audit(conn, host, "tmux_dispatch", pane, %{command: result.command})
          json(conn, %{ok: true, paneId: pane})

        {:error, :empty_command} ->
          error(conn, 400, "Command is required")

        {:error, :multiline_command} ->
          error(conn, 400, "Command must be a single line")

        {:error, :invalid_pane} ->
          error(conn, 400, "Invalid pane ID")

        {:error, reason} ->
          send_tmux_error(conn, reason)
      end
    end)
  end

  # POST /tmux_monitor/:hostId/send-keys  body {paneId, text?, keys?}
  #
  # The quick-reply case: answer a prompt without pressing Enter, or send a control key.
  def send_keys(conn, %{"hostId" => host_id_param} = params) do
    with_orchestration(conn, host_id_param, params["paneId"], fn conn, host, pane ->
      case parse_keys(params) do
        {:ok, []} ->
          error(conn, 400, "Nothing to send")

        {:ok, keys} ->
          case Orchestrator.send_keys(host, pane, keys) do
            :ok ->
              # The TEXT is deliberately not audited. This is the verb used to answer a
              # password prompt, and an audit trail that records the answer is worse than no
              # audit trail at all.
              audit(conn, host, "tmux_send_keys", pane, %{keys: length(keys)})
              json(conn, %{ok: true, paneId: pane})

            {:error, :invalid_pane} ->
              error(conn, 400, "Invalid pane ID")

            {:error, {:unsupported_key, _key}} ->
              error(conn, 400, "Unsupported key")

            {:error, reason} ->
              send_tmux_error(conn, reason)
          end

        :error ->
          error(conn, 400, "Invalid keys")
      end
    end)
  end

  # GET /tmux_monitor/:hostId/capture?paneId=&lines=
  def capture(conn, %{"hostId" => host_id_param} = params) do
    with_orchestration(conn, host_id_param, params["paneId"], fn conn, host, pane ->
      lines = params |> Map.get("lines") |> to_int()

      case Orchestrator.capture(host, pane, lines: lines) do
        {:ok, result} ->
          json(conn, %{
            paneId: pane,
            lines: result.lines,
            text: result.text,
            activity: result.activity
          })

        {:error, :invalid_pane} ->
          error(conn, 400, "Invalid pane ID")

        {:error, reason} ->
          send_tmux_error(conn, reason)
      end
    end)
  end

  # POST /tmux_monitor/:hostId/wait  body {paneId, until?, timeoutMs?}
  #
  # Held open until the pane reaches a target state. Not rate-limited by the orchestration
  # budget: a wait costs no SSH of its own (it rides the watcher that is already polling), and
  # counting it would penalise exactly the pattern this endpoint exists to encourage — waiting
  # instead of polling.
  def wait(conn, %{"hostId" => host_id_param} = params) do
    user_id = conn.assigns.current_user_id

    with {:ok, host} <- require_host(conn, host_id_param, user_id),
         pane when is_binary(pane) <- params["paneId"] do
      until = parse_until(params["until"])
      timeout = params |> Map.get("timeoutMs") |> to_int() |> clamp_wait_timeout()

      case Orchestrator.wait(user_id, host.id, pane, until: until, timeout_ms: timeout) do
        {:ok, result} ->
          json(conn, %{ok: true, paneId: pane, state: result.state, waitedMs: result[:waited_ms]})

        {:error, :timeout, result} ->
          # 200, not 408. A wait that ran its course without the pane changing is a correct
          # answer to the question asked — the caller needs the last known state, and an error
          # status would push it into a retry loop over something that is simply still working.
          json(conn, %{ok: false, paneId: pane, state: result.state, timedOut: true})

        {:error, :invalid_pane} ->
          error(conn, 400, "Invalid pane ID")

        {:error, {:unknown_states, _states}} ->
          error(conn, 400, "Unknown wait state")

        {:error, reason} ->
          send_tmux_error(conn, reason)
      end
    else
      {:error, %Plug.Conn{} = conn} -> conn
      _ -> error(conn, 400, "Invalid pane ID")
    end
  end

  # The orchestration gate: the monitor's host check, plus a per-(user, host) budget. These
  # verbs put keystrokes into a live terminal, and nothing downstream limits how fast a shell
  # will accept them.
  defp with_orchestration(conn, host_id_param, pane, fun) do
    user_id = conn.assigns.current_user_id

    with {:ok, host} <- require_host(conn, host_id_param, user_id),
         pane when is_binary(pane) and pane != "" <- pane,
         :ok <- RateLimiter.check_orchestrate(user_id, host.id) do
      RateLimiter.record_orchestrate(user_id, host.id)
      fun.(conn, host, pane)
    else
      {:error, %Plug.Conn{} = conn} ->
        conn

      {:error, retry_after} when is_integer(retry_after) ->
        conn
        |> put_resp_header("retry-after", Integer.to_string(retry_after))
        |> error(429, "Too many tmux commands for this host")

      _ ->
        error(conn, 400, "Invalid pane ID")
    end
  end

  defp parse_keys(params) do
    text = params["text"]
    named = params["keys"] || []

    literal = if is_binary(text) and text != "", do: [{:literal, text}], else: []

    case Enum.reduce_while(List.wrap(named), {:ok, []}, &named_key/2) do
      {:ok, keys} -> {:ok, literal ++ keys}
      :error -> :error
    end
  end

  defp named_key("enter", {:ok, acc}), do: {:cont, {:ok, acc ++ [:enter]}}
  defp named_key("ctrl_c", {:ok, acc}), do: {:cont, {:ok, acc ++ [:ctrl_c]}}
  defp named_key("escape", {:ok, acc}), do: {:cont, {:ok, acc ++ [:escape]}}
  defp named_key(_other, _acc), do: {:halt, :error}

  defp parse_until(nil), do: Orchestrator.default_until()

  defp parse_until(states) when is_list(states) do
    Enum.map(states, fn
      state when is_binary(state) -> safe_state(state)
      state -> state
    end)
  end

  defp parse_until(state) when is_binary(state), do: parse_until([state])
  defp parse_until(_other), do: Orchestrator.default_until()

  # `String.to_existing_atom/1` and not `to_atom/1`: these come off the wire, and an unbounded
  # atom table is a memory leak an attacker controls. An unknown name stays a string, which
  # `Orchestrator.validate_states/1` then rejects by name.
  defp safe_state(state) do
    String.to_existing_atom(state)
  rescue
    ArgumentError -> state
  end

  # A wait holds a connection, so the ceiling is a resource decision, not a preference.
  defp clamp_wait_timeout(nil), do: 300_000
  defp clamp_wait_timeout(ms) when is_integer(ms) and ms > 0, do: min(ms, 900_000)
  defp clamp_wait_timeout(_other), do: 300_000

  defp to_int(nil), do: nil
  defp to_int(value) when is_integer(value), do: value

  defp to_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> nil
    end
  end

  defp to_int(_value), do: nil

  # --- host gate (port of index.ts:requireHost) -------------------------------

  # `{:ok, host}` when the request may proceed, else `{:error, conn}` with the error already
  # written. Ordering mirrors the Node route: bad id → 400, locked DEK → 401, unknown/unowned
  # host → 404, monitor-disabled host → 403.
  defp require_host(conn, host_id_param, user_id) do
    case parse_host_id(host_id_param) do
      nil ->
        {:error, error(conn, 400, "Invalid host ID")}

      host_id ->
        cond do
          UserKeyManager.try_get_user_dek(user_id) == nil ->
            {:error, error(conn, 401, "User data is locked")}

          true ->
            resolve(conn, host_id, user_id)
        end
    end
  end

  defp resolve(conn, host_id, user_id) do
    case Hosts.fetch_for_connect(host_id, user_id) do
      {:ok, %{enableTmuxMonitor: true} = host} -> {:ok, host}
      {:ok, _host} -> {:error, error(conn, 403, "Tmux Monitor is not enabled for this host")}
      {:error, :locked} -> {:error, error(conn, 423, "Encrypted data is locked")}
      {:error, :not_found} -> {:error, error(conn, 404, "Host not found")}
    end
  end

  # parseInt-style: a leading integer (routes only ever produce plain digits), else nil.
  defp parse_host_id(id) when is_integer(id), do: id

  defp parse_host_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {n, _rest} -> n
      :error -> nil
    end
  end

  defp parse_host_id(_), do: nil

  # --- action combinators ------------------------------------------------------

  # Run `fun` with the gated host, else the error response require_host already wrote.
  defp with_host(conn, host_id_param, fun) do
    case require_host(conn, host_id_param, conn.assigns.current_user_id) do
      {:error, conn} -> conn
      {:ok, host} -> fun.(conn, host)
    end
  end

  # Gate + pane-id validation (`PANE_ID_RE`).
  defp with_host_and_pane(conn, host_id_param, pane_id, fun) do
    with_host(conn, host_id_param, fn conn, host ->
      pane_id = str(pane_id)

      if Regex.match?(@pane_id_re, pane_id),
        do: fun.(conn, host, pane_id),
        else: error(conn, 400, "Invalid pane ID")
    end)
  end

  # Gate + existing-session-name validation (non-empty, no target-breaking chars).
  defp with_host_and_session(conn, host_id_param, session_name, fun) do
    with_host(conn, host_id_param, fn conn, host ->
      session = String.trim(str(session_name))

      if session != "" and not Regex.match?(@target_breaking_re, session),
        do: fun.(conn, host, session),
        else: error(conn, 400, "Invalid session name")
    end)
  end

  # String(x || "") — the Node routes coerce every body field this way before validating.
  defp str(v) when is_binary(v), do: v
  defp str(_), do: ""

  # --- body validation --------------------------------------------------------

  # Node: `!sessionName || typeof sessionName !== "string"` → 400.
  defp valid_session_name?(v), do: is_binary(v) and v != ""

  # Node: `!Array.isArray(tags) || tags.some(t => typeof t !== "string")` → 400.
  defp valid_tags?(tags), do: is_list(tags) and Enum.all?(tags, &is_binary/1)

  # --- remote-error classification + audit -------------------------------------

  # Map tmux's own stderr text onto the contract's 404/409s (the Node routes' regexes).
  defp classify_remote({:command, msg}) do
    cond do
      msg =~ ~r/duplicate session/i -> :duplicate
      msg =~ ~r/can't find session|no such session/i -> :session_not_found
      msg =~ ~r/can't find window|no such window/i -> :window_not_found
      msg =~ ~r/can't find pane|no such pane/i -> :pane_not_found
      true -> :other
    end
  end

  defp classify_remote(_), do: :other

  # Destructive tmux actions terminate processes on the remote host, so they land in the
  # audit log like other host-level mutations (Node's `auditTmuxAction`).
  defp audit(conn, host, action, resource_name, details \\ nil) do
    Audit.log(conn.assigns.current_user, action, "host", %{
      resource_id: to_string(host.id),
      resource_name: resource_name,
      details: details && Jason.encode!(details),
      ip_address: client_ip(conn),
      user_agent: header(conn, "user-agent", "")
    })
  end

  defp header(conn, name, default) do
    case get_req_header(conn, name) do
      [v | _] -> v
      _ -> default
    end
  end

  # --- error classification (port of index.ts:classifyTmuxError/sendTmuxError) --

  # The overview only surfaces `{:ssh, reason}` (a probe connect failure); the classifier is
  # kept general so it maps the same buckets the Node route did.
  defp send_tmux_error(conn, reason) do
    message = error_message(reason)
    {code, http_status} = classify(message)

    error_text =
      case code do
        "TMUX_NOT_INSTALLED" -> "tmux is not installed on this host"
        "TMUX_NO_SERVER" -> "No tmux server is running on this host"
        "HOST_UNREACHABLE" -> "Could not connect to the host"
        "TMUX_ERROR" -> message
      end

    conn |> put_status(http_status) |> json(%{error: error_text, code: code})
  end

  defp classify(message) do
    cond do
      message =~ ~r/command not found|exited with code 127/i -> {"TMUX_NOT_INSTALLED", 503}
      message =~ ~r/no server running|lost server/i -> {"TMUX_NO_SERVER", 503}
      message =~ unreachable_regex() -> {"HOST_UNREACHABLE", 503}
      true -> {"TMUX_ERROR", 500}
    end
  end

  defp unreachable_regex do
    ~r/timeout|timed out|econnrefused|ehostunreach|enotfound|enetunreach|econnreset|authentication|handshake|keepalive|nxdomain/i
  end

  defp error_message({:ssh, {:connect_failed, reason}}),
    do: "connect failed: #{reason_text(reason)}"

  defp error_message({:ssh, reason}), do: reason_text(reason)
  defp error_message({:command, msg}), do: msg
  defp error_message(other), do: inspect(other)

  defp reason_text(reason) when is_binary(reason), do: reason
  defp reason_text(reason) when is_list(reason), do: List.to_string(reason)
  defp reason_text(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp reason_text(reason), do: inspect(reason)

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
