defmodule TermelixWeb.EventController do
  @moduledoc """
  `GET /events` — the server-to-client push channel, and the piece that makes the whole agent
  loop possible from a browser.

  Everything before this was pull: the monitor polled, the terminal polled, and a state change
  reached a human only when their browser next happened to ask. "Dispatch a command, walk away,
  get told when it needs you" cannot be built on that at all — a client that has to ask cannot
  be told.

  ## Why SSE and not a WebSocket

  One direction, text, and it must survive an idle proxy. SSE is HTTP: it inherits the JWT
  cookie, the `:authenticated` pipeline and the reverse proxy's existing configuration, and it
  reconnects with `Last-Event-ID` without a line of client code. A WebSocket would need its own
  auth handshake and its own reconnect logic to deliver strictly less.

  ## Scoping

  Per user. A stream carries `tmux:<user_id>` only, so there is no filtering step in which a
  future subsystem could publish to the wrong topic and have it forwarded — the subscription
  itself is the boundary.

  ## Backfill

  A reconnect passes `Last-Event-ID` (or `?lastEventId=`), and the stream answers with a
  current snapshot of every host it can serve from cache before resuming live events. It is
  deliberately a SNAPSHOT rather than a replay of missed events: replay needs a durable buffer
  and gives the client a history it has to fold, while the client only ever wanted the current
  state. This costs the client nothing and cannot get out of step.

  ## Heartbeat

  A comment frame every `@heartbeat_ms`. Idle proxies close silent connections, and without it
  the failure mode is the worst kind: a stream that looks connected and delivers nothing.

  **The existing poll stays.** This is an addition, not a replacement: a client that never
  subscribes keeps working exactly as it did.
  """
  use TermelixWeb, :controller

  require Logger

  alias Termelix.Hosts
  alias Termelix.Tmux.Watcher

  # Also the liveness probe: blocked in `receive`, this process cannot be told the client went
  # away, so the failing `chunk/2` on the next heartbeat is how an abandoned stream is noticed
  # and its slot released. That makes the interval a detection window, not just proxy hygiene —
  # 25 s meant a user reloading their page five times inside it locked themselves out.
  @heartbeat_ms 15_000

  # Configurable because it is two things at once, and an operator may need to tune either: a
  # proxy in front with a short idle timeout needs it lower, and it is also how fast an
  # abandoned stream is reclaimed.
  defp heartbeat_ms, do: Application.get_env(:termelix, :sse_heartbeat_ms, @heartbeat_ms)

  # A stream is a held connection, so this is a real resource limit, not a rate limit. Past it a
  # client falls back to the poll it already has.
  @max_streams_per_user 8

  @doc """
  Open the stream. Does not return until the client disconnects or the user is revoked.
  """
  def stream(conn, params) do
    user_id = conn.assigns.current_user_id

    case claim_stream(user_id) do
      :ok ->
        try do
          run_stream(conn, user_id, params)
        after
          release_stream(user_id)
        end

      :error ->
        conn
        |> put_status(429)
        |> json(%{error: "Too many open event streams"})
    end
  end

  defp run_stream(conn, user_id, params) do
    Phoenix.PubSub.subscribe(Termelix.PubSub, Watcher.user_topic(user_id))
    # Also the revocation topic. Without this the stream is the ONE thing `Termelix.Revocation`
    # cannot reach: sessions, tunnels and pooled connections all stop, and a held HTTP
    # connection keeps delivering this user's fleet state to whoever still has the socket.
    Phoenix.PubSub.subscribe(Termelix.PubSub, Termelix.Revocation.topic())

    conn =
      conn
      |> put_resp_header("content-type", "text/event-stream")
      |> put_resp_header("cache-control", "no-cache, no-store")
      # Proxies that buffer will hold every event until the connection closes, which is
      # indistinguishable from a broken stream. nginx honours this header.
      |> put_resp_header("x-accel-buffering", "no")
      |> send_chunked(200)

    with {:ok, conn} <- send_event(conn, "ready", %{userId: user_id}),
         {:ok, conn} <- backfill(conn, user_id, last_event_id(conn, params)) do
      loop(conn, user_id, 0)
    else
      {:error, _reason} -> conn
    end
  end

  # Start every watcher the user has an interest in, then send what each already knows. A
  # subscriber arriving is exactly the "interest" that justifies the SSH loop existing.
  defp backfill(conn, user_id, _last_event_id) do
    user_id
    |> watchable_hosts()
    |> Enum.reduce_while({:ok, conn}, fn host, {:ok, conn} ->
      Watcher.ensure_started(user_id, host.id)

      case Watcher.snapshot(user_id, host.id) do
        {:ok, snapshot} ->
          case send_event(conn, "tmux_state", encode_snapshot(host.id, snapshot)) do
            {:ok, conn} -> {:cont, {:ok, conn}}
            error -> {:halt, error}
          end

        :miss ->
          {:cont, {:ok, conn}}
      end
    end)
  end

  defp watchable_hosts(user_id) do
    user_id
    |> Hosts.list_for_user(decrypt: false)
    |> Enum.filter(&(&1.enableTmuxMonitor == true and &1.enableSsh != false))
  end

  defp loop(conn, user_id, event_id) do
    receive do
      {:tmux_state, host_id, snapshot} ->
        continue(conn, user_id, event_id, "tmux_state", encode_snapshot(host_id, snapshot))

      {:tmux_transition, host_id, transition} ->
        continue(conn, user_id, event_id, "tmux_transition", %{
          hostId: host_id,
          paneId: transition.pane_id,
          from: transition.from,
          to: transition.to
        })

      {:revoked, ^user_id, reason} ->
        # Access is gone; the stream must not outlive it. Everything else this user held was
        # already torn down by `Termelix.Revocation` — a held HTTP connection would be the one
        # survivor, and it is the one that keeps delivering their data.
        {:ok, conn} = send_event(conn, "revoked", %{reason: reason})
        conn

      _other ->
        loop(conn, user_id, event_id)
    after
      heartbeat_ms() ->
        # A comment frame: valid SSE, ignored by every client, and the only thing that keeps an
        # idle proxy from closing a stream that is working perfectly well.
        case chunk(conn, ": heartbeat\n\n") do
          {:ok, conn} -> loop(conn, user_id, event_id)
          {:error, _reason} -> conn
        end
    end
  end

  defp continue(conn, user_id, event_id, type, payload) do
    # Keeps the watchers alive: an open stream IS the interest that justifies them.
    touch_all(user_id, payload)

    case send_event(conn, type, payload, event_id + 1) do
      {:ok, conn} -> loop(conn, user_id, event_id + 1)
      {:error, _reason} -> conn
    end
  end

  defp touch_all(user_id, %{hostId: host_id}) when is_integer(host_id),
    do: Watcher.touch(user_id, host_id)

  defp touch_all(_user_id, _payload), do: :ok

  defp send_event(conn, type, payload, id \\ 0) do
    frame = "id: #{id}\nevent: #{type}\ndata: #{Jason.encode!(payload)}\n\n"
    chunk(conn, frame)
  rescue
    # An unencodable payload must not kill the stream — drop the event, keep the channel.
    error ->
      Logger.warning("SSE: dropping #{type}: #{Exception.message(error)}")
      {:ok, conn}
  end

  defp encode_snapshot(host_id, snapshot) do
    %{
      hostId: host_id,
      ageMs: Map.get(snapshot, :age_ms, 0),
      available: Map.get(snapshot, :available, false),
      unwatchable: Map.get(snapshot, :unwatchable),
      sessions: Map.get(snapshot, :sessions, [])
    }
  end

  defp last_event_id(conn, params) do
    case get_req_header(conn, "last-event-id") do
      [id | _] -> id
      [] -> params["lastEventId"]
    end
  end

  # --- stream accounting ------------------------------------------------------

  @counter_table :termelix_event_streams

  defp claim_stream(user_id) do
    ensure_counter_table()

    if :ets.update_counter(@counter_table, user_id, {2, 1}, {user_id, 0}) >
         @max_streams_per_user do
      :ets.update_counter(@counter_table, user_id, {2, -1}, {user_id, 0})
      :error
    else
      :ok
    end
  end

  defp release_stream(user_id) do
    ensure_counter_table()
    :ets.update_counter(@counter_table, user_id, {2, -1, 0, 0}, {user_id, 0})
    :ok
  rescue
    _ -> :ok
  end

  @doc false
  @spec ensure_counter_table() :: :ok
  def ensure_counter_table do
    case :ets.whereis(@counter_table) do
      :undefined ->
        :ets.new(@counter_table, [:named_table, :public, :set, write_concurrency: true])
        :ok

      _tid ->
        :ok
    end
  rescue
    # Another process created it between the `whereis` and here.
    ArgumentError -> :ok
  end
end
