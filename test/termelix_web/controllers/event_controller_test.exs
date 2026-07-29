defmodule TermelixWeb.EventControllerTest do
  @moduledoc """
  `GET /events` is a HELD connection, and `Plug.Test`'s adapter only accumulates chunks into
  state that the caller reads when the conn returns — which, for a stream, is never. Driving
  this through `ConnCase` would assert on a return value that does not exist yet, so these
  tests start the real endpoint and read the response off a real socket.

  That is not ceremony. Everything interesting about SSE lives in the parts `ConnCase` cannot
  see: whether the headers say `text/event-stream`, whether frames are actually flushed rather
  than buffered until close, and whether the connection stays open between them.
  """
  use Termelix.DataCase, async: false

  alias Termelix.{Accounts, Hosts}
  alias Termelix.Tmux.Watcher

  @moduletag :sse

  setup_all do
    # `config/test.exs` runs the endpoint with `server: false`, so there is no listener. Rather
    # than restart the application endpoint (every other test in the VM shares it), put a
    # second Bandit listener in front of the SAME plug on a random port. Same code path, no
    # global state touched.
    {:ok, server} =
      Bandit.start_link(plug: TermelixWeb.Endpoint, scheme: :http, ip: {127, 0, 0, 1}, port: 0)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)

    # The heartbeat is also how an abandoned stream is noticed: blocked in `receive`, the
    # handler cannot be told the client went away, so the next failing `chunk/2` is what
    # releases it. 200ms here keeps teardown fast AND makes that reclaim observable.
    Application.put_env(:termelix, :sse_heartbeat_ms, 200)

    # Bounded: a stream still held open would otherwise make teardown wait for it.
    on_exit(fn ->
      # Kill, do not stop: ThousandIsland's graceful shutdown waits for in-flight connections,
      # and a stream is in-flight by design — a graceful stop would wait for the very thing
      # this endpoint exists to hold open. Reverting the heartbeat AFTER, so any stream still
      # looping keeps the short one.
      if Process.alive?(server), do: Process.exit(server, :kill)
      Application.delete_env(:termelix, :sse_heartbeat_ms)
    end)

    %{port: port}
  end

  setup %{port: port} do
    # No sandbox call here: `Termelix.DataCase` already starts a SHARED owner for a non-async
    # module, which is what lets the Bandit connection processes see the same transaction.
    # Re-setting the mode to `{:shared, self()}` fights that owner and the request processes
    # lose their access mid-stream.
    username = "sse-#{System.unique_integer([:positive])}"
    {:ok, user, _} = Accounts.register_user(username, "password-123-abc")
    token = login(port, username, "password-123-abc")

    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "sse-host",
        ip: "127.0.0.1",
        port: 22,
        username: "tester",
        authType: "password",
        password: "secret",
        enableTmuxMonitor: false
      })

    on_exit(fn -> Watcher.stop(user.id, host.id) end)
    %{user: user, token: token, host: host, port: port}
  end

  test "unauthenticated is refused", %{port: port} do
    {:ok, socket} = connect(port, nil)
    assert read_until(socket, ~r/HTTP\/1.1 (401|403)/, 5_000)
  end

  test "the stream announces itself with SSE headers and a ready event", ctx do
    {:ok, socket} = connect(ctx.port, ctx.token)

    assert head = read_until(socket, ~r/event: ready/, 5_000)
    assert head =~ "HTTP/1.1 200"
    assert head =~ "text/event-stream"
    # Without this an nginx in front holds every frame until the connection closes, which is
    # indistinguishable from a stream that is simply broken.
    assert head =~ "x-accel-buffering: no"
    assert head =~ ctx.user.id

    :gen_tcp.close(socket)
  end

  test "a watcher's state event reaches the client, with its age", ctx do
    {:ok, socket} = connect(ctx.port, ctx.token)
    assert read_until(socket, ~r/event: ready/, 5_000)

    broadcast(
      ctx.user.id,
      {:tmux_state, ctx.host.id, %{available: true, sessions: [], age_ms: 4}}
    )

    assert frame = read_until(socket, ~r/event: tmux_state/, 5_000)
    assert frame =~ ~s("hostId":#{ctx.host.id})
    # A cached value with no age is indistinguishable from a live one.
    assert frame =~ ~s("ageMs":4)

    :gen_tcp.close(socket)
  end

  test "a notable transition reaches the client — the event the agent loop is built on", ctx do
    {:ok, socket} = connect(ctx.port, ctx.token)
    assert read_until(socket, ~r/event: ready/, 5_000)

    broadcast(
      ctx.user.id,
      {:tmux_transition, ctx.host.id, %{pane_id: "%3", from: :working, to: :awaiting_input}}
    )

    assert frame = read_until(socket, ~r/event: tmux_transition/, 5_000)
    assert frame =~ ~s("paneId":"%3")
    assert frame =~ ~s("to":"awaiting_input")

    :gen_tcp.close(socket)
  end

  test "one user's events never reach another user's stream", ctx do
    {:ok, other, _} =
      Accounts.register_user("sse-o-#{System.unique_integer([:positive])}", "password-123-abc")

    {:ok, socket} = connect(ctx.port, ctx.token)
    assert read_until(socket, ~r/event: ready/, 5_000)

    broadcast(other.id, {:tmux_state, 999, %{available: true, sessions: []}})

    refute read_until(socket, ~r/event: tmux_state/, 800)
    :gen_tcp.close(socket)
  end

  test "a client that goes away releases its slot instead of holding it forever", ctx do
    # Blocked in `receive`, the handler cannot be told the socket closed. The heartbeat's
    # failing write is the only thing that notices — without it, a user reloading their page
    # would lock themselves out of their own event stream.
    for _ <- 1..8 do
      {:ok, socket} = connect(ctx.port, ctx.token)
      assert read_until(socket, ~r/event: ready/, 5_000)
      :gen_tcp.close(socket)
    end

    # At the cap with every one of them abandoned. A ninth is refused until the heartbeats have
    # swept, and MUST succeed once they have — retried against a deadline rather than slept
    # past, so this fails loudly if the reclaim ever stops working instead of just being slow.
    assert eventually(5_000, fn ->
             {:ok, socket} = connect(ctx.port, ctx.token)
             got = read_until(socket, ~r/event: ready/, 400)
             :gen_tcp.close(socket)
             got != nil
           end),
           "the slots were never reclaimed"
  end

  test "revocation closes the stream — it must not be the one thing that survives", ctx do
    {:ok, socket} = connect(ctx.port, ctx.token)
    assert read_until(socket, ~r/event: ready/, 5_000)

    # Sessions, tunnels and pooled connections are all torn down by `Termelix.Revocation`. A
    # held HTTP connection would be the sole survivor, and it is the one that keeps delivering
    # this user's fleet state to whoever still holds the socket.
    Termelix.Revocation.revoke_user(ctx.user.id, :test)

    assert seen = read_until(socket, ~r/event: revoked/, 5_000)

    # The RESPONSE must end, which in HTTP/1.1 chunked encoding is the zero-length terminating
    # chunk — not a TCP close. Bandit keeps the connection for keep-alive, correctly, so
    # asserting on a socket close would be asserting on the wrong layer and would pass only by
    # accident on a server that did not implement keep-alive.
    assert read_until(socket, ~r/\r\n0\r\n\r\n/, 5_000, seen), "the stream never terminated"
    :gen_tcp.close(socket)
  end

  # --- helpers ---------------------------------------------------------------

  defp eventually(timeout, fun) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_eventually(deadline, fun)
  end

  defp do_eventually(deadline, fun) do
    cond do
      fun.() -> true
      System.monotonic_time(:millisecond) >= deadline -> false
      true -> do_eventually(deadline, fun)
    end
  end

  defp broadcast(user_id, message),
    do: Phoenix.PubSub.broadcast(Termelix.PubSub, Watcher.user_topic(user_id), message)

  defp login(port, username, password) do
    body = Jason.encode!(%{username: username, password: password})

    request =
      "POST /users/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n" <>
        "Content-Length: #{byte_size(body)}\r\nConnection: close\r\n\r\n" <> body

    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)
    :ok = :gen_tcp.send(socket, request)
    response = read_all(socket, 5_000)
    :gen_tcp.close(socket)

    [_, token] = Regex.run(~r/jwt=([^;]+);/, response)
    token
  end

  defp connect(port, token) do
    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)

    auth = if token, do: "Authorization: Bearer #{token}\r\n", else: ""

    request =
      "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n" <> auth <> "\r\n"

    :ok = :gen_tcp.send(socket, request)
    {:ok, socket}
  end

  # Read until `pattern` matches everything seen so far, or the deadline passes. Returns the
  # WHOLE accumulated buffer on a match and `nil` on timeout, so a `refute` reads naturally.
  #
  # The buffer is threaded between calls on purpose. Returning only the matched portion loses
  # whatever arrived in the same TCP segment after it — and the terminating chunk of a stream
  # routinely arrives in the same segment as the last event, so a second assertion would wait
  # forever for bytes the first assertion had already thrown away.
  defp read_until(socket, pattern, timeout, acc \\ "") do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_read_until(socket, pattern, deadline, acc)
  end

  defp do_read_until(socket, pattern, deadline, acc) do
    remaining = deadline - System.monotonic_time(:millisecond)

    cond do
      Regex.match?(pattern, acc) ->
        acc

      remaining <= 0 ->
        nil

      true ->
        case :gen_tcp.recv(socket, 0, min(remaining, 250)) do
          {:ok, data} -> do_read_until(socket, pattern, deadline, acc <> data)
          {:error, :timeout} -> do_read_until(socket, pattern, deadline, acc)
          {:error, _closed} -> if Regex.match?(pattern, acc), do: acc, else: nil
        end
    end
  end

  defp read_all(socket, timeout, acc \\ "") do
    case :gen_tcp.recv(socket, 0, timeout) do
      {:ok, data} -> read_all(socket, timeout, acc <> data)
      {:error, _} -> acc
    end
  end
end
