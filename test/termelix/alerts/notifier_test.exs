defmodule Termelix.Alerts.NotifierTest do
  @moduledoc """
  Outbound alert delivery. `Req` is stubbed through the `:alerts_req_options` app env (a
  `Req.Test` plug), so the webhook/ntfy request shape — method, path, headers, body — is asserted
  without real network I/O. Also covers the disabled-channel and unsupported-type short-circuits
  and the one-retry-then-error behaviour on persistent failure.
  """
  use ExUnit.Case, async: false

  alias Termelix.Alerts.Notifier

  @stub Termelix.Alerts.NotifierTest.Stub

  setup do
    Application.put_env(:termelix, :alerts_req_options, plug: {Req.Test, @stub})
    on_exit(fn -> Application.delete_env(:termelix, :alerts_req_options) end)
    :ok
  end

  describe "send_webhook/2" do
    test "POSTs the JSON payload with a merged content-type" do
      capture()

      assert :ok == Notifier.send_webhook(%{"url" => "https://example.com/hook"}, payload())

      assert_receive {:hit, method, "/hook", body, headers}
      assert method == "POST"
      assert {:ok, decoded} = Jason.decode(body)
      assert decoded["message"] == "CPU usage at 96.0% (threshold: 80%)"
      assert decoded["hostName"] == "web-1"
      assert decoded["severity"] == "critical"
      assert header(headers, "content-type") =~ "application/json"
    end

    test "honours a PUT method and custom headers from config" do
      capture()

      config = %{
        "url" => "https://example.com/hook",
        "method" => "PUT",
        "headers" => %{"x-token" => "abc"}
      }

      assert :ok == Notifier.send_webhook(config, payload())

      assert_receive {:hit, "PUT", "/hook", _body, headers}
      assert header(headers, "x-token") == "abc"
    end
  end

  describe "send_ntfy/2" do
    test "POSTs the message to <url>/<topic> with title/priority/tags/auth headers" do
      capture()

      config = %{"url" => "https://ntfy.sh", "topic" => "alerts", "token" => "tok"}
      assert :ok == Notifier.send_ntfy(config, payload())

      assert_receive {:hit, "POST", "/alerts", body, headers}
      assert body == "CPU usage at 96.0% (threshold: 80%)"
      assert header(headers, "title") == "[Termelix] web-1: cpu high"
      assert header(headers, "priority") == "5"
      assert header(headers, "tags") == "rotating_light"
      assert header(headers, "authorization") == "Bearer tok"
    end

    test "omits the Authorization header when no token is set" do
      capture()

      assert :ok ==
               Notifier.send_ntfy(
                 %{"url" => "https://ntfy.sh/", "topic" => "t"},
                 warning_payload()
               )

      assert_receive {:hit, "POST", "/t", _body, headers}
      assert header(headers, "authorization") == nil
      assert header(headers, "priority") == "3"
      assert header(headers, "tags") == "warning"
    end
  end

  describe "send_notification/2" do
    test "dispatches an enabled webhook channel" do
      capture()

      channel = %{type: "webhook", config: ~s({"url":"https://example.com/hook"}), enabled: true}
      assert :ok == Notifier.send_notification(channel, payload())
      assert_receive {:hit, "POST", "/hook", _, _}
    end

    test "a disabled channel is a silent no-op" do
      capture()

      channel = %{type: "webhook", config: ~s({"url":"https://example.com/hook"}), enabled: false}
      assert :ok == Notifier.send_notification(channel, payload())
      refute_receive {:hit, _, _, _, _}
    end

    test "an unparseable config is a silent no-op" do
      capture()

      channel = %{type: "webhook", config: "not json", enabled: true}
      assert :ok == Notifier.send_notification(channel, payload())
      refute_receive {:hit, _, _, _, _}
    end

    test "an unsupported channel type is reported as an error" do
      channel = %{type: "slack", config: "{}", enabled: true}
      assert {:error, :unsupported_channel} == Notifier.send_notification(channel, payload())
    end
  end

  describe "retry" do
    test "retries once, then returns an error on persistent failure" do
      {:ok, counter} = Agent.start_link(fn -> 0 end)

      Req.Test.stub(@stub, fn conn ->
        Agent.update(counter, &(&1 + 1))
        Req.Test.transport_error(conn, :econnrefused)
      end)

      assert {:error, _reason} =
               Notifier.send_webhook(%{"url" => "https://example.com/hook"}, payload())

      assert Agent.get(counter, & &1) == 2
    end

    test "a non-2xx status is a failure" do
      Req.Test.stub(@stub, fn conn -> Plug.Conn.send_resp(conn, 500, "boom") end)

      assert {:error, {:http_status, 500}} =
               Notifier.send_webhook(%{"url" => "https://example.com/hook"}, payload())
    end

    test "a 3xx redirect is NOT followed and fails delivery (SSRF hop guard)" do
      {:ok, paths} = Agent.start_link(fn -> [] end)

      Req.Test.stub(@stub, fn conn ->
        Agent.update(paths, &[conn.request_path | &1])

        case conn.request_path do
          "/hook" ->
            conn
            |> Plug.Conn.put_resp_header("location", "http://169.254.169.254/latest/meta-data")
            |> Plug.Conn.send_resp(302, "")

          _ ->
            Req.Test.json(conn, %{ok: true})
        end
      end)

      assert {:error, {:http_status, 302}} =
               Notifier.send_webhook(%{"url" => "https://example.com/hook"}, payload())

      # Both attempts (initial + one retry) stopped at the 302 — the redirect target was never
      # requested, so the Egress check on the channel URL cannot be hopped around.
      assert Agent.get(paths, &Enum.sort/1) == ["/hook", "/hook"]
    end
  end

  # --- helpers ----------------------------------------------------------------

  # Stub that echoes each request back to the test process, then replies 200.
  defp capture do
    test_pid = self()

    Req.Test.stub(@stub, fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      send(test_pid, {:hit, conn.method, conn.request_path, body, conn.req_headers})
      Req.Test.json(conn, %{ok: true})
    end)
  end

  defp header(headers, name) do
    case List.keyfind(headers, name, 0) do
      {^name, value} -> value
      nil -> nil
    end
  end

  defp payload do
    %{
      hostName: "web-1",
      hostId: 5,
      triggerType: "cpu_threshold",
      value: 96.0,
      threshold: 80.0,
      message: "CPU usage at 96.0% (threshold: 80%)",
      severity: "critical",
      timestamp: "2026-07-23T00:00:00.000Z",
      ruleId: 1,
      ruleName: "cpu high"
    }
  end

  defp warning_payload, do: %{payload() | severity: "warning"}
end
