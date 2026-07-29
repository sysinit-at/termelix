defmodule Termelix.WsTicketsTest do
  @moduledoc """
  Single-use enforcement for WS-upgrade tickets: a minted ticket verifies exactly once, two
  distinct tickets are independent, wrong-salt/expired/garbage tickets never consume, and the
  sweeper bounds the jti table. (`async: false` — the ETS table is shared node-wide.)
  """
  use ExUnit.Case, async: false

  alias Termelix.WsTickets

  setup do
    WsTickets.reset_all()
    :ok
  end

  test "a ticket verifies exactly once; the second consume is rejected" do
    ticket = WsTickets.mint("user-1", "ssh")

    assert {:ok, "user-1"} = WsTickets.consume("ssh", ticket)
    assert :error = WsTickets.consume("ssh", ticket)
  end

  test "two different tickets for the same user both work" do
    ticket_a = WsTickets.mint("user-1", "ssh")
    ticket_b = WsTickets.mint("user-1", "ssh")

    assert ticket_a != ticket_b
    assert {:ok, "user-1"} = WsTickets.consume("ssh", ticket_a)
    assert {:ok, "user-1"} = WsTickets.consume("ssh", ticket_b)
  end

  test "a wrong-salt ticket is rejected WITHOUT consuming its jti" do
    ticket = WsTickets.mint("user-1", "ssh")

    assert :error = WsTickets.consume("other", ticket)
    assert {:ok, "user-1"} = WsTickets.consume("ssh", ticket)
  end

  test "garbage and legacy (jti-less) payloads are rejected" do
    assert :error = WsTickets.consume("ssh", "not-a-token")

    legacy = Phoenix.Token.sign(TermelixWeb.Endpoint, "ssh_ws", "user-1")
    assert :error = WsTickets.consume("ssh", legacy)
  end

  test "an expired ticket is rejected" do
    ticket =
      Phoenix.Token.sign(TermelixWeb.Endpoint, "ssh_ws", %{uid: "user-1", jti: "stale"},
        signed_at: System.system_time(:second) - 3600
      )

    assert :error = WsTickets.consume("ssh", ticket)
  end

  test "sweep_expired removes only lapsed jtis" do
    ticket = WsTickets.mint("user-1", "ssh")
    assert {:ok, "user-1"} = WsTickets.consume("ssh", ticket)
    now = System.monotonic_time(:millisecond)

    assert WsTickets.sweep_expired(now) == 0
    assert WsTickets.sweep_expired(now + 61_000) == 1
    assert WsTickets.sweep_expired(now + 61_000) == 0
  end
end
