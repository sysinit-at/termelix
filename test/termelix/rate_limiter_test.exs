defmodule Termelix.RateLimiterTest do
  @moduledoc """
  Unit tests for the fixed-window buckets. Time is injected (`now_ms`) so windows
  advance instantly instead of sleeping. The named table is owned for the node's
  lifetime by `Termelix.EtsOwner` (started with the app); `reset_all/0` clears it
  between tests so each starts from a clean slate.

  async: false because the named ETS table is VM-global.
  """
  use ExUnit.Case, async: false

  alias Termelix.RateLimiter

  @t0 1_000_000_000

  setup do
    RateLimiter.reset_all()
    :ok
  end

  test "ensure_table/0 is idempotent" do
    assert :ok = RateLimiter.ensure_table()
    assert :ok = RateLimiter.ensure_table()
  end

  describe "login bucket (10 failures / 10 minutes per IP+username)" do
    test "the 11th failure is refused with a countdown retry-after" do
      assert :ok = RateLimiter.check_login("1.2.3.4", "alice", @t0)

      assert Enum.map(1..10, fn _ -> RateLimiter.record_login_failure("1.2.3.4", "alice", @t0) end) ==
               Enum.to_list(1..10)

      # Full window (600s) is quoted at the moment of the last failure...
      assert {:error, 600} = RateLimiter.check_login("1.2.3.4", "alice", @t0)
      # ...and counts down as the window elapses.
      assert {:error, 300} = RateLimiter.check_login("1.2.3.4", "alice", @t0 + 300_000)
      # Once the window expires the bucket reopens.
      assert :ok = RateLimiter.check_login("1.2.3.4", "alice", @t0 + 600_000)
    end

    test "under the limit the check stays open" do
      for _ <- 1..9, do: RateLimiter.record_login_failure("1.2.3.4", "alice", @t0)
      assert :ok = RateLimiter.check_login("1.2.3.4", "alice", @t0)
    end

    test "a record after window expiry starts a fresh window" do
      for _ <- 1..10, do: RateLimiter.record_login_failure("1.2.3.4", "alice", @t0)
      assert {:error, _} = RateLimiter.check_login("1.2.3.4", "alice", @t0)

      assert 1 = RateLimiter.record_login_failure("1.2.3.4", "alice", @t0 + 600_001)
      assert :ok = RateLimiter.check_login("1.2.3.4", "alice", @t0 + 600_001)
    end

    test "reset_login/2 clears the bucket (successful login)" do
      for _ <- 1..10, do: RateLimiter.record_login_failure("1.2.3.4", "alice", @t0)
      assert {:error, _} = RateLimiter.check_login("1.2.3.4", "alice", @t0)

      assert :ok = RateLimiter.reset_login("1.2.3.4", "alice")
      assert :ok = RateLimiter.check_login("1.2.3.4", "alice", @t0)
    end

    test "buckets are independent per IP+username" do
      for _ <- 1..10, do: RateLimiter.record_login_failure("1.2.3.4", "alice", @t0)

      assert {:error, _} = RateLimiter.check_login("1.2.3.4", "alice", @t0)
      assert :ok = RateLimiter.check_login("1.2.3.4", "bob", @t0)
      assert :ok = RateLimiter.check_login("5.6.7.8", "alice", @t0)
    end
  end

  describe "totp bucket (5 failures / 10 minutes per user)" do
    test "failures report remaining attempts down to lockout" do
      assert :ok = RateLimiter.check_totp("user-1", @t0)

      assert 4 = RateLimiter.record_totp_failure("user-1", @t0)
      assert 3 = RateLimiter.record_totp_failure("user-1", @t0)
      assert 2 = RateLimiter.record_totp_failure("user-1", @t0)
      assert 1 = RateLimiter.record_totp_failure("user-1", @t0)
      assert 0 = RateLimiter.record_totp_failure("user-1", @t0)

      assert {:error, 600} = RateLimiter.check_totp("user-1", @t0)
      assert :ok = RateLimiter.check_totp("user-2", @t0)
    end

    test "reset_totp/1 reopens the bucket" do
      for _ <- 1..5, do: RateLimiter.record_totp_failure("user-1", @t0)
      assert {:error, _} = RateLimiter.check_totp("user-1", @t0)

      assert :ok = RateLimiter.reset_totp("user-1")
      assert :ok = RateLimiter.check_totp("user-1", @t0)
    end
  end

  describe "registration bucket (10 attempts / hour per IP)" do
    test "the 11th attempt is refused until the hour elapses" do
      assert Enum.map(1..10, fn _ -> RateLimiter.record_register_attempt("1.2.3.4", @t0) end) ==
               Enum.to_list(1..10)

      assert {:error, 3600} = RateLimiter.check_register("1.2.3.4", @t0)
      assert :ok = RateLimiter.check_register("5.6.7.8", @t0)
      assert :ok = RateLimiter.check_register("1.2.3.4", @t0 + 3_600_000)
    end
  end

  describe "totp anti-replay marker" do
    test "the accepted step only advances strictly" do
      assert nil == RateLimiter.last_totp_step("user-1")

      assert :ok = RateLimiter.record_totp_step("user-1", 100)
      assert 100 = RateLimiter.last_totp_step("user-1")

      # Same or older steps are replays and rejected.
      assert :error = RateLimiter.record_totp_step("user-1", 100)
      assert :error = RateLimiter.record_totp_step("user-1", 99)
      assert 100 = RateLimiter.last_totp_step("user-1")

      assert :ok = RateLimiter.record_totp_step("user-1", 101)
      assert 101 = RateLimiter.last_totp_step("user-1")
    end

    test "reset_totp_step/1 forgets the marker" do
      assert :ok = RateLimiter.record_totp_step("user-1", 100)
      assert :ok = RateLimiter.reset_totp_step("user-1")
      assert nil == RateLimiter.last_totp_step("user-1")
      assert :ok = RateLimiter.record_totp_step("user-1", 100)
    end

    test "concurrent first-ever claim of a step: exactly one caller wins" do
      RateLimiter.reset_totp_step("race-a")

      results =
        1..200
        |> Task.async_stream(fn _ -> RateLimiter.record_totp_step("race-a", 500) end,
          max_concurrency: 50,
          ordered: false
        )
        |> Enum.map(fn {:ok, r} -> r end)

      assert Enum.count(results, &(&1 == :ok)) == 1
      assert Enum.count(results, &(&1 == :error)) == 199
      assert 500 == RateLimiter.last_totp_step("race-a")
    end

    test "concurrent advance of an existing marker: exactly one caller wins" do
      RateLimiter.reset_totp_step("race-b")
      assert :ok = RateLimiter.record_totp_step("race-b", 100)

      results =
        1..200
        |> Task.async_stream(fn _ -> RateLimiter.record_totp_step("race-b", 200) end,
          max_concurrency: 50,
          ordered: false
        )
        |> Enum.map(fn {:ok, r} -> r end)

      assert Enum.count(results, &(&1 == :ok)) == 1
      assert Enum.count(results, &(&1 == :error)) == 199
      assert 200 == RateLimiter.last_totp_step("race-b")
    end
  end

  describe "sweep_expired/1" do
    test "removes buckets whose window has elapsed, keeping live buckets and totp_step markers" do
      RateLimiter.record_login_failure("1.2.3.4", "alice", @t0)
      RateLimiter.record_totp_failure("user-1", @t0)
      RateLimiter.record_reauth_failure("user-1", @t0)
      RateLimiter.record_register_attempt("1.2.3.4", @t0)
      # The anti-replay marker is windowless and must never be swept on the time basis.
      assert :ok = RateLimiter.record_totp_step("user-1", 100)

      # Nothing has elapsed yet.
      assert 0 = RateLimiter.sweep_expired(@t0)

      # Past the 10-min login/totp/reauth windows but before the 60-min register
      # window: those three buckets are removed; the register bucket and the marker
      # remain.
      assert 3 = RateLimiter.sweep_expired(@t0 + 600_001)
      assert :ok = RateLimiter.check_login("1.2.3.4", "alice", @t0 + 600_001)
      assert :ok = RateLimiter.check_totp("user-1", @t0 + 600_001)
      assert :ok = RateLimiter.check_reauth("user-1", @t0 + 600_001)
      assert 100 = RateLimiter.last_totp_step("user-1")

      # Past the hour the registration bucket goes too; the marker still survives.
      assert 1 = RateLimiter.sweep_expired(@t0 + 3_600_001)
      assert 100 = RateLimiter.last_totp_step("user-1")
    end
  end
end
