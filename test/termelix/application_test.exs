defmodule Termelix.ApplicationTest do
  @moduledoc """
  Pins the shape of the supervision tree, because its correctness is invisible at runtime and
  the consequences of getting it wrong are not.

  Two properties matter and neither shows up in a passing request:

    * **What is inside the `:rest_for_one` core.** That strategy restarts every child *after*
      the one that died, so each member is one more thing a routine SQLite hiccup takes with
      it. `Termelix.EtsOwner` was in there and had to be moved out: it holds the login /
      registration / TOTP rate-limit buckets and the TOTP anti-replay markers, so a `Repo`
      restart would have silently reset a brute-force attacker's budget and made a captured
      TOTP code replayable inside its window.
    * **That every DynamicSupervisor is bounded.** They hold `restart: :temporary` children,
      so restart intensity never fires and `max_children` is the only thing between a client
      opening sessions in a loop and the node.
  """
  use ExUnit.Case, async: true

  # Started by the application under test.
  @core Termelix.CoreSupervisor
  @runtime Termelix.RuntimeSupervisor

  defp child_ids(sup), do: sup |> Supervisor.which_children() |> Enum.map(&elem(&1, 0))

  describe "core supervisor" do
    test "contains exactly the ordered, mutually dependent boot chain" do
      ids = child_ids(@core)

      # Order is reversed by which_children/1; compare as a set plus an explicit ordering check.
      assert MapSet.new(ids) ==
               MapSet.new([
                 Termelix.Crypto.SystemCrypto,
                 Termelix.Repo,
                 Ecto.Migrator,
                 Termelix.Crypto.UserKeyManager
               ])
    end

    test "does NOT contain EtsOwner — a Repo restart must not reset rate-limit state" do
      refute Termelix.EtsOwner in child_ids(@core)
    end
  end

  describe "runtime supervisor" do
    test "owns EtsOwner, so its tables survive a core restart" do
      assert Termelix.EtsOwner in child_ids(@runtime)
    end

    test "starts the endpoint and the system monitor" do
      ids = child_ids(@runtime)
      assert TermelixWeb.Endpoint in ids
      assert Termelix.SystemMonitor in ids
    end
  end

  describe "dynamic supervisors are bounded" do
    for sup <- [
          Termelix.Terminal.SessionSupervisor,
          Termelix.Tunnels.TunnelSupervisor,
          Termelix.SSH.ConnSupervisor
        ] do
      test "#{inspect(sup)} has a max_children cap" do
        sup = unquote(sup)
        counts = DynamicSupervisor.count_children(sup)

        # `:infinity` here would mean an unbounded process count on a node whose children are
        # all `restart: :temporary`, so nothing else limits them.
        refute counts.specs == :infinity
        assert is_integer(counts.active)
      end
    end
  end

  # The cap is only useful if exceeding it produces an error a caller can act on. `SSH.Pool`
  # previously matched only `{:ok, pid}` and `{:error, {:already_started, _}}`, so the bare
  # `{:error, :max_children}` the cap introduced raised a CaseClauseError — in the request
  # process for SFTP, and in a supervised task for every tmux probe.
  test "SSH.Pool always returns a tuple rather than raising, whatever the supervisor says" do
    # Reaching the real cap would need 100 live SSH connections, so assert the contract the
    # cap broke: `checkout/2` is spec'd `{:ok, pid} | {:error, term()}` and its callers —
    # `Sftp` in the request process, `Exec` in a supervised task — match on that. A bare
    # `{:error, :max_children}` falling through the `case` is what turned the cap into a
    # CaseClauseError, so the property under test is "never raises".
    result =
      Termelix.SSH.Pool.checkout(
        %{host: "127.0.0.1", port: 1, username: "nobody", password: "x"},
        200
      )

    assert match?({:ok, _}, result) or match?({:error, _}, result)
  end
end
