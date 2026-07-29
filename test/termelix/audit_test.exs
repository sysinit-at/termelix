defmodule Termelix.AuditTest do
  @moduledoc """
  Data-layer tests for `Termelix.Audit`: the `log/4` convenience, `record/1`'s best-effort
  write, and the paginated/filterable read surface (`list_page/1`, `list_distinct_actions/0`,
  `delete_by_user_id/1`).
  """
  use Termelix.DataCase

  alias Termelix.Audit
  alias Termelix.Schema.User

  setup do
    # These tests insert rows directly, which the write-path counter cannot see. Production
    # never does that — `log/4` is the only writer — so the counter is reset here rather than
    # made to re-scan on every call.
    Termelix.Audit.forget_row_count()

    alice = make_user("alice", true)
    bob = make_user("bob", false)
    %{alice: alice, bob: bob}
  end

  describe "log/4 and record/1" do
    test "log/4 persists a row with the supplied metadata", %{alice: alice} do
      Audit.log(alice, "make_admin", "user", %{
        resource_id: "target-1",
        resource_name: "victim",
        ip_address: "203.0.113.7",
        user_agent: "TestAgent/1.0"
      })

      %{logs: [log], total: 1} = Audit.list_page(page(%{}))

      assert log.userId == alice.id
      assert log.username == "alice"
      assert log.action == "make_admin"
      assert log.resourceType == "user"
      assert log.resourceId == "target-1"
      assert log.resourceName == "victim"
      assert log.ipAddress == "203.0.113.7"
      assert log.userAgent == "TestAgent/1.0"
      assert log.success == true
      assert is_binary(log.timestamp)
    end

    test "username falls back to the id when the struct username is nil", %{alice: alice} do
      # FK is on the id (which exists); only the display username is nil here.
      assert :ok = Audit.log(%User{id: alice.id, username: nil}, "login", "user", %{})

      %{logs: [log]} = Audit.list_page(page(%{}))
      assert log.username == alice.id
      assert log.success == true
    end

    test "record/1 never raises on a bad row" do
      # userId is NOT NULL — the insert fails, but the caller must see :ok, not a crash.
      assert :ok = Audit.record(%{username: "nobody", action: "boom", resourceType: "user"})
    end
  end

  describe "pruning" do
    test "consent rows survive pruning even as the oldest entries", %{alice: alice} do
      # The consent row is deliberately the OLDEST row — the first pruning candidate if
      # it were not exempt.
      Audit.record_strict!(%{
        userId: alice.id,
        username: alice.username,
        action: "error_reporting_enable",
        resourceType: "settings",
        timestamp: "2020-01-01T00:00:00Z"
      })

      # Bulk-fill past the prune threshold (10_000). Chunked: SQLite caps bind params.
      filler =
        for n <- 1..10_000 do
          %{
            userId: alice.id,
            username: alice.username,
            action: "filler",
            resourceType: "test",
            success: true,
            timestamp: "2021-01-01T00:00:0#{rem(n, 10)}Z"
          }
        end

      filler
      |> Enum.chunk_every(500)
      |> Enum.each(&Termelix.Repo.insert_all(Termelix.Schema.AuditLog, &1))

      # `insert_all` bypasses the write path, so the row counter has not seen those 10_000
      # rows. Production never bulk-inserts audit rows — `record/1` is the only writer — so the
      # counter is forgotten here rather than made to re-scan on every write, which is the whole
      # point of having it. Erasing it makes the next write re-seed from the database, which is
      # the same self-correction a prune performs.
      Audit.forget_row_count()

      # The next best-effort write trips the prune.
      Audit.log(alice, "trigger", "test")

      %{total: 1} = Audit.list_page(page(%{action: "error_reporting_enable"}))
      %{total: total} = Audit.list_page(page(%{}))
      assert total <= 9_001
    end
  end

  describe "list_page/1 filtering and pagination" do
    setup %{alice: alice, bob: bob} do
      rec(alice, "make_admin", "user", "2026-01-01T00:00:00Z", true)
      rec(alice, "delete_user", "user", "2026-02-01T00:00:00Z", false)
      rec(bob, "revoke_session", "session", "2026-03-01T00:00:00Z", true)
      :ok
    end

    test "orders newest-first and reports the total" do
      %{logs: logs, total: total} = Audit.list_page(page(%{}))
      assert total == 3
      assert Enum.map(logs, & &1.action) == ["revoke_session", "delete_user", "make_admin"]
    end

    test "paginates with limit/offset" do
      %{logs: page1, total: 3} = Audit.list_page(%{filters: %{}, limit: 2, offset: 0})
      %{logs: page2} = Audit.list_page(%{filters: %{}, limit: 2, offset: 2})
      assert length(page1) == 2
      assert length(page2) == 1
    end

    test "filters by userId", %{bob: bob} do
      %{logs: logs, total: 1} = Audit.list_page(page(%{userId: bob.id}))
      assert Enum.map(logs, & &1.action) == ["revoke_session"]
    end

    test "filters by action" do
      %{logs: [log], total: 1} = Audit.list_page(page(%{action: "delete_user"}))
      assert log.action == "delete_user"
    end

    test "filters by resourceType" do
      %{total: total} = Audit.list_page(page(%{resourceType: "session"}))
      assert total == 1
    end

    test "filters by success boolean" do
      %{total: ok} = Audit.list_page(page(%{success: true}))
      %{total: failed} = Audit.list_page(page(%{success: false}))
      assert ok == 2
      assert failed == 1
    end

    test "filters by inclusive date range" do
      %{logs: logs} =
        Audit.list_page(
          page(%{startDate: "2026-01-15T00:00:00Z", endDate: "2026-02-15T00:00:00Z"})
        )

      assert Enum.map(logs, & &1.action) == ["delete_user"]
    end

    test "nil and empty filters are ignored" do
      %{total: total} = Audit.list_page(page(%{userId: nil, action: ""}))
      assert total == 3
    end
  end

  describe "list_distinct_actions/0 and delete_by_user_id/1" do
    test "distinct actions come back sorted", %{alice: alice} do
      Audit.log(alice, "zeta", "user", %{})
      Audit.log(alice, "alpha", "user", %{})
      Audit.log(alice, "alpha", "user", %{})

      assert Audit.list_distinct_actions() == ["alpha", "zeta"]
    end

    test "delete_by_user_id removes only that user's rows", %{alice: alice, bob: bob} do
      Audit.log(alice, "a1", "user", %{})
      Audit.log(alice, "a2", "user", %{})
      Audit.log(bob, "b1", "user", %{})

      assert Audit.delete_by_user_id(alice.id) == 2
      assert %{total: 1} = Audit.list_page(page(%{}))
    end

    test "delete_by_user_id anonymizes consent rows instead of deleting them", %{alice: alice} do
      Audit.log(alice, "ordinary", "user", %{})
      Audit.log(alice, "error_reporting_enable", "settings", %{})

      assert Audit.delete_by_user_id(alice.id) == 1

      %{logs: [consent], total: 1} = Audit.list_page(page(%{}))
      assert consent.action == "error_reporting_enable"
      assert consent.userId == nil
      # Username stays for audit integrity — the row must remain attributable.
      assert consent.username == "alice"
    end

    test "deleting the user row itself leaves consent rows anonymized (FK SET NULL)", %{
      alice: alice
    } do
      Audit.log(alice, "error_reporting_disable", "settings", %{})

      Termelix.Repo.delete!(alice)

      %{logs: [consent]} = Audit.list_page(page(%{action: "error_reporting_disable"}))
      assert consent.userId == nil
      assert consent.username == "alice"
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp page(filters), do: %{filters: filters, limit: 50, offset: 0}

  defp rec(user, action, resource_type, timestamp, success) do
    Audit.record(%{
      userId: user.id,
      username: user.username,
      action: action,
      resourceType: resource_type,
      success: success,
      timestamp: timestamp
    })
  end

  defp make_user(username, admin?) do
    Repo.insert!(%User{
      id: Termelix.Id.generate(),
      username: username,
      passwordHash: "x",
      isAdmin: admin?,
      isOidc: false,
      totpEnabled: false,
      donationModalDismissed: false,
      registeredAt: DateTime.utc_now() |> DateTime.to_iso8601()
    })
  end
end
