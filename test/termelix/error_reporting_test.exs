defmodule Termelix.ErrorReportingTest do
  @moduledoc """
  The Sentry opt-in gate: reporting is off (and undecided) until an admin opts in, the
  decision persists in Settings and flips in both directions, and `before_send/1` drops
  every event while reporting is not explicitly enabled.
  """
  use Termelix.DataCase, async: false

  alias Termelix.ErrorReporting

  test "default state is disabled and undecided" do
    assert %{enabled: false, decided: false} = ErrorReporting.status()
    refute ErrorReporting.enabled?()
  end

  test "availability follows the configured DSN" do
    refute ErrorReporting.available?()
    assert %{available: false} = ErrorReporting.status()

    Application.put_env(:sentry, :dsn, "https://public@sentry.example/1")
    on_exit(fn -> Application.delete_env(:sentry, :dsn) end)

    assert ErrorReporting.available?()
    assert %{available: true} = ErrorReporting.status()

    Application.put_env(:sentry, :dsn, "   ")
    refute ErrorReporting.available?()
  end

  test "set_enabled persists and flips in both directions" do
    :ok = ErrorReporting.set_enabled(true)
    assert %{enabled: true, decided: true} = ErrorReporting.status()
    assert ErrorReporting.enabled?()

    :ok = ErrorReporting.set_enabled(false)
    assert %{enabled: false, decided: true} = ErrorReporting.status()
    refute ErrorReporting.enabled?()
  end

  test "before_send drops events until opted in, passes them through after" do
    event = %{fake: :event}

    assert ErrorReporting.before_send(event) == nil

    :ok = ErrorReporting.set_enabled(true)
    assert ErrorReporting.before_send(event) == event

    :ok = ErrorReporting.set_enabled(false)
    assert ErrorReporting.before_send(event) == nil
  end

  test "the sentry config routes events through the gate" do
    assert Application.get_env(:sentry, :before_send) == {ErrorReporting, :before_send}
  end

  describe "record_decision/3 (consent + audit, atomically)" do
    setup do
      {:ok, user, _admin?} = Termelix.Accounts.register_user("consent-admin", "a long passphrase")
      %{user: user}
    end

    test "persists the decision and its audit row together", %{user: user} do
      assert {:ok, %{enabled: true, decided: true}} =
               ErrorReporting.record_decision(user, true, %{ip_address: "127.0.0.1"})

      assert ErrorReporting.enabled?()

      %{logs: [row]} =
        Termelix.Audit.list_page(%{
          filters: %{action: "error_reporting_enable"},
          limit: 10,
          offset: 0
        })

      assert row.userId == user.id
      assert row.resourceType == "settings"
      assert row.ipAddress == "127.0.0.1"
      assert row.details =~ ~s("enabled":true)
      assert row.details =~ ~s("previous")
    end

    test "a failed audit write rolls the consent change back", %{user: _user} do
      # userId is NOT NULL, so an actor without an id makes the audit insert fail —
      # the transaction must roll back and leave the consent state untouched.
      assert {:error, _reason} =
               ErrorReporting.record_decision(%{id: nil, username: nil}, true)

      assert %{enabled: false, decided: false} = ErrorReporting.status()

      %{total: 0} =
        Termelix.Audit.list_page(%{
          filters: %{action: "error_reporting_enable"},
          limit: 1,
          offset: 0
        })
    end
  end
end
