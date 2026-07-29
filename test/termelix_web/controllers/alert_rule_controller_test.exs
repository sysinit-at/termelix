defmodule TermelixWeb.AlertRuleControllerTest do
  @moduledoc """
  The `/alert-rules` CRUD surface. Actions are invoked directly with an authenticated conn (the
  routes are returned to the integrator). Covers the Node validations, the snake_case + `0/1` +
  `channels` response shape, the create-echoes-request vs. update-returns-linked channel
  difference, and host-scoped rules (whose `host_id` FK requires a real host row).
  """
  use TermelixWeb.ConnCase, async: true

  alias TermelixWeb.AlertRuleController
  alias Termelix.{Alerts, Repo}
  alias Termelix.Schema.{User, Host}

  setup do
    %{user: make_user("alice"), other: make_user("bob")}
  end

  describe "create/2" do
    test "creates a global threshold rule", %{user: user} do
      body =
        create(user, %{
          "name" => "  cpu  ",
          "triggerType" => "cpu_threshold",
          "thresholdValue" => 80,
          "thresholdDurationSeconds" => 60,
          "cooldownMinutes" => 10
        })
        |> json_response(201)

      assert is_integer(body["id"])
      assert body["user_id"] == user.id
      assert body["host_id"] == nil
      assert body["name"] == "cpu"
      assert body["enabled"] == 1
      assert body["trigger_type"] == "cpu_threshold"
      assert body["threshold_value"] == 80.0
      assert body["threshold_duration_seconds"] == 60
      assert body["cooldown_minutes"] == 10
      assert body["channels"] == []
    end

    test "defaults cooldown to 15 and enabled to true", %{user: user} do
      body =
        create(user, %{"name" => "d", "triggerType" => "disk_threshold", "thresholdValue" => 90})
        |> json_response(201)

      assert body["cooldown_minutes"] == 15
      assert body["enabled"] == 1
    end

    test "binds a host scope", %{user: user} do
      host = make_host(user)

      body =
        create(user, %{"name" => "h", "triggerType" => "memory_threshold", "hostId" => host.id})
        |> json_response(201)

      assert body["host_id"] == host.id
    end

    test "echoes the requested channels", %{user: user} do
      channel_id = channel(user)

      body =
        create(user, %{
          "name" => "c",
          "triggerType" => "cpu_threshold",
          "channels" => [channel_id]
        })
        |> json_response(201)

      assert body["channels"] == [channel_id]

      # And the link is persisted (visible on list).
      [listed] = user |> user_conn() |> AlertRuleController.index(%{}) |> json_response(200)
      assert listed["channels"] == [channel_id]
    end

    test "rejects an unknown trigger type", %{user: user} do
      body = create(user, %{"name" => "x", "triggerType" => "nope"}) |> json_response(400)
      assert body["error"] == "Invalid triggerType"
    end

    test "rejects an out-of-range threshold", %{user: user} do
      body =
        create(user, %{"name" => "x", "triggerType" => "cpu_threshold", "thresholdValue" => 150})
        |> json_response(400)

      assert body["error"] == "thresholdValue must be between 0 and 100"
    end

    test "rejects a blank name", %{user: user} do
      body = create(user, %{"triggerType" => "cpu_threshold"}) |> json_response(400)
      assert body["error"] == "name is required"
    end
  end

  describe "index/2" do
    test "lists only the caller's rules", %{user: user, other: other} do
      rule(user, "mine")
      rule(other, "theirs")

      rows = user |> user_conn() |> AlertRuleController.index(%{}) |> json_response(200)
      assert Enum.map(rows, & &1["name"]) == ["mine"]
    end
  end

  describe "update/2" do
    test "updates present fields", %{user: user} do
      id = rule(user, "old")

      body =
        user
        |> user_conn()
        |> AlertRuleController.update(%{
          "id" => to_string(id),
          "name" => "new",
          "thresholdValue" => 55,
          "enabled" => false
        })
        |> json_response(200)

      assert body["name"] == "new"
      assert body["threshold_value"] == 55.0
      assert body["enabled"] == 0
    end

    test "replaces the linked channels and returns the persisted set", %{user: user} do
      c1 = channel(user)
      c2 = channel(user)
      id = rule_with_channels(user, [c1])

      body =
        user
        |> user_conn()
        |> AlertRuleController.update(%{"id" => to_string(id), "channels" => [c2]})
        |> json_response(200)

      assert body["channels"] == [c2]
    end

    test "rejects an invalid trigger on update", %{user: user} do
      id = rule(user, "x")

      body =
        user
        |> user_conn()
        |> AlertRuleController.update(%{"id" => to_string(id), "triggerType" => "bogus"})
        |> json_response(400)

      assert body["error"] == "Invalid triggerType"
    end

    test "404 for another user's rule", %{user: user, other: other} do
      id = rule(other, "x")

      body =
        user
        |> user_conn()
        |> AlertRuleController.update(%{"id" => to_string(id), "name" => "y"})
        |> json_response(404)

      assert body["error"] == "Alert rule not found"
    end
  end

  describe "delete/2" do
    test "deletes an owned rule", %{user: user} do
      id = rule(user, "x")

      body =
        user
        |> user_conn()
        |> AlertRuleController.delete(%{"id" => to_string(id)})
        |> json_response(200)

      assert body == %{"success" => true}
    end

    test "404 for a missing rule", %{user: user} do
      body =
        user
        |> user_conn()
        |> AlertRuleController.delete(%{"id" => "999999"})
        |> json_response(404)

      assert body["error"] == "Alert rule not found"
    end
  end

  # --- helpers ----------------------------------------------------------------

  defp create(user, params), do: user |> user_conn() |> AlertRuleController.create(params)

  defp rule(user, name), do: rule_with_channels(user, [], name)

  defp rule_with_channels(user, channels, name \\ "rule") do
    {:ok, rule, _} =
      Alerts.create_alert_rule(%{
        userId: user.id,
        hostId: nil,
        name: name,
        enabled: true,
        triggerType: "cpu_threshold",
        thresholdValue: 80,
        thresholdDurationSeconds: 0,
        cooldownMinutes: 15,
        channels: channels,
        now: iso_now()
      })

    rule.id
  end

  defp channel(user) do
    {:ok, ch} =
      Alerts.create_notification_channel(%{
        userId: user.id,
        name: "ch-#{System.unique_integer([:positive])}",
        type: "webhook",
        config: ~s({"url":"https://x"}),
        enabled: true
      })

    ch.id
  end

  defp make_host(user) do
    Repo.insert!(
      Ecto.Changeset.change(%Host{}, %{
        userId: user.id,
        name: "web",
        ip: "10.0.0.1",
        port: 22,
        username: "root",
        authType: "password"
      })
    )
  end

  defp user_conn(user) do
    build_conn()
    |> Plug.Conn.assign(:current_user_id, user.id)
    |> Plug.Conn.assign(:current_user, user)
  end

  defp make_user(username) do
    Repo.insert!(%User{
      id: Termelix.Id.generate(),
      username: username,
      passwordHash: "x",
      isAdmin: false,
      isOidc: false,
      totpEnabled: false,
      donationModalDismissed: false,
      registeredAt: DateTime.utc_now() |> DateTime.to_iso8601()
    })
  end

  defp iso_now, do: DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()
end
