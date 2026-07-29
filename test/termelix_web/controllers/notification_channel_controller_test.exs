defmodule TermelixWeb.NotificationChannelControllerTest do
  @moduledoc """
  The `/notification-channels` CRUD surface. Actions are invoked directly with a conn carrying
  the authenticated user's assign (the route wiring is returned to the integrator, not yet in the
  router), and every response is asserted against the Node snake_case + `0/1` wire shape. Rows
  live behind an enforced `user_id` FK, so a real user is inserted for each case.
  """
  use TermelixWeb.ConnCase, async: true

  alias TermelixWeb.NotificationChannelController
  alias Termelix.{Alerts, Repo}
  alias Termelix.Schema.User

  setup do
    %{user: make_user("alice"), other: make_user("bob")}
  end

  describe "create/2" do
    test "creates a webhook channel (trimming the name)", %{user: user} do
      body =
        create(user, %{
          "name" => "  hook  ",
          "type" => "webhook",
          "config" => %{"url" => "https://example.com/h"}
        })
        |> json_response(201)

      assert is_integer(body["id"])
      assert body["user_id"] == user.id
      assert body["name"] == "hook"
      assert body["type"] == "webhook"
      assert body["config"] == ~s({"url":"https://example.com/h"})
      assert body["enabled"] == 1
    end

    test "enabled defaults on and honours an explicit false", %{user: user} do
      body =
        create(user, %{
          "name" => "off",
          "type" => "ntfy",
          "config" => %{"url" => "https://ntfy.sh", "topic" => "t"},
          "enabled" => false
        })
        |> json_response(201)

      assert body["enabled"] == 0
    end

    test "rejects a blank name", %{user: user} do
      body =
        create(user, %{"type" => "webhook", "config" => %{"url" => "x"}}) |> json_response(400)

      assert body["error"] == "name is required"
    end

    test "rejects an unknown type", %{user: user} do
      body =
        create(user, %{"name" => "x", "type" => "slack", "config" => %{}}) |> json_response(400)

      assert body["error"] == "type must be 'webhook' or 'ntfy'"
    end

    test "ntfy requires a topic", %{user: user} do
      body =
        create(user, %{"name" => "n", "type" => "ntfy", "config" => %{"url" => "https://ntfy.sh"}})
        |> json_response(400)

      assert body["error"] == "ntfy config requires topic"
    end

    test "webhook requires a url", %{user: user} do
      body =
        create(user, %{"name" => "w", "type" => "webhook", "config" => %{}}) |> json_response(400)

      assert body["error"] == "webhook config requires url"
    end
  end

  describe "index/2" do
    test "lists only the caller's channels", %{user: user, other: other} do
      channel(user, "mine")
      channel(other, "theirs")

      rows = user |> user_conn() |> NotificationChannelController.index(%{}) |> json_response(200)

      assert Enum.map(rows, & &1["name"]) == ["mine"]
    end
  end

  describe "update/2" do
    test "updates the present fields only", %{user: user} do
      id = channel(user, "old")

      body =
        user
        |> user_conn()
        |> NotificationChannelController.update(%{
          "id" => to_string(id),
          "name" => "new",
          "enabled" => false
        })
        |> json_response(200)

      assert body["name"] == "new"
      assert body["enabled"] == 0
      assert body["type"] == "webhook"
    end

    test "an empty change set returns success", %{user: user} do
      id = channel(user, "x")

      body =
        user
        |> user_conn()
        |> NotificationChannelController.update(%{"id" => to_string(id)})
        |> json_response(200)

      assert body == %{"success" => true}
    end

    test "404 for another user's channel", %{user: user, other: other} do
      id = channel(other, "x")

      body =
        user
        |> user_conn()
        |> NotificationChannelController.update(%{"id" => to_string(id), "name" => "y"})
        |> json_response(404)

      assert body["error"] == "Channel not found"
    end
  end

  describe "delete/2" do
    test "deletes an owned channel", %{user: user} do
      id = channel(user, "x")

      body =
        user
        |> user_conn()
        |> NotificationChannelController.delete(%{"id" => to_string(id)})
        |> json_response(200)

      assert body == %{"success" => true}
      assert Alerts.list_notification_channels(user.id) == []
    end

    test "404 for a missing channel", %{user: user} do
      body =
        user
        |> user_conn()
        |> NotificationChannelController.delete(%{"id" => "999999"})
        |> json_response(404)

      assert body["error"] == "Channel not found"
    end
  end

  describe "test/2" do
    test "404 for a missing channel", %{user: user} do
      body =
        user
        |> user_conn()
        |> NotificationChannelController.test(%{"id" => "999999"})
        |> json_response(404)

      assert body["error"] == "Channel not found"
    end
  end

  # --- helpers ----------------------------------------------------------------

  defp create(user, params) do
    user |> user_conn() |> NotificationChannelController.create(params)
  end

  defp channel(user, name) do
    {:ok, ch} =
      Alerts.create_notification_channel(%{
        userId: user.id,
        name: name,
        type: "webhook",
        config: ~s({"url":"https://x"}),
        enabled: true
      })

    ch.id
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
end
