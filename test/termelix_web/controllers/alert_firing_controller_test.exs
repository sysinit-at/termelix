defmodule TermelixWeb.AlertFiringControllerTest do
  @moduledoc """
  The `/alert-firings` surface: the paginated newest-first list (with the joined rule name and
  acknowledgement filter) and the acknowledge one/all actions. Firings are inserted with explicit
  `fired_at` values so ordering is deterministic; their `rule_id`/`user_id` FKs reference real
  rows.
  """
  use TermelixWeb.ConnCase, async: true

  alias TermelixWeb.AlertFiringController
  alias Termelix.{Alerts, Repo}
  alias Termelix.Schema.{User, AlertFiring}

  setup do
    user = make_user("alice")
    other = make_user("bob")
    %{user: user, other: other, rule: rule(user, "cpu high")}
  end

  describe "index/2" do
    test "returns firings newest-first with the rule name and total", %{user: user, rule: rule} do
      firing(user, rule, fired_at: "2026-01-01 00:00:01")
      firing(user, rule, fired_at: "2026-01-01 00:00:03")
      firing(user, rule, fired_at: "2026-01-01 00:00:02")

      body = user |> user_conn() |> AlertFiringController.index(%{}) |> json_response(200)

      assert body["total"] == 3

      assert Enum.map(body["firings"], & &1["fired_at"]) ==
               ["2026-01-01 00:00:03", "2026-01-01 00:00:02", "2026-01-01 00:00:01"]

      assert Enum.all?(body["firings"], &(&1["rule_name"] == "cpu high"))
      assert hd(body["firings"])["acknowledged"] == 0
    end

    test "filters by acknowledgement", %{user: user, rule: rule} do
      firing(user, rule, acknowledged: true)
      firing(user, rule, acknowledged: false)

      acked =
        user
        |> user_conn()
        |> AlertFiringController.index(%{"acknowledged" => "true"})
        |> json_response(200)

      assert acked["total"] == 1
      assert hd(acked["firings"])["acknowledged"] == 1

      unacked =
        user
        |> user_conn()
        |> AlertFiringController.index(%{"acknowledged" => "false"})
        |> json_response(200)

      assert unacked["total"] == 1
      assert hd(unacked["firings"])["acknowledged"] == 0
    end

    test "paginates without affecting the total", %{user: user, rule: rule} do
      for i <- 1..3, do: firing(user, rule, fired_at: "2026-01-01 00:00:0#{i}")

      body =
        user
        |> user_conn()
        |> AlertFiringController.index(%{"limit" => "1", "offset" => "0"})
        |> json_response(200)

      assert length(body["firings"]) == 1
      assert body["total"] == 3
    end

    test "shows only the caller's firings", %{user: user, other: other, rule: rule} do
      other_rule = rule(other, "theirs")
      firing(user, rule, [])
      firing(other, other_rule, [])

      body = user |> user_conn() |> AlertFiringController.index(%{}) |> json_response(200)
      assert body["total"] == 1
    end
  end

  describe "acknowledge/2" do
    test "acknowledges one firing", %{user: user, rule: rule} do
      f = firing(user, rule, [])

      body =
        user
        |> user_conn()
        |> AlertFiringController.acknowledge(%{"id" => to_string(f.id)})
        |> json_response(200)

      assert body == %{"success" => true}
      assert Repo.get!(AlertFiring, f.id).acknowledged == true
    end

    test "another user cannot acknowledge someone else's firing", %{
      user: user,
      other: other,
      rule: rule
    } do
      f = firing(user, rule, [])

      other |> user_conn() |> AlertFiringController.acknowledge(%{"id" => to_string(f.id)})

      assert Repo.get!(AlertFiring, f.id).acknowledged == false
    end
  end

  describe "acknowledge_all/2" do
    test "acknowledges every firing of the caller", %{user: user, rule: rule} do
      firing(user, rule, [])
      firing(user, rule, [])

      body =
        user |> user_conn() |> AlertFiringController.acknowledge_all(%{}) |> json_response(200)

      assert body == %{"success" => true}

      {_rows, total} =
        Alerts.list_alert_firings(%{userId: user.id, acknowledged: false, limit: 50, offset: 0})

      assert total == 0
    end
  end

  # --- helpers ----------------------------------------------------------------

  defp firing(user, rule_id, opts) do
    Repo.insert!(
      Ecto.Changeset.change(%AlertFiring{}, %{
        userId: user.id,
        ruleId: rule_id,
        hostId: 1,
        hostName: "web-1",
        firedAt: Keyword.get(opts, :fired_at, "2026-01-01 00:00:00"),
        message: "msg",
        severity: "warning",
        acknowledged: Keyword.get(opts, :acknowledged, false)
      })
    )
  end

  defp rule(user, name) do
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
        channels: [],
        now: DateTime.utc_now() |> DateTime.to_iso8601()
      })

    rule.id
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
