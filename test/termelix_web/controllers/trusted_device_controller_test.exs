defmodule TermelixWeb.TrustedDeviceControllerTest do
  @moduledoc """
  HTTP tests for the trusted-device management surface (`/users/trusted-devices`): listing
  (most-recent-first, fingerprint omitted) and ownership-enforced revocation. Requires the
  returned routes wired into the authenticated `/users` scope.
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, Repo}
  alias Termelix.Schema.TrustedDevice

  @password "correct horse battery staple"

  setup do
    {alice_token, alice} = register_and_login("alice", @password)
    {bob_token, bob} = register_and_login("bob", "another good long passphrase")

    older = insert_device("td-a1", alice.id, "web", "Chrome on macOS", "2026-07-01T10:00:00.000Z")

    newer =
      insert_device("td-a2", alice.id, "desktop", "Termelix Desktop", "2026-07-20T10:00:00.000Z")

    bob_device =
      insert_device("td-b1", bob.id, "mobile", "Termelix Mobile", "2026-07-19T10:00:00.000Z")

    %{
      alice_token: alice_token,
      bob_token: bob_token,
      older: older,
      newer: newer,
      bob_device: bob_device
    }
  end

  describe "GET /users/trusted-devices" do
    test "lists the user's devices most-recently-used first, without the fingerprint", ctx do
      body = authed(ctx.alice_token) |> get("/users/trusted-devices") |> json_response(200)

      assert [first, second] = body["devices"]
      assert first["id"] == "td-a2"
      assert second["id"] == "td-a1"
      assert first["deviceType"] == "desktop"
      assert first["deviceInfo"] == "Termelix Desktop"
      assert is_binary(first["expiresAt"])
      # Fingerprint and owning userId are never exposed.
      refute Map.has_key?(first, "deviceFingerprint")
      refute Map.has_key?(first, "userId")
    end

    test "does not leak another user's devices", ctx do
      body = authed(ctx.bob_token) |> get("/users/trusted-devices") |> json_response(200)
      assert [only] = body["devices"]
      assert only["id"] == "td-b1"
    end
  end

  describe "DELETE /users/trusted-devices/:id" do
    test "revokes an owned device", ctx do
      assert %{"success" => true} =
               authed(ctx.alice_token)
               |> delete("/users/trusted-devices/td-a1")
               |> json_response(200)

      assert Repo.get(TrustedDevice, "td-a1") == nil
      # The user's other device is untouched.
      assert Repo.get(TrustedDevice, "td-a2") != nil
    end

    test "cannot revoke another user's device (404, row survives)", ctx do
      assert %{"error" => "Trusted device not found"} =
               authed(ctx.alice_token)
               |> delete("/users/trusted-devices/td-b1")
               |> json_response(404)

      assert Repo.get(TrustedDevice, "td-b1") != nil
    end

    test "unknown device is 404", ctx do
      assert %{"error" => "Trusted device not found"} =
               authed(ctx.alice_token)
               |> delete("/users/trusted-devices/nope")
               |> json_response(404)
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    login = post(conn, "/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp authed(token), do: build_conn() |> put_req_header("authorization", "Bearer #{token}")

  defp insert_device(id, user_id, type, info, last_used) do
    Repo.insert!(%TrustedDevice{
      id: id,
      userId: user_id,
      deviceFingerprint: "fp-#{id}",
      deviceType: type,
      deviceInfo: info,
      createdAt: "2026-07-01T09:00:00.000Z",
      expiresAt: "2026-08-01T09:00:00.000Z",
      lastUsedAt: last_used
    })
  end
end
