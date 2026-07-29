defmodule TermelixWeb.AdminPipelineTest do
  @moduledoc """
  Every route behind an admin pipeline refuses a non-admin — enumerated from the router itself
  rather than from a hand-written list, so a route added to an admin scope tomorrow is covered
  without anyone remembering to extend this file.

  This exists because P2 moved authorization out of six per-controller `admin?/1` copies and
  into the router. That is a strict improvement, but it has one sharp edge: tests that call a
  controller action *directly* bypass the pipeline entirely, so they silently stop testing the
  authorization they were written to test. Two OIDC tests did exactly that — a non-admin call
  to `link_oidc_to_password/2` went from 403 to a successful account merge, with the test
  passing right up until it was converted. The authorization was never actually broken; the
  proof of it was. This file is that proof, in the one place the pipeline is real.
  """
  use TermelixWeb.ConnCase

  @router_source "lib/termelix_web/router.ex"
  @admin_pipelines ~w(admin admin_access admin_privileges)

  # Phoenix 1.8's `__routes__/0` does NOT carry `pipe_through` (verified: the route maps hold
  # only path/metadata/plug/plug_opts/helper/verb), so the pipeline a route sits behind cannot
  # be recovered from the compiled table. Read it out of the router source instead: one file,
  # explicit markers, and it still picks up routes added later without editing this test.
  # If the router's shape ever changes enough to break this, the "has admin-gated routes" test
  # below fails loudly rather than letting every assertion pass vacuously.
  defp admin_routes do
    @router_source
    |> File.read!()
    |> String.split("\n")
    |> Enum.reduce({nil, false, []}, fn line, {scope, admin?, acc} = state ->
      scope_match = Regex.run(~r/^\s*scope\s+"([^"]*)"/, line)
      route_match = Regex.run(~r/^\s*(get|post|put|patch|delete)\s+"([^"]*)"/, line)

      cond do
        scope_match ->
          {Enum.at(scope_match, 1), false, acc}

        Regex.match?(~r/^\s*pipe_through\s+/, line) ->
          {scope, Enum.any?(@admin_pipelines, &String.contains?(line, ":" <> &1)), acc}

        admin? and route_match ->
          [_, verb, path] = route_match
          {scope, admin?, [%{verb: String.to_atom(verb), path: join(scope, path)} | acc]}

        true ->
          state
      end
    end)
    |> elem(2)
  end

  defp join(scope, "/"), do: if(scope in [nil, "/"], do: "/", else: scope)
  defp join(nil, path), do: path
  defp join("/", path), do: path
  defp join(scope, path), do: scope <> path

  # A path with :params substituted for something syntactically valid. The value never matters:
  # the pipeline halts before the action runs, which is the property under test.
  defp concrete_path(path) do
    path
    |> String.split("/")
    |> Enum.map(fn
      ":" <> _param -> "1"
      "*" <> _glob -> "1"
      segment -> segment
    end)
    |> Enum.join("/")
  end

  defp request(conn, verb, path) do
    case verb do
      :get -> get(conn, path)
      :post -> post(conn, path, %{})
      :put -> put(conn, path, %{})
      :patch -> patch(conn, path, %{})
      :delete -> delete(conn, path)
    end
  end

  setup do
    # First registered user becomes admin, so register the admin first and the member second.
    {_admin_token, _admin} = register_and_login("alice", "correct horse battery staple")
    {member_token, member} = register_and_login("bob", "another good long passphrase")

    refute member.isAdmin, "the second registered user must not be an admin"
    %{member_token: member_token}
  end

  # Deriving the list from the router means a route that LOSES its admin pipeline simply stops
  # being enumerated — it would not fail the 403 test, it would just quietly not be checked.
  # These anchors close that hole: each must be present in the admin set by name.
  @must_be_admin [
    {:post, "/users/make-admin"},
    {:post, "/users/remove-admin"},
    {:post, "/users/admin-create"},
    {:delete, "/users/delete-user"},
    {:get, "/users/sso-providers/admin"},
    {:post, "/users/sso-providers"},
    {:get, "/audit-logs"},
    {:get, "/rbac/permissions/catalog"},
    {:get, "/users/admin/export/:userId"},
    # Defect 42: creating a channel names a URL the SERVER will dial, and `/:id/test` returns
    # the outcome — a request forger with a read-back, inside the network perimeter.
    {:post, "/notification-channels"},
    {:put, "/notification-channels/:id"},
    {:delete, "/notification-channels/:id"},
    {:post, "/notification-channels/:id/test"}
  ]

  test "the router actually has admin-gated routes" do
    # Guards against the enumeration matching nothing, which would make the 403 test vacuous.
    assert length(admin_routes()) >= 15
  end

  test "the routes that must never be reachable by a non-admin are in fact admin-gated" do
    found = admin_routes() |> Enum.map(&{&1.verb, &1.path}) |> MapSet.new()

    missing = Enum.reject(@must_be_admin, &MapSet.member?(found, &1))

    assert missing == [],
           "these routes are NOT behind an admin pipeline:\n" <>
             Enum.map_join(missing, "\n", fn {v, p} ->
               "  #{v |> to_string() |> String.upcase()} #{p}"
             end)
  end

  test "every admin-pipeline route refuses a non-admin with 403", %{member_token: token} do
    failures =
      for route <- admin_routes(), reduce: [] do
        acc ->
          path = concrete_path(route.path)
          conn = request(authed(token), route.verb, path)

          if conn.status == 403 do
            acc
          else
            [{route.verb, route.path, conn.status} | acc]
          end
      end

    assert failures == [],
           "these admin routes did not answer 403 to a non-admin:\n" <>
             Enum.map_join(failures, "\n", fn {v, p, s} ->
               "  #{v |> to_string() |> String.upcase()} #{p} -> #{s}"
             end)
  end

  test "an unauthenticated caller gets 401, not 403", %{member_token: _} do
    # Order matters: :authenticated runs before the admin plug, so a missing identity must be
    # reported as missing rather than as insufficient privilege.
    for route <- Enum.take(admin_routes(), 5) do
      conn = request(build_conn(), route.verb, concrete_path(route.path))

      assert conn.status == 401,
             "#{route.verb} #{route.path} answered #{conn.status} to an anonymous caller"
    end
  end

  # Same shape as the other controller tests in this tree; kept local rather than hoisted into
  # ConnCase because those files already define private copies, and a local definition
  # conflicts with an import of the same name/arity.
  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    login = post(conn, "/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Termelix.Accounts.get_user_by_username(username)}
  end

  defp authed(token), do: build_conn() |> put_req_header("authorization", "Bearer #{token}")
end
