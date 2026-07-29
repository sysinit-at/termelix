defmodule TermelixWeb.ApiKeyController do
  @moduledoc """
  Human-facing management of agent credentials.

  Behind `:authenticated`, never `:api_key`: minting an agent credential must not be something
  an agent credential can do, or the scoping is decorative — any key could widen itself by
  issuing a broader one.
  """
  use TermelixWeb, :controller

  alias Termelix.ApiKeys

  def index(conn, _params) do
    keys =
      conn.assigns.current_user_id |> ApiKeys.list_for_user() |> Enum.map(&ApiKeys.to_public/1)

    json(conn, %{keys: keys, availableScopes: ApiKeys.scopes()})
  end

  def create(conn, params) do
    case ApiKeys.create(conn.assigns.current_user_id, params) do
      {:ok, key, token} ->
        # The ONLY time the token exists outside the caller's hands. Said plainly in the
        # response, because a client that does not store it now cannot recover it later.
        json(conn, %{
          key: ApiKeys.to_public(key),
          token: token,
          warning: "This token is shown once and cannot be recovered."
        })

      {:error, :name_required} ->
        error(conn, 400, "A name is required")

      {:error, :name_too_long} ->
        error(conn, 400, "Name is too long")

      {:error, :scopes_required} ->
        error(conn, 400, "At least one scope is required")

      {:error, {:unknown_scopes, unknown}} ->
        error(conn, 400, "Unknown scopes: #{Enum.join(unknown, ", ")}")

      {:error, :invalid_host_id} ->
        error(conn, 400, "Invalid host id")

      {:error, {:hosts_not_owned, ids}} ->
        error(conn, 403, "Not your hosts: #{Enum.join(ids, ", ")}")

      {:error, _reason} ->
        error(conn, 500, "Could not create the key")
    end
  end

  def delete(conn, %{"id" => id}) do
    ApiKeys.delete(conn.assigns.current_user_id, id)
    json(conn, %{ok: true})
  end

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
