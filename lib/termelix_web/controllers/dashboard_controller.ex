defmodule TermelixWeb.DashboardController do
  @moduledoc """
  Ports the dashboard surface (dashboardApi, root base, port 30006): server uptime
  (`dashboard.ts`) and service-link CRUD (`dashboard-service-links-routes.ts`).

  The `Authenticate` plug has already run, so the owner is `conn.assigns.current_user_id`; a
  body `userId` is never trusted. (The `/activity/*` endpoints of the same Node service are
  ported separately by `TermelixWeb.HistoryController` under the `/activity` scope; the Node
  `DatabaseSaveTrigger` backup hook has no analogue in this port and is intentionally
  dropped.)
  """
  use Phoenix.Controller, formats: [:json]

  alias Termelix.Dashboard

  # --- uptime ---------------------------------------------------------------

  # GET /uptime — server (BEAM) wall-clock uptime, in the shape the dashboard tile consumes.
  def uptime(conn, _params) do
    {uptime_ms, _since_last} = :erlang.statistics(:wall_clock)
    seconds = div(uptime_ms, 1000)
    days = div(seconds, 86_400)
    hours = div(rem(seconds, 86_400), 3600)
    minutes = div(rem(seconds, 3600), 60)

    json(conn, %{
      uptimeMs: uptime_ms,
      uptimeSeconds: seconds,
      formatted: "#{days}d #{hours}h #{minutes}m"
    })
  end

  # --- service links --------------------------------------------------------

  # GET /service-links
  def index_links(conn, _params) do
    links =
      conn.assigns.current_user_id
      |> Dashboard.list_service_links()
      |> Enum.map(&link_view/1)

    json(conn, links)
  end

  # POST /service-links
  def create_link(conn, params) do
    # Trim first, then validate — a padded but otherwise valid URL is accepted.
    label = trim_or_nil(params["label"])
    url = trim_or_nil(params["url"])

    cond do
      not (non_empty_string?(label) and non_empty_string?(url)) ->
        error(conn, 400, "label and url are required")

      not valid_url?(url) ->
        error(conn, 400, "url must be a valid http or https URL")

      true ->
        {:ok, link} = Dashboard.create_service_link(conn.assigns.current_user_id, label, url)
        conn |> put_status(201) |> json(link_view(link))
    end
  end

  defp trim_or_nil(nil), do: nil
  defp trim_or_nil(s) when is_binary(s), do: String.trim(s)
  defp trim_or_nil(other), do: other

  # PUT /service-links/:id
  def update_link(conn, %{"id" => id_param} = params) do
    url = params["url"]

    with {:ok, id} <- parse_id(id_param),
         :ok <- validate_optional_url(url),
         %{} = existing <- Dashboard.get_service_link(conn.assigns.current_user_id, id),
         {:ok, changes} <- link_changes(params) do
      updated = Dashboard.update_service_link(conn.assigns.current_user_id, id, changes)
      json(conn, link_view(updated || existing))
    else
      :invalid_id -> error(conn, 400, "Invalid id")
      :invalid_url -> error(conn, 400, "url must be a valid http or https URL")
      nil -> error(conn, 404, "Not found")
      :empty -> error(conn, 400, "Nothing to update")
    end
  end

  # DELETE /service-links/:id
  def delete_link(conn, %{"id" => id_param}) do
    case parse_id(id_param) do
      :invalid_id ->
        error(conn, 400, "Invalid id")

      {:ok, id} ->
        user_id = conn.assigns.current_user_id

        case Dashboard.get_service_link(user_id, id) do
          nil ->
            error(conn, 404, "Not found")

          %{} ->
            Dashboard.delete_service_link(user_id, id)
            json(conn, %{message: "Service link deleted"})
        end
    end
  end

  # --- views ----------------------------------------------------------------

  defp link_view(link) do
    %{
      id: link.id,
      userId: link.userId,
      label: link.label,
      url: link.url,
      order: link.order,
      createdAt: link.createdAt
    }
  end

  # --- request helpers ------------------------------------------------------

  # Only trimmed, non-empty label/url are written; empty updates → :empty (→ 400).
  defp link_changes(params) do
    changes =
      %{}
      |> put_if_non_empty(params, "label", :label)
      |> put_if_non_empty(params, "url", :url)

    if map_size(changes) == 0, do: :empty, else: {:ok, changes}
  end

  defp put_if_non_empty(changes, params, key, field) do
    value = params[key]
    if non_empty_string?(value), do: Map.put(changes, field, String.trim(value)), else: changes
  end

  # In the Node route the url-validity check runs before the ownership check and only fires
  # when a url is present.
  defp validate_optional_url(nil), do: :ok
  defp validate_optional_url(url), do: if(valid_url?(url), do: :ok, else: :invalid_url)

  defp valid_url?(url) when is_binary(url) do
    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host}}
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        true

      _ ->
        false
    end
  end

  defp valid_url?(_), do: false

  defp non_empty_string?(v), do: is_binary(v) and String.trim(v) != ""

  defp parse_id(value) do
    case Integer.parse(to_string(value)) do
      {int, _rest} -> {:ok, int}
      :error -> :invalid_id
    end
  end

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
