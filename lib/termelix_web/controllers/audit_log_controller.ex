defmodule TermelixWeb.AuditLogController do
  @moduledoc """
  Ports the admin audit surface (`audit-log-routes.ts`): `GET /audit-logs` (paginated,
  filterable) and `GET /audit-logs/actions` (distinct actions for the filter dropdown).

  The whole scope is admin-gated by `TermelixWeb.Plugs.RequireAdmin` in the router; a non-admin
  gets `403 {error: "Not authorized"}`. Rows are rendered with the camelCase keys the frontend's
  `mapAuditLog` expects.
  """
  use Phoenix.Controller, formats: [:json]

  alias Termelix.Audit

  @default_limit 50
  @max_limit 200

  # GET /audit-logs
  def index(conn, params) do
    page = max(1, int_or(params["page"], 1))
    limit = min(@max_limit, max(1, int_or(params["limit"], @default_limit)))
    offset = (page - 1) * limit

    %{logs: logs, total: total} =
      Audit.list_page(%{filters: filters(params), limit: limit, offset: offset})

    total_pages = if limit > 0, do: ceil_div(total, limit), else: 0

    json(conn, %{
      logs: Enum.map(logs, &render_log/1),
      total: total,
      page: page,
      totalPages: total_pages
    })
  end

  # GET /audit-logs/actions
  def actions(conn, _params), do: json(conn, %{actions: Audit.list_distinct_actions()})

  # --- rendering -------------------------------------------------------------

  defp render_log(log) do
    %{
      id: log.id,
      userId: log.userId,
      username: log.username,
      action: log.action,
      resourceType: log.resourceType,
      resourceId: log.resourceId,
      resourceName: log.resourceName,
      details: log.details,
      ipAddress: log.ipAddress,
      userAgent: log.userAgent,
      success: log.success == true,
      errorMessage: log.errorMessage,
      timestamp: log.timestamp
    }
  end

  # --- filters ---------------------------------------------------------------

  defp filters(params) do
    %{
      userId: presence(params["userId"]),
      action: presence(params["action"]),
      resourceType: presence(params["resourceType"]),
      success: success_filter(params["success"]),
      startDate: presence(params["startDate"]),
      endDate: presence(params["endDate"])
    }
  end

  # success is applied only when present and non-empty (matches the Node ternary).
  defp success_filter(v) when v in [nil, ""], do: nil
  defp success_filter("true"), do: true
  defp success_filter("false"), do: false
  defp success_filter(true), do: true
  defp success_filter(false), do: false
  defp success_filter(_), do: nil

  # --- helpers ---------------------------------------------------------------

  # parseInt(query || default): the caller then applies Math.max(1, …)/Math.min(200, …).
  defp int_or(nil, default), do: default
  defp int_or("", default), do: default
  defp int_or(v, _default) when is_integer(v), do: v

  defp int_or(v, default) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> default
    end
  end

  defp int_or(_, default), do: default

  defp ceil_div(_total, 0), do: 0
  defp ceil_div(total, limit), do: div(total + limit - 1, limit)

  defp presence(v) when is_binary(v) and v != "", do: v
  defp presence(_), do: nil
end
