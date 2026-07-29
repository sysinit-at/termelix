defmodule TermelixWeb.AlertFiringController do
  @moduledoc """
  Ports the `/alert-firings` surface (`database/routes/alert-rules-routes.ts`) the frontend
  `alerts-api.ts` calls: a paginated, newest-first list of the firings the alert engine has
  recorded (optionally filtered by acknowledgement), plus acknowledge-one and acknowledge-all.
  The `Authenticate` plug has run, so ownership is `conn.assigns.current_user_id`.

  The list response is `{firings, total}`, each firing rendered snake_case (with its joined
  `rule_name`) via `Termelix.Alerts.firing_json/2` — the shape `mapAlertFiring` reads.
  """
  use Phoenix.Controller, formats: [:json]

  alias Termelix.Alerts

  @default_limit 50
  @max_limit 200

  # GET /alert-firings?limit=&offset=&acknowledged=
  def index(conn, params) do
    user_id = conn.assigns.current_user_id

    {firings, total} =
      Alerts.list_alert_firings(%{
        userId: user_id,
        acknowledged: acknowledged_filter(params["acknowledged"]),
        limit: parse_limit(params["limit"]),
        offset: parse_offset(params["offset"])
      })

    rows = Enum.map(firings, fn {firing, rule_name} -> Alerts.firing_json(firing, rule_name) end)
    json(conn, %{firings: rows, total: total})
  end

  # POST /alert-firings/:id/acknowledge
  def acknowledge(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case parse_id(id) do
      {:ok, firing_id} -> Alerts.acknowledge_firing(firing_id, user_id)
      {:error, :invalid_id} -> :noop
    end

    json(conn, %{success: true})
  end

  # POST /alert-firings/acknowledge-all
  def acknowledge_all(conn, _params) do
    Alerts.acknowledge_all_firings(conn.assigns.current_user_id)
    json(conn, %{success: true})
  end

  # --- param parsing ----------------------------------------------------------

  # "true"/"false" → boolean filter; anything else → no filter (Node's tri-state).
  defp acknowledged_filter("true"), do: true
  defp acknowledged_filter("false"), do: false
  defp acknowledged_filter(_), do: nil

  defp parse_limit(value) do
    case parse_int(value) do
      n when is_integer(n) and n > 0 -> min(n, @max_limit)
      _ -> @default_limit
    end
  end

  defp parse_offset(value) do
    case parse_int(value) do
      n when is_integer(n) and n >= 0 -> n
      _ -> 0
    end
  end

  defp parse_int(value) when is_integer(value), do: value

  defp parse_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, _} -> n
      :error -> nil
    end
  end

  defp parse_int(_), do: nil

  defp parse_id(id) when is_integer(id) and id > 0, do: {:ok, id}

  defp parse_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {n, ""} when n > 0 -> {:ok, n}
      _ -> {:error, :invalid_id}
    end
  end

  defp parse_id(_), do: {:error, :invalid_id}
end
