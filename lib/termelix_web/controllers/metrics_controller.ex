defmodule TermelixWeb.MetricsController do
  @moduledoc """
  Host reachability status — what powers the sidebar's per-host online/offline indicators.
  Callers live in `host-metrics-status-api.ts` (`getAllServerStatuses`, `getServerStatusById`).

  The `Authenticate` plug has run, so the owning user is `conn.assigns.current_user_id` — a
  body/route `userId` is never trusted. Status is a live TCP reachability probe per request;
  when the user's data key is locked we return the same `SESSION_EXPIRED` 401 the Node
  service did.

  The former Host Metrics dashboard (CPU/mem/disk collection, `/metrics/:id`, history, and
  the viewer lifecycle) was removed as low-value for the SRE/sysadmin audience; only the
  reachability status the online indicators need remains. `/refresh`, `/host-updated`, and
  `/host-deleted` stay as acknowledgement stubs the SPA fires after host mutations to nudge a
  status refresh.
  """
  use Phoenix.Controller, formats: [:json]

  import TermelixWeb.ControllerHelpers, only: [error: 3]

  alias Termelix.Metrics
  alias Termelix.Crypto.UserKeyManager

  # GET /status/:id
  def status(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    if unlocked?(user_id) do
      with {:ok, host_id} <- parse_id(id),
           {:ok, status} <- Metrics.ping(host_id, user_id) do
        json(conn, %{status: to_string(status), lastChecked: now_iso()})
      else
        {:error, :invalid_id} -> error(conn, 400, "Invalid host ID")
        {:error, :not_found} -> error(conn, 404, "Status not available")
      end
    else
      session_expired(conn)
    end
  end

  # GET /status
  def status_all(conn, _params) do
    user_id = conn.assigns.current_user_id

    if unlocked?(user_id) do
      checked = now_iso()

      statuses =
        user_id
        |> Metrics.ping_all()
        |> Map.new(fn {id, status} ->
          {id, %{status: to_string(status), lastChecked: checked}}
        end)

      json(conn, statuses)
    else
      session_expired(conn)
    end
  end

  # POST /refresh, /host-updated, /host-deleted — poller notifications the SPA fires after
  # host mutations (fire-and-forget). Status is computed live per request, so acknowledging
  # suffices; without them the SPA's post-mutation refresh would 404.
  def poller_ack(conn, _params), do: json(conn, %{success: true})

  # --- helpers ----------------------------------------------------------------

  # The user's DEK must be unsealed to resolve their hosts. Mirrors Node's
  # `DataCrypto.getUserDataKey === null` gate.
  defp unlocked?(user_id), do: UserKeyManager.try_get_user_dek(user_id) != nil

  defp session_expired(conn) do
    conn
    |> put_status(401)
    |> json(%{error: "Session expired - please log in again", code: "SESSION_EXPIRED"})
  end

  # Node `validateHostId`: a positive integer.
  defp parse_id(id) when is_integer(id) and id > 0, do: {:ok, id}

  defp parse_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {n, ""} when n > 0 -> {:ok, n}
      _ -> {:error, :invalid_id}
    end
  end

  defp parse_id(_), do: {:error, :invalid_id}

  # Millisecond-precision ISO-8601, matching JS `new Date().toISOString()`.
  defp now_iso, do: DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()
end
