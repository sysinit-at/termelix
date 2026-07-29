defmodule TermelixWeb.SystemController do
  @moduledoc """
  Ports the system-bootstrap surface the UI hits at boot: the version/update check
  (`/version`, `database.ts`), the releases feed (`/releases/rss`, `database.ts`), and the
  announcement-alerts surface (`/alerts` + dismissals, `routes/alerts.ts`).

  The `Authenticate` plug has already run, so the owner is `conn.assigns.current_user_id`;
  a body `userId` is never trusted. GitHub is reached through `Termelix.System`, which degrades
  gracefully on any outbound failure — `/version` then returns the local-only shape the
  frontend tolerates (`%{localVersion, status: "update_check_disabled"}`), `/releases/rss` an
  empty feed, and `/alerts` an empty list — so the boot flow never fails on a network error.
  """
  use Phoenix.Controller, formats: [:json]

  alias Termelix.System
  alias Termelix.DismissedAlerts

  @default_per_page 20
  @max_per_page 100
  # GitHub returns `200 []` for out-of-range pages, so an uncapped `?page=` would let any
  # authenticated user mint an unbounded number of distinct `HttpCache` keys. Clamp it.
  @max_page 100

  # GET /version
  def version(conn, params) do
    local = System.local_version()

    if params["checkRemote"] == "false" or not update_check_enabled?() do
      json(conn, %{
        localVersion: local,
        buildTime: System.build_time(),
        status: "update_check_disabled"
      })
    else
      json(conn, version_payload(local))
    end
  end

  # GET /releases/rss
  def releases_rss(conn, params) do
    page = min(positive_int(params["page"], 1), @max_page)
    per_page = min(positive_int(params["per_page"], @default_per_page), @max_per_page)

    with true <- update_check_enabled?(),
         {:ok, releases} <- System.list_releases(page, per_page) do
      json(conn, releases_payload(releases))
    else
      _ -> json(conn, empty_releases_payload())
    end
  end

  # Kill switch for the outbound GitHub release/update checks (`config :termelix,
  # :update_check_enabled`) — off until a public repo for this port exists. The disabled
  # shapes are the same graceful ones an unreachable GitHub already produced, so the SPA
  # needs no special casing.
  defp update_check_enabled?, do: Application.get_env(:termelix, :update_check_enabled, false)

  # GET /alerts
  def alerts(conn, _params) do
    all_alerts = System.fetch_alerts()
    dismissed = MapSet.new(DismissedAlerts.list_alert_ids_for_user(conn.assigns.current_user_id))

    active = Enum.reject(all_alerts, fn alert -> MapSet.member?(dismissed, alert["id"]) end)

    json(conn, %{alerts: active, cached: false, total_count: length(active)})
  end

  # POST /alerts/dismiss
  def dismiss(conn, params) do
    alert_id = params["alertId"]

    if blank?(alert_id) do
      error(conn, 400, "Alert ID is required")
    else
      case DismissedAlerts.dismiss(conn.assigns.current_user_id, alert_id) do
        :ok -> json(conn, %{message: "Alert dismissed successfully"})
        {:error, :already_dismissed} -> error(conn, 409, "Alert already dismissed")
      end
    end
  end

  # GET /alerts/dismissed
  def dismissed(conn, _params) do
    records =
      conn.assigns.current_user_id
      |> DismissedAlerts.list_for_user()
      |> Enum.map(&dismissed_record/1)

    json(conn, %{dismissed_alerts: records, total_count: length(records)})
  end

  # DELETE /alerts/dismiss
  def undismiss(conn, params) do
    alert_id = params["alertId"]

    cond do
      blank?(alert_id) ->
        error(conn, 400, "Alert ID is required")

      DismissedAlerts.undismiss(conn.assigns.current_user_id, alert_id) ->
        json(conn, %{message: "Alert undismissed successfully"})

      true ->
        error(conn, 404, "Dismissed alert not found")
    end
  end

  # --- payload builders -----------------------------------------------------

  # Full update-check shape on a successful fetch; the local-only fallback the frontend
  # tolerates when GitHub is unreachable or the remote version cannot be determined.
  defp version_payload(local) do
    with {:ok, release} <- System.latest_release(),
         raw_tag <- release["tag_name"] || release["name"] || "",
         remote when is_binary(remote) <- System.extract_version(raw_tag) do
      %{
        status: System.version_status(local, remote),
        localVersion: local,
        buildTime: System.build_time(),
        version: remote,
        remoteVersion: remote,
        latest_release: %{
          tag_name: release["tag_name"],
          name: release["name"],
          published_at: release["published_at"],
          html_url: release["html_url"]
        },
        cached: false
      }
    else
      _ ->
        %{
          localVersion: local,
          buildTime: System.build_time(),
          status: "update_check_disabled"
        }
    end
  end

  defp releases_payload(releases) do
    items = Enum.map(releases, &rss_item/1)
    %{feed: feed_meta(), items: items, total_count: length(items), cached: false}
  end

  defp empty_releases_payload do
    %{feed: feed_meta(), items: [], total_count: 0, cached: false}
  end

  defp feed_meta do
    owner = System.repo_owner()
    name = System.repo_name()

    %{
      title: "#{name} Releases",
      description: "Latest releases from #{name} repository",
      link: "https://github.com/#{owner}/#{name}/releases",
      updated: DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()
    }
  end

  defp rss_item(release) do
    %{
      id: release["id"],
      title: release["name"] || release["tag_name"],
      description: release["body"],
      link: release["html_url"],
      pubDate: release["published_at"],
      version: release["tag_name"],
      isPrerelease: release["prerelease"],
      isDraft: release["draft"],
      assets: Enum.map(release["assets"] || [], &rss_asset/1)
    }
  end

  defp rss_asset(asset) do
    %{
      name: asset["name"],
      size: asset["size"],
      download_count: asset["download_count"],
      download_url: asset["browser_download_url"]
    }
  end

  defp dismissed_record(record) do
    %{
      id: record.id,
      userId: record.userId,
      alertId: record.alertId,
      dismissedAt: record.dismissedAt
    }
  end

  # --- helpers --------------------------------------------------------------

  # parseInt(value) || default, floored at 1 (matches the Node `|| N` guards).
  defp positive_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} when int > 0 -> int
      _ -> default
    end
  end

  defp positive_int(value, _default) when is_integer(value) and value > 0, do: value
  defp positive_int(_value, default), do: default

  defp blank?(nil), do: true
  defp blank?(v) when is_binary(v), do: String.trim(v) == ""
  defp blank?(_), do: false

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
