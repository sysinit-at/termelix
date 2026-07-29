defmodule TermelixWeb.OpenTabController do
  @moduledoc """
  Ports the `/open-tabs` surface (`routes/open-tabs.ts`): persistence of the user's open
  terminal/file tabs (`getOpenTabs` / `addOpenTab` / `syncOpenTabs` / `patchOpenTab` /
  `deleteOpenTab`).

  The `Authenticate` plug has already run, so the owner is `conn.assigns.current_user_id`;
  a `userId` in the body is never trusted. Listing applies the same TTL window as Node — only
  tabs updated within `terminal_session_timeout_minutes` (default 30) are returned. Tab types
  are returned verbatim: the frontend already drops any type it no longer knows
  (`KNOWN_TAB_TYPES` in `src/ui/shell/known-tab-types.ts`), which is where retired types are
  filtered out.

  Node's `LEGACY_TAB_TYPE_MAP` (`stats` → `host-metrics`) is deliberately **not** ported. It is
  the one Node-parity gap here, and it is a no-op by construction: vk543 removed the Host
  Metrics tab, so `host-metrics` is no longer in `KNOWN_TAB_TYPES` either — the mapping would
  only rename one dropped type into another dropped type. Reinstating it would require
  reinstating the tab first.

  `/open-tabs/active-sessions` is served here as well, even though it reads the terminal
  session manager rather than `user_open_tabs`: that is the path the SPA calls, and while the
  route was missing the SPA catch-all answered it with `index.html` at 200, which
  `getActiveSessions` (`src/ui/api/open-tabs-api.ts`) silently turned into an empty list on
  every login and tab restore. Sessions are joined back to tabs by `backendSessionId` — the
  key the Connections panel indexes them by.
  """
  use Phoenix.Controller, formats: [:json]

  import TermelixWeb.ControllerHelpers

  alias Termelix.{OpenTabs, Settings}
  alias Termelix.Terminal.SessionManager

  @default_tab_ttl_minutes 30

  # GET /open-tabs
  def index(conn, _params) do
    cutoff = cutoff_iso()

    tabs =
      conn.assigns.current_user_id
      |> OpenTabs.list_recent_for_user(cutoff)
      |> Enum.map(&to_json/1)

    json(conn, tabs)
  end

  # GET /open-tabs/active-sessions
  def active_sessions(conn, _params) do
    user_id = conn.assigns.current_user_id
    tab_ids = tab_ids_by_session(user_id)

    sessions =
      user_id
      |> SessionManager.list_user_sessions()
      |> Enum.map(fn {session_id, _pid, meta} ->
        %{
          sessionId: session_id,
          hostId: meta.host_id,
          hostName: meta.host_name,
          tabInstanceId: Map.get(tab_ids, session_id),
          # Being *listed* is not the same as being connected: the session registers before its
          # SSH handshake completes, so it appears here for up to the connect timeout while
          # still dialling, and for the whole time it is failing auth. The session publishes
          # readiness into its own registry value on `{:ssh_ready}`, which is why this can be
          # honest without a blocking `GenServer.call` per row on an endpoint the SPA polls.
          isConnected: Map.get(meta, :ready, false),
          createdAt: meta.created_at
        }
      end)

    json(conn, sessions)
  end

  # POST /open-tabs
  def create(conn, params) do
    if missing?(params["id"]) or missing?(params["tabType"]) or missing?(params["label"]) do
      error(conn, 400, "id, tabType, and label are required")
    else
      OpenTabs.upsert_for_user(conn.assigns.current_user_id, params)
      json(conn, %{success: true})
    end
  end

  # PUT /open-tabs
  def update(conn, %{"tabs" => tabs}) when is_list(tabs) do
    OpenTabs.replace_for_user(conn.assigns.current_user_id, tabs)
    json(conn, %{success: true})
  end

  def update(conn, _params), do: error(conn, 400, "tabs must be an array")

  # PATCH /open-tabs/:id
  def patch(conn, %{"id" => id} = params) do
    if OpenTabs.update_for_user(conn.assigns.current_user_id, id, params) do
      json(conn, %{success: true})
    else
      error(conn, 404, "Tab not found")
    end
  end

  # DELETE /open-tabs/:id
  def delete(conn, %{"id" => id}) do
    OpenTabs.delete_for_user(conn.assigns.current_user_id, id)
    json(conn, %{success: true})
  end

  # --- helpers --------------------------------------------------------------

  # `backendSessionId` → tab id, over the same TTL window `index/2` serves: a tab outside that
  # window is not in the client's tab list either, so there is nothing for it to light up.
  defp tab_ids_by_session(user_id) do
    user_id
    |> OpenTabs.list_recent_for_user(cutoff_iso())
    |> Enum.reduce(%{}, fn
      %{backendSessionId: nil}, acc -> acc
      tab, acc -> Map.put(acc, tab.backendSessionId, tab.id)
    end)
  end

  # now - TTL, as a JS-style ISO 8601 string, mirroring `new Date(Date.now() - ttl).toISOString()`.
  defp cutoff_iso do
    DateTime.utc_now()
    |> DateTime.add(-tab_ttl_ms(), :millisecond)
    |> DateTime.truncate(:millisecond)
    |> DateTime.to_iso8601()
  end

  # TTL window in ms from the `terminal_session_timeout_minutes` setting (a positive integer),
  # else the 30-minute default — mirrors `getTabTtlMs`.
  defp tab_ttl_ms do
    with value when is_binary(value) <- Settings.get_value("terminal_session_timeout_minutes"),
         {minutes, _rest} when minutes > 0 <- Integer.parse(value) do
      minutes * 60_000
    else
      _ -> @default_tab_ttl_minutes * 60_000
    end
  end

  defp to_json(struct), do: struct |> Map.from_struct() |> Map.drop([:__meta__])

  # Node's `!value` falsy check: an absent or empty-string field fails validation (whitespace,
  # like Node, counts as present).
  defp missing?(nil), do: true
  defp missing?(""), do: true
  defp missing?(_), do: false
end
