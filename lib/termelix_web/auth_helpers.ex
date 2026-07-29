defmodule TermelixWeb.AuthHelpers do
  @moduledoc "Shared login/cookie helpers matching `auth-manager.ts` cookie + client semantics."
  import Plug.Conn

  @doc """
  True for native clients (Electron desktop / mobile), which receive the JWT in the JSON
  body and send it as a bearer header. Detected via `X-Electron-App: true` or a
  `Termelix-Mobile/*` User-Agent, matching `isNativeAppRequest`.
  """
  @spec native_app?(Plug.Conn.t()) :: boolean()
  def native_app?(conn) do
    electron = get_req_header(conn, "x-electron-app") == ["true"]
    mobile = conn |> user_agent() |> String.starts_with?("Termelix-Mobile/")
    electron or mobile
  end

  @doc "Coarse `{device_type, device_info}` from the User-Agent (web|desktop|mobile)."
  @spec device(Plug.Conn.t()) :: {String.t(), String.t()}
  def device(conn) do
    ua = user_agent(conn)

    cond do
      String.starts_with?(ua, "Termelix-Mobile/") -> {"mobile", "Termelix Mobile"}
      get_req_header(conn, "x-electron-app") == ["true"] -> {"desktop", "Termelix Desktop"}
      true -> {"web", ua |> String.slice(0, 200) |> nonempty("Web browser")}
    end
  end

  @doc "Set the httpOnly `jwt` cookie with the original's options (`max_age` in seconds)."
  @spec put_jwt_cookie(Plug.Conn.t(), String.t(), non_neg_integer()) :: Plug.Conn.t()
  def put_jwt_cookie(conn, token, max_age_seconds) do
    put_resp_cookie(conn, "jwt", token,
      http_only: true,
      same_site: "Lax",
      secure: https?(conn),
      path: "/",
      max_age: max_age_seconds
    )
  end

  @doc "Clear the `jwt` cookie (logout / auth failure)."
  @spec clear_jwt_cookie(Plug.Conn.t()) :: Plug.Conn.t()
  def clear_jwt_cookie(conn) do
    delete_resp_cookie(conn, "jwt",
      http_only: true,
      same_site: "Lax",
      secure: https?(conn),
      path: "/"
    )
  end

  # `TermelixWeb.Plugs.TrustedProxy` already folds a *trusted* proxy's `x-forwarded-proto` into
  # `conn.scheme`, so reading the header here only re-admitted the untrusted value: a direct
  # client asserting it over plain HTTP got a `Secure` cookie the browser refuses to store, and
  # a set/clear pair that disagreed on the flag left a cookie logout could not delete. Same
  # rule (and reason) as `plugs/authenticate.ex:97`.
  @spec https?(Plug.Conn.t()) :: boolean()
  def https?(conn), do: conn.scheme == :https

  defp user_agent(conn) do
    case get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      _ -> ""
    end
  end

  defp nonempty("", default), do: default
  defp nonempty(str, _default), do: str
end
