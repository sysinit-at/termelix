defmodule TermelixWeb.PageController do
  @moduledoc """
  Serves the React SPA's index.html for the root and any client-side route that the API
  router did not match. Static assets are served earlier by `Plug.Static`; only non-asset,
  non-API GETs reach here.
  """
  use Phoenix.Controller, formats: [:html]

  def index(conn, _params) do
    path = Path.join(:code.priv_dir(:termelix), "static/spa/index.html")

    if File.exists?(path) do
      conn
      |> put_resp_header("content-type", "text/html; charset=utf-8")
      # index.html is the deploy manifest for the fingerprinted assets — never cache it.
      |> put_resp_header("cache-control", "no-cache")
      |> Plug.Conn.send_file(200, path)
    else
      conn
      |> put_resp_content_type("text/plain")
      |> Plug.Conn.send_resp(
        200,
        "Termelix (BEAM) backend is running. Build the frontend to serve the UI."
      )
    end
  end
end
