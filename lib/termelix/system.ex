defmodule Termelix.System do
  @moduledoc """
  System-bootstrap domain: the local application version, the GitHub update check, the
  releases feed, and the announcement-alerts JSON — the Elixir port of the `/version` and
  `/releases/rss` handlers in `database.ts` plus `fetchAlertsFromGitHub` in `alerts.ts`.

  Every outbound call is resilient: a network error, a non-2xx status, or a malformed body
  degrades to a caller-tolerated fallback (`:error` for the version/releases fetches, an
  empty list for alerts) rather than raising, so the boot endpoints stay up when GitHub is
  unreachable. HTTP goes through `Req`; tests inject a stub via the `:req_options` app env.

  Successful fetches are cached through `Termelix.HttpCache` so the boot endpoints stop hitting
  GitHub live per request: the latest-release check 1h, the releases list 1h (per
  page/per_page), and the alerts feed 5min. Errors and degraded responses are never cached.
  (The `cached: false` field in the HTTP payloads is stamped by the controller and is part of
  the wire shape; it is unchanged.)
  """
  require Logger

  alias Termelix.HttpCache

  @github_api_base "https://api.github.com"
  @github_raw_base "https://raw.githubusercontent.com"
  @repo_owner "Termelix-SSH"
  @repo_name "Termelix"
  @alerts_repo "Termelix-SSH/Docs"
  @alerts_file "main/termelix-alerts.json"
  @timeout 5_000

  @latest_release_ttl :timer.hours(1)
  @releases_ttl :timer.hours(1)
  @alerts_ttl :timer.minutes(5)

  # Stamped when this module compiles — in the Docker release build that is the image
  # build; a cached layer means an identical build, so the stamp stays truthful.
  @build_time DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()

  @doc "UTC build timestamp (ISO 8601): when this build was compiled."
  @spec build_time() :: String.t()
  def build_time, do: @build_time

  @doc "Repo owner the releases feed links to."
  @spec repo_owner() :: String.t()
  def repo_owner, do: @repo_owner

  @doc "Repo name the releases feed links to."
  @spec repo_name() :: String.t()
  def repo_name, do: @repo_name

  @doc "Local application version: env `VERSION`, else the compiled `:termelix` app vsn."
  @spec local_version() :: String.t()
  def local_version do
    case System.get_env("VERSION") do
      v when is_binary(v) and v != "" -> v
      _ -> Application.spec(:termelix, :vsn) |> to_string()
    end
  end

  @doc "The latest GitHub release (decoded map), or `:error` on any outbound failure."
  @spec latest_release() :: {:ok, map()} | :error
  def latest_release do
    HttpCache.fetch({__MODULE__, :latest_release}, @latest_release_ttl, fn ->
      case api_get("/repos/#{@repo_owner}/#{@repo_name}/releases/latest") do
        {:ok, body} when is_map(body) -> {:ok, body}
        _ -> :error
      end
    end)
  end

  @doc "A page of GitHub releases (list of decoded maps), or `:error` on any outbound failure."
  @spec list_releases(pos_integer(), pos_integer()) :: {:ok, [map()]} | :error
  def list_releases(page, per_page) do
    HttpCache.fetch({__MODULE__, :releases, page, per_page}, @releases_ttl, fn ->
      case api_get(
             "/repos/#{@repo_owner}/#{@repo_name}/releases?page=#{page}&per_page=#{per_page}"
           ) do
        {:ok, body} when is_list(body) -> {:ok, body}
        _ -> :error
      end
    end)
  end

  @doc """
  Active announcement alerts from the Docs-repo JSON, with expired entries removed. Returns
  the raw string-keyed alert maps, or `[]` on any outbound/parse failure — mirrors
  `fetchAlertsFromGitHub`. The raw feed is cached for 5min; expiry filtering runs per call.
  """
  @spec fetch_alerts() :: [map()]
  def fetch_alerts do
    case HttpCache.fetch({__MODULE__, :alerts}, @alerts_ttl, &fetch_alerts_raw/0) do
      {:ok, alerts} -> Enum.filter(alerts, &alert_active?/1)
      {:error, _} -> []
    end
  end

  # The raw (unfiltered) alerts list, wrapped for the cache: {:ok, alerts} on success.
  defp fetch_alerts_raw do
    url = "#{@github_raw_base}/#{@alerts_repo}/#{@alerts_file}"
    headers = [{"accept", "application/json"}, {"user-agent", "TermelixAlertChecker/1.0"}]

    with {:ok, body} <- request(url, headers),
         {:ok, alerts} when is_list(alerts) <- as_json(body) do
      {:ok, alerts}
    else
      _ -> {:error, :fetch_failed}
    end
  end

  @doc "Extract an `x.y[.z]` version from a raw tag/name, or nil. Mirrors the Node tag regex."
  @spec extract_version(String.t() | nil) :: String.t() | nil
  def extract_version(raw) when is_binary(raw) do
    case Regex.run(~r/(\d+\.\d+(\.\d+)?)/, raw) do
      [_, version | _] -> version
      _ -> nil
    end
  end

  def extract_version(_), do: nil

  @doc """
  Update status of `local` against `remote`: `"up_to_date"` when equal or incomparable,
  `"beta"` when local is ahead, `"requires_update"` when local is behind. Mirrors the Node
  `compareSemver` result plus its status mapping.
  """
  @spec version_status(String.t() | nil, String.t() | nil) :: String.t()
  def version_status(local, remote) do
    case compare_semver(local, remote) do
      c when c in [nil, 0] -> "up_to_date"
      c when c > 0 -> "beta"
      _ -> "requires_update"
    end
  end

  # --- GitHub HTTP ----------------------------------------------------------

  defp api_get(path) do
    request(@github_api_base <> path, [
      {"accept", "application/vnd.github+json"},
      {"user-agent", "TermelixUpdateChecker/1.0"},
      {"x-github-api-version", "2022-11-28"}
    ])
  end

  # One resilient GET. Returns `{:ok, body}` for 2xx (Req auto-decodes JSON), `{:error, reason}`
  # for a non-2xx status or transport error, and never raises (any exception is caught too).
  defp request(url, headers) do
    opts = [headers: headers, receive_timeout: @timeout, retry: false] ++ req_options()

    case Req.get(url, opts) do
      {:ok, %Req.Response{status: status, body: body}} when status in 200..299 ->
        {:ok, body}

      {:ok, %Req.Response{status: status}} ->
        {:error, {:http_status, status}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    error ->
      Logger.warning("GitHub request failed: #{Exception.message(error)}")
      {:error, error}
  end

  defp req_options, do: Application.get_env(:termelix, :req_options, [])

  # Req decodes JSON responses eagerly; a raw text/plain body arrives as a binary to decode.
  defp as_json(body) when is_list(body) or is_map(body), do: {:ok, body}
  defp as_json(body) when is_binary(body), do: Jason.decode(body)
  defp as_json(_), do: :error

  defp alert_active?(%{"expiresAt" => expires_at}) when is_binary(expires_at) do
    case DateTime.from_iso8601(expires_at) do
      {:ok, dt, _} -> DateTime.compare(dt, DateTime.utc_now()) == :gt
      _ -> false
    end
  end

  defp alert_active?(_), do: false

  # Mirrors compareSemver: parse "x.y[.z]" from each; 1/-1/0, or nil if either is unparseable.
  defp compare_semver(a, b) do
    with parsed_a when is_list(parsed_a) <- parse_semver(a),
         parsed_b when is_list(parsed_b) <- parse_semver(b) do
      cond do
        parsed_a > parsed_b -> 1
        parsed_a < parsed_b -> -1
        true -> 0
      end
    else
      _ -> nil
    end
  end

  defp parse_semver(version) do
    case Regex.run(~r/(\d+)\.(\d+)(?:\.(\d+))?/, to_string(version)) do
      [_, major, minor | rest] ->
        patch = List.first(rest) || "0"
        [String.to_integer(major), String.to_integer(minor), String.to_integer(patch)]

      _ ->
        nil
    end
  end
end
