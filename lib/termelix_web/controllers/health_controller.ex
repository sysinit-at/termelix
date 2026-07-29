defmodule TermelixWeb.HealthController do
  @moduledoc """
  Liveness and readiness probes.

  `/health/live` — and `/health`, its unchanged legacy alias, kept because existing pollers
  already point at it — answer from the endpoint alone: "the BEAM is up and Bandit is serving",
  nothing more. `/health/ready` additionally round-trips SQLite, so it can report a wedged,
  locked, or missing database instead of a process that is merely alive.

  Only the liveness probe is the container `HEALTHCHECK` (`docker/Dockerfile`) — never the
  readiness one; the comment there explains why.
  """
  use Phoenix.Controller, formats: [:json]
  require Logger

  # Well under the Dockerfile's `--timeout=10s`: a stuck database must produce a 503 *inside*
  # the probe's window, rather than letting the probe itself time out.
  @db_timeout_ms 2_000

  # GET /health and GET /health/live — no I/O, so nothing but a dead BEAM can fail it.
  def index(conn, _params), do: json(conn, %{status: "ok", service: "termelix"})

  # GET /health/ready
  def ready(conn, _params) do
    case check_db() do
      :ok ->
        json(conn, %{status: "ready"})

      {:error, detail} ->
        # The detail goes to the log, never to the caller. This route is on the unauthenticated
        # `:api` pipeline, and the reasons here are `Exqlite.Error`/`DBConnection.ConnectionError`
        # messages that embed the database path, adapter module names and pool internals — a
        # free filesystem-layout disclosure to anyone who can reach the port whenever the
        # database is unhappy. The operator reads the log; the prober only needs the verdict.
        Logger.error("health/ready: database check failed: #{detail}")

        conn
        |> put_status(503)
        |> json(%{status: "unavailable", error: "database_unavailable"})
    end
  end

  # `select 1` through the pool, so both a broken database file and an exhausted or unstarted
  # connection pool are caught. This must never raise: a probe that 500s tells the operator
  # less than one that names the failure.
  defp check_db do
    case Termelix.Repo.query("select 1", [], timeout: @db_timeout_ms) do
      {:ok, _result} -> :ok
      {:error, reason} -> {:error, describe(reason)}
    end
  catch
    # A pool checkout timeout, or a Repo that is not running at all, exits instead of returning.
    kind, reason -> {:error, Exception.format_banner(kind, reason)}
  end

  defp describe(reason) when is_exception(reason), do: Exception.message(reason)
  defp describe(reason), do: inspect(reason)
end
