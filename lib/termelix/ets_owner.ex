defmodule Termelix.EtsOwner do
  @moduledoc """
  Node-lifetime owner of the process-less ETS tables shared by `Termelix.RateLimiter`,
  `Termelix.HttpCache`, `Termelix.FileManagerSessions`, `Termelix.Oidc`,
  `Termelix.WsTickets` and `Termelix.Tmux.Availability`.

  All these tables are `:named_table, :public`. They used to be created lazily by
  whichever request process touched them first, which made them children of a
  transient Bandit connection: when that process died BEAM destroyed the table with
  it, wiping every login/registration/TOTP budget and the TOTP anti-replay markers.
  Nothing swept stale rows either, so attacker-supplied usernames (each minting a
  `{:login, ip, username}` bucket) were an unbounded-memory foothold. Creating the
  tables in this supervised GenServer's `init/1` ties their lifetime to the
  application instead of to a request.

  A 60-second timer sweeps expired rows from each table via each module's
  `sweep_expired/1` (`:ets.select_delete`), so lapsed rate-limit buckets, cache
  entries and OIDC flow states are erased rather than merely ignored on the next read.

  `Termelix.Oidc`'s table is the newest tenant: its flow state used to be five rows per
  unauthenticated `GET /users/oidc/authorize` in the `settings` table, permanent and
  sharing that table with every user's wrapped DEK. It belongs here for the same reason
  the rate-limit buckets do — unauthenticated writers need a bound and a sweeper.
  """

  use GenServer

  @sweep_interval_ms 60_000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    # Owning process is this GenServer, so the tables live as long as the node.
    Termelix.RateLimiter.ensure_table()
    Termelix.HttpCache.ensure_table()
    Termelix.FileManagerSessions.ensure_table()
    Termelix.Oidc.ensure_table()
    Termelix.WsTickets.ensure_table()

    # Whether a host has tmux. Cached — including the negative answer — because otherwise every
    # terminal open pays an extra SSH round trip on the one latency number users actually feel.
    Termelix.Tmux.Availability.ensure_table()
    TermelixWeb.EventController.ensure_counter_table()
    Termelix.Agent.ensure_wait_table()
    Termelix.ApiKeys.Usage.ensure_table()
    Termelix.Settings.Cache.ensure_table()
    schedule_sweep()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:sweep, state) do
    Termelix.RateLimiter.sweep_expired()
    Termelix.HttpCache.sweep_expired()
    Termelix.FileManagerSessions.sweep_expired()
    Termelix.Oidc.sweep_expired()
    Termelix.WsTickets.sweep_expired()
    Termelix.Tmux.Availability.sweep_expired()
    schedule_sweep()
    {:noreply, state}
  end

  defp schedule_sweep, do: Process.send_after(self(), :sweep, @sweep_interval_ms)
end
