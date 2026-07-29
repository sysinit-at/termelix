defmodule Termelix.Revocation do
  @moduledoc """
  Makes losing access mean losing the connections it bought.

  Authorization was only ever checked when a session or tunnel was *created*. Deleting a user,
  or revoking every one of their auth sessions, deleted rows in `sessions` — so nothing new
  could be opened — and left everything already open running: a shell on a production host,
  and forwarded ports, belonging to an account that no longer exists. A tunnel in particular
  is a listening socket on this node that anyone who can reach it may use, with no further
  authentication of its own.

  This module closes that gap. It is deliberately *not* called from every revoke: sparing one
  session ("log out my other devices") leaves the user with access, and killing the terminal
  they are typing into would be a bug, not security. The rule is that the data plane follows
  the control plane — when the last auth session is gone, so are the connections.

  Broadcast on `Phoenix.PubSub` as well as acted on directly, so a subsystem added later
  subscribes instead of being wired into every call site — and so an operator watching the
  topic can see revocations happen.
  """

  require Logger

  alias Termelix.ApiKeys
  alias Termelix.SSH.Pool
  alias Termelix.Tmux.Watcher
  alias Termelix.Terminal.SessionManager
  alias Termelix.Tunnels

  @topic "revocation"

  @doc "PubSub topic carrying `{:revoked, user_id, reason}`."
  @spec topic() :: String.t()
  def topic, do: @topic

  @doc """
  Tear down everything `user_id` holds on this node, returning what was stopped.

  Idempotent, and safe to call for a user who holds nothing.
  """
  @spec revoke_user(String.t(), atom()) :: %{
          sessions: non_neg_integer(),
          tunnels: non_neg_integer(),
          pooled: non_neg_integer(),
          watchers: non_neg_integer(),
          keys: non_neg_integer()
        }
  def revoke_user(user_id, reason \\ :revoked) when is_binary(user_id) do
    Phoenix.PubSub.broadcast(Termelix.PubSub, @topic, {:revoked, user_id, reason})

    stopped = %{
      sessions: SessionManager.stop_user_sessions(user_id),
      tunnels: Tunnels.stop_user_tunnels(user_id),
      # Sessions and tunnels are the connections a user can SEE. The pool is the one they
      # cannot: an authenticated connection kept warm for the next sftp listing or tmux probe,
      # held 60s past its last use and indefinitely while a channel is open. Stopping the
      # visible two and leaving this behind is the difference between revocation and the
      # appearance of it.
      pooled: Pool.close_user_conns(user_id),
      # And the watchers. Least visible of the four and the easiest to forget, because a
      # watcher is not something the user opened — it is something the server started on
      # their behalf, holding their credentials and dialing their host on a timer. It also
      # deliberately does not idle out while a pane awaits input, so left alone it would
      # poll a revoked user's machine forever.
      watchers: Watcher.stop_user_watchers(user_id),
      # And the API keys — the surface that would have made every other one pointless. A key
      # is long-lived by design and carries no session, so stopping a user's terminals,
      # tunnels, pooled connections and watchers left the one credential that can re-open all
      # of it still working. Deactivated, not deleted: the row is the audit trail's link
      # between an action and the credential that took it.
      keys: ApiKeys.deactivate_all_for_user(user_id)
    }

    # Emitted on every sweep, including the empty ones: "revocation ran and found nothing" is
    # the observation that distinguishes a working revocation from one that was never called.
    :telemetry.execute([:termelix, :revocation, :swept], Map.put(stopped, :count, 1), %{
      user_id: user_id,
      reason: reason
    })

    if Enum.any?(Map.values(stopped), &(&1 > 0)) do
      Logger.info(
        "revocation (#{reason}) for #{user_id}: #{stopped.sessions} session(s), " <>
          "#{stopped.tunnels} tunnel(s), #{stopped.pooled} pooled connection(s), " <>
          "#{stopped.watchers} watcher(s), #{stopped.keys} api key(s)"
      )
    end

    stopped
  end
end
