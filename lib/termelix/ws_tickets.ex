defmodule Termelix.WsTickets do
  @moduledoc """
  Mint-and-consume for the short-lived WebSocket tickets that `POST /users/ws-ticket` issues
  for native WebSocket upgrades (the SSH terminal).

  A ticket is a scoped `Phoenix.Token` (`"\#{scope}_ws"` salt, 30s TTL) whose payload carries a
  random `jti` alongside the user id. Verification alone is stateless — the token would stay
  valid for its full 30s for anyone holding it (a server access log, the WebView page) — so
  the first successful verification CONSUMES the jti: it is recorded in a public ETS table
  with `:ets.insert_new/2`, the atomic check-and-insert exactly one concurrent caller wins.
  A second upgrade carrying the same ticket finds the jti taken and is rejected — the
  documented single-use design, enforced.

  The table is owned for the node's lifetime by `Termelix.EtsOwner` (created in that
  GenServer's `init/1`, like the rate-limit and OIDC flow-state tables; `ensure_table/0` stays
  an idempotent fallback) and swept every 60s via `sweep_expired/1`. Rows live for `@ttl_ms` —
  deliberately longer than the token's 30s TTL, so a jti always outlives every ticket that
  could carry it — which keeps the table bounded.
  """

  @table :termelix_ws_tickets
  @ttl_ms 60_000
  @max_age_s 30

  @doc """
  Create the ETS table if it does not exist yet. Idempotent: the `ArgumentError` raised when
  the named table already exists means the owner (`Termelix.EtsOwner`) or another caller beat
  us to it.
  """
  @spec ensure_table() :: :ok
  def ensure_table do
    try do
      :ets.new(@table, [:named_table, :public, :set, {:write_concurrency, true}])
      :ok
    rescue
      ArgumentError -> :ok
    end
  end

  @doc "Mint a fresh single-use ticket for `user_id` under `scope` (e.g. `\"ssh\"`)."
  @spec mint(String.t(), String.t()) :: String.t()
  def mint(user_id, scope) do
    jti = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
    Phoenix.Token.sign(TermelixWeb.Endpoint, salt(scope), %{uid: user_id, jti: jti})
  end

  @doc """
  Verify `ticket` under `scope`'s salt (30s TTL) and consume its jti. Returns `{:ok, user_id}`
  exactly once per ticket — every later call with the same ticket, and any call with an
  invalid, expired, or wrong-salt ticket, returns `:error`.
  """
  @spec consume(String.t(), String.t()) :: {:ok, String.t()} | :error
  def consume(scope, ticket) when is_binary(ticket) do
    with {:ok, %{uid: user_id, jti: jti}} <-
           Phoenix.Token.verify(TermelixWeb.Endpoint, salt(scope), ticket, max_age: @max_age_s),
         true <- consume_jti(jti) do
      {:ok, user_id}
    else
      _ -> :error
    end
  end

  # Atomic check-and-consume: only the first caller to insert this jti sees `true`.
  defp consume_jti(jti) do
    ensure_table()
    :ets.insert_new(@table, {jti, System.monotonic_time(:millisecond) + @ttl_ms})
  end

  @doc """
  Delete every consumed jti whose retention has lapsed as of `now_ms`, returning the number
  removed. Driven every 60s by `Termelix.EtsOwner`.
  """
  @spec sweep_expired(integer()) :: non_neg_integer()
  def sweep_expired(now_ms \\ System.monotonic_time(:millisecond)) do
    ensure_table()
    spec = [{{:_, :"$1"}, [{:"=<", :"$1", now_ms}], [true]}]
    :ets.select_delete(@table, spec)
  end

  @doc false
  @spec reset_all() :: :ok
  def reset_all do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp salt(scope), do: "#{scope}_ws"
end
