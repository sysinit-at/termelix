defmodule Termelix.RateLimiter do
  @moduledoc """
  Fixed-window rate limiting over a named public ETS table owned for the node's
  lifetime by `Termelix.EtsOwner` (created in that GenServer's `init/1`, so the table —
  and every login/TOTP/registration budget and TOTP anti-replay marker it holds —
  survives the death of any request process). `ensure_table/0` stays an idempotent
  fallback that lazily creates the table should a caller run before the owner.

  `Termelix.EtsOwner` also drives a periodic `sweep_expired/1` that garbage-collects
  buckets whose window has elapsed, so an attacker cannot grow the table without
  bound by varying the username in `{:login, ip, username}` keys.

  Bucket rows are `{key, count, window_start_ms}` under keys `{:login, ip, username}`,
  `{:totp, user_id}` and `{:register, ip}`; the anti-replay marker for TOTP codes is
  `{key, step}` under `{:totp_step, user_id}` — windowless, so the sweep never
  touches it.

  Policies (the Node backend's exact numbers are unknown; chosen to be strict enough
  to matter and lenient enough for real users):

    * login — 10 failed attempts per 10-minute window per IP+username
    * TOTP — 5 failed code attempts per 10-minute window per user (aligned with the
      10-minute `pendingTOTP` interim token TTL, so a lockout never outlives the
      login session it protects)
    * registration — 10 attempts per hour per IP

  All public functions accept an optional trailing `now_ms` (monotonic wall clock in
  milliseconds) so tests can advance time instead of sleeping.
  """

  @table :termelix_rate_limiter

  @login_limit 10
  @login_window_ms 10 * 60 * 1000

  @totp_limit 5
  @totp_window_ms 10 * 60 * 1000

  @register_limit 10
  @register_window_ms 60 * 60 * 1000

  @doc """
  Create the ETS table if it does not exist yet. Idempotent: the `ArgumentError`
  raised when the named table already exists means another process beat us to it.
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

  # --- login (per IP + username) ---------------------------------------------

  @doc """
  `:ok` while the IP+username pair is under the failed-login budget,
  `{:error, retry_after_seconds}` once 10 failures landed inside the 10-minute window.
  """
  @spec check_login(String.t(), String.t(), integer()) :: :ok | {:error, pos_integer()}
  def check_login(ip, username, now_ms \\ now()),
    do: check({:login, ip, username}, @login_limit, @login_window_ms, now_ms)

  @doc "Record a failed login attempt; returns the failure count inside the window."
  @spec record_login_failure(String.t(), String.t(), integer()) :: non_neg_integer()
  def record_login_failure(ip, username, now_ms \\ now()),
    do: record({:login, ip, username}, @login_window_ms, now_ms)

  @doc "Clear the login bucket (on successful authentication)."
  @spec reset_login(String.t(), String.t()) :: :ok
  def reset_login(ip, username), do: delete({:login, ip, username})

  # --- tmux orchestration (per user + host) ------------------------------------

  @orchestrate_limit 60
  @orchestrate_window_ms 60 * 1000

  @doc """
  `:ok` while this user is under the orchestration budget for `host_id`, else
  `{:error, retry_after_seconds}`.

  These verbs type keystrokes into a live terminal and open an SSH exec each. Unbounded, a
  looping agent turns into a keyboard mashing someone's production shell — and the damage is
  not rate-limited by anything downstream, because the shell will run whatever it is given as
  fast as it arrives. Per (user, host) rather than per user, so a busy host cannot starve the
  others.
  """
  @spec check_orchestrate(String.t(), integer(), integer()) :: :ok | {:error, pos_integer()}
  def check_orchestrate(user_id, host_id, now_ms \\ now()),
    do:
      check(
        {:orchestrate, user_id, host_id},
        @orchestrate_limit,
        @orchestrate_window_ms,
        now_ms
      )

  @doc "Record one orchestration verb against the (user, host) budget."
  @spec record_orchestrate(String.t(), integer(), integer()) :: non_neg_integer()
  def record_orchestrate(user_id, host_id, now_ms \\ now()),
    do: record({:orchestrate, user_id, host_id}, @orchestrate_window_ms, now_ms)

  # --- TOTP (per user) ---------------------------------------------------------

  @doc """
  `:ok` while the user is under the failed-TOTP budget, `{:error, retry_after_seconds}`
  once 5 failures landed inside the 10-minute window.
  """
  @spec check_totp(String.t(), integer()) :: :ok | {:error, pos_integer()}
  def check_totp(user_id, now_ms \\ now()),
    do: check({:totp, user_id}, @totp_limit, @totp_window_ms, now_ms)

  @doc """
  Record a failed TOTP code attempt; returns how many attempts remain before lockout
  (0 once the budget is exhausted — the *next* attempt is then refused by
  `check_totp/2`).
  """
  @spec record_totp_failure(String.t(), integer()) :: non_neg_integer()
  def record_totp_failure(user_id, now_ms \\ now()) do
    count = record({:totp, user_id}, @totp_window_ms, now_ms)
    max(@totp_limit - count, 0)
  end

  @doc "Clear the TOTP failure bucket (on successful verification)."
  @spec reset_totp(String.t()) :: :ok
  def reset_totp(user_id), do: delete({:totp, user_id})

  @doc """
  A budget for password re-confirmation on an ALREADY-authenticated session — `unlock-data`
  and `totp/disable`.

  Deliberately its own bucket family rather than reusing `{:totp, user_id}`: that one gates
  *logging in*, so spending it on a fumbled password inside the app would lock the user out
  of the front door for something they did while already signed in. Same reasoning keeps it
  off the login bucket. Keyed on the user, not the IP — the threat here is someone holding a
  stolen session cookie, and they can rotate source addresses freely.
  """
  @spec check_reauth(String.t(), integer()) :: :ok | {:error, pos_integer()}
  def check_reauth(user_id, now_ms \\ now()),
    do: check({:reauth, user_id}, @totp_limit, @totp_window_ms, now_ms)

  @doc "Record a failed password re-confirmation; returns the attempts remaining."
  @spec record_reauth_failure(String.t(), integer()) :: non_neg_integer()
  def record_reauth_failure(user_id, now_ms \\ now()) do
    count = record({:reauth, user_id}, @totp_window_ms, now_ms)
    max(@totp_limit - count, 0)
  end

  @doc "Clear the re-confirmation bucket (on success)."
  @spec reset_reauth(String.t()) :: :ok
  def reset_reauth(user_id), do: delete({:reauth, user_id})

  # --- TOTP anti-replay marker ---------------------------------------------------

  @doc "The newest TOTP timestep accepted for this user, or nil when none yet."
  @spec last_totp_step(String.t()) :: integer() | nil
  def last_totp_step(user_id) do
    ensure_table()

    case :ets.lookup(@table, {:totp_step, user_id}) do
      [{_, step}] -> step
      [] -> nil
    end
  end

  @doc """
  Record `step` as the newest accepted TOTP timestep for the user via an atomic
  compare-and-swap. Returns `:error` (recording nothing) when `step` is not strictly
  newer than the last accepted step — that is the replay rejection.

  Concurrency invariant: given several simultaneous callers with the *same* `step`
  that is strictly newer than the stored one, exactly one wins `:ok` and the rest
  get `:error`. The first-ever step is claimed with `:ets.insert_new/2` (only one
  concurrent insert of a fresh key succeeds); a later step is advanced with a guarded
  `:ets.select_replace/2` (`stored < step`), which the VM applies atomically per
  object, so only one caller can move a given value.
  """
  @spec record_totp_step(String.t(), integer()) :: :ok | :error
  def record_totp_step(user_id, step) do
    ensure_table()
    cas_totp_step({:totp_step, user_id}, step)
  end

  defp cas_totp_step(key, step) do
    if :ets.insert_new(@table, {key, step}) do
      :ok
    else
      case :ets.lookup(@table, key) do
        [{_, last}] when step <= last ->
          :error

        [{_, _last}] ->
          # A strictly newer step. Advance atomically, guarded on the value we just
          # observed still being older than `step`; if a concurrent caller moved it
          # first, `select_replace` matches nothing (0) and we re-evaluate.
          spec = [{{key, :"$1"}, [{:<, :"$1", step}], [{{{:const, key}, step}}]}]

          case :ets.select_replace(@table, spec) do
            1 -> :ok
            0 -> cas_totp_step(key, step)
          end

        [] ->
          # The marker was reset between the failed insert and this read; retry.
          cas_totp_step(key, step)
      end
    end
  end

  @doc "Forget the anti-replay marker (fresh secret chain on setup, clean slate on disable)."
  @spec reset_totp_step(String.t()) :: :ok
  def reset_totp_step(user_id), do: delete({:totp_step, user_id})

  # --- registration (per IP) -----------------------------------------------------

  @doc """
  `:ok` while the IP is under the registration budget, `{:error, retry_after_seconds}`
  once 10 attempts landed inside the 1-hour window.
  """
  @spec check_register(String.t(), integer()) :: :ok | {:error, pos_integer()}
  def check_register(ip, now_ms \\ now()),
    do: check({:register, ip}, @register_limit, @register_window_ms, now_ms)

  @doc "Record a registration attempt (success or failure); returns the window count."
  @spec record_register_attempt(String.t(), integer()) :: non_neg_integer()
  def record_register_attempt(ip, now_ms \\ now()),
    do: record({:register, ip}, @register_window_ms, now_ms)

  # --- expiry sweep --------------------------------------------------------------

  @doc """
  Delete every bucket whose fixed window has elapsed as of `now_ms`, returning the
  number of rows removed. Driven every 60s by `Termelix.EtsOwner`. The bucket
  families carry different windows, so each is swept with its own guard; the
  windowless `{:totp_step, _}` markers are 2-tuples and match none of the 3-tuple
  bucket specs, so they are left untouched.
  """
  @spec sweep_expired(integer()) :: non_neg_integer()
  def sweep_expired(now_ms \\ now()) do
    ensure_table()

    sweep_bucket({:orchestrate, :_, :_}, @orchestrate_window_ms, now_ms) +
      sweep_bucket({:login, :_, :_}, @login_window_ms, now_ms) +
      sweep_bucket({:totp, :_}, @totp_window_ms, now_ms) +
      sweep_bucket({:reauth, :_}, @totp_window_ms, now_ms) +
      sweep_bucket({:register, :_}, @register_window_ms, now_ms)
  end

  # A bucket row is `{key, count, window_start_ms}`; delete it once the window has
  # fully elapsed (`now_ms - start >= window_ms`), which is exactly when `check/4`
  # already treats it as no bucket.
  defp sweep_bucket(key_pattern, window_ms, now_ms) do
    spec = [{{key_pattern, :_, :"$1"}, [{:>=, {:-, now_ms, :"$1"}, window_ms}], [true]}]
    :ets.select_delete(@table, spec)
  end

  # --- test/maintenance helper ---------------------------------------------------

  @doc false
  @spec reset_all() :: :ok
  def reset_all do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  # --- fixed-window core ---------------------------------------------------------

  # Refuse when the bucket is at/over the limit and still inside its window; a stale
  # bucket (window elapsed) is treated as no bucket and the next `record` restarts it.
  defp check(key, limit, window_ms, now_ms) do
    ensure_table()

    case :ets.lookup(@table, key) do
      [{_, count, start}] when count >= limit and now_ms - start < window_ms ->
        {:error, ceil_div(window_ms - (now_ms - start), 1000)}

      _ ->
        :ok
    end
  end

  # Increment the bucket, restarting the window when the previous one expired. The
  # increment itself is atomic via `:ets.update_counter`; the surrounding
  # read-modify-write may race under concurrency, which is acceptable for a limiter
  # (worst case a bucket resets a window early or a count is lost).
  defp record(key, window_ms, now_ms) do
    ensure_table()

    case :ets.lookup(@table, key) do
      [{_, count, start}] when now_ms - start < window_ms ->
        :ets.update_counter(@table, key, {2, 1}, {key, 0, now_ms})
        count + 1

      _ ->
        :ets.insert(@table, {key, 1, now_ms})
        1
    end
  end

  defp delete(key) do
    ensure_table()
    :ets.delete(@table, key)
    :ok
  end

  defp ceil_div(a, b), do: div(a + b - 1, b)

  defp now, do: System.system_time(:millisecond)
end
