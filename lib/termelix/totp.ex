defmodule Termelix.Totp do
  @moduledoc """
  TOTP 2FA — the Elixir port of `user-totp-routes.ts` (setup / enable / disable / the
  second `verify-login` step).

  The shared HMAC secret is a speakeasy-style RFC 4648 base32 string (uppercase, no
  padding). It lives in the encrypted `totpSecret` user field and, together with the
  JSON-array `totpBackupCodes`, is sealed under the owning user's DEK via `DataCrypto`
  (`FieldCrypto`'s `users` entry lists both fields) and read back lazily — plaintext or a
  DEK envelope both decode. `NimbleTOTP` operates on the *raw* secret binary, so
  verification decodes the base32 first and checks the current and previous `@window`
  30-second steps (the past half of speakeasy `window: 2`), or a one-time backup code
  (consumed on use).

  Two protections the original had and the first port dropped live here:

    * Rate limiting: 5 failed code attempts per user per 10-minute window (see
      `Termelix.RateLimiter`), enforced on `verify_login`, `enable` and `disable`.
    * Replay protection: an accepted TOTP code is matched to its exact 30-second
      timestep, which must be strictly newer than the last accepted step for the user
      (tracked in the rate-limiter table under `{:totp_step, user_id}`). The same code
      — or one from an older step — is rejected on reuse. Only past/current steps are
      accepted so a future-step code can never poison the marker.

  `verify_login/3`, `enable/3` and `disable/4` take an optional `now` (seconds) so
  tests can pick their timesteps instead of sleeping.

  Not ported (consistent with the login fold-in's trusted-device note in `UserController`):
  the trusted-device "Remember Me" bypass, the enable-time revoke-other-sessions sweep,
  and the standalone backup-code regeneration route.
  """

  alias Termelix.Repo
  alias Termelix.Schema.User
  alias Termelix.{Accounts, RateLimiter}
  alias Termelix.Auth.Token
  alias Termelix.Crypto.{UserKeyManager, DataCrypto}

  @period 30
  @window 2
  @backup_code_count 8
  @backup_code_length 8
  @backup_alphabet ~c"0123456789abcdefghijklmnopqrstuvwxyz"

  # --- setup ----------------------------------------------------------------

  @doc """
  Begin TOTP setup: mint a fresh base32 secret, persist it (DEK-encrypted) as the user's
  `totpSecret`, and return the secret plus its `otpauth://` URL for QR rendering. Fails with
  `:already_enabled` when 2FA is already on.
  """
  @spec setup(User.t()) ::
          {:ok, %{secret: String.t(), otpauth_url: String.t()}} | {:error, :already_enabled}
  def setup(%User{totpEnabled: true}), do: {:error, :already_enabled}

  def setup(%User{} = user) do
    raw = :crypto.strong_rand_bytes(20)
    secret = Base.encode32(raw, padding: false)
    otpauth_url = NimbleTOTP.otpauth_uri("Termelix (#{user.username})", raw)

    # A fresh secret starts a fresh anti-replay chain.
    RateLimiter.reset_totp_step(user.id)
    update_user(user, %{totpSecret: secret})
    {:ok, %{secret: secret, otpauth_url: otpauth_url}}
  end

  # --- enable ---------------------------------------------------------------

  @doc """
  Enable TOTP after verifying the initial `code` against the pending `totpSecret`. On success
  mints and stores (DEK-encrypted) a fresh set of backup codes, flips `totpEnabled`, and
  returns `{:ok, backup_codes}`. Guards mirror the Node route's error ladder; code attempts
  are rate limited and replay-protected (see the moduledoc).
  """
  @spec enable(User.t(), String.t(), integer()) ::
          {:ok, [String.t()]}
          | {:error, :password_login_disabled | :already_enabled | :not_initiated | :invalid_code}
          | {:error, :rate_limited, pos_integer()}
  def enable(%User{} = user, code, now \\ System.os_time(:second)) do
    du = decrypt_user(user)

    cond do
      not Accounts.password_login_allowed?() ->
        {:error, :password_login_disabled}

      du.totpEnabled == true ->
        {:error, :already_enabled}

      blank?(du.totpSecret) ->
        {:error, :not_initiated}

      true ->
        case RateLimiter.check_totp(user.id) do
          {:error, retry_after} ->
            {:error, :rate_limited, retry_after}

          :ok ->
            if reauth(du, code, now) do
              RateLimiter.reset_totp(user.id)
              codes = generate_backup_codes()
              update_user(du, %{totpEnabled: true, totpBackupCodes: Jason.encode!(codes)})
              {:ok, codes}
            else
              RateLimiter.record_totp_failure(user.id)
              {:error, :invalid_code}
            end
        end
    end
  end

  # --- disable --------------------------------------------------------------

  @doc """
  Disable TOTP. Requires a valid `code` (a TOTP code or an unused backup code) plus, for
  non-OIDC users, the account `password`. Clears `totpSecret`/`totpBackupCodes` and flips
  `totpEnabled` off. Error tags mirror the Node route; `{:missing_credentials, oidc?}`
  carries whether the user is OIDC so the controller can pick the right 400 message.
  Code attempts are rate limited and replay-protected (see the moduledoc).
  """
  @spec disable(User.t(), String.t() | nil, String.t() | nil, integer()) ::
          :ok
          | {:error,
             {:missing_credentials, boolean()}
             | :incorrect_password
             | :not_enabled
             | :invalid_reauth}
          | {:error, :rate_limited, pos_integer()}
  def disable(%User{} = user, password, code, now \\ System.os_time(:second)) do
    du = decrypt_user(user)
    oidc? = du.isOidc == true

    cond do
      blank?(code) or (not oidc? and blank?(password)) ->
        {:error, {:missing_credentials, oidc?}}

      not oidc? and not valid_password?(du, password) ->
        {:error, :incorrect_password}

      du.totpEnabled != true ->
        {:error, :not_enabled}

      true ->
        case RateLimiter.check_totp(user.id) do
          {:error, retry_after} ->
            {:error, :rate_limited, retry_after}

          :ok ->
            if reauth(du, code, now) do
              RateLimiter.reset_totp(user.id)
              RateLimiter.reset_totp_step(user.id)
              update_user(du, %{totpEnabled: false, totpSecret: nil, totpBackupCodes: nil})
              :ok
            else
              RateLimiter.record_totp_failure(user.id)
              {:error, :invalid_reauth}
            end
        end
    end
  end

  # --- verify-login (second login step) -------------------------------------

  @doc """
  Second login step: validate the `pendingTOTP` interim token, then verify `code` against the
  user's secret (replay-protected, see the moduledoc) or a one-time backup code (consumed on
  use). Returns `{:ok, user}` for the controller to mint a real session, or a tagged error
  mirroring the Node route.

  Failed codes count against the per-user TOTP budget: `{:error, :invalid_code, remaining}`
  carries the attempts left before lockout, and once the budget is exhausted every attempt
  (valid code or not) is refused with `{:error, :rate_limited, retry_after_seconds}`.

  The interim token is verified directly (not via `Accounts.verify_token`, which rejects
  `pendingTOTP`) and must carry `pendingTOTP: true`.
  """
  @spec verify_login(String.t(), String.t(), integer()) ::
          {:ok, User.t()}
          | {:error, :invalid_token | :user_not_found | :not_enabled | :session_expired}
          | {:error, :invalid_code, non_neg_integer()}
          | {:error, :rate_limited, pos_integer()}
  def verify_login(temp_token, code, now \\ System.os_time(:second)) do
    with {:ok, user} <- resolve_pending_user(temp_token),
         :ok <- check_totp_rate(user.id),
         :ok <- ensure_enabled(user),
         {:ok, du} <- decrypt_with_dek(user),
         :ok <- check_login_code(du, code, now) do
      RateLimiter.reset_totp(user.id)
      {:ok, user}
    end
  end

  defp resolve_pending_user(temp_token) do
    with {:ok, %{"pendingTOTP" => true, "userId" => user_id}} <- Token.verify(temp_token),
         %User{} = user <- Accounts.get_user(user_id) do
      {:ok, user}
    else
      nil -> {:error, :user_not_found}
      _ -> {:error, :invalid_token}
    end
  end

  # `totpSecret`/`totpEnabled` here are the encrypted-at-rest columns; a present (non-blank)
  # ciphertext is enough to know 2FA is configured.
  defp ensure_enabled(%User{totpEnabled: true} = user) do
    if present?(user.totpSecret), do: :ok, else: {:error, :not_enabled}
  end

  defp ensure_enabled(_), do: {:error, :not_enabled}

  # The port can always unseal a user's DEK from the instance ENCRYPTION_KEY, so this only
  # fails for a user with no DEK at all — mapped to SESSION_EXPIRED like the Node route.
  defp decrypt_with_dek(%User{id: id} = user) do
    case UserKeyManager.try_get_user_dek(id) do
      nil -> {:error, :session_expired}
      dek -> {:ok, DataCrypto.decrypt_record("users", user, dek)}
    end
  end

  defp check_totp_rate(user_id) do
    case RateLimiter.check_totp(user_id) do
      :ok -> :ok
      {:error, retry_after} -> {:error, :rate_limited, retry_after}
    end
  end

  defp check_login_code(du, code, now) do
    if reauth(du, code, now) do
      :ok
    else
      {:error, :invalid_code, RateLimiter.record_totp_failure(du.id)}
    end
  end

  # --- verification ---------------------------------------------------------

  # A valid TOTP whose matched timestep is strictly newer than the last accepted one
  # (anti-replay), or a one-time backup code (consumed and re-persisted). `du` must
  # already be DEK-decrypted.
  defp reauth(%User{} = du, code, now) do
    verify_fresh_totp(du, code, now) or consume_backup_code(du, code)
  end

  # `totpSecret` is the decrypted speakeasy base32 secret; decode it to the raw binary
  # NimbleTOTP expects, find the exact timestep the code belongs to, and accept it only
  # when that step is strictly newer than the last accepted step for the user. The
  # check-and-record is a single atomic compare-and-swap inside
  # `RateLimiter.record_totp_step/2`, so two concurrent verifications of the same code
  # cannot both succeed (exactly one advances the marker; the other is rejected as replay).
  defp verify_fresh_totp(%User{id: id, totpSecret: secret}, code, now)
       when is_binary(secret) and is_binary(code) do
    with {:ok, raw} <- decode_base32(secret),
         step when is_integer(step) <- matching_step(raw, code, now),
         :ok <- RateLimiter.record_totp_step(id, step) do
      true
    else
      _ -> false
    end
  end

  defp verify_fresh_totp(_, _, _), do: false

  # The newest timestep within `current - @window..current` (the past half of speakeasy
  # `window: 2`) whose code matches, or nil. Each candidate is validated at exactly its
  # own step (speakeasy `window: 0`); future steps are deliberately not accepted, so an
  # accepted code can never poison the anti-replay marker with a future step.
  defp matching_step(raw, code, now) do
    current = div(now, @period)

    (current - @window)..current
    |> Enum.filter(fn step ->
      NimbleTOTP.valid?(raw, code, time: step * @period, period: @period)
    end)
    |> Enum.max(fn -> nil end)
  end

  # speakeasy secrets are RFC 4648 base32 without padding; upcase for robustness then decode.
  defp decode_base32(secret) do
    secret |> String.upcase() |> Base.decode32(padding: false, case: :upper)
  end

  defp consume_backup_code(%User{} = du, code) when is_binary(code) do
    codes = parse_backup_codes(du.totpBackupCodes)

    if code in codes do
      remaining = List.delete(codes, code)
      update_user(du, %{totpBackupCodes: Jason.encode!(remaining)})
      true
    else
      false
    end
  end

  defp consume_backup_code(_, _), do: false

  defp parse_backup_codes(json) when is_binary(json) and json != "" do
    case Jason.decode(json) do
      {:ok, list} when is_list(list) -> list
      _ -> []
    end
  end

  defp parse_backup_codes(_), do: []

  # 8 codes of 8 uppercased base36 characters (matches the Node backup-code shape, minted with
  # cryptographic randomness rather than Math.random).
  defp generate_backup_codes do
    for _ <- 1..@backup_code_count, do: random_backup_code()
  end

  defp random_backup_code do
    @backup_code_length
    |> :crypto.strong_rand_bytes()
    |> :binary.bin_to_list()
    |> Enum.map_join(fn byte -> <<Enum.at(@backup_alphabet, rem(byte, 36))>> end)
    |> String.upcase()
  end

  # --- persistence + secret handling ----------------------------------------

  defp valid_password?(%User{passwordHash: hash}, password) do
    present?(hash) and is_binary(password) and Bcrypt.verify_pass(password, hash)
  end

  # Decrypt the user's DEK-sealed fields (totpSecret / totpBackupCodes / passwordHash) in
  # memory. Falls back to the raw struct when the DEK is unavailable (lazy-safe).
  defp decrypt_user(%User{id: id} = user) do
    case UserKeyManager.try_get_user_dek(id) do
      nil -> user
      dek -> DataCrypto.decrypt_record("users", user, dek)
    end
  end

  # Persist `attrs` onto the user row, DEK-encrypting any present secret fields first. Only
  # keys in `attrs` are written, so untouched columns (e.g. the stored `totpSecret` on an
  # enable) keep their ciphertext. Nils and booleans pass through unencrypted.
  defp update_user(%User{id: id} = user, attrs) do
    attrs =
      if Enum.any?([:totpSecret, :totpBackupCodes], &encryptable?(Map.get(attrs, &1))) do
        DataCrypto.encrypt_record("users", attrs, id, UserKeyManager.get_user_dek(id))
      else
        attrs
      end

    user |> Ecto.Changeset.change(attrs) |> Repo.update!()
  end

  defp encryptable?(v), do: is_binary(v) and v != ""

  # --- small helpers --------------------------------------------------------

  defp blank?(nil), do: true
  defp blank?(str) when is_binary(str), do: String.trim(str) == ""
  defp blank?(_), do: false

  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: false
end
