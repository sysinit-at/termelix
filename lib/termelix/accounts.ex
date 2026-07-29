defmodule Termelix.Accounts do
  @moduledoc """
  User registration, authentication, and session management — the Elixir port of the
  relevant `users.ts` / `auth-manager.ts` logic.

  Sensitive user fields (notably `passwordHash`) are stored *lazily encrypted*: a freshly
  registered user's hash is plaintext, and only later logins migrate it under the DEK. Reads
  therefore go through `DataCrypto.safe_decrypt`, which returns plaintext as-is and unseals
  envelopes — so `authenticate/2` works against both.
  """
  import Ecto.Query, only: [from: 2]
  require Logger

  alias Termelix.Repo
  alias Termelix.Schema.{User, Session}
  alias Termelix.Crypto.{UserKeyManager, DataCrypto}
  alias Termelix.Auth.Token
  alias Termelix.{Id, Settings}

  @default_session_timeout_hours 24
  @min_password_length 8

  # --- policy toggles -------------------------------------------------------

  @doc "Whether self-registration is allowed (env ALLOW_REGISTRATION, else setting, else true)."
  @spec registration_allowed?() :: boolean()
  def registration_allowed?, do: bool_toggle("ALLOW_REGISTRATION", "allow_registration", true)

  @doc "Whether password login is allowed."
  @spec password_login_allowed?() :: boolean()
  def password_login_allowed?,
    do: bool_toggle("ALLOW_PASSWORD_LOGIN", "allow_password_login", true)

  @doc "Total number of users."
  @spec user_count() :: non_neg_integer()
  def user_count, do: Repo.aggregate(User, :count, :id)

  @doc "Session lifetime in hours (setting `session_timeout_hours`, default 24)."
  @spec session_timeout_hours() :: pos_integer()
  def session_timeout_hours do
    case Settings.get_value("session_timeout_hours") do
      nil -> @default_session_timeout_hours
      v -> String.to_integer(v)
    end
  rescue
    _ -> @default_session_timeout_hours
  end

  # --- lookups --------------------------------------------------------------

  @spec get_user(String.t()) :: User.t() | nil
  def get_user(id), do: Repo.get(User, id)

  @spec get_user_by_username(String.t()) :: User.t() | nil
  def get_user_by_username(username), do: Repo.get_by(User, username: username)

  # --- registration ---------------------------------------------------------

  @doc """
  Register a local user. First user becomes admin. Returns `{:ok, user, first_user?}`.
  Creates the user's DEK; if that fails the user row is rolled back.

  Passwords must be at least #{@min_password_length} characters (`:password_too_short`).
  Username uniqueness is guarded twice: the friendly `:username_taken` pre-check, plus a
  `unique_constraint` backstop on insert so a check-then-insert race maps to the same error
  once the database unique index (added separately) exists.
  """
  @spec register_user(String.t() | nil, String.t() | nil) ::
          {:ok, User.t(), boolean()} | {:error, atom()}
  def register_user(username, password) do
    cond do
      not registration_allowed?() ->
        {:error, :registration_disabled}

      blank?(username) or blank?(password) ->
        {:error, :missing_fields}

      not is_binary(password) or String.length(password) < @min_password_length ->
        {:error, :password_too_short}

      get_user_by_username(username) ->
        {:error, :username_taken}

      true ->
        insert_user(username, password, admin?: user_count() == 0)
    end
  end

  @doc """
  Admin-created user: never admin, no first-user logic. Same input policy as
  `register_user/2` (including the minimum password length).
  """
  @spec admin_create_user(String.t() | nil, String.t() | nil) ::
          {:ok, User.t()} | {:error, atom()}
  def admin_create_user(username, password) do
    cond do
      blank?(username) or blank?(password) ->
        {:error, :missing_fields}

      not is_binary(password) or String.length(password) < @min_password_length ->
        {:error, :password_too_short}

      get_user_by_username(username) ->
        {:error, :username_taken}

      true ->
        with {:ok, user, _} <- insert_user(username, password, admin?: false), do: {:ok, user}
    end
  end

  defp insert_user(username, password, admin?: admin?) do
    id = Id.generate()
    hash = Bcrypt.hash_pwd_salt(password, log_rounds: 10)

    changeset =
      %User{
        id: id,
        username: username,
        passwordHash: hash,
        isAdmin: admin?,
        isOidc: false,
        scopes: "openid email profile",
        totpEnabled: false,
        donationModalDismissed: false
      }
      |> Ecto.Changeset.change()
      # Backstop for the check-then-insert race above: harmless while no DB unique
      # index exists, and converts the constraint violation into :username_taken once
      # the separately-provided index is in place.
      |> Ecto.Changeset.unique_constraint(:username)

    case Repo.insert(changeset) do
      {:ok, user} ->
        try do
          UserKeyManager.create_user_dek(id)
          {:ok, user, admin?}
        rescue
          error ->
            Logger.error("DEK creation failed for #{id}: #{Exception.message(error)}")
            Repo.delete(user)
            {:error, :encryption_setup_failed}
        end

      {:error, changeset} ->
        if username_unique_violation?(changeset),
          do: {:error, :username_taken},
          else: {:error, :insert_failed}
    end
  end

  defp username_unique_violation?(changeset) do
    Enum.any?(changeset.errors, fn
      {:username, {_message, opts}} -> opts[:constraint] == :unique
      _other -> false
    end)
  end

  # --- authentication -------------------------------------------------------

  @doc """
  Verify a username/password. Returns `{:ok, user}` or a tagged error:
  `:not_found`, `:external_auth` (OIDC-only user), `:invalid` (bad password).
  """
  @spec authenticate(String.t() | nil, String.t() | nil) ::
          {:ok, User.t()} | {:error, :not_found | :external_auth | :invalid}
  def authenticate(username, password) do
    case get_user_by_username(username) do
      nil ->
        # Constant-time-ish: still run a hash to blunt user-enumeration timing.
        Bcrypt.no_user_verify()
        {:error, :not_found}

      %User{} = user ->
        stored = stored_password_hash(user)

        cond do
          blank?(stored) -> {:error, :external_auth}
          Bcrypt.verify_pass(password, stored) -> {:ok, user}
          true -> {:error, :invalid}
        end
    end
  end

  # passwordHash may be plaintext (fresh) or a DEK-sealed envelope (migrated). Unseal safely.
  defp stored_password_hash(%User{id: id, passwordHash: hash}) do
    case UserKeyManager.try_get_user_dek(id) do
      nil -> hash
      dek -> DataCrypto.decrypt_record("users", %{id: id, passwordHash: hash}, dek).passwordHash
    end
  end

  # --- sessions -------------------------------------------------------------

  @doc """
  Create a login session and issue a session-bound JWT. Returns `{:ok, token, session}`.
  `ttl_seconds` sets both the JWT expiry and the session row's expires_at.
  """
  @spec create_session(User.t(), String.t(), String.t(), pos_integer()) ::
          {:ok, String.t(), Session.t()}
  def create_session(%User{id: user_id}, device_type, device_info, ttl_seconds) do
    session_id = Id.generate()
    token = Token.sign(%{"userId" => user_id, "sessionId" => session_id}, ttl_seconds)
    now = DateTime.utc_now()

    session =
      Repo.insert!(%Session{
        id: session_id,
        userId: user_id,
        jwtToken: token,
        deviceType: device_type,
        deviceInfo: device_info,
        createdAt: DateTime.to_iso8601(now),
        expiresAt: now |> DateTime.add(ttl_seconds, :second) |> DateTime.to_iso8601(),
        lastActiveAt: DateTime.to_iso8601(now)
      })

    {:ok, token, session}
  end

  @doc "Issue a short-lived interim token that only marks that TOTP is still required."
  @spec pending_totp_token(User.t()) :: String.t()
  def pending_totp_token(%User{id: user_id}),
    do: Token.sign(%{"userId" => user_id, "pendingTOTP" => true}, 600)

  @doc "Revoke a single session row by id."
  @spec revoke_session(String.t()) :: :ok
  def revoke_session(session_id) do
    Repo.delete_all(from(s in Session, where: s.id == ^session_id))
    :ok
  end

  @doc """
  Revoke every session belonging to a user, and with them the connections those sessions
  authorized.

  The data-plane sweep lives HERE rather than at the call sites, because there are two of
  them and they had drifted: `TermelixWeb.OidcController` deletes an account through this
  function, and it revoked the rows while leaving the account's shells and forwarded ports
  running. Putting it behind the function means "this user has no auth sessions left" and
  "this user holds no connections" cannot disagree again.

  Ordered: rows first, connections second. The reverse leaves a window in which a request
  that is still authorized re-opens what was just closed.
  """
  @spec revoke_all_sessions(String.t()) :: :ok
  def revoke_all_sessions(user_id) do
    Repo.delete_all(from(s in Session, where: s.userId == ^user_id))
    Termelix.Revocation.revoke_user(user_id, :sessions_revoked)
    :ok
  end

  @doc """
  Verify a JWT and the session it is bound to, returning the resolved user.

  Errors mirror the original's 401 discriminators:
  `:invalid`, `:expired`, `:totp_required`, `:session_not_found`, `:session_expired`,
  `:user_not_found`.
  """
  @spec verify_token(String.t()) ::
          {:ok, %{user: User.t(), claims: map()}}
          | {:error, atom()}
  def verify_token(token) do
    with {:ok, claims} <- Token.verify(token),
         :ok <- reject_pending_totp(claims),
         {:ok, _session} <- check_session(claims),
         %User{} = user <- fetch_claim_user(claims) do
      {:ok, %{user: user, claims: claims}}
    else
      {:error, reason} -> {:error, reason}
      nil -> {:error, :user_not_found}
    end
  end

  defp reject_pending_totp(%{"pendingTOTP" => true}), do: {:error, :totp_required}
  defp reject_pending_totp(_), do: :ok

  defp check_session(%{"sessionId" => sid}) when is_binary(sid) do
    case Repo.get(Session, sid) do
      nil ->
        {:error, :session_not_found}

      %Session{expiresAt: expires_at} = session ->
        # Fail closed via `Termelix.Time`: an absent or unparseable `expiresAt` is expired, not
        # valid-forever. This used to be a local parser that returned "not expired" on both.
        if Termelix.Time.expired?(expires_at) do
          {:error, :session_expired}
        else
          {:ok, session}
        end
    end
  end

  defp check_session(_), do: {:ok, :no_session}

  defp fetch_claim_user(%{"userId" => user_id}) when is_binary(user_id), do: get_user(user_id)
  defp fetch_claim_user(_), do: nil

  # --- helpers --------------------------------------------------------------

  defp blank?(nil), do: true
  defp blank?(str) when is_binary(str), do: String.trim(str) == ""
  defp blank?(_), do: false

  defp bool_toggle(env_var, setting_key, default) do
    case System.get_env(env_var) do
      "true" ->
        true

      "false" ->
        false

      _ ->
        case safe_setting(setting_key) do
          "true" -> true
          "false" -> false
          _ -> default
        end
    end
  end

  defp safe_setting(key) do
    Settings.get_value(key)
  rescue
    _ -> nil
  end
end
