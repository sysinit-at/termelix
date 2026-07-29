defmodule TermelixWeb.TotpTest do
  @moduledoc """
  Coverage for the TOTP 2FA surface (`Termelix.Totp` + `TermelixWeb.TotpController`): setup mints
  and DEK-encrypts a base32 secret; enable verifies the initial code and issues backup codes;
  verify-login validates the `pendingTOTP` interim token and completes the second login step
  (TOTP code or a one-time backup code), minting a session + `jwt` cookie; disable requires
  password + code and clears the secret. Also covered: the TOTP rate limiter (5 failures →
  lockout, `remainingAttempts` in the 401 envelope, 429 `TOTP_RATE_LIMITED`) and timestep
  anti-replay protection (an accepted code cannot be reused).

  The context is exercised directly, and the controller actions are invoked directly with a
  conn carrying the authenticated-user assigns (the same pattern as `sftp_test.exs`), so the
  suite does not depend on the TOTP routes being wired into the router. The one routed call is
  `/users/login`, to prove the existing login fold-in returns `requires_totp` + `temp_token`.

  Time is never slept on: `enable_totp!/1` enables at an already-elapsed step (real now − 60s)
  so codes generated for the real current step are strictly newer than the enable-time step
  (the anti-replay rule), and the replay tests inject explicit `now` values.
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, RateLimiter, Totp}
  alias TermelixWeb.TotpController

  @password "correct horse battery staple"

  setup do
    RateLimiter.reset_all()
    {:ok, user, true} = Accounts.register_user("alice", @password)
    %{user: user}
  end

  describe "Totp context" do
    test "setup mints a base32 secret + otpauth url and stores it encrypted", %{user: user} do
      assert {:ok, %{secret: secret, otpauth_url: url}} = Totp.setup(user)
      assert {:ok, _raw} = Base.decode32(secret, padding: false)
      assert String.starts_with?(url, "otpauth://totp/Termelix")
      assert String.contains?(url, "secret=#{secret}")

      # Persisted as a DEK envelope, never as the plaintext base32.
      stored = Accounts.get_user(user.id).totpSecret
      assert String.starts_with?(stored, "{")
      refute stored == secret
    end

    test "setup is rejected once TOTP is enabled", %{user: user} do
      {enabled_user, _secret, _codes} = enable_totp!(user)
      assert {:error, :already_enabled} = Totp.setup(enabled_user)
    end

    test "enable verifies the code, flips totpEnabled, and returns 8 backup codes", %{user: user} do
      {:ok, %{secret: secret}} = Totp.setup(user)
      user = Accounts.get_user(user.id)

      assert {:ok, codes} = Totp.enable(user, current_code(secret))
      assert length(codes) == 8
      assert Enum.all?(codes, &(String.length(&1) == 8))

      reloaded = Accounts.get_user(user.id)
      assert reloaded.totpEnabled == true
      # Backup codes are stored encrypted, not as the plaintext JSON array.
      assert String.starts_with?(reloaded.totpBackupCodes, "{")
    end

    test "enable rejects an invalid code", %{user: user} do
      {:ok, %{secret: secret}} = Totp.setup(user)
      user = Accounts.get_user(user.id)
      assert {:error, :invalid_code} = Totp.enable(user, invalid_code(secret))
    end

    test "enable before setup is not_initiated", %{user: user} do
      assert {:error, :not_initiated} = Totp.enable(user, "123456")
    end

    test "verify_login accepts a valid pending token + current code", %{user: user} do
      {enabled_user, secret, _codes} = enable_totp!(user)
      temp = Accounts.pending_totp_token(enabled_user)

      assert {:ok, verified} = Totp.verify_login(temp, current_code(secret))
      assert verified.id == enabled_user.id
    end

    test "verify_login accepts a backup code once, then rejects its reuse", %{user: user} do
      {enabled_user, _secret, codes} = enable_totp!(user)
      code = hd(codes)

      assert {:ok, _} = Totp.verify_login(Accounts.pending_totp_token(enabled_user), code)
      # A backup code is single-use — consumed above, it no longer validates.
      assert {:error, :invalid_code, _remaining} =
               Totp.verify_login(Accounts.pending_totp_token(enabled_user), code)
    end

    test "verify_login rejects a garbage token", %{user: user} do
      {_enabled_user, secret, _codes} = enable_totp!(user)
      assert {:error, :invalid_token} = Totp.verify_login("not-a-jwt", current_code(secret))
    end

    test "verify_login rejects a non-pending (real session) token", %{user: user} do
      {enabled_user, secret, _codes} = enable_totp!(user)
      {:ok, real_token, _session} = Accounts.create_session(enabled_user, "web", "test", 3600)
      assert {:error, :invalid_token} = Totp.verify_login(real_token, current_code(secret))
    end

    test "disable with password + code clears the secret and backup codes", %{user: user} do
      {enabled_user, secret, _codes} = enable_totp!(user)

      assert :ok = Totp.disable(enabled_user, @password, current_code(secret))

      reloaded = Accounts.get_user(user.id)
      assert reloaded.totpEnabled == false
      assert reloaded.totpSecret == nil
      assert reloaded.totpBackupCodes == nil
    end

    test "disable accepts a backup code in place of a TOTP code", %{user: user} do
      {enabled_user, _secret, codes} = enable_totp!(user)
      assert :ok = Totp.disable(enabled_user, @password, hd(codes))
    end

    test "disable rejects a wrong password", %{user: user} do
      {enabled_user, secret, _codes} = enable_totp!(user)

      assert {:error, :incorrect_password} =
               Totp.disable(enabled_user, "wrong-password", current_code(secret))
    end

    test "disable without a code is missing_credentials", %{user: user} do
      {enabled_user, _secret, _codes} = enable_totp!(user)
      assert {:error, {:missing_credentials, false}} = Totp.disable(enabled_user, @password, nil)
    end
  end

  describe "TOTP replay protection" do
    test "the same code cannot be used twice at verify-login", %{user: user} do
      {enabled_user, secret, _codes} = enable_totp!(user)
      now = System.os_time(:second)
      code = code_at(secret, now)

      assert {:ok, _} = Totp.verify_login(Accounts.pending_totp_token(enabled_user), code, now)

      assert {:error, :invalid_code, _remaining} =
               Totp.verify_login(Accounts.pending_totp_token(enabled_user), code, now)
    end

    test "the code consumed at enable cannot be replayed at verify-login", %{user: user} do
      {:ok, %{secret: secret}} = Totp.setup(user)
      now = System.os_time(:second)
      code = code_at(secret, now)

      assert {:ok, _codes} = Totp.enable(Accounts.get_user(user.id), code, now)

      temp = Accounts.pending_totp_token(Accounts.get_user(user.id))
      assert {:error, :invalid_code, _} = Totp.verify_login(temp, code, now)
    end

    test "an older-step code is rejected once a newer step was accepted", %{user: user} do
      {enabled_user, secret, _codes} = enable_totp!(user)
      now = System.os_time(:second)

      assert {:ok, _} =
               Totp.verify_login(
                 Accounts.pending_totp_token(enabled_user),
                 code_at(secret, now),
                 now
               )

      # The previous step's code is inside the acceptance window but older than the
      # last accepted step — a replay.
      assert {:error, :invalid_code, _} =
               Totp.verify_login(
                 Accounts.pending_totp_token(enabled_user),
                 code_at(secret, now - 30),
                 now
               )
    end

    test "codes from successive steps are each accepted once", %{user: user} do
      {enabled_user, secret, _codes} = enable_totp!(user)
      now = System.os_time(:second)

      assert {:ok, _} =
               Totp.verify_login(
                 Accounts.pending_totp_token(enabled_user),
                 code_at(secret, now),
                 now
               )

      assert {:ok, _} =
               Totp.verify_login(
                 Accounts.pending_totp_token(enabled_user),
                 code_at(secret, now + 30),
                 now + 30
               )
    end

    test "re-enabling after disable starts a fresh anti-replay chain", %{user: user} do
      {enabled_user, secret, _codes} = enable_totp!(user)
      now = System.os_time(:second)

      assert :ok = Totp.disable(enabled_user, @password, code_at(secret, now), now)

      # Fresh secret + enable at the same wall-clock step works (no stale marker).
      {:ok, %{secret: new_secret}} = Totp.setup(Accounts.get_user(user.id))

      assert {:ok, _codes} =
               Totp.enable(Accounts.get_user(user.id), code_at(new_secret, now), now)
    end
  end

  describe "TOTP rate limiting" do
    test "verify-login reports remaining attempts, then locks out with retry-after", %{
      user: user
    } do
      {enabled_user, secret, _codes} = enable_totp!(user)
      bad = invalid_code(secret)

      for remaining <- 4..0//-1 do
        assert {:error, :invalid_code, ^remaining} =
                 Totp.verify_login(Accounts.pending_totp_token(enabled_user), bad)
      end

      assert {:error, :rate_limited, retry} =
               Totp.verify_login(Accounts.pending_totp_token(enabled_user), bad)

      assert is_integer(retry) and retry > 0

      # Even a valid code is refused while locked out.
      assert {:error, :rate_limited, _} =
               Totp.verify_login(Accounts.pending_totp_token(enabled_user), current_code(secret))
    end

    test "a successful verify-login resets the failure budget", %{user: user} do
      {enabled_user, secret, _codes} = enable_totp!(user)
      bad = invalid_code(secret)

      for _ <- 1..4 do
        assert {:error, :invalid_code, _} =
                 Totp.verify_login(Accounts.pending_totp_token(enabled_user), bad)
      end

      assert {:ok, _} =
               Totp.verify_login(Accounts.pending_totp_token(enabled_user), current_code(secret))

      # Budget restored: the next failure is a plain 401 with 4 attempts left, not a lockout.
      assert {:error, :invalid_code, 4} =
               Totp.verify_login(Accounts.pending_totp_token(enabled_user), bad)
    end

    test "enable locks out after 5 bad codes", %{user: user} do
      {:ok, %{secret: secret}} = Totp.setup(user)
      user = Accounts.get_user(user.id)
      bad = invalid_code(secret)

      for _ <- 1..5 do
        assert {:error, :invalid_code} = Totp.enable(user, bad)
      end

      assert {:error, :rate_limited, retry} = Totp.enable(user, bad)
      assert is_integer(retry) and retry > 0
    end
  end

  describe "TotpController rate-limit envelopes" do
    test "verify-login failures carry remainingAttempts; lockout is a 429", %{user: user} do
      {enabled_user, secret, _codes} = enable_totp!(user)
      temp = Accounts.pending_totp_token(enabled_user)
      bad = invalid_code(secret)

      resp =
        build_conn()
        |> TotpController.verify_login(%{"temp_token" => temp, "totp_code" => bad})
        |> json_response(401)

      assert resp["error"] == "Invalid TOTP code"
      assert resp["remainingAttempts"] == 4

      for _ <- 1..4 do
        build_conn()
        |> TotpController.verify_login(%{"temp_token" => temp, "totp_code" => bad})
        |> json_response(401)
      end

      resp =
        build_conn()
        |> TotpController.verify_login(%{"temp_token" => temp, "totp_code" => bad})
        |> json_response(429)

      assert resp["code"] == "TOTP_RATE_LIMITED"
      assert is_integer(resp["remainingTime"]) and resp["remainingTime"] > 0
    end

    test "enable lockout is the same 429 contract shape", %{user: user} do
      {:ok, %{secret: secret}} = Totp.setup(user)
      user = Accounts.get_user(user.id)
      bad = invalid_code(secret)

      for _ <- 1..5 do
        user |> user_conn() |> TotpController.enable(%{"totp_code" => bad}) |> json_response(401)
      end

      resp =
        user
        |> user_conn()
        |> TotpController.enable(%{"totp_code" => bad})
        |> json_response(429)

      assert resp["code"] == "TOTP_RATE_LIMITED"
    end
  end

  describe "TotpController actions" do
    test "POST setup returns the secret + a PNG data-uri qr_code", %{user: user} do
      resp = user |> user_conn() |> TotpController.setup(%{}) |> json_response(200)

      assert {:ok, _raw} = Base.decode32(resp["secret"], padding: false)
      assert String.starts_with?(resp["qr_code"], "data:image/png;base64,")
    end

    test "POST setup once enabled is a 400", %{user: user} do
      {enabled_user, _secret, _codes} = enable_totp!(user)

      resp = enabled_user |> user_conn() |> TotpController.setup(%{}) |> json_response(400)
      assert resp["error"] == "TOTP is already enabled"
    end

    test "POST enable returns a message + backup codes", %{user: user} do
      {:ok, %{secret: secret}} = Totp.setup(user)
      reloaded = Accounts.get_user(user.id)

      resp =
        reloaded
        |> user_conn()
        |> TotpController.enable(%{"totp_code" => current_code(secret)})
        |> json_response(200)

      assert resp["message"] == "TOTP enabled successfully"
      assert length(resp["backup_codes"]) == 8
    end

    test "POST enable without a code is a 400", %{user: user} do
      resp = user |> user_conn() |> TotpController.enable(%{}) |> json_response(400)
      assert resp["error"] == "TOTP code is required"
    end

    test "POST disable with a wrong password is a 401", %{user: user} do
      {enabled_user, secret, _codes} = enable_totp!(user)

      resp =
        enabled_user
        |> user_conn()
        |> TotpController.disable(%{"password" => "nope", "totp_code" => current_code(secret)})
        |> json_response(401)

      assert resp["error"] == "Incorrect password"
    end

    test "POST verify-login mints a session (jwt cookie) and returns the auth shape", %{
      user: user
    } do
      {enabled_user, secret, _codes} = enable_totp!(user)
      temp = Accounts.pending_totp_token(enabled_user)

      conn =
        build_conn()
        |> TotpController.verify_login(%{
          "temp_token" => temp,
          "totp_code" => current_code(secret)
        })

      resp = json_response(conn, 200)
      assert resp["success"] == true
      assert resp["userId"] == enabled_user.id
      assert resp["username"] == "alice"
      assert resp["is_admin"] == true
      assert resp["is_oidc"] == false
      assert resp["totp_enabled"] == true
      # Browser clients receive the token via the httpOnly cookie, not the body.
      refute Map.has_key?(resp, "token")
      assert %{"jwt" => %{value: jwt}} = conn.resp_cookies
      assert is_binary(jwt) and jwt != ""
    end

    test "POST verify-login with a bad token is a 401" do
      resp =
        build_conn()
        |> TotpController.verify_login(%{"temp_token" => "nope", "totp_code" => "123456"})
        |> json_response(401)

      assert resp["error"] == "Invalid temporary token"
    end

    test "POST verify-login missing fields is a 400" do
      resp =
        build_conn()
        |> TotpController.verify_login(%{"temp_token" => ""})
        |> json_response(400)

      assert resp["error"] == "Token and TOTP code are required"
    end
  end

  describe "login fold-in → verify-login (end to end)" do
    test "login returns requires_totp + temp_token, and verify-login completes it", %{
      conn: conn,
      user: user
    } do
      {_enabled_user, secret, _codes} = enable_totp!(user)

      login =
        conn
        |> post("/users/login", %{username: "alice", password: @password})
        |> json_response(200)

      assert login["success"] == true
      assert login["requires_totp"] == true
      assert is_binary(login["temp_token"])
      # No session cookie is set at the interim step.
      refute Map.has_key?(login, "is_admin")

      verified =
        build_conn()
        |> TotpController.verify_login(%{
          "temp_token" => login["temp_token"],
          "totp_code" => current_code(secret)
        })
        |> json_response(200)

      assert verified["success"] == true
      assert verified["userId"] == user.id
      assert verified["totp_enabled"] == true
    end
  end

  # --- helpers --------------------------------------------------------------

  # Full setup + enable, returning the reloaded (enabled) user, the base32 secret, and the
  # issued backup codes. Enable runs at an already-elapsed step (real now − 60s) so a code
  # generated for the real current step afterwards is strictly newer than the enable-time
  # step and passes the anti-replay rule without sleeping.
  defp enable_totp!(user) do
    {:ok, %{secret: secret}} = Totp.setup(user)
    past = System.os_time(:second) - 60
    {:ok, backup_codes} = Totp.enable(Accounts.get_user(user.id), code_at(secret, past), past)
    {Accounts.get_user(user.id), secret, backup_codes}
  end

  # The current 6-digit code for a base32 secret (the authenticator app's view).
  defp current_code(secret) do
    secret |> raw_secret() |> NimbleTOTP.verification_code()
  end

  # The 6-digit code valid at an explicit time (seconds).
  defp code_at(secret, time) do
    NimbleTOTP.verification_code(raw_secret(secret), time: time)
  end

  # A 6-digit code guaranteed to fall outside the ±2-step acceptance window: pick a repdigit
  # ("000000".."999999") that is none of the (at most 5) in-window valid codes.
  defp invalid_code(secret) do
    raw = raw_secret(secret)
    now = System.os_time(:second)

    valid =
      for s <- -2..2,
          into: MapSet.new(),
          do: NimbleTOTP.verification_code(raw, time: now + s * 30)

    0..9
    |> Enum.map(&String.duplicate(Integer.to_string(&1), 6))
    |> Enum.find(&(&1 not in valid))
  end

  defp raw_secret(secret), do: secret |> String.upcase() |> Base.decode32!(padding: false)

  defp user_conn(user) do
    build_conn()
    |> Plug.Conn.assign(:current_user_id, user.id)
    |> Plug.Conn.assign(:current_user, user)
  end
end
