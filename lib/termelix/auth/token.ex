defmodule Termelix.Auth.Token do
  @moduledoc """
  HS256 JWTs, compatible with the original `auth-manager.ts`.

  The signing key is the raw `JWT_SECRET` *string* (not hex-decoded), exactly as
  `jsonwebtoken` uses it. Claims are `{userId, sessionId?, pendingTOTP?, iat, exp}` — the
  identity claim is the custom top-level `userId`, never `sub`.
  """
  alias Termelix.Crypto.SystemCrypto

  @doc "Sign `claims` (a string-keyed map) with an `iat`/`exp` covering `ttl_seconds`."
  @spec sign(map(), non_neg_integer()) :: String.t()
  def sign(claims, ttl_seconds) do
    now = System.system_time(:second)

    payload =
      claims
      |> Map.new(fn {k, v} -> {to_string(k), v} end)
      |> Map.put("iat", now)
      |> Map.put("exp", now + ttl_seconds)

    Joken.generate_and_sign!(%{}, payload, signer())
  end

  @doc """
  Verify the signature and return the claims. Also enforces `exp` (jsonwebtoken does this
  automatically; Joken with an empty config does not, so we check it here).
  """
  @spec verify(String.t()) :: {:ok, map()} | {:error, atom()}
  def verify(token) do
    case Joken.verify(token, signer()) do
      {:ok, claims} ->
        if expired?(claims), do: {:error, :expired}, else: {:ok, claims}

      {:error, _reason} ->
        {:error, :invalid}
    end
  end

  defp expired?(%{"exp" => exp}) when is_integer(exp), do: exp < System.system_time(:second)
  defp expired?(_), do: false

  defp signer, do: Joken.Signer.create("HS256", SystemCrypto.jwt_secret())
end
