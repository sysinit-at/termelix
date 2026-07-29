defmodule Termelix.TrustedDevices do
  @moduledoc """
  Trusted-device access for a user — the Elixir port of the read/management subset of
  `trusted-device-repository.ts` plus `auth-manager.ts`'s trusted-device helpers.

  A trusted device is a row the 2FA "remember this device" flow created so TOTP is bypassed
  on that device until the row expires. Every read and write is scoped to the owning user
  (ownership enforced in every query; a body/route `userId` is never trusted).

  The Node backend has no HTTP surface for *listing* or *revoking* trusted devices — it only
  adds/touches/removes them internally by `(userId, deviceFingerprint)`. This context adds the
  minimal management surface the port exposes: list the user's devices and revoke one by row id.
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.TrustedDevice

  @doc "Every trusted device owned by the user, most-recently-used first."
  @spec list_for_user(String.t()) :: [TrustedDevice.t()]
  def list_for_user(user_id) do
    Repo.all(
      from d in TrustedDevice,
        where: d.userId == ^user_id,
        order_by: [desc: d.lastUsedAt]
    )
  end

  @doc "A single trusted device owned by the user, or nil."
  @spec get_for_user(String.t(), String.t()) :: TrustedDevice.t() | nil
  def get_for_user(id, user_id), do: Repo.get_by(TrustedDevice, id: id, userId: user_id)

  @doc """
  Revoke (delete) a trusted device the user owns. Returns `{:ok, device}` or
  `{:error, :not_found}` when the row is not owned by the user (ownership enforced — a device
  belonging to another user can never be revoked here).
  """
  @spec revoke(String.t(), String.t()) :: {:ok, TrustedDevice.t()} | {:error, :not_found}
  def revoke(user_id, id) do
    case get_for_user(id, user_id) do
      nil -> {:error, :not_found}
      %TrustedDevice{} = device -> Repo.delete(device)
    end
  end
end
