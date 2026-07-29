defmodule TermelixWeb.TrustedDeviceController do
  @moduledoc """
  The trusted-device management surface (`/users/trusted-devices`): list the signed-in user's
  trusted devices and revoke one. These back the 2FA "remember this device" flow — a revoked
  device must present TOTP again on its next login.

  The `Authenticate` plug has run, so the owner is `conn.assigns.current_user_id`; a route
  `userId` is never trusted and ownership is enforced in the context (a device belonging to
  another user is invisible here → `404`).

  The device fingerprint is a per-device hash, never a credential; the wire shape omits it (and
  the `userId`) and returns just what a device-management UI needs.
  """
  use Phoenix.Controller, formats: [:json]

  alias Termelix.TrustedDevices

  # GET /users/trusted-devices
  def index(conn, _params) do
    devices =
      conn.assigns.current_user_id
      |> TrustedDevices.list_for_user()
      |> Enum.map(&render_device/1)

    json(conn, %{devices: devices})
  end

  # DELETE /users/trusted-devices/:id
  def delete(conn, %{"id" => id}) do
    case TrustedDevices.revoke(conn.assigns.current_user_id, id) do
      {:ok, _device} -> json(conn, %{success: true})
      {:error, :not_found} -> error(conn, 404, "Trusted device not found")
    end
  end

  # --- rendering --------------------------------------------------------------

  defp render_device(device) do
    %{
      id: device.id,
      deviceType: device.deviceType,
      deviceInfo: device.deviceInfo,
      createdAt: device.createdAt,
      expiresAt: device.expiresAt,
      lastUsedAt: device.lastUsedAt
    }
  end

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
