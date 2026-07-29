defmodule TermelixWeb.SsoProviderController do
  @moduledoc """
  Ports the SSO-provider surface under `/users/sso-providers` (`sso-provider-routes.ts`).

  `index/2` is the public login-screen list (mounted without the auth pipeline); the rest live
  in the router's admin scope (`TermelixWeb.Plugs.RequireAdmin`), which answers a non-admin with
  `403 {error: "Admin access required"}` — the Elixir counterpart of the Node `requireAdmin`
  middleware. Responses emit the DB row's camelCase keys with the `config` field decoded, minus
  its secrets: those are write-only and surface only as `hasClientSecret` / `hasBindPassword`.
  """
  use Phoenix.Controller, formats: [:json]

  alias Termelix.{Oidc, SsoProviders}

  @valid_types ~w(oidc ldap github google)
  # The config keys `SsoProviders` (de)codes as secrets (see sso_providers.ex:103) — never
  # rendered, and blank on update means "keep the stored one".
  @secret_config_fields ~w(client_secret bindPassword)
  @oidc_required ~w(client_id client_secret issuer_url authorization_url token_url)
  @ldap_required ~w(host port bindDN bindPassword userSearchBase userSearchFilter usernameAttribute)

  # GET /users/sso-providers  (public)
  def index(conn, _params) do
    providers = SsoProviders.list_enabled_public()

    providers =
      if providers == [] and Oidc.get_oidc_config_from_env() != nil do
        [%{id: 0, name: "SSO", type: "oidc", displayOrder: 0}]
      else
        providers
      end

    json(conn, providers)
  end

  # GET /users/sso-providers/admin  (admin)
  def admin_index(conn, _params) do
    json(conn, Enum.map(SsoProviders.list_all(), &render_provider/1))
  end

  # POST /users/sso-providers  (admin)
  def create(conn, params) do
    name = params["name"]
    type = params["type"]
    raw_config = normalize_config(params["config"])

    with :ok <- validate_name(name),
         :ok <- validate_type(type),
         config = SsoProviders.apply_create_defaults(type, raw_config),
         :ok <- validate_config(type, config) do
      provider =
        SsoProviders.create(%{
          name: String.trim(name),
          type: type,
          enabled: Map.get(params, "enabled", true),
          displayOrder: Map.get(params, "displayOrder", 0),
          config: SsoProviders.encrypt_provider_config(config)
        })

      conn |> put_status(201) |> json(render_provider(provider))
    else
      {:error, status, message} -> error(conn, status, message)
    end
  end

  # PUT /users/sso-providers/:id  (admin)
  def update(conn, %{"id" => id_param} = params) do
    case to_int(id_param) do
      nil -> error(conn, 400, "Invalid provider ID")
      id -> do_update(conn, id, params)
    end
  end

  defp do_update(conn, id, params) do
    case SsoProviders.find_by_id(id) do
      nil ->
        error(conn, 404, "SSO provider not found")

      existing ->
        updates =
          %{updatedAt: iso_now()}
          |> put_if_present(params, "name", :name, &String.trim/1)
          |> put_if_present(params, "type", :type)
          |> put_if_present(params, "enabled", :enabled)
          |> put_if_present(params, "displayOrder", :displayOrder)
          |> maybe_merge_config(existing, params)

        case SsoProviders.update(id, updates) do
          nil -> error(conn, 404, "SSO provider not found")
          provider -> json(conn, render_provider(provider))
        end
    end
  end

  # DELETE /users/sso-providers/:id  (admin)
  def delete(conn, %{"id" => id_param}) do
    case to_int(id_param) do
      nil -> error(conn, 400, "Invalid provider ID")
      id -> do_delete(conn, id)
    end
  end

  defp do_delete(conn, id) do
    case SsoProviders.find_by_id(id) do
      nil ->
        error(conn, 404, "SSO provider not found")

      _provider ->
        case SsoProviders.count_users_by_provider_id(id) do
          count when count > 0 ->
            error(conn, 409, "Cannot delete provider: #{count} user(s) are associated with it")

          _ ->
            SsoProviders.delete(id)
            json(conn, %{message: "SSO provider deleted"})
        end
    end
  end

  # --- validation -----------------------------------------------------------

  defp validate_name(name) when is_binary(name) do
    if String.trim(name) == "", do: {:error, 400, "Provider name is required"}, else: :ok
  end

  defp validate_name(_), do: {:error, 400, "Provider name is required"}

  defp validate_type(type) when type in @valid_types, do: :ok
  defp validate_type(_), do: {:error, 400, "Invalid provider type"}

  defp validate_config("oidc", config) do
    case Enum.reject(@oidc_required, &present?(config[&1])) do
      [] -> :ok
      missing -> {:error, 400, "Missing required OIDC fields: #{Enum.join(missing, ", ")}"}
    end
  end

  defp validate_config(type, config) when type in ~w(github google) do
    if present?(config["client_id"]) and present?(config["client_secret"]) do
      :ok
    else
      {:error, 400, "Client ID and Client Secret are required"}
    end
  end

  defp validate_config("ldap", config) do
    case Enum.reject(@ldap_required, &present?(config[&1])) do
      [] -> :ok
      missing -> {:error, 400, "Missing required LDAP fields: #{Enum.join(missing, ", ")}"}
    end
  end

  defp validate_config(_type, _config), do: :ok

  # --- config merge on update -----------------------------------------------

  defp maybe_merge_config(updates, existing, params) do
    case Map.get(params, "config") do
      nil ->
        updates

      raw ->
        # Blank secret means "keep the stored one": render_provider/1 no longer hands the value
        # back, so a resubmitted admin form carries "" for an untouched secret and would
        # otherwise wipe it. Same replace-only rule as credential_controller.ex:233-236.
        incoming = raw |> normalize_config() |> drop_blank_secrets()

        merged = Map.merge(SsoProviders.decrypt_provider_config(existing.config), incoming)

        Map.put(updates, :config, SsoProviders.encrypt_provider_config(merged))
    end
  end

  defp drop_blank_secrets(config) do
    Enum.reduce(@secret_config_fields, config, fn field, acc ->
      case Map.fetch(acc, field) do
        {:ok, value} -> if present?(value), do: acc, else: Map.delete(acc, field)
        :error -> acc
      end
    end)
  end

  # --- rendering ------------------------------------------------------------

  # Shared by admin_index/2, create/2 and update/2 — the only paths that expose a stored config.
  defp render_provider(provider) do
    config = SsoProviders.decrypt_provider_config(provider.config)

    %{
      id: provider.id,
      name: provider.name,
      type: provider.type,
      enabled: provider.enabled == true,
      displayOrder: provider.displayOrder,
      # Write-only secret store (CLAUDE.md), as in credential_controller.ex:97-102: the OIDC
      # client_secret and the LDAP bindPassword never leave the server — only presence booleans,
      # so the editor can show "set, leave blank to keep" without the value reaching the browser.
      config: Map.drop(config, @secret_config_fields),
      hasClientSecret: present?(config["client_secret"]),
      hasBindPassword: present?(config["bindPassword"]),
      createdAt: provider.createdAt,
      updatedAt: provider.updatedAt
    }
  end

  # --- helpers --------------------------------------------------------------

  defp normalize_config(config) when is_map(config), do: config
  defp normalize_config(_), do: %{}

  defp put_if_present(map, params, param_key, field, transform \\ & &1) do
    case Map.fetch(params, param_key) do
      {:ok, value} -> Map.put(map, field, transform.(value))
      :error -> map
    end
  end

  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(v) when is_integer(v), do: true
  defp present?(_), do: false

  defp to_int(v) when is_integer(v), do: v

  defp to_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {int, ""} -> int
      _ -> nil
    end
  end

  defp to_int(_), do: nil

  defp iso_now, do: DateTime.utc_now() |> DateTime.to_iso8601()

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
