defmodule Termelix.LdapFakeClient do
  @moduledoc """
  A `Termelix.Ldap.Client` fake for tests — stands in for a live directory, which CI does not
  have. Wire it in with `Application.put_env(:termelix, :ldap_client, Termelix.LdapFakeClient)` and
  describe the directory via `Application.put_env(:termelix, :ldap_fake, scenario)`.

  Scenario keys (all optional):

    * `:bind_dn` / `:bind_password` — the service account the flow binds first.
    * `:user_password`              — the correct password for the user re-bind.
    * `:entries`                    — entries returned for a search under `userSearchBase`.
    * `:group_entries`              — entries returned for a search under `groupSearchBase`.
    * `:open_error`                 — when truthy, `open/1` fails (connect failure).
    * `:search_error`               — when truthy, the user search fails.

  Entries are plain `%{dn: ..., attributes: %{"uid" => ["alice"], ...}}` maps, i.e. already in
  the normalised shape `Termelix.Ldap.Client.search/2` promises.
  """
  @behaviour Termelix.Ldap.Client

  @impl true
  def open(_config) do
    if scenario()[:open_error] do
      {:error, :connect_failed}
    else
      {:ok, make_ref()}
    end
  end

  @impl true
  def bind(_handle, dn, password) do
    s = scenario()

    cond do
      dn == s[:bind_dn] ->
        if password == s[:bind_password], do: :ok, else: {:error, :invalidCredentials}

      is_binary(s[:user_password]) and password == s[:user_password] ->
        :ok

      true ->
        {:error, :invalidCredentials}
    end
  end

  @impl true
  def search(_handle, req) do
    s = scenario()

    cond do
      s[:search_error] && req.base == s[:user_search_base] ->
        {:error, :search_failed}

      req.base == s[:group_search_base] ->
        {:ok, Map.get(s, :group_entries, [])}

      true ->
        {:ok, Map.get(s, :entries, [])}
    end
  end

  @impl true
  def close(_handle), do: :ok

  defp scenario, do: Application.get_env(:termelix, :ldap_fake, %{})
end
