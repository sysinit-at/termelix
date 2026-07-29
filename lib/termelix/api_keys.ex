defmodule Termelix.ApiKeys do
  @moduledoc """
  Scoped, revocable credentials for non-human callers.

  The authority model, decided deliberately: an agent key can do **tmux verbs on named hosts**
  and nothing else. Not credential read, not host CRUD, not raw exec outside a tmux session,
  not user administration. A key that could do those would be a password with extra steps, and
  the reason to hand a machine a credential at all is that it can be *narrower* than the human
  who issued it.

  ## Scopes

    * `tmux:read`  — overview, capture, snapshot
    * `tmux:write` — dispatch, send-keys (typing into a live terminal)
    * `tmux:wait`  — block until a pane changes state

  `tmux:wait` is separate from `tmux:read` on purpose. A wait holds a connection for minutes;
  handing that out is a resource decision, not a data-access one, and an operator may
  reasonably want an agent that can look but not camp.

  ## Hosts

  A key names its hosts explicitly. There is no "all hosts" value, and an empty list means no
  hosts rather than every host — the alternative silently widens a key whenever a new host is
  added, which is precisely what a scoped credential is for.

  Host scope is checked against the key AND ownership is checked against the user: narrowing a
  key can never widen it past its owner, so a key naming a host its owner does not own is
  simply refused.

  ## The token

  `tmx_` + 32 random bytes, base64url. Stored only as SHA-256; the plaintext is returned once,
  at creation, and cannot be recovered. SHA-256 rather than a password hash because this is a
  256-bit random secret, not a memorable one: there is nothing to brute-force, and a slow KDF
  on every agent request would buy nothing and cost latency.
  """

  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.ApiKey

  @prefix "tmx_"
  @prefix_length 12
  @token_bytes 32

  @scopes ~w(tmux:read tmux:write tmux:wait)

  @doc "Every scope an API key may hold."
  @spec scopes() :: [String.t()]
  def scopes, do: @scopes

  @doc """
  Create a key for `user_id`. Returns `{:ok, key_struct, plaintext}` — the ONLY time the
  plaintext exists outside the caller's hands.

  Scopes and host ids are both filtered to what the user may actually grant: an unknown scope
  is rejected outright (a typo that silently produced a key with no authority would be worse
  than an error), and a host the user does not own is rejected rather than dropped, because
  quietly issuing a key narrower than what was asked for is how a broken automation gets
  debugged for an hour.
  """
  @spec create(String.t(), map()) :: {:ok, ApiKey.t(), String.t()} | {:error, term()}
  def create(user_id, attrs) do
    name = attrs |> Map.get(:name, Map.get(attrs, "name")) |> to_string() |> String.trim()
    scopes = attrs |> Map.get(:scopes, Map.get(attrs, "scopes", [])) |> List.wrap()
    host_ids = attrs |> Map.get(:host_ids, Map.get(attrs, "hostIds", [])) |> List.wrap()
    expires_at = Map.get(attrs, :expires_at, Map.get(attrs, "expiresAt"))

    with :ok <- validate_name(name),
         :ok <- validate_scopes(scopes),
         {:ok, host_ids} <- validate_hosts(user_id, host_ids) do
      token = generate_token()

      row = %ApiKey{
        id: Termelix.Id.generate(),
        userId: user_id,
        name: name,
        keyHash: hash(token),
        keyPrefix: String.slice(token, 0, @prefix_length),
        scopes: Jason.encode!(scopes),
        hostIds: Jason.encode!(host_ids),
        expiresAt: expires_at,
        isActive: true,
        createdAt: DateTime.utc_now() |> DateTime.to_iso8601()
      }

      case Repo.insert(row) do
        {:ok, key} -> {:ok, key, token}
        {:error, changeset} -> {:error, changeset}
      end
    end
  end

  @doc """
  Resolve a plaintext token to its key, or a typed refusal.

  `{:error, :expired}` is distinct from `{:error, :invalid}` on purpose: an agent whose key
  expired needs to be told that, and conflating the two sends whoever is debugging it looking
  for a typo.
  """
  @spec authenticate(String.t()) :: {:ok, ApiKey.t()} | {:error, :invalid | :expired}
  def authenticate(token) when is_binary(token) do
    case Repo.one(from k in ApiKey, where: k.keyHash == ^hash(token)) do
      nil ->
        {:error, :invalid}

      %ApiKey{isActive: false} ->
        # The table has carried `is_active` since the Node port. A deactivated key must be
        # refused, not merely hidden from a listing.
        {:error, :invalid}

      %ApiKey{} = key ->
        if expired?(key) do
          {:error, :expired}
        else
          touch(key)
          {:ok, key}
        end
    end
  end

  def authenticate(_token), do: {:error, :invalid}

  @doc "Whether `key` carries `scope`."
  @spec has_scope?(ApiKey.t(), String.t()) :: boolean()
  def has_scope?(key, scope), do: scope in decode_list(key.scopes)

  @doc """
  Whether `key` may act on `host_id`.

  Both halves are required: the host must be named on the key AND owned by the key's user.
  Checking only the key would let a key outlive the ownership it was issued under — a host
  transferred or recreated with the same id would silently remain in scope.
  """
  @spec allows_host?(ApiKey.t(), integer()) :: boolean()
  def allows_host?(key, host_id) when is_integer(host_id) do
    host_id in decode_list(key.hostIds) and
      Repo.exists?(
        from h in Termelix.Schema.Host, where: h.id == ^host_id and h.userId == ^key.userId
      )
  end

  def allows_host?(_key, _host_id), do: false

  @doc "A user's keys, newest first. Never includes the token — there is none to include."
  @spec list_for_user(String.t()) :: [ApiKey.t()]
  def list_for_user(user_id),
    do: Repo.all(from k in ApiKey, where: k.userId == ^user_id, order_by: [desc: k.id])

  @doc """
  Deactivate every key belonging to `user_id`, returning how many were still active.

  Revocation's fifth surface, and the one that would have made the other four pointless. An
  API key is long-lived by design and carries no session — so revoking a user's auth sessions,
  stopping their terminals, their tunnels, their pooled connections and their watchers left the
  one credential that could re-open all of it still working. An agent holding that key would
  simply carry on.

  Deactivated rather than deleted: the row is the audit trail's link between an action and the
  credential that took it, and destroying it would erase what a revocation most needs to
  explain afterwards. `authenticate/1` refuses an inactive key outright.
  """
  @spec deactivate_all_for_user(String.t()) :: non_neg_integer()
  def deactivate_all_for_user(user_id) do
    {count, _} =
      Repo.update_all(
        from(k in ApiKey, where: k.userId == ^user_id and k.isActive == true),
        set: [isActive: false]
      )

    count
  end

  @doc "Delete one of the user's keys. Idempotent."
  @spec delete(String.t(), integer()) :: :ok
  def delete(user_id, id) do
    Repo.delete_all(from k in ApiKey, where: k.id == ^id and k.userId == ^user_id)
    :ok
  end

  @doc "The public shape of a key: everything except anything that could be replayed."
  @spec to_public(ApiKey.t()) :: map()
  def to_public(key) do
    %{
      id: key.id,
      name: key.name,
      keyPrefix: key.keyPrefix,
      scopes: decode_list(key.scopes),
      hostIds: decode_list(key.hostIds),
      expiresAt: key.expiresAt,
      isActive: key.isActive,
      lastUsedAt: key.lastUsedAt,
      createdAt: key.createdAt
    }
  end

  # --- internals --------------------------------------------------------------

  defp generate_token,
    do: @prefix <> Base.url_encode64(:crypto.strong_rand_bytes(@token_bytes), padding: false)

  @doc false
  @spec hash(String.t()) :: String.t()
  def hash(token), do: :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

  defp validate_name(""), do: {:error, :name_required}
  defp validate_name(name) when byte_size(name) > 100, do: {:error, :name_too_long}
  defp validate_name(_name), do: :ok

  defp validate_scopes([]), do: {:error, :scopes_required}

  defp validate_scopes(scopes) do
    case Enum.reject(scopes, &(&1 in @scopes)) do
      [] -> :ok
      unknown -> {:error, {:unknown_scopes, unknown}}
    end
  end

  # Refused, not filtered. Silently issuing a key narrower than what was asked for is how an
  # automation gets debugged for an hour before anyone looks at the key.
  defp validate_hosts(user_id, host_ids) do
    ids = Enum.map(host_ids, &to_host_id/1)

    cond do
      Enum.any?(ids, &is_nil/1) ->
        {:error, :invalid_host_id}

      true ->
        owned =
          Repo.all(from h in Termelix.Schema.Host, where: h.userId == ^user_id, select: h.id)
          |> MapSet.new()

        case Enum.reject(ids, &MapSet.member?(owned, &1)) do
          [] -> {:ok, ids}
          not_owned -> {:error, {:hosts_not_owned, not_owned}}
        end
    end
  end

  defp to_host_id(id) when is_integer(id), do: id

  defp to_host_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {int, ""} -> int
      _ -> nil
    end
  end

  defp to_host_id(_id), do: nil

  defp expired?(%ApiKey{expiresAt: nil}), do: false

  defp expired?(%ApiKey{expiresAt: at}) do
    case DateTime.from_iso8601(to_string(at)) do
      {:ok, dt, _} -> DateTime.compare(DateTime.utc_now(), dt) == :gt
      # An unparseable expiry is treated as expired. The alternative — treating it as "no
      # expiry" — turns a corrupt field into an immortal credential.
      _ -> true
    end
  end

  # Recorded in memory, flushed on a timer — NOT a row per request.
  #
  # SQLite has one writer and this app runs in `:immediate` mode, so an `UPDATE` on every
  # authenticated agent call serializes against every other write in the system. An agent
  # polling `list_panes` in a loop would have been writing to the database as fast as it could
  # read, to maintain a field whose whole purpose is answering "is this key still in use" —
  # a question that does not need second-level precision.
  #
  # `Termelix.ApiKeys.Usage` owns the buffer and the flush. Losing the last interval's worth of
  # timestamps on a crash is the intended trade: the alternative costs a write per request
  # forever to make a field that nobody reads in real time slightly fresher.
  defp touch(key), do: Termelix.ApiKeys.Usage.touch(key.id)

  defp decode_list(nil), do: []

  defp decode_list(json) do
    case Jason.decode(json) do
      {:ok, list} when is_list(list) -> list
      _ -> []
    end
  end
end
