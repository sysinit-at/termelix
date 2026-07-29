defmodule Termelix.Settings do
  @moduledoc """
  Read/write access to the `settings` key/value table.

  `get_value/1` is read-through cached in `:persistent_term` (keyed by
  `{Termelix.Settings, key}`); `put_value/2` and `delete/1` invalidate the cached
  key rather than installing a value. The cache is single-node only — fine for
  this self-hosted single-node app, but a setting changed directly in the
  database (bypassing this module) will not be seen until restart.

  The cache is skipped entirely inside an open DB transaction and whenever the
  repo runs on the SQL sandbox (i.e. the test env): a rolled-back transaction
  would otherwise leak phantom values into the cache.

  ## Write invalidation, not write-through

  Writes invalidate instead of caching the new value. Outside a transaction
  `Repo.insert!` has already committed by the time `put_value/2` invalidates, so
  this is a post-commit invalidation: the next reader re-fetches the committed
  value. Inside a transaction the invalidation runs before the enclosing commit,
  which cannot be hooked from here — a caller that writes inside a transaction
  MUST therefore call `invalidate_cache/1` again after its transaction commits
  (see `Termelix.ErrorReporting.record_decision/3`).

  Installs are **version-guarded** (`Termelix.Settings.Cache`): every
  invalidation bumps one global cache version, and a reader only installs what
  it fetched under the version it observed before the DB read. A reader holding
  a pre-commit value therefore cannot re-cache it past the post-commit
  invalidation, whichever way the read, install, commit, and invalidation
  interleave. (Global rather than per-key so one-shot keys — the per-login
  `oidc_*_<state>` values — leave no per-key residue behind.)
  """
  import Ecto.Query, only: [from: 2]
  alias Termelix.Repo
  alias Termelix.Schema.Setting
  alias Termelix.Settings.Cache

  @doc "Return the string value for `key`, or nil."
  @spec get_value(String.t()) :: String.t() | nil
  def get_value(key) do
    if cache_enabled?() do
      case Cache.get(key) do
        {:ok, value} -> value
        :miss -> read_and_cache(key)
      end
    else
      fetch(key)
    end
  end

  @doc "Insert or update `key` with `value`."
  @spec put_value(String.t(), String.t()) :: Setting.t()
  def put_value(key, value) do
    setting =
      Repo.insert!(%Setting{key: key, value: value},
        on_conflict: [set: [value: value]],
        conflict_target: :key
      )

    # Always invalidate rather than install the new value. Outside a transaction
    # the insert has committed, so this is a post-commit invalidation and the next
    # reader re-fetches the committed value; caching here would also risk being
    # clobbered by a concurrent reader that had just cached the old value. Inside
    # a transaction a rollback could undo the write, so a cached value would be a
    # phantom. See the module doc for the residual cross-process window.
    invalidate(key)

    setting
  end

  @doc "Delete `key` if present."
  @spec delete(String.t()) :: :ok
  def delete(key) do
    Repo.delete_all(from(s in Setting, where: s.key == ^key))
    invalidate(key)
    :ok
  end

  # The version observed BEFORE the DB read guards the install: if any invalidation
  # (which bumps the version) interleaves with the read, the install refuses or undoes
  # itself — a pre-commit value can never stay cached past that commit's invalidation.
  defp read_and_cache(key) do
    observed = Cache.version()
    value = fetch(key)
    Cache.install(key, observed, value)
    value
  end

  defp fetch(key) do
    case Repo.get(Setting, key) do
      nil -> nil
      %Setting{value: value} -> value
    end
  end

  @doc """
  Drop `key` from the read-through cache so the next reader re-fetches from the DB.
  Required after a transaction that wrote the key commits (see the moduledoc): the bump
  it applies to the key's cache version makes any in-flight reader's install of the
  pre-commit value refuse or undo itself.
  """
  @spec invalidate_cache(String.t()) :: :ok
  def invalidate_cache(key), do: invalidate(key)

  defp invalidate(key), do: Cache.invalidate(key)

  # Transactional readers must see their own uncommitted writes (and must not
  # poison the cache for others), and the sandbox pool means a test whose
  # transaction is rolled back at the end — cached values would outlive the
  # data they were read from.
  defp cache_enabled? do
    not Repo.in_transaction?() and Repo.config()[:pool] != Ecto.Adapters.SQL.Sandbox
  end
end
