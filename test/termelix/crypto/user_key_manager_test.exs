defmodule Termelix.Crypto.UserKeyManagerTest do
  @moduledoc """
  Covers the ETS read-through DEK cache: population, TTL semantics, invalidation,
  and the non-raising create path.
  """
  use Termelix.DataCase

  alias Termelix.Crypto.{UserKeyManager, UserKeyUnavailableError}
  alias Termelix.Settings

  @table UserKeyManager
  @ttl_ms 15 * 60 * 1000

  # Unique per test so recycled ids and the cross-test ETS cache cannot interfere.
  setup do
    user_id = "u#{System.unique_integer([:positive])}"
    on_exit(fn -> UserKeyManager.invalidate(user_id) end)
    {:ok, user_id: user_id}
  end

  defp cache_entry(user_id) do
    case :ets.lookup(@table, user_id) do
      [{^user_id, dek, expires_at}] -> {dek, expires_at}
      [] -> nil
    end
  end

  test "get_user_dek raises / try_get_user_dek returns nil for a user without a DEK",
       %{user_id: user_id} do
    assert_raise UserKeyUnavailableError, fn -> UserKeyManager.get_user_dek(user_id) end
    assert UserKeyManager.try_get_user_dek(user_id) == nil
    refute UserKeyManager.has_user_dek?(user_id)
  end

  test "create_user_dek persists a 32-byte DEK and populates the ETS cache with a TTL",
       %{user_id: user_id} do
    dek = UserKeyManager.create_user_dek(user_id)
    assert byte_size(dek) == 32
    assert UserKeyManager.has_user_dek?(user_id)

    now = System.monotonic_time(:millisecond)
    assert {^dek, expires_at} = cache_entry(user_id)
    assert_in_delta expires_at - now, @ttl_ms, 1000
  end

  # This used to poison the cache with `:ets.insert/2` from the test process. That is exactly the
  # write the table being `:protected` now forbids — so the property is asserted from the outside
  # instead: delete the stored wrap, and a read that still succeeds can only have come from the
  # cache. Stronger than the poison version, which proved the read did not *re-wrap* but not that
  # it never touched the database.
  test "get_user_dek is served from the ETS cache, not the database", %{user_id: user_id} do
    dek = UserKeyManager.create_user_dek(user_id)
    assert cache_entry(user_id) != nil

    Settings.delete("user_dek_v3_#{user_id}")

    assert UserKeyManager.get_user_dek(user_id) == dek
    assert UserKeyManager.try_get_user_dek(user_id) == dek

    # Drop the cache and the same read now has nowhere to go — proving the previous two came
    # from the cache rather than a surviving copy somewhere else.
    UserKeyManager.invalidate(user_id)
    assert_raise UserKeyUnavailableError, fn -> UserKeyManager.get_user_dek(user_id) end
  end

  test "expired entries are treated as a miss and refreshed from the wrapped copy",
       %{user_id: user_id} do
    # A `:protected` table cannot be seeded with an already-expired entry from here, and waiting
    # out the real 15-minute TTL is not a test — so shorten the TTL for this one case.
    Application.put_env(:termelix, :user_dek_cache_ttl_ms, 1)
    on_exit(fn -> Application.delete_env(:termelix, :user_dek_cache_ttl_ms) end)

    dek = UserKeyManager.create_user_dek(user_id)
    assert {^dek, _} = cache_entry(user_id)

    Process.sleep(5)

    # Expired: the read must fall through to the wrapped copy and produce the same DEK, then
    # re-cache it with a fresh deadline.
    Application.put_env(:termelix, :user_dek_cache_ttl_ms, 60_000)
    assert UserKeyManager.get_user_dek(user_id) == dek

    now = System.monotonic_time(:millisecond)
    assert {^dek, expires_at} = cache_entry(user_id)
    assert expires_at > now
  end

  test "invalidate drops the cache entry; the next read re-unwraps from the database",
       %{user_id: user_id} do
    dek = UserKeyManager.create_user_dek(user_id)
    assert cache_entry(user_id) != nil

    assert UserKeyManager.invalidate(user_id) == :ok
    assert cache_entry(user_id) == nil

    assert UserKeyManager.get_user_dek(user_id) == dek
    assert cache_entry(user_id) != nil
  end

  test "create_user_dek raises when the user already has a DEK", %{user_id: user_id} do
    UserKeyManager.create_user_dek(user_id)

    assert_raise RuntimeError, ~r/already has a data encryption key/, fn ->
      UserKeyManager.create_user_dek(user_id)
    end
  end
end
