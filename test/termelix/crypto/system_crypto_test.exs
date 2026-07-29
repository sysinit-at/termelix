defmodule Termelix.Crypto.SystemCryptoTest do
  @moduledoc """
  Covers the `:persistent_term` fast path for the root key accessors and the
  0600 permission enforcement on `DATA_DIR/.env`.
  """
  use ExUnit.Case, async: false

  alias Termelix.Crypto.SystemCrypto

  @keys_term {SystemCrypto, :keys}

  test "accessors return the boot-time values published to :persistent_term" do
    keys = :persistent_term.get(@keys_term, nil)
    assert is_map(keys)

    assert SystemCrypto.jwt_secret() == keys.jwt_secret
    assert SystemCrypto.encryption_key() == keys.encryption_key
  end

  # `DATABASE_KEY` and `INTERNAL_AUTH_TOKEN` were removed: the first documented whole-database
  # encryption that never existed (nothing read it but its own accessor), the second was a relic
  # of the retired Node services. Pinning their absence is the actual contract — a reader who
  # sees them come back should have to delete this assertion deliberately.
  test "the two retired root secrets are no longer generated" do
    keys = :persistent_term.get(@keys_term, nil)

    refute Map.has_key?(keys, :database_key)
    refute Map.has_key?(keys, :internal_auth_token)
    refute function_exported?(SystemCrypto, :database_key, 0)
    refute function_exported?(SystemCrypto, :internal_auth_token, 0)
  end

  test "values match the GenServer state and have the expected shapes" do
    state = :sys.get_state(SystemCrypto)

    assert SystemCrypto.jwt_secret() == state.jwt_secret
    assert is_binary(state.jwt_secret) and byte_size(state.jwt_secret) >= 64
    assert byte_size(SystemCrypto.encryption_key()) == 32
  end

  test "accessors fall back to the GenServer when the persistent_term entry is absent" do
    saved = :persistent_term.get(@keys_term)
    :persistent_term.erase(@keys_term)

    try do
      assert :persistent_term.get(@keys_term, :absent) == :absent
      assert SystemCrypto.jwt_secret() == saved.jwt_secret
      assert SystemCrypto.encryption_key() == saved.encryption_key
    after
      :persistent_term.put(@keys_term, saved)
    end
  end

  test "DATA_DIR/.env is not readable by group/others (mode 0600)" do
    data_dir = Application.get_env(:termelix, :data_dir)
    path = Path.join(data_dir, ".env")
    assert File.exists?(path), "expected #{path} to exist after SystemCrypto boot"

    mode = File.stat!(path).mode

    assert Bitwise.band(mode, 0o777) == 0o600,
           "expected .env mode 0600, got #{Integer.to_string(mode, 8)}"
  end
end
