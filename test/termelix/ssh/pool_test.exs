defmodule Termelix.SSH.PoolTest do
  @moduledoc "Pool Registry-key derivation: which credential sets share a pooled connection."
  use ExUnit.Case, async: true

  alias Termelix.SSH.Pool

  defp opts(overrides) do
    Map.merge(
      %{
        host: "10.0.0.1",
        port: 22,
        username: "root",
        password: nil,
        private_key: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB...\n-----END-----",
        key_password: "secret"
      },
      Map.new(overrides)
    )
  end

  test "identical credentials map to the same key" do
    assert Pool.key_for(opts([])) == Pool.key_for(opts([]))
  end

  test "a different PEM passphrase yields a different key (passphrase is part of identity)" do
    # Same host+port+username+encrypted private_key, differing only in :key_password: the
    # encrypted key alone must not check out a connection authenticated with its passphrase.
    refute Pool.key_for(opts(key_password: "secret")) ==
             Pool.key_for(opts(key_password: "other"))
  end

  test "a missing passphrase differs from a present one" do
    refute Pool.key_for(opts(key_password: nil)) ==
             Pool.key_for(opts(key_password: "secret"))
  end
end
