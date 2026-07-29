import Config

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :termelix, Termelix.Repo,
  database: Path.expand("../termelix_test.db", __DIR__),
  # SQLite is single-writer: async tests each own a sandbox connection, and two writers
  # in WAL mode hit an immediate `Exqlite.Error: Database busy` that busy_timeout cannot
  # wait out. pool_size: 1 serializes the sandbox owners so there is never more than one
  # writer, eliminating the seed-dependent flakiness; the async portion of the suite is
  # sub-second, so the serialization cost is negligible. The generous busy_timeout is a
  # belt-and-suspenders ceiling for any residual lock wait.
  pool_size: 1,
  busy_timeout: 30_000,
  pool: Ecto.Adapters.SQL.Sandbox

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :termelix, TermelixWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "vZ8JeRjkKEb5vlA513W9ahlQ8gHnrm3SxehRbz7t2eT7Reoc0VgAW1lmrZ0cYzNK",
  server: false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true

config :termelix, data_dir: Path.expand("../priv/tmp/test-data", __DIR__)
