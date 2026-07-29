# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :termelix,
  ecto_repos: [Termelix.Repo],
  generators: [timestamp_type: :utc_datetime],
  # Outbound GitHub release/update checks. Off until a public repo for this port exists —
  # flip to true then; the endpoints degrade to their local-only shapes meanwhile.
  update_check_enabled: false

# Error reporting is opt-in: every event passes through the ErrorReporting gate, which
# drops it unless an admin has enabled reporting (persisted setting; see that module).
config :sentry, before_send: {Termelix.ErrorReporting, :before_send}

# SQLite concurrency: WAL lets readers run alongside the single writer, and a busy timeout
# makes pool connections wait instead of erroring during the migrate-on-boot race.
config :termelix, Termelix.Repo,
  journal_mode: :wal,
  busy_timeout: 5_000,
  cache_size: -64_000

# Configure the endpoint
# `Plug.Conn.Utils`/Phoenix map an Accept header to an extension through this table, and
# `plug :accepts, ["sse"]` needs `text/event-stream` to have one. Without it a browser's
# `new EventSource("/events")` — which sends `Accept: text/event-stream` — is answered 406.
config :mime, :types, %{"text/event-stream" => ["sse"]}

config :termelix, TermelixWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [json: TermelixWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Termelix.PubSub,
  live_view: [signing_salt: "66rNSMJo"]

# Configure Elixir's Logger. `:request_id` only ever populates on HTTP request processes —
# the session/socket processes carry their identity in the other keys, and metadata not on
# this allowlist is silently dropped from the formatted line.
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id, :session_id, :user_id, :host_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
