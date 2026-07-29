import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/termelix start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :termelix, TermelixWeb.Endpoint, server: true
end

config :termelix, TermelixWeb.Endpoint,
  http: [port: String.to_integer(System.get_env("PORT", "4000"))]

# Comma-separated list of extra allowed CORS/WebSocket origins, e.g.
# ALLOWED_ORIGINS="https://termelix.example.com, https://termelix.internal".
# Unset in dev: allow the Vite dev server so `npm run dev` keeps working.
config :termelix,
       :allowed_origins,
       (case System.get_env("ALLOWED_ORIGINS") do
          nil ->
            if config_env() == :dev,
              do: ["http://localhost:5173", "http://127.0.0.1:5173"],
              else: []

          value ->
            value
            |> String.split(",", trim: true)
            |> Enum.map(&String.trim/1)
            |> Enum.reject(&(&1 == ""))
        end)

# Which direct peers may speak for a client via `x-forwarded-for` / `x-forwarded-proto`
# (`TermelixWeb.Plugs.TrustedProxy`). Comma-separated CIDRs, bare addresses, or the tokens
# `loopback`, `private`, `none` — e.g. TRUSTED_PROXIES="10.23.56.5,192.168.0.0/16".
#
# The default covers a reverse proxy on the same host or container network. It deliberately does
# NOT include CGNAT/tailnet space (100.64.0.0/10): clients commonly reach the app port directly
# over a tailnet, and trusting that range would let any of them forge their own address in the
# audit trail and their own rate-limit bucket. A proxy that connects from a tailnet address has
# to be listed explicitly.
config :termelix, :trusted_proxies, System.get_env("TRUSTED_PROXIES", "loopback,private")

# Sentry error reporting — an unset/empty SENTRY_DSN disables reporting entirely.
config :sentry,
  dsn:
    (case System.get_env("SENTRY_DSN", "") do
       "" -> nil
       dsn -> dsn
     end),
  environment_name: System.get_env("SENTRY_ENVIRONMENT", to_string(config_env()))

if config_env() == :prod do
  # Self-hosted defaults: everything lives under DATA_DIR (like the original Termix),
  # so a bare `docker run -v data:/app/data` works with zero mandatory configuration.
  data_dir = System.get_env("DATA_DIR") || "/app/data"
  File.mkdir_p!(data_dir)

  config :termelix, :data_dir, data_dir

  # Default DB filename changed with the Termix→Termelix rename. An existing deployment
  # has its data in termix.db — keep using it rather than silently starting a fresh
  # database; only brand-new data dirs get the new name.
  database_path =
    System.get_env("DATABASE_PATH") ||
      (fn ->
         new_path = Path.join(data_dir, "termelix.db")
         legacy_path = Path.join(data_dir, "termix.db")

         if not File.exists?(new_path) and File.exists?(legacy_path),
           do: legacy_path,
           else: new_path
       end).()

  config :termelix, Termelix.Repo,
    database: database_path,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "5"),
    # SQLite default is 2000ms; a longer busy timeout smooths over concurrent
    # writers (settings writes vs. request reads) on the single database file.
    busy_timeout: 5000,
    # A deferred transaction that reads first and writes later can lose the write to
    # SQLITE_BUSY_SNAPSHOT — an immediate hard error that busy_timeout does not absorb,
    # because the snapshot is already stale and no amount of waiting fixes it.
    # `BEGIN IMMEDIATE` takes the RESERVED lock up front instead, so the wait happens
    # where busy_timeout can cover it. The honest cost: this serializes EVERY
    # transaction across the pool, not just the read-then-write ones.
    default_transaction_mode: :immediate

  # The secret key base signs/encrypts cookies. Like the app's other root secrets
  # (SystemCrypto), it is auto-generated once and persisted to DATA_DIR/.env when not
  # provided via the environment.
  env_file = Path.join(data_dir, ".env")

  read_env_value = fn name ->
    with {:ok, contents} <- File.read(env_file),
         [_, value] <- Regex.run(~r/^#{name}=(.+)$/m, contents) do
      String.trim(value)
    else
      _ -> nil
    end
  end

  secret_key_base =
    System.get_env("SECRET_KEY_BASE") || read_env_value.("SECRET_KEY_BASE") ||
      (fn ->
         secret = :crypto.strong_rand_bytes(48) |> Base.encode64(padding: false)
         contents = if File.exists?(env_file), do: File.read!(env_file), else: ""
         # Lock the file to 0600 BEFORE writing the secret: a freshly created file
         # lands at the umask default (typically 0644) and would be briefly
         # world-readable with the secret inside if we chmod only afterwards.
         # Touching + chmod first means only an empty file is ever world-readable.
         File.touch!(env_file)
         _ = File.chmod(env_file, 0o600)
         File.write!(env_file, contents <> "SECRET_KEY_BASE=#{secret}\n")
         secret
       end).()

  host = System.get_env("PHX_HOST") || "example.com"

  # BIND=loopback restricts the listener to 127.0.0.1 (IPv4, matching every localhost URL
  # the tooling uses). The default binds all interfaces over dual-stack IPv6, which is what
  # a container wants — but a bare-metal disposable instance (scripts/e2e-stack.sh) must not
  # expose itself to the network while claiming to be local-only.
  bind_ip =
    case System.get_env("BIND") do
      "loopback" -> {127, 0, 0, 1}
      _ -> {0, 0, 0, 0, 0, 0, 0, 0}
    end

  config :termelix, TermelixWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # See https://bandit.hexdocs.pm/Bandit.html#t:options/0 for IPv6 vs IPv4 and
      # loopback vs public addresses.
      ip: bind_ip
    ],
    secret_key_base: secret_key_base

  # HTTPS enforcement, applied by `TermelixWeb.Plugs.ForceSSL` (see `config/prod.exs` for why it
  # is not Phoenix's compile-time `:force_ssl`). The `hosts` exclusion is what lets the container
  # healthcheck reach `http://localhost:PORT/health` without being redirected. No `:rewrite_on` —
  # `TermelixWeb.Plugs.TrustedProxy` has already resolved the scheme under a trust check.
  config :termelix, :force_ssl, exclude: [hosts: ["localhost", "127.0.0.1"]]

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :termelix, TermelixWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://plug.hexdocs.pm/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :termelix, TermelixWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.

  # --- SSH policy switches ------------------------------------------------------------------
  #
  # Both are read from the `settings` table first (changeable at runtime, no restart) and fall
  # back to application config, which is what makes them usable when the database is the thing
  # that is broken. Declared here so the kill switches are discoverable rather than folklore.
  #
  #   ssh_host_key_policy      "tofu_warn" (default) records and allows a changed host key;
  #                            "enforce" refuses it. See Termelix.SSH.HostKeyPolicy.
  #   host_key_format_validation  :reject (default) refuses an unusable private key at save time;
  #                            :warn logs and saves anyway; :off skips the check.
  #
  # config :termelix, :ssh_host_key_policy, "tofu_warn"
  # config :termelix, :host_key_format_validation, :reject
end
