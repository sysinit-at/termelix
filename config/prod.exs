import Config

# HTTPS enforcement (redirect + HSTS) is configured at *runtime* in `config/runtime.exs` under
# `:termelix, :force_ssl` and applied by `TermelixWeb.Plugs.ForceSSL`, not by Phoenix's
# compile-time `:force_ssl` endpoint option. Phoenix installs that option's `Plug.SSL` ahead of
# every endpoint plug, which would have it act on an `x-forwarded-proto` no one had trust-checked
# yet; see `TermelixWeb.Plugs.TrustedProxy`.

# Do not print debug messages in production
config :logger, level: :info

# Runtime production configuration, including reading
# of environment variables, is done on config/runtime.exs.
