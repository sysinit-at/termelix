defmodule Termelix.MixProject do
  use Mix.Project

  def project do
    [
      app: :termelix,
      version: "0.1.0",
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      releases: releases(),
      listeners: [Phoenix.CodeReloader]
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {Termelix.Application, []},
      extra_applications: [:logger, :runtime_tools, :ssh, :public_key, :crypto, :eldap, :inets]
    ]
  end

  def cli do
    [
      preferred_envs: [precommit: :test]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      # Property tests over the tmux parsers and the UTF-8 splitter — the two places where
      # hand-written cases keep missing the input that actually breaks them.
      {:stream_data, "~> 1.4", only: [:dev, :test]},
      {:phoenix, "~> 1.8.9"},
      {:phoenix_ecto, "~> 4.5"},
      {:ecto_sql, "~> 3.13"},
      {:ecto_sqlite3, ">= 0.0.0"},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_poller, "~> 1.0"},
      {:jason, "~> 1.2"},
      {:bandit, "~> 1.5"},

      # Auth / crypto
      {:joken, "~> 2.6"},
      {:bcrypt_elixir, "~> 3.3"},
      {:nimble_totp, "~> 1.0"},
      {:eqrcode, "~> 0.2"},

      # Outbound HTTP + config formats
      {:req, "~> 0.5"},
      {:sentry, "~> 13.3"},
      {:yaml_elixir, "~> 2.11"}
    ]
  end

  # Release definition. The security-relevant settings live in `rel/env.sh.eex`, which `mix
  # release` picks up automatically and bakes into `releases/<vsn>/env.sh` — sourced by
  # `bin/termelix` before every command (see that file for what it turns off and why).
  defp releases do
    [
      termelix: [
        # The image is Linux-only (`docker/Dockerfile`). The Windows launchers source `env.bat`,
        # generated from a separate template we do not ship, so they would run without the
        # hardening in `rel/env.sh.eex`.
        include_executables_for: [:unix]
      ]
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  # For example, to install project dependencies and perform other setup tasks, run:
  #
  #     $ mix setup
  #
  # See the documentation for `Mix` for more info on aliases.
  defp aliases do
    [
      setup: ["deps.get", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"],
      precommit: ["compile --warnings-as-errors", "deps.unlock --unused", "format", "test"]
    ]
  end
end
