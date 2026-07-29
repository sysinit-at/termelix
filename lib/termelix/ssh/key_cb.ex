defmodule Termelix.SSH.KeyCb do
  @moduledoc """
  @behaviour :ssh_client_key_api

  OTP `:ssh` client-key callback module (the `ssh_client_key_api` contract) for every outbound
  connection this app makes.

  It does two jobs:

    * **user key** — authenticate with a private key held in the database (decrypted under the
      user's DEK) without ever writing it to disk. `Termelix.SSH.KeyDecode` turns the stored
      PEM/OpenSSH text into the term OTP wants.
    * **host key** — decide whether the peer is the host we pinned. `Termelix.SSH.HostKeyPolicy`
      owns that decision; this module is only the OTP-facing shell around it.

  `Termelix.SSH.ConnectOpts` attaches us on every authentication branch and passes what we need
  under `:key_cb_private`: `:key`, `:passphrase`, `:auth` and `:host_key` (connect_opts.ex:156).

  ## Three OTP details this module is shaped by

  **1. One of each pair must exist.** `ssh_client_key_api` marks `is_host_key/4,5` and
  `add_host_key/3,4` as `-optional_callbacks` with the source comment "One in the pair must be
  defined" (ssh_client_key_api.erl:104-106 and :175-177). Optional means the *pair* is optional,
  not each arity: define neither and the handshake dies on `undef`.

  **2. `undef` inside the preferred arity silently downgrades the decision.** `known_host_key/3`
  calls `is_host_key/5` inside `try … catch error:undef -> is_host_key/4` (ssh_transport.erl:
  1188-1197), and `add_host_key/4` the same way (:1206-1213). It cannot tell "this module has no
  /5" from "the /5 body called something that does not exist", so one typo or one unloaded
  module inside the trust decision would quietly fall through to the legacy arity — and if that
  arity returned `true`, to accepting any key at all. Two defences: `is_host_key/5` catches its
  own failures and answers per the configured mode instead of letting `undef` escape, and
  `is_host_key/4` **raises** rather than deciding, so a future regression that gets past the
  first defence fails loudly instead of silently trusting.

  **3. `false` does not mean "refuse".** When `is_host_key` returns `false` OTP treats the key as
  merely unknown and consults `accepted_host/5`, which under `silently_accept_hosts: true`
  (connect_opts.ex:116) returns `true` and then calls `add_host_key`
  (ssh_transport.erl:1200-1212). A refusal has to be `{:error, reason}`; `false` would be an
  accept. `Termelix.SSH.HostKeyPolicy.check/5` therefore never returns `false`.

  The callbacks run **inside the handshake process**, where the remote's `LoginGraceTime` is
  ticking. Nothing here touches SQLite: the pin is resolved before `:ssh.connect/4` is called
  and the resulting writes are dispatched to an owner process.
  """

  require Logger

  alias Termelix.SSH.HostKeyPolicy
  alias Termelix.SSH.KeyDecode

  @doc """
  Host-identity check — the arity OTP prefers, and the only one that decides anything.

  Returns `true` to accept or `{:error, reason}` to refuse (never `false`, see the moduledoc).
  Internal failures are caught here rather than allowed to reach OTP's `catch error:undef`:
  under `:tofu_warn` a bug in our own code must not make a host unconnectable, and under
  `:enforce` it must not silently become an accept.
  """
  def is_host_key(key, host, port, algorithm, opts) do
    HostKeyPolicy.check(key, host, port, algorithm, host_key_pin(opts))
  rescue
    error -> check_failed(opts, safe(error))
  catch
    kind, reason -> check_failed(opts, "#{inspect(kind)} #{inspect(reason)}")
  end

  @doc """
  Legacy host-identity arity. A tripwire, not a decision.

  OTP reaches it only after `is_host_key/5` raised `error:undef` (ssh_transport.erl:1188-1197),
  which `is_host_key/5` is written not to do. Getting here means the trust decision was about to
  be made by code that cannot see the port and has no policy behind it, so it fails the
  handshake instead — loudly, and without ever answering `true`.
  """
  def is_host_key(_key, _host, _algorithm, _opts) do
    raise "Termelix.SSH.KeyCb.is_host_key/4 was consulted. OTP only falls back to this arity " <>
            "when is_host_key/5 raises `error:undef` (ssh_transport.erl:1188-1197); the host " <>
            "key was NOT verified. Fix the undef in the /5 path rather than this function."
  end

  @doc """
  Trust-store write, preferred arity. Unreachable by construction: OTP calls it only after
  `is_host_key` returned `false`, and `Termelix.SSH.HostKeyPolicy.check/5` never does.

  Returns `:ok` anyway — OTP has already decided to accept the connection by the time it gets
  here (ssh_transport.erl:1200-1212), so raising would only break a session without changing
  the trust outcome. The log line is the signal that the invariant broke.
  """
  def add_host_key(_host, _port, _public_key, _opts) do
    Logger.error(
      "Termelix.SSH.KeyCb.add_host_key/4 was called: is_host_key/5 returned `false`, so OTP " <>
        "accepted this host key without the policy recording it (ssh_transport.erl:1200-1212)."
    )

    :ok
  end

  @doc """
  Legacy trust-store arity — the same tripwire as `is_host_key/4`, for the `add_host_key/3,4`
  pair (ssh_transport.erl:1206-1213).
  """
  def add_host_key(_host, _public_key, _opts) do
    raise "Termelix.SSH.KeyCb.add_host_key/3 was consulted. OTP only falls back to this arity " <>
            "when add_host_key/4 raises `error:undef` (ssh_transport.erl:1206-1213)."
  end

  @doc """
  The client's private key for `algorithm`, decoded in memory. `Termelix.SSH.KeyDecode` owns the
  format handling (PEM/PKCS#1/PKCS#8 and unencrypted OpenSSH v1) and the named failures.
  """
  def user_key(_algorithm, opts) do
    private = private_opts(opts)
    KeyDecode.decode(fetch(private, :key), fetch(private, :passphrase))
  end

  # --- internals -------------------------------------------------------------

  defp host_key_pin(opts), do: opts |> private_opts() |> fetch(:host_key)

  defp private_opts(opts) when is_list(opts), do: :proplists.get_value(:key_cb_private, opts, [])
  defp private_opts(_opts), do: []

  # Deliberately free of any call into another Termelix module: this runs because one of them
  # just failed, and a second failure here would escape into OTP's `catch error:undef`.
  defp check_failed(opts, detail) do
    mode = fallback_mode(opts)

    Logger.error(
      "SSH host key check failed internally (#{detail}); answering per mode #{inspect(mode)}"
    )

    case mode do
      :enforce -> {:error, :host_key_check_unavailable}
      _tofu_warn -> true
    end
  end

  # Mirrors `Termelix.SSH.HostKeyPolicy.mode/0` without calling it — pin first, then application
  # config. The settings row is deliberately not read: this is the handshake process.
  defp fallback_mode(opts) do
    pin = host_key_pin(opts)

    cond do
      is_map(pin) and Map.get(pin, :mode) == :enforce -> :enforce
      Application.get_env(:termelix, :ssh_host_key_policy) in ["enforce", :enforce] -> :enforce
      true -> :tofu_warn
    end
  rescue
    _error -> :tofu_warn
  end

  defp fetch(opts, key) when is_list(opts) do
    Keyword.get(opts, key) || :proplists.get_value(key, opts, nil)
  end

  defp fetch(_opts, _key), do: nil

  # Type and message only. `opts` here carries the decrypted private key and its passphrase, so
  # nothing that might have closed over them may reach a log line.
  defp safe(%{__struct__: module} = error), do: "#{inspect(module)}: #{Exception.message(error)}"
end
