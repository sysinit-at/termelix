defmodule Termelix.Repo.Migrations.ScrubSudoPasswordFromTerminalConfig do
  @moduledoc """
  Remove the sudo password from the `terminal_config` JSON blob.

  The host editor wrote it there, and `terminal_config` is a plain `TEXT` column: not in
  `FieldCrypto`'s encrypted set and not reachable by the normalizer's top-level `Map.drop`. So the
  same secret existed twice — once correctly field-encrypted under `sudo_password`, and once in
  **cleartext**, in a blob returned verbatim in every host-list response.

  This strips the cleartext copy. It does NOT try to migrate the value into `sudo_password`:
  writing there requires the DEK, which a migration has no business unlocking, and the encrypted
  column was in any case being NULLed by every save (the controller wrote
  `sudoPassword: nilify(params["sudoPassword"])` unconditionally while the editor only ever sent a
  nested value). So for affected hosts there is nothing trustworthy left to preserve, and anyone
  using sudo auto-fill re-enters it once.

  Irreversible on purpose. `down` cannot put a secret back, and pretending otherwise would be
  worse than admitting it — the whole point is that the cleartext is gone.
  """
  use Ecto.Migration

  import Ecto.Query, only: [from: 2]

  def up do
    # Raw SQL rather than the schema: a migration must not depend on the current struct, and
    # this needs no decryption — `terminal_config` is plaintext, which is the bug.
    repo().all(
      from(h in "ssh_data",
        where: not is_nil(h.terminal_config) and like(h.terminal_config, "%sudoPassword%"),
        select: {h.id, h.terminal_config}
      )
    )
    |> Enum.each(fn {id, blob} -> scrub_row(id, blob) end)
  end

  def down do
    :ok
  end

  defp scrub_row(id, blob) do
    case Jason.decode(blob) do
      {:ok, decoded} when is_map(decoded) ->
        cleaned = Map.delete(decoded, "sudoPassword")

        # Only write when something actually changed, so a row whose blob merely mentions the
        # string is left byte-identical rather than being re-encoded for nothing.
        if map_size(cleaned) != map_size(decoded) do
          repo().update_all(
            from(h in "ssh_data", where: h.id == ^id),
            set: [terminal_config: Jason.encode!(cleaned)]
          )
        end

      _not_json ->
        # An unparseable blob cannot be edited safely, and blanking it would discard the user's
        # terminal preferences. Left alone: the normalizer strips the key on read regardless, so
        # the value stops reaching the browser either way.
        :ok
    end
  end
end
