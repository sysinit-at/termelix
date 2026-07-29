defmodule Termelix.Repo.Migrations.ScrubNestedSudoPasswords do
  @moduledoc """
  Strip `sudoPassword` from `terminal_config` at every depth, for rows already stored.

  `20260726200000` decoded each blob and did `Map.delete(decoded, "sudoPassword")` — the top-level
  key of an object, and nothing else. Two shapes survived it, and survived the write and read paths
  too until those were made recursive:

      [{"sudoPassword":"..."}]
      {"a":{"sudoPassword":"..."}}

  The read path now scrubs recursively, so these no longer reach a browser. That is not a reason to
  leave them on disk: a plaintext credential at rest is still readable by anything with the file —
  a backup, the database-export endpoint, an operator with shell access — and "the current code
  does not happen to return it" is the same argument that made the original bug survive review.

  Done in Elixir rather than SQL because removing a key at arbitrary depth with `json_remove`
  requires enumerating paths from `json_tree` and reapplying them as the document shifts underneath.
  Decoding, scrubbing and re-encoding is the same operation stated once.

  Irreversible: `down` cannot restore a secret, and should not want to.
  """
  use Ecto.Migration

  import Ecto.Query, only: [from: 2]

  @secret_keys ~w(sudoPassword password keyPassword)

  def up do
    repo().all(
      from(h in "ssh_data",
        where: not is_nil(h.terminal_config),
        select: {h.id, h.terminal_config}
      )
    )
    |> Enum.each(&scrub_row/1)
  end

  def down, do: :ok

  defp scrub_row({id, blob}) do
    with {:ok, decoded} <- Jason.decode(blob),
         scrubbed when scrubbed != decoded <- scrub(decoded) do
      repo().update_all(
        from(h in "ssh_data", where: h.id == ^id),
        set: [terminal_config: Jason.encode!(scrubbed)]
      )
    else
      # Unchanged, or not decodable. A blob that will not parse cannot be edited safely and cannot
      # be read as configuration either — `parse_json/2` returns nil for it, so the field comes back
      # null rather than as raw text. Blanking it would discard the user's terminal preferences to
      # no benefit.
      _ -> :ok
    end
  end

  defp scrub(value) when is_map(value) do
    value
    |> Enum.reject(fn {key, _} -> key in @secret_keys end)
    |> Map.new(fn {key, nested} -> {key, scrub(nested)} end)
  end

  defp scrub(value) when is_list(value), do: Enum.map(value, &scrub/1)
  defp scrub(value), do: value
end
