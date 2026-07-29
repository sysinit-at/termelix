defmodule TermelixWeb.ControllerHelpers do
  @moduledoc """
  Small shared helpers for JSON controllers: the canonical `{error: message}` envelope the
  frontend reads (`main-axios.ts` reads `error` first), and lenient path-id parsing.

  `error/3` is exactly the `defp error/3` the controllers previously each defined locally;
  `parse_id/1` mirrors JS `parseInt`: a leading integer prefix parses, anything else is
  `:error` — callers decide whether an unparsable id maps to a 400 or to the same 404 a
  nonexistent numeric id returns (so probing cannot distinguish "bad id" from "no such row").
  """
  import Plug.Conn, only: [put_status: 2]
  import Phoenix.Controller, only: [json: 2]

  @doc "Respond with `status` and the canonical `{\"error\": message}` JSON envelope."
  @spec error(Plug.Conn.t(), non_neg_integer(), String.t()) :: Plug.Conn.t()
  def error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})

  @doc """
  Parse an id path/body param into an integer. Integers pass through; binaries parse like
  JS `parseInt` (leading integer prefix wins, e.g. `"12abc"` → `{:ok, 12}`); anything else
  is `:error`.
  """
  @spec parse_id(term()) :: {:ok, integer()} | :error
  def parse_id(id) when is_integer(id), do: {:ok, id}

  def parse_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {int, _rest} -> {:ok, int}
      :error -> :error
    end
  end

  def parse_id(_), do: :error

  @doc """
  The client's IP address as a string, for audit/session rows and rate-limit buckets.

  Reads `conn.remote_ip`, which `TermelixWeb.Plugs.TrustedProxy` has already resolved from
  `x-forwarded-for` *if and only if* the direct peer is a configured trusted proxy. Never read
  the header here: doing so is what previously let anyone able to reach the app port directly
  write a forged address into the audit trail.
  """
  @spec client_ip(Plug.Conn.t()) :: String.t()
  def client_ip(conn), do: conn.remote_ip |> :inet.ntoa() |> to_string()
end
