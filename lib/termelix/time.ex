defmodule Termelix.Time do
  @moduledoc """
  Canonical parsing of the ISO-8601 timestamps SQLite stores as text (`sessions.expiresAt`
  and friends).

  One parser with one failure policy: an absent or unparseable timestamp counts as **already
  elapsed**. The two independent copies this replaces disagreed — `Accounts.session_expired?/1`
  read a malformed `expiresAt` as "still valid" (a corrupt row became a session that never
  expires) while `Sessions.remaining_seconds/1` read the same value as 0. A control that gates
  access has to fail closed, so that is the rule here.
  """

  @doc "Parse an ISO-8601 timestamp; `:error` for nil, a non-string, or unparseable text."
  @spec parse_iso8601(term()) :: {:ok, DateTime.t()} | :error
  def parse_iso8601(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _utc_offset} -> {:ok, datetime}
      {:error, _reason} -> :error
    end
  end

  def parse_iso8601(_value), do: :error

  @doc "True when the timestamp lies in the past — and, failing closed, when it will not parse."
  @spec expired?(term(), DateTime.t()) :: boolean()
  def expired?(value, now \\ DateTime.utc_now()) do
    case parse_iso8601(value) do
      {:ok, datetime} -> DateTime.compare(datetime, now) == :lt
      :error -> true
    end
  end

  @doc "Seconds left until the timestamp, clamped at 0 — including 0 when it will not parse."
  @spec remaining_seconds(term(), DateTime.t()) :: non_neg_integer()
  def remaining_seconds(value, now \\ DateTime.utc_now()) do
    case parse_iso8601(value) do
      {:ok, datetime} -> max(DateTime.diff(datetime, now, :second), 0)
      :error -> 0
    end
  end
end
