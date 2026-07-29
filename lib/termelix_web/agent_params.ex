defmodule TermelixWeb.AgentParams do
  @moduledoc """
  Wire params → context arguments, shared by the REST and MCP doors.

  Small on purpose, and shared on purpose: two doors parsing `until` differently is how one of
  them ends up accepting a state the other rejects.
  """

  alias Termelix.Tmux.Orchestrator

  @doc "`until` states, defaulting to what is actually observable."
  @spec until(term()) :: [atom() | String.t()]
  def until(nil), do: Orchestrator.default_until()
  def until(states) when is_list(states), do: Enum.map(states, &state/1)
  def until(state) when is_binary(state), do: until([state])
  def until(_other), do: Orchestrator.default_until()

  # `to_existing_atom`: these come off the wire, and an unbounded atom table is a memory leak
  # the caller controls. An unknown name stays a string and is rejected by name downstream.
  defp state(value) when is_binary(value) do
    String.to_existing_atom(value)
  rescue
    ArgumentError -> value
  end

  defp state(value), do: value

  @doc "A wait holds a connection, so the ceiling is a resource decision, not a preference."
  @spec timeout(term()) :: pos_integer()
  def timeout(ms) when is_integer(ms) and ms > 0, do: min(ms, 900_000)

  def timeout(ms) when is_binary(ms) do
    case Integer.parse(ms) do
      {int, _} -> timeout(int)
      :error -> 300_000
    end
  end

  def timeout(_other), do: 300_000

  @doc "Text plus named keys → the orchestrator's key list."
  @spec keys(term(), term()) :: [term()]
  def keys(text, named) do
    literal = if is_binary(text) and text != "", do: [{:literal, text}], else: []
    literal ++ Enum.map(List.wrap(named || []), &named_key/1)
  end

  defp named_key("enter"), do: :enter
  defp named_key("ctrl_c"), do: :ctrl_c
  defp named_key("escape"), do: :escape
  # Passed through unchanged so the context refuses it by name — silently dropping an
  # unrecognised key would send the rest and report success.
  defp named_key(other), do: other

  @doc false
  @spec to_int(term()) :: integer() | nil
  def to_int(value) when is_integer(value), do: value

  def to_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> nil
    end
  end

  def to_int(_value), do: nil
end
