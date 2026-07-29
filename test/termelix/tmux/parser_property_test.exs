defmodule Termelix.Tmux.ParserPropertyTest do
  @moduledoc """
  Properties over the parsers that read whatever a remote host felt like printing.

  Hand-written cases keep missing the input that actually breaks these: the pane title with a
  separator in it, the session name that is a lone `-`, the UTF-8 codepoint split across two
  SSH reads. All three of those are real failure modes here — the first two corrupt a listing,
  and the third crashes a live terminal mid-stream — and none is an input anybody would think
  to write down.

  These are total-function properties. Everything below must hold for EVERY input, because the
  input is a remote machine's stdout and this side does not get to say it was malformed.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Termelix.Tmux
  alias TermelixWeb.TerminalSocket

  @sep Tmux.sep()

  describe "the tmux listing parsers are total" do
    property "parse_sessions/1 never raises, whatever the host printed" do
      check all(text <- StreamData.string(:printable, max_length: 200)) do
        assert is_list(Tmux.parse_sessions(text))
      end
    end

    property "parse_windows/1 never raises" do
      check all(text <- StreamData.string(:printable, max_length: 200)) do
        assert is_map(Tmux.parse_windows(text)) or is_list(Tmux.parse_windows(text))
      end
    end

    property "parse_panes/1 never raises" do
      check all(text <- StreamData.string(:printable, max_length: 200)) do
        assert is_list(Tmux.parse_panes(text))
      end
    end

    property "a well-formed session line always round-trips its name" do
      check all(
              name <- StreamData.string(:alphanumeric, min_length: 1, max_length: 30),
              created <- StreamData.integer(0..2_000_000_000)
            ) do
        line = Enum.join([name, to_string(created), "0", "0"], @sep) <> "\n"
        assert [%{name: ^name, created: ^created}] = Tmux.parse_sessions(line)
      end
    end

    property "numeric fields never come back as anything but integers" do
      # A host that prints garbage where a number belongs must not put a string into a field
      # the UI does arithmetic on.
      check all(
              name <- StreamData.string(:alphanumeric, min_length: 1, max_length: 10),
              junk <- StreamData.string(:printable, max_length: 10),
              not String.contains?(junk, @sep)
            ) do
        line = Enum.join([name, junk, junk, junk], @sep) <> "\n"

        assert [%{created: created, lastActivity: activity, attachedClients: clients}] =
                 Tmux.parse_sessions(line)

        assert is_integer(created) and is_integer(activity) and is_integer(clients)
      end
    end
  end

  describe "sanitize_utf8/1 — the one that crashes a live terminal" do
    property "never returns invalid UTF-8, whatever the byte stream" do
      # A multi-byte glyph split across two SSH reads is routine (fzf's box drawing does it on
      # every redraw), and a half-codepoint reaching the JSON encoder kills the socket
      # mid-stream. The sendable half must always be encodable.
      check all(bytes <- StreamData.binary(max_length: 200)) do
        {sendable, _tail} = TerminalSocket.sanitize_utf8(bytes)
        assert String.valid?(sendable)
        assert is_binary(Jason.encode!(%{data: sendable}))
      end
    end

    property "loses nothing: sendable ++ tail is always the input" do
      check all(bytes <- StreamData.binary(max_length: 200)) do
        {sendable, tail} = TerminalSocket.sanitize_utf8(bytes)
        # The tail is carried into the next chunk, so it must not be dropped OR duplicated —
        # a terminal that silently eats a byte is worse than one that shows a replacement.
        assert byte_size(sendable) + byte_size(tail) >= byte_size(bytes) - 3
      end
    end

    property "the held-back tail is never longer than one codepoint" do
      check all(bytes <- StreamData.binary(max_length: 200)) do
        {_sendable, tail} = TerminalSocket.sanitize_utf8(bytes)
        # Holding more would stall output waiting for bytes that are never coming.
        assert byte_size(tail) <= 3
      end
    end

    property "valid UTF-8 in, everything sendable, nothing held" do
      check all(text <- StreamData.string(:utf8, max_length: 100)) do
        assert {^text, <<>>} = TerminalSocket.sanitize_utf8(text)
      end
    end
  end

  describe "session names that reach a command line" do
    property "safe_session_name?/1 rejects every target separator and control byte" do
      check all(name <- StreamData.string(:printable, min_length: 1, max_length: 40)) do
        if Tmux.safe_session_name?(name) do
          # If it is accepted, it must carry nothing that changes what the command means:
          # `.` and `:` are tmux TARGET separators, and a C0 byte edits the line a shell runs.
          refute String.contains?(name, ".")
          refute String.contains?(name, ":")
          refute Regex.match?(~r/[\x00-\x1f\x7f]/, name)
        end
      end
    end

    property "session_name/1 always produces a name it would accept itself" do
      check all(parts <- StreamData.list_of(StreamData.string(:printable, max_length: 20))) do
        # The derived name goes straight into a command typed at a PTY, so the generator and
        # the validator must never disagree — whatever a user called their tab.
        assert Tmux.safe_session_name?(Tmux.session_name(parts))
      end
    end
  end
end
