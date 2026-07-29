defmodule Termelix.Repo do
  use Ecto.Repo,
    otp_app: :termelix,
    adapter: Ecto.Adapters.SQLite3
end
