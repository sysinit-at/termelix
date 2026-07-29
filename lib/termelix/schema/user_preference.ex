defmodule Termelix.Schema.UserPreference do
  @moduledoc "The `user_preferences` table (one row per user; user_id is the PK)."
  use Ecto.Schema

  @primary_key {:userId, :string, autogenerate: false, source: :user_id}
  schema "user_preferences" do
    field :reopenTabsOnLogin, :boolean, source: :reopen_tabs_on_login
    field :theme, :string
    field :fontSize, :string, source: :font_size
    field :accentColor, :string, source: :accent_color
    field :language, :string
    field :storageMode, :string, source: :storage_mode
    field :commandAutocomplete, :boolean, source: :command_autocomplete
    field :commandPaletteEnabled, :boolean, source: :command_palette_enabled
    field :showHostTags, :boolean, source: :show_host_tags
    field :hostTrayOnClick, :boolean, source: :host_tray_on_click
    field :pinAppRail, :boolean, source: :pin_app_rail
    field :expandAppRailOnHover, :boolean, source: :expand_app_rail_on_hover
    field :foldersCollapsed, :boolean, source: :folders_collapsed
    field :confirmSnippetExecution, :boolean, source: :confirm_snippet_execution
    field :disableUpdateCheck, :boolean, source: :disable_update_check
    field :confirmTabClose, :boolean, source: :confirm_tab_close
    field :hiddenRailTabs, :string, source: :hidden_rail_tabs
    field :compactHostView, :boolean, source: :compact_host_view
    field :statusColorScheme, :string, source: :status_color_scheme
    field :updatedAt, :string, source: :updated_at
  end
end
