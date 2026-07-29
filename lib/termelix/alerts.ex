defmodule Termelix.Alerts do
  @moduledoc """
  The alerts data layer — the port of Node's `AlertRepository` (`database/repositories/
  alert-repository.ts`). Covers three user-scoped CRUD surfaces (notification channels, alert
  rules with their linked channels, and alert firings) plus the read paths the background
  `Termelix.Alerts.Engine` uses to evaluate rules and fan out notifications.

  Ownership is always enforced by a `user_id` filter (a body `userId` is never trusted upstream).
  Wire rendering (`*_json/1,2`) reproduces the snake_case + `0/1` boolean shape the Node
  repository mappers emit, which the frontend `alerts-api.ts` mappers read.

  FKs are enforced by SQLite: `alert_rules.user_id`/`host_id`, `notification_channels.user_id`,
  `alert_rule_channels.rule_id`/`channel_id`, and `alert_firings.user_id`/`rule_id` all
  reference real rows (`alert_firings.host_id` is a plain integer, not an FK).
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.{AlertRule, AlertRuleChannel, AlertFiring, NotificationChannel, Host}

  # --- notification channels --------------------------------------------------

  @doc "A user's notification channels, oldest id first."
  @spec list_notification_channels(String.t()) :: [NotificationChannel.t()]
  def list_notification_channels(user_id) do
    Repo.all(from c in NotificationChannel, where: c.userId == ^user_id, order_by: [asc: c.id])
  end

  @doc "A single channel owned by the user, or nil."
  @spec find_notification_channel_for_user(integer(), String.t()) :: NotificationChannel.t() | nil
  def find_notification_channel_for_user(id, user_id) do
    Repo.get_by(NotificationChannel, id: id, userId: user_id)
  end

  @doc "Create a channel for the user. Returns `{:ok, channel}` with the DB-generated `createdAt`."
  @spec create_notification_channel(map()) :: {:ok, NotificationChannel.t()}
  def create_notification_channel(attrs) do
    {:ok, created} =
      %NotificationChannel{}
      |> Ecto.Changeset.change(%{
        userId: attrs.userId,
        name: attrs.name,
        type: attrs.type,
        config: attrs.config,
        enabled: attrs.enabled
      })
      |> Repo.insert()

    {:ok, Repo.get!(NotificationChannel, created.id)}
  end

  @doc """
  Update an owned channel with the present keys of `changes` (`:name`/`:type`/`:config`/
  `:enabled`). Returns `{:ok, channel}`, or `nil` when the channel is not owned by the user.
  """
  @spec update_notification_channel(integer(), String.t(), map()) ::
          {:ok, NotificationChannel.t()} | nil
  def update_notification_channel(id, user_id, changes) do
    case find_notification_channel_for_user(id, user_id) do
      nil ->
        nil

      channel ->
        {:ok, updated} =
          channel
          |> Ecto.Changeset.change(Map.take(changes, [:name, :type, :config, :enabled]))
          |> Repo.update()

        {:ok, updated}
    end
  end

  @doc "Delete an owned channel. Returns `true` when a row was removed, else `false`."
  @spec delete_notification_channel(integer(), String.t()) :: boolean()
  def delete_notification_channel(id, user_id) do
    {count, _} =
      Repo.delete_all(from c in NotificationChannel, where: c.id == ^id and c.userId == ^user_id)

    count > 0
  end

  # --- alert rules ------------------------------------------------------------

  @doc "A user's alert rules (oldest id first), each with its linked channel ids."
  @spec list_alert_rules(String.t()) :: [{AlertRule.t(), [integer()]}]
  def list_alert_rules(user_id) do
    Repo.all(from r in AlertRule, where: r.userId == ^user_id, order_by: [asc: r.id])
    |> Enum.map(fn rule -> {rule, channel_ids_for_rule(rule.id)} end)
  end

  @doc "A single rule owned by the user, or nil."
  @spec find_alert_rule_for_user(integer(), String.t()) :: AlertRule.t() | nil
  def find_alert_rule_for_user(id, user_id) do
    Repo.get_by(AlertRule, id: id, userId: user_id)
  end

  @doc """
  Create a rule and link its channels (only the user's own channels are linked). `attrs` carries
  `:userId`, `:hostId`, `:name`, `:enabled`, `:triggerType`, `:thresholdValue`,
  `:thresholdDurationSeconds`, `:cooldownMinutes`, `:channels`, `:now`. Returns
  `{:ok, rule, linked_channel_ids}`.
  """
  @spec create_alert_rule(map()) :: {:ok, AlertRule.t(), [integer()]}
  def create_alert_rule(attrs) do
    {:ok, created} =
      %AlertRule{}
      |> Ecto.Changeset.change(%{
        userId: attrs.userId,
        hostId: attrs.hostId,
        name: attrs.name,
        enabled: attrs.enabled,
        triggerType: attrs.triggerType,
        thresholdValue: to_float(attrs.thresholdValue),
        thresholdDurationSeconds: attrs.thresholdDurationSeconds,
        cooldownMinutes: attrs.cooldownMinutes,
        createdAt: attrs.now,
        updatedAt: attrs.now
      })
      |> Repo.insert()

    linked = replace_rule_channels(created.id, attrs.userId, attrs.channels)
    {:ok, created, linked}
  end

  @doc """
  Update an owned rule with the present keys of `changes` (same field set as create, plus
  `:now`; `:channels` when present replaces the links, otherwise the existing links are kept).
  Returns `{:ok, rule, channel_ids}`, or `nil` when the rule is not owned by the user.
  """
  @spec update_alert_rule(integer(), String.t(), map()) :: {:ok, AlertRule.t(), [integer()]} | nil
  def update_alert_rule(id, user_id, changes) do
    case find_alert_rule_for_user(id, user_id) do
      nil ->
        nil

      rule ->
        set =
          changes
          |> Map.take([
            :name,
            :hostId,
            :enabled,
            :triggerType,
            :thresholdValue,
            :thresholdDurationSeconds,
            :cooldownMinutes
          ])
          |> maybe_float(:thresholdValue)
          |> Map.put(:updatedAt, changes.now)

        {:ok, updated} = rule |> Ecto.Changeset.change(set) |> Repo.update()

        channels =
          case Map.fetch(changes, :channels) do
            {:ok, channel_ids} -> replace_rule_channels(id, user_id, channel_ids)
            :error -> channel_ids_for_rule(id)
          end

        {:ok, updated, channels}
    end
  end

  @doc "Delete an owned rule (its channel links + firings cascade via FK). Returns a boolean."
  @spec delete_alert_rule(integer(), String.t()) :: boolean()
  def delete_alert_rule(id, user_id) do
    {count, _} =
      Repo.delete_all(from r in AlertRule, where: r.id == ^id and r.userId == ^user_id)

    count > 0
  end

  @doc "The channel ids linked to a rule."
  @spec channel_ids_for_rule(integer()) :: [integer()]
  def channel_ids_for_rule(rule_id) do
    Repo.all(from rc in AlertRuleChannel, where: rc.ruleId == ^rule_id, select: rc.channelId)
  end

  # Replace a rule's channel links with `channel_ids`, keeping only ids the user owns. Returns
  # the linked ids (Node's `replaceRuleChannels`).
  defp replace_rule_channels(rule_id, user_id, channel_ids) do
    Repo.delete_all(from rc in AlertRuleChannel, where: rc.ruleId == ^rule_id)

    Enum.flat_map(channel_ids || [], fn channel_id ->
      case find_notification_channel_for_user(channel_id, user_id) do
        nil ->
          []

        _channel ->
          Repo.insert!(
            Ecto.Changeset.change(%AlertRuleChannel{}, %{
              ruleId: rule_id,
              channelId: channel_id
            })
          )

          [channel_id]
      end
    end)
  end

  # --- alert firings ----------------------------------------------------------

  @doc """
  A page of a user's firings, newest first, with each firing's rule name joined in. `opts` has
  `:userId`, `:limit`, `:offset`, and optional `:acknowledged` (true/false to filter). Returns
  `{[{firing, rule_name}], total}`.
  """
  @spec list_alert_firings(map()) :: {[{AlertFiring.t(), String.t() | nil}], non_neg_integer()}
  def list_alert_firings(%{userId: user_id, limit: limit, offset: offset} = opts) do
    query = from f in AlertFiring, where: f.userId == ^user_id

    query =
      case Map.get(opts, :acknowledged) do
        nil -> query
        ack -> from f in query, where: f.acknowledged == ^ack
      end

    total = Repo.aggregate(query, :count, :id)

    rows =
      Repo.all(
        from f in query,
          left_join: r in AlertRule,
          on: r.id == f.ruleId,
          order_by: [desc: f.firedAt],
          limit: ^limit,
          offset: ^offset,
          select: {f, r.name}
      )

    {rows, total}
  end

  @doc """
  Record a firing. `attrs` carries `:userId`, `:ruleId`, `:hostId`, `:hostName`, `:value`,
  `:message`, `:severity`. `firedAt` and `acknowledged` fall to their SQLite defaults.
  """
  @spec create_firing(map()) :: :ok
  def create_firing(attrs) do
    %AlertFiring{}
    |> Ecto.Changeset.change(%{
      userId: attrs.userId,
      ruleId: attrs.ruleId,
      hostId: attrs.hostId,
      hostName: attrs.hostName,
      value: to_float(Map.get(attrs, :value)),
      message: attrs.message,
      severity: attrs.severity
    })
    |> Repo.insert()

    :ok
  end

  @doc "Acknowledge one owned firing (idempotent — a missing/foreign firing is a no-op)."
  @spec acknowledge_firing(integer(), String.t()) :: :ok
  def acknowledge_firing(id, user_id) do
    Repo.update_all(
      from(f in AlertFiring, where: f.id == ^id and f.userId == ^user_id),
      set: [acknowledged: true]
    )

    :ok
  end

  @doc "Acknowledge all of a user's firings."
  @spec acknowledge_all_firings(String.t()) :: :ok
  def acknowledge_all_firings(user_id) do
    Repo.update_all(
      from(f in AlertFiring, where: f.userId == ^user_id),
      set: [acknowledged: true]
    )

    :ok
  end

  @doc "Delete a user's firings older than `days` (uses SQLite `datetime('now', ...)`)."
  @spec prune_firings_older_than(String.t(), pos_integer()) :: :ok
  def prune_firings_older_than(user_id, days) do
    cutoff = "-#{days} days"

    Repo.delete_all(
      from f in AlertFiring,
        where: f.userId == ^user_id and f.firedAt < fragment("datetime('now', ?)", ^cutoff)
    )

    :ok
  end

  # --- engine read paths ------------------------------------------------------

  @doc "Enabled rules that apply to a host (host-specific or global `host_id IS NULL`)."
  @spec list_enabled_rules_for_host(integer()) :: [AlertRule.t()]
  def list_enabled_rules_for_host(host_id) do
    Repo.all(
      from r in AlertRule,
        where: r.enabled == true and (r.hostId == ^host_id or is_nil(r.hostId))
    )
  end

  @doc "A rule by id (any owner), or nil."
  @spec find_rule_by_id(integer()) :: AlertRule.t() | nil
  def find_rule_by_id(id), do: Repo.get(AlertRule, id)

  @doc "Enabled notification channels linked to a rule."
  @spec list_enabled_channels_for_rule(integer()) :: [NotificationChannel.t()]
  def list_enabled_channels_for_rule(rule_id) do
    Repo.all(
      from c in NotificationChannel,
        join: rc in AlertRuleChannel,
        on: rc.channelId == c.id,
        where: rc.ruleId == ^rule_id and c.enabled == true
    )
  end

  @doc "A host display name: `name` when set, otherwise `ip`, or nil when the host is gone."
  @spec host_display_name(integer()) :: String.t() | nil
  def host_display_name(host_id) do
    case Repo.one(from h in Host, where: h.id == ^host_id, select: {h.name, h.ip}) do
      {name, _ip} when is_binary(name) and name != "" -> name
      {_name, ip} -> ip
      nil -> nil
    end
  end

  # --- wire rendering (Node repository mapper shapes) --------------------------

  @doc "Render a channel to the snake_case + `0/1` shape (`mapChannelRow`)."
  @spec channel_json(NotificationChannel.t()) :: map()
  def channel_json(%NotificationChannel{} = c) do
    %{
      id: c.id,
      user_id: c.userId,
      name: c.name,
      type: c.type,
      config: c.config,
      enabled: bool_int(c.enabled),
      created_at: c.createdAt
    }
  end

  @doc "Render a rule + its channel ids (`mapRuleRow` + `channels`)."
  @spec rule_json(AlertRule.t(), [integer()]) :: map()
  def rule_json(%AlertRule{} = r, channel_ids) do
    %{
      id: r.id,
      user_id: r.userId,
      host_id: r.hostId,
      name: r.name,
      enabled: bool_int(r.enabled),
      trigger_type: r.triggerType,
      threshold_value: r.thresholdValue,
      threshold_duration_seconds: r.thresholdDurationSeconds,
      cooldown_minutes: r.cooldownMinutes,
      created_at: r.createdAt,
      updated_at: r.updatedAt,
      channels: channel_ids
    }
  end

  @doc "Render a firing + its rule name (`mapFiringRow`)."
  @spec firing_json(AlertFiring.t(), String.t() | nil) :: map()
  def firing_json(%AlertFiring{} = f, rule_name) do
    %{
      id: f.id,
      user_id: f.userId,
      rule_id: f.ruleId,
      host_id: f.hostId,
      host_name: f.hostName,
      fired_at: f.firedAt,
      resolved_at: f.resolvedAt,
      value: f.value,
      message: f.message,
      severity: f.severity,
      acknowledged: bool_int(f.acknowledged),
      rule_name: rule_name
    }
  end

  # --- helpers ----------------------------------------------------------------

  defp bool_int(true), do: 1
  defp bool_int(_), do: 0

  defp maybe_float(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> Map.put(map, key, to_float(value))
      :error -> map
    end
  end

  defp to_float(nil), do: nil
  defp to_float(n) when is_integer(n), do: n * 1.0
  defp to_float(n) when is_float(n), do: n
  defp to_float(_), do: nil
end
