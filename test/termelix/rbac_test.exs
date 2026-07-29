defmodule Termelix.RbacTest do
  @moduledoc """
  Context-level coverage for the `Termelix.Rbac` write paths that now run through changesets
  and unique constraints: role creation/update and user-role assignment.
  """
  use Termelix.DataCase, async: false

  alias Termelix.{Accounts, Rbac}

  @password "correct horse battery staple"

  setup do
    {:ok, user, _first?} = Accounts.register_user("alice", @password)
    %{user: user}
  end

  defp role_attrs(name, overrides \\ %{}) do
    Map.merge(%{name: name, displayName: "Ops", description: nil, permissions: nil}, overrides)
  end

  describe "create_role/1" do
    test "a malformed name fails validation", %{user: _user} do
      assert {:error, %Ecto.Changeset{} = changeset} = Rbac.create_role(role_attrs("Bad Name"))
      assert {"has invalid format", _} = changeset.errors[:name]

      assert {:error, %Ecto.Changeset{} = blank} = Rbac.create_role(role_attrs(""))

      assert Enum.any?(Keyword.get_values(blank.errors, :name), fn {message, _} ->
               message == "can't be blank"
             end)
    end

    test "a duplicate name maps to the unique constraint", %{user: _user} do
      assert {:ok, id} = Rbac.create_role(role_attrs("ops"))
      assert is_integer(id)

      assert {:error, %Ecto.Changeset{} = changeset} = Rbac.create_role(role_attrs("ops"))
      assert {"has already been taken", _} = changeset.errors[:name]
    end
  end

  describe "update_role/2" do
    test "unknown role is :not_found; otherwise the update applies", %{user: _user} do
      assert {:error, :not_found} = Rbac.update_role(999_999, %{displayName: "x"})

      {:ok, id} = Rbac.create_role(role_attrs("ops"))
      assert {:ok, role} = Rbac.update_role(id, %{displayName: "Operators"})
      assert role.displayName == "Operators"
    end
  end

  describe "assign_role_to_user/3" do
    test "a duplicate assignment maps to :already_assigned", %{user: user} do
      {:ok, role_id} = Rbac.create_role(role_attrs("ops"))

      assert :ok = Rbac.assign_role_to_user(user.id, role_id, user.id)
      assert {:error, :already_assigned} = Rbac.assign_role_to_user(user.id, role_id, user.id)
      assert [^role_id] = Rbac.list_user_role_ids(user.id)
    end
  end
end
