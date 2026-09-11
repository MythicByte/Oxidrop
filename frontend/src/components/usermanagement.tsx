import { useEffect, useState } from "react";
import { Edit2, Eye, EyeOff, Plus, Trash2, Users } from "lucide-react";
import type { components } from "../api/schema.d.ts";
import { Button } from "./ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.tsx";
import { Label } from "./ui/label.tsx";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./ui/table.tsx";
import { client } from "./api.tsx";

type UserRow = components["schemas"]["UserRow"];
type Role = components["schemas"]["RolesUser"];

const permissionOptions = [
  { label: "Create", description: "Create new firewall resources", bit: 1 },
  {
    label: "Modify",
    description: "Change existing firewall resources",
    bit: 2,
  },
  { label: "Delete", description: "Remove firewall resources", bit: 4 },
] as const;

function serializePermissions(value: number): string {
  return permissionOptions
    .filter(({ bit }) => (value & bit) !== 0)
    .map(({ label }) => label.toUpperCase())
    .join("|");
}

export function UserManagement() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [editingUser, setEditingUser] = useState<UserRow | null>(null);
  const [editRole, setEditRole] = useState<Role>("Viewer");
  const [editPermissions, setEditPermissions] = useState(0);
  const [editPassword, setEditPassword] = useState("");
  const [showEditPassword, setShowEditPassword] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [createSuccess, setCreateSuccess] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [deleteUsername, setDeleteUsername] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [newUser, setNewUser] = useState({
    username: "",
    password: "",
    role: "Viewer" as Role,
    permissions: 0,
    password_must_be_changed: true,
  });

  useEffect(() => {
    async function fetchState() {
      try {
        const [rbacRes, usersRes] = await Promise.all([
          client.GET("/api/v1/role_and_permissions"),
          client.GET("/api/v1/users/get_all_user"),
        ]);
        if (rbacRes.response.ok && rbacRes.data) {
          setPermissions(rbacRes.data.permissions);
        }
        if (usersRes.response.ok && usersRes.data) setUsers(usersRes.data);
      } catch (error) {
        console.error("Failed to fetch users:", error);
      } finally {
        setIsLoading(false);
      }
    }
    void fetchState();
  }, []);

  const hasModify = permissions.includes("Modify");
  const hasCreate = permissions.includes("Create");

  const createUser = async () => {
    if (!newUser.username.trim() || !newUser.password) {
      setCreateError("Username and password are required.");
      return;
    }
    setCreateError(null);
    setCreateSuccess(null);
    setIsSaving(true);
    try {
      const response = await fetch("/api/v1/users/create_user", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
        body: JSON.stringify({
          username: newUser.username,
          password: newUser.password,
          role: newUser.role,
          permissions: serializePermissions(newUser.permissions),
          password_must_be_changed: newUser.password_must_be_changed,
        }),
      });
      if (response.ok) {
        const refreshed = await client.GET("/api/v1/users/get_all_user");
        if (refreshed.response.ok && refreshed.data) setUsers(refreshed.data);
        setNewUser({
          username: "",
          password: "",
          role: "Viewer",
          permissions: 0,
          password_must_be_changed: true,
        });
        setIsCreating(false);
        setCreateSuccess(`User ${newUser.username} was created.`);
      } else {
        const message = await response.text();
        setCreateError(
          message ||
            `Unable to create user (HTTP ${response.status}). Check the username, password, and permissions.`,
        );
      }
    } catch (error) {
      console.error("Failed to create user:", error);
      setCreateError(
        error instanceof Error
          ? error.message
          : "Unable to reach the user service.",
      );
    } finally {
      setIsSaving(false);
    }
  };

  const openEditor = (user: UserRow) => {
    setEditingUser(user);
    setEditRole(user.role.toLowerCase() === "admin" ? "Admin" : "Viewer");
    setEditPermissions(user.permissions & 7);
    setEditPassword("");
    setShowEditPassword(false);
  };

  const saveUser = async () => {
    if (!editingUser) return;
    setIsSaving(true);
    try {
      const { response } = await client.PUT("/api/v1/users/modify_user", {
        body: {
          target_username: editingUser.username,
          role: editRole,
          permissions: serializePermissions(editPermissions),
          is_active: editingUser.is_active ? 1 : 0,
          ...(editPassword ? { password: editPassword } : {}),
        },
      });
      if (response.ok) {
        setUsers(
          users.map((user) =>
            user.id === editingUser.id
              ? { ...user, role: editRole, permissions: editPermissions }
              : user
          ),
        );
        setEditingUser(null);
      } else {
        alert("Unable to update this user.");
      }
    } catch (error) {
      console.error("Failed to update user:", error);
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteUsername) return;
    const username = deleteUsername;
    setIsSaving(true);
    setDeleteError(null);
    try {
      const { response } = await client.DELETE("/api/v1/users/delete_user", {
        body: { target_username: username },
      });
      if (response.ok) {
        setUsers(users.filter((user) => user.username !== username));
        setDeleteUsername(null);
      } else {
        setDeleteError(
          `Failed to delete ${username} (HTTP ${response.status}).`,
        );
      }
    } catch (error) {
      console.error("Failed to delete user:", error);
      setDeleteError(
        error instanceof Error
          ? error.message
          : "Unable to reach the user service.",
      );
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6 p-4 sm:p-6 lg:p-8">
      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-primary">
          Access control
        </p>
        <h1 className="text-3xl font-bold tracking-tight">Database users</h1>
        <p className="mt-2 text-muted-foreground">
          Manage roles and permissions without editing numeric bitmasks.
        </p>
        {createSuccess && (
          <div
            role="status"
            className="mt-4 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-700"
          >
            {createSuccess}
          </div>
        )}
        {hasCreate && (
          <Button
            type="button"
            className="mt-4"
            onClick={() => {
              setCreateError(null);
              setCreateSuccess(null);
              setShowPassword(false);
              setIsCreating(true);
            }}
          >
            <Plus className="size-4" /> Add user
          </Button>
        )}
      </div>
      <Card className="border-0 shadow-sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="size-5" /> System operators
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading
            ? (
              <div className="py-6 text-center text-muted-foreground">
                Loading users…
              </div>
            )
            : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Username</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Permissions</TableHead>
                    <TableHead>Status</TableHead>
                    {hasModify && (
                      <TableHead className="text-right">Actions</TableHead>
                    )}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.length === 0 && (
                    <TableRow>
                      <TableCell
                        colSpan={5}
                        className="py-6 text-center text-muted-foreground"
                      >
                        No users found.
                      </TableCell>
                    </TableRow>
                  )}
                  {users.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell className="font-medium">
                        {user.username}
                      </TableCell>
                      <TableCell>{user.role}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1.5">
                          {permissionOptions.filter(({ bit }) =>
                            (user.permissions & bit) !== 0
                          ).map(({ label }) => (
                            <span
                              key={label}
                              className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary"
                            >
                              {label}
                            </span>
                          ))}
                          {(user.permissions & 7) === 0 && (
                            <span className="text-xs text-muted-foreground">
                              None
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {user.is_active ? "Active" : "Disabled"}
                      </TableCell>
                      {hasModify && (
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openEditor(user)}
                            aria-label={`Edit ${user.username}`}
                          >
                            <Edit2 className="size-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-destructive"
                            onClick={() => {
                              setDeleteError(null);
                              setDeleteUsername(user.username);
                            }}
                            aria-label={`Delete ${user.username}`}
                          >
                            <Trash2 className="size-4" />
                          </Button>
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
        </CardContent>
      </Card>
      {editingUser && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-4"
          onClick={() => setEditingUser(null)}
        >
          <section
            className="w-full max-w-md rounded-2xl border bg-background p-6 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <h2 className="text-xl font-bold">Edit {editingUser.username}</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Choose capabilities using plain language.
            </p>
            <div className="mt-6 space-y-4">
              <div className="space-y-2">
                <Label htmlFor="user-role">Role</Label>
                <select
                  id="user-role"
                  value={editRole}
                  onChange={(event) => setEditRole(event.target.value as Role)}
                  className="h-9 w-full rounded-lg border border-input bg-background px-3 text-sm"
                >
                  <option value="Viewer">Viewer</option>
                  <option value="Admin">Admin</option>
                </select>
              </div>
              <div className="space-y-3">
                <Label>Permissions</Label>
                {permissionOptions.map(({ label, description, bit }) => (
                  <label
                    key={label}
                    className="flex cursor-pointer items-center justify-between rounded-xl border p-3 hover:bg-muted/50"
                  >
                    <span>
                      <span className="block text-sm font-medium">{label}</span>
                      <span className="block text-xs text-muted-foreground">
                        {description}
                      </span>
                    </span>
                    <input
                      type="checkbox"
                      checked={(editPermissions & bit) !== 0}
                      onChange={() =>
                        setEditPermissions((value) => value ^ bit)}
                      className="size-4 accent-primary"
                    />
                  </label>
                ))}
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-password">New password (optional)</Label>
                <div className="relative">
                  <input
                    id="edit-password"
                    minLength={12}
                    type={showEditPassword ? "text" : "password"}
                    value={editPassword}
                    onChange={(event) => setEditPassword(event.target.value)}
                    className="h-9 w-full rounded-lg border border-input bg-background px-3 pr-10 text-sm"
                    placeholder="Leave blank to keep current password"
                  />
                  <button
                    type="button"
                    className="absolute inset-y-0 right-0 grid w-10 place-items-center text-muted-foreground"
                    onClick={() => setShowEditPassword((value) => !value)}
                    aria-label={showEditPassword
                      ? "Hide password"
                      : "Show password"}
                  >
                    {showEditPassword
                      ? <EyeOff className="size-4" />
                      : <Eye className="size-4" />}
                  </button>
                </div>
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-2">
              <Button variant="outline" onClick={() => setEditingUser(null)}>
                Cancel
              </Button>
              <Button onClick={saveUser} disabled={isSaving}>
                {isSaving ? "Saving…" : "Save changes"}
              </Button>
            </div>
          </section>
        </div>
      )}
      {isCreating && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm"
          onClick={() => setIsCreating(false)}
        >
          <section
            className="w-full max-w-md rounded-2xl border bg-background p-6 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <h2 className="text-xl font-bold">Add user</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Create an operator account and assign its initial access.
            </p>
            {createError && (
              <div
                role="alert"
                className="mt-4 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                {createError}
              </div>
            )}
            <form
              className="mt-6 space-y-4"
              onSubmit={(event) => {
                event.preventDefault();
                void createUser();
              }}
            >
              <div className="space-y-2">
                <Label htmlFor="new-username">Username</Label>
                <input
                  id="new-username"
                  autoFocus
                  required
                  value={newUser.username}
                  onChange={(event) =>
                    setNewUser({ ...newUser, username: event.target.value })}
                  className="h-9 w-full rounded-lg border border-input bg-background px-3 text-sm"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-password">Password</Label>
                <div className="relative">
                  <input
                    id="new-password"
                    required
                    type={showPassword ? "text" : "password"}
                    value={newUser.password}
                    onChange={(event) =>
                      setNewUser({ ...newUser, password: event.target.value })}
                    className="h-9 w-full rounded-lg border border-input bg-background px-3 pr-10 text-sm"
                  />
                  <button
                    type="button"
                    className="absolute inset-y-0 right-0 grid w-10 place-items-center text-muted-foreground hover:text-foreground"
                    onClick={() => setShowPassword((visible) => !visible)}
                    aria-label={showPassword
                      ? "Hide password"
                      : "Show password"}
                  >
                    {showPassword
                      ? <EyeOff className="size-4" />
                      : <Eye className="size-4" />}
                  </button>
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-role">Role</Label>
                <select
                  id="new-role"
                  value={newUser.role}
                  onChange={(event) =>
                    setNewUser({
                      ...newUser,
                      role: event.target.value as Role,
                    })}
                  className="h-9 w-full rounded-lg border border-input bg-background px-3 text-sm"
                >
                  <option>Viewer</option>
                  <option>Admin</option>
                </select>
              </div>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={newUser.password_must_be_changed}
                  onChange={(event) =>
                    setNewUser((value) => ({
                      ...value,
                      password_must_be_changed: event.target.checked,
                    }))}
                  className="size-4 accent-primary"
                />{" "}
                Require password change after first login
              </label>
              <div className="space-y-3">
                <Label>Permissions</Label>
                {permissionOptions.map(({ label, description, bit }) => (
                  <label
                    key={label}
                    className="flex cursor-pointer items-center justify-between rounded-xl border p-3 hover:bg-muted/50"
                  >
                    <span>
                      <span className="block text-sm font-medium">{label}</span>
                      <span className="block text-xs text-muted-foreground">
                        {description}
                      </span>
                    </span>
                    <input
                      type="checkbox"
                      checked={(newUser.permissions & bit) !== 0}
                      onChange={() =>
                        setNewUser((value) => ({
                          ...value,
                          permissions: value.permissions ^ bit,
                        }))}
                      className="size-4 accent-primary"
                    />
                  </label>
                ))}
              </div>
              <div className="flex justify-end gap-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setIsCreating(false)}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={isSaving}>
                  {isSaving ? "Creating…" : "Create user"}
                </Button>
              </div>
            </form>
          </section>
        </div>
      )}
      {deleteUsername && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm"
          onClick={() => !isSaving && setDeleteUsername(null)}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-user-title"
            className="w-full max-w-md animate-in zoom-in-95 rounded-2xl border bg-background p-6 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-start gap-4">
              <div className="grid size-11 shrink-0 place-items-center rounded-xl bg-destructive/15 text-destructive">
                <Trash2 className="size-5" />
              </div>
              <div>
                <h2 id="delete-user-title" className="text-lg font-semibold">
                  Delete user?
                </h2>
                <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                  This permanently removes{" "}
                  <span className="font-medium text-foreground">
                    {deleteUsername}
                  </span>{" "}
                  and cannot be undone.
                </p>
              </div>
            </div>
            {deleteError && (
              <p
                role="alert"
                className="mt-4 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                {deleteError}
              </p>
            )}
            <div className="mt-6 flex justify-end gap-2">
              <Button
                variant="outline"
                onClick={() => setDeleteUsername(null)}
                disabled={isSaving}
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={() => void handleDelete()}
                disabled={isSaving}
              >
                {isSaving ? "Deleting…" : "Delete user"}
              </Button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
