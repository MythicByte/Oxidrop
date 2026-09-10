import { useEffect, useState } from "react";
import { Edit2, Trash2, Users } from "lucide-react";
import type { components } from "@/api/schema";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { client } from "./api";

type UserRow = components["schemas"]["UserRow"];
type Role = components["schemas"]["RolesUser"];

const permissionOptions = [
  { label: "Create", description: "Create new firewall resources", bit: 1 },
  { label: "Modify", description: "Change existing firewall resources", bit: 2 },
  { label: "Delete", description: "Remove firewall resources", bit: 4 },
] as const;

export function UserManagement() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [hasModify, setHasModify] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [editingUser, setEditingUser] = useState<UserRow | null>(null);
  const [editRole, setEditRole] = useState<Role>("Viewer");
  const [editPermissions, setEditPermissions] = useState(0);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    async function fetchState() {
      try {
        const [rbacRes, usersRes] = await Promise.all([
          client.GET("/api/v1/role_and_permissions"),
          client.GET("/api/v1/users/get_all_user"),
        ]);
        if (rbacRes.response.ok && rbacRes.data) {
          setHasModify(rbacRes.data.permissions.includes("Modify"));
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

  const openEditor = (user: UserRow) => {
    setEditingUser(user);
    setEditRole(user.role === "Admin" ? "Admin" : "Viewer");
    setEditPermissions(user.permissions & 7);
  };

  const saveUser = async () => {
    if (!editingUser) return;
    setIsSaving(true);
    try {
      const { response } = await client.PUT("/api/v1/users/modify_user", {
        body: {
          target_username: editingUser.username,
          role: editRole,
          permissions: editPermissions,
          is_active: editingUser.is_active ? 1 : 0,
        },
      });
      if (response.ok) {
        setUsers(users.map((user) => user.id === editingUser.id
          ? { ...user, role: editRole, permissions: editPermissions }
          : user));
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

  const handleDelete = async (username: string) => {
    if (!confirm(`Are you sure you want to delete ${username}?`)) return;
    try {
      const { response } = await client.DELETE("/api/v1/users/delete_user", {
        body: { target_username: username },
      });
      if (response.ok) setUsers(users.filter((user) => user.username !== username));
      else alert("Failed to delete user.");
    } catch (error) {
      console.error("Failed to delete user:", error);
    }
  };

  return (
    <div className="space-y-6 p-4 sm:p-6 lg:p-8">
      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-primary">Access control</p>
        <h1 className="text-3xl font-bold tracking-tight">Database users</h1>
        <p className="mt-2 text-muted-foreground">Manage roles and permissions without editing numeric bitmasks.</p>
      </div>
      <Card className="border-0 shadow-sm">
        <CardHeader><CardTitle className="flex items-center gap-2"><Users className="size-5" /> System operators</CardTitle></CardHeader>
        <CardContent>
          {isLoading ? <div className="py-6 text-center text-muted-foreground">Loading users…</div> : (
            <Table>
              <TableHeader><TableRow><TableHead>Username</TableHead><TableHead>Role</TableHead><TableHead>Permissions</TableHead><TableHead>Status</TableHead>{hasModify && <TableHead className="text-right">Actions</TableHead>}</TableRow></TableHeader>
              <TableBody>
                {users.length === 0 && <TableRow><TableCell colSpan={5} className="py-6 text-center text-muted-foreground">No users found.</TableCell></TableRow>}
                {users.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell className="font-medium">{user.username}</TableCell>
                    <TableCell>{user.role}</TableCell>
                    <TableCell><div className="flex flex-wrap gap-1.5">{permissionOptions.filter(({ bit }) => (user.permissions & bit) !== 0).map(({ label }) => <span key={label} className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">{label}</span>)}{(user.permissions & 7) === 0 && <span className="text-xs text-muted-foreground">None</span>}</div></TableCell>
                    <TableCell>{user.is_active ? "Active" : "Disabled"}</TableCell>
                    {hasModify && <TableCell className="text-right"><Button variant="ghost" size="icon" onClick={() => openEditor(user)} aria-label={`Edit ${user.username}`}><Edit2 className="size-4" /></Button><Button variant="ghost" size="icon" className="text-destructive" onClick={() => handleDelete(user.username)} aria-label={`Delete ${user.username}`}><Trash2 className="size-4" /></Button></TableCell>}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
      {editingUser && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-4" onClick={() => setEditingUser(null)}>
          <section className="w-full max-w-md rounded-2xl border bg-background p-6 shadow-2xl" onClick={(event) => event.stopPropagation()}>
            <h2 className="text-xl font-bold">Edit {editingUser.username}</h2>
            <p className="mt-1 text-sm text-muted-foreground">Choose capabilities using plain language.</p>
            <div className="mt-6 space-y-4">
              <div className="space-y-2"><Label htmlFor="user-role">Role</Label><select id="user-role" value={editRole} onChange={(event) => setEditRole(event.target.value as Role)} className="h-9 w-full rounded-lg border border-input bg-background px-3 text-sm"><option value="Viewer">Viewer</option><option value="Admin">Admin</option></select></div>
              <div className="space-y-3"><Label>Permissions</Label>{permissionOptions.map(({ label, description, bit }) => <label key={label} className="flex cursor-pointer items-center justify-between rounded-xl border p-3 hover:bg-muted/50"><span><span className="block text-sm font-medium">{label}</span><span className="block text-xs text-muted-foreground">{description}</span></span><input type="checkbox" checked={(editPermissions & bit) !== 0} onChange={() => setEditPermissions((value) => value ^ bit)} className="size-4 accent-primary" /></label>)}</div>
            </div>
            <div className="mt-6 flex justify-end gap-2"><Button variant="outline" onClick={() => setEditingUser(null)}>Cancel</Button><Button onClick={saveUser} disabled={isSaving}>{isSaving ? "Saving…" : "Save changes"}</Button></div>
          </section>
        </div>
      )}
    </div>
  );
}
