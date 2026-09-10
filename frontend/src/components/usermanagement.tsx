import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Edit2, Trash2, Users } from "lucide-react";
import type { components } from "@/api/schema";
import { client } from "./api";

type UserRow = components["schemas"]["UserRow"];

export function UserManagement() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [hasModify, setHasModify] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function fetchState() {
      try {
        const rbacRes = await client.GET("/api/v1/role_and_permissions");
        if (rbacRes.response.ok && rbacRes.data) {
          setHasModify(rbacRes.data.permissions.includes("Modify"));
        }

        const usersRes = await client.GET("/api/v1/users/get_all_user");
        if (usersRes.response.ok && usersRes.data) {
          setUsers(usersRes.data as unknown as UserRow[]);
        }
      } catch (error) {
        console.error("Failed to fetch users:", error);
      } finally {
        setIsLoading(false);
      }
    }
    fetchState();
  }, []);

  const handleDelete = async (username: string) => {
    if (!confirm(`Are you sure you want to delete ${username}?`)) return;

    try {
      const { response } = await client.DELETE("/api/v1/users/delete_user", {
        body: { target_username: username },
      });
      if (response.ok) {
        setUsers(users.filter((u) => u.username !== username));
      } else {
        alert("Failed to delete user.");
      }
    } catch (error) {
      console.error("Failed to delete user", error);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Database Users</h2>
          <p className="text-muted-foreground">
            Manage RBAC identities for the firewall.
          </p>
        </div>
        {hasModify && <Button>+ Create New User</Button>}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" /> System Operators
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading
            ? (
              <div className="text-center py-4 text-muted-foreground">
                Loading users...
              </div>
            )
            : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Username</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Permissions (Bitmask)</TableHead>
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
                        className="text-center text-muted-foreground py-6"
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
                      <TableCell className="capitalize">{user.role}</TableCell>
                      <TableCell>{user.permissions}</TableCell>
                      <TableCell>
                        {user.is_active ? "Active" : "Disabled"}
                      </TableCell>
                      {hasModify && (
                        <TableCell className="text-right">
                          <Button variant="ghost" size="icon">
                            <Edit2 className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-destructive"
                            onClick={() => handleDelete(user.username)}
                          >
                            <Trash2 className="h-4 w-4" />
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
    </div>
  );
}
