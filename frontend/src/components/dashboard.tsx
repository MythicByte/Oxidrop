import { useEffect, useRef, useState } from "react";
import { Outlet, useNavigate } from "react-router";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Activity,
  LogOut,
  Network,
  Settings,
  Shield,
  User,
  Users,
  X,
} from "lucide-react";
import { client } from "./api";

export function Dashboard() {
  const navigate = useNavigate();
  const username = localStorage.getItem("username") || "Unknown";

  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const [isConfigModalOpen, setIsConfigModalOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // New state to hold the fetched RBAC profile
  const [roleData, setRoleData] = useState<
    { role: string; permissions: string[] } | null
  >(null);
  const [isLoadingRole, setIsLoadingRole] = useState(false);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setIsDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Fetch the role and permissions only when the modal is opened
  useEffect(() => {
    if (!isConfigModalOpen) return;

    const fetchRoleData = async () => {
      setIsLoadingRole(true);
      try {
        const { response, data } = await client.GET(
          "/api/v1/role_and_permissions" as any,
          {},
        );

        if (response.ok && data) {
          setRoleData(data as { role: string; permissions: string[] });
        } else {
          console.error(`Failed to load role data. Status: ${response.status}`);
        }
      } catch (e) {
        console.error("Error fetching role data:", e);
      } finally {
        setIsLoadingRole(false);
      }
    };

    // Only fetch if we haven't already loaded it
    if (!roleData) {
      fetchRoleData();
    }
  }, [isConfigModalOpen, roleData]);

  const handleLogout = async () => {
    try {
      await client.GET("/api/v1/logout");
    } catch (e) {
      console.error("Failed to cleanly logout from server:", e);
    } finally {
      localStorage.removeItem("isAuthenticated");
      localStorage.removeItem("username");
      window.location.href = "/login";
    }
  };

  return (
    <div className="min-h-screen bg-muted/40 text-foreground relative">
      <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b bg-background px-6 shadow-sm">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2 font-bold text-xl tracking-tight text-primary">
            <Shield className="h-6 w-6" />
            OxiDrop
          </div>

          <nav className="hidden md:flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              className="gap-2"
              onClick={() => navigate("/dashboard")}
            >
              <Activity className="h-4 w-4" /> Overview
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="gap-2"
              onClick={() => navigate("/dashboard/allow-lists")}
            >
              <Network className="h-4 w-4" /> Allow Lists
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="gap-2"
              onClick={() => navigate("/dashboard/configuration")}
            >
              <Settings className="h-4 w-4" /> Configuration
            </Button>
            {/* Add the Users button back here */}
            <Button
              variant="ghost"
              size="sm"
              className="gap-2"
              onClick={() => navigate("/dashboard/users")}
            >
              <Users className="h-4 w-4" /> Users
            </Button>
          </nav>
        </div>

        {/* User Dropdown Area */}
        <div className="relative flex items-center gap-4" ref={dropdownRef}>
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            onClick={() => setIsDropdownOpen(!isDropdownOpen)}
          >
            <User className="h-4 w-4" />
            <span className="capitalize">{username}</span>
          </Button>

          {/* The Dropdown Menu */}
          {isDropdownOpen && (
            <div className="absolute right-0 top-full mt-2 w-48 rounded-md border bg-background shadow-lg z-50 overflow-hidden">
              <div className="p-1">
                <button
                  onClick={() => {
                    setIsConfigModalOpen(true);
                    setIsDropdownOpen(false);
                  }}
                  className="flex w-full items-center gap-2 rounded-sm px-2 py-2 text-sm hover:bg-muted cursor-pointer"
                >
                  <Settings className="h-4 w-4" />
                  User Configuration
                </button>
              </div>
              <div className="border-t border-border p-1">
                <button
                  onClick={handleLogout}
                  className="flex w-full items-center gap-2 rounded-sm px-2 py-2 text-sm text-destructive hover:bg-muted cursor-pointer"
                >
                  <LogOut className="h-4 w-4" />
                  Logout
                </button>
              </div>
            </div>
          )}
        </div>
      </header>

      {/* Main Content Area */}
      <main>
        <Outlet />
      </main>
      {/* User Configuration Modal */}
      {isConfigModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-lg border bg-background p-6 shadow-lg">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold ">User Configuration</h2>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setIsConfigModalOpen(false)}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>

            <div className="space-y-4">
              <div>
                <p className="text-sm font-medium text-muted-foreground mb-1">
                  Username
                </p>
                <div className="px-3 py-2 bg-muted rounded-md border font-medium capitalize">
                  {username}
                </div>
              </div>

              <div>
                <p className="text-sm font-medium text-muted-foreground mb-1">
                  Role
                </p>
                <div className="px-3 py-2 bg-muted rounded-md border font-medium capitalize">
                  {isLoadingRole ? "Loading..." : (roleData?.role || "Unknown")}
                </div>
              </div>

              <div>
                <p className="text-sm font-medium text-muted-foreground mb-1">
                  Permissions
                </p>
                <div className="min-h-[42px] px-3 py-2 bg-muted rounded-md border flex flex-wrap gap-2 items-center">
                  {isLoadingRole
                    ? (
                      <span className="text-sm text-muted-foreground">
                        Loading...
                      </span>
                    )
                    : roleData?.permissions && roleData.permissions.length > 0
                    ? (
                      roleData.permissions.map((perm) => (
                        <span
                          key={perm}
                          className="px-2 py-0.5 bg-primary text-primary-foreground text-xs font-semibold rounded-sm shadow-sm"
                        >
                          {perm}
                        </span>
                      ))
                    )
                    : (
                      <span className="text-sm text-muted-foreground">
                        No explicit permissions
                      </span>
                    )}
                </div>
              </div>

              <div className="flex justify-center pt-4 border-t">
                <Button onClick={() => setIsConfigModalOpen(false)}>
                  Close
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
