import { useNavigate } from "react-router";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Activity,
  LogOut,
  Network,
  Settings,
  Shield,
  User,
} from "lucide-react";
import { client } from "./api";

export function Dashboard() {
  const navigate = useNavigate();

  const username = localStorage.getItem("username") || "Unknown";

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
    <div className="min-h-screen bg-muted/40 text-foreground">
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
          </nav>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-sm font-medium px-3 py-1.5 bg-muted rounded-md">
            <User className="h-4 w-4" />
            {/* Display the dynamically loaded username here */}
            <span className="capitalize">{username}</span>
          </div>
          <Button
            variant="destructive"
            size="sm"
            onClick={handleLogout}
            className="gap-2"
          >
            <LogOut className="h-4 w-4" />
            Logout
          </Button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="p-6">
        <div className="mb-6">
          <h2 className="text-3xl font-bold tracking-tight">
            Firewall Overview
          </h2>
          <p className="text-muted-foreground">
            Real-time metrics from the eBPF backend.
          </p>
        </div>

        {/* Stats Grid */}
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                IPv4 Packets Allowed
              </CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">---</div>
              <p className="text-xs text-muted-foreground">
                Awaiting backend connection
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                IPv6 Packets Allowed
              </CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">---</div>
              <p className="text-xs text-muted-foreground">
                Awaiting backend connection
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                Active Allow List Rules
              </CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">---</div>
              <p className="text-xs text-muted-foreground">Across v4 and v6</p>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
