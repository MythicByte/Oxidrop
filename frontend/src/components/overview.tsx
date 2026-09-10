import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Activity, Shield } from "lucide-react";

export function DashboardOverview() {
  return (
    <div className="p-6">
      <div className="mb-6">
        <h2 className="text-3xl font-bold tracking-tight">Firewall Overview</h2>
        <p className="text-muted-foreground">
          Real-time metrics from the eBPF backend.
        </p>
      </div>

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
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
