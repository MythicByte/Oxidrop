import { useEffect, useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Network, ShieldAlert } from "lucide-react";
import { client } from "./api";
export function FirewallConfiguration() {
  const [config, setConfig] = useState<any>(null);
  const [adapters, setAdapters] = useState<{ index: number; name: string }[]>(
    [],
  );
  const [permissions, setPermissions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const hasModify = permissions.includes("Modify");

  useEffect(() => {
    async function fetchState() {
      try {
        // Fetch RBAC, Config, and Adapters in parallel
        const [rbacRes, configRes, adapterRes] = await Promise.all([
          client.GET("/api/v1/role_and_permissions"),
          client.GET("/api/v1/config"),
          client.GET("/api/v1/config/adapters"),
        ]);

        if (rbacRes.response.ok && rbacRes.data) {
          setPermissions(rbacRes.data.permissions);
        }
        if (configRes.response.ok && configRes.data) setConfig(configRes.data);
        if (adapterRes.response.ok && adapterRes.data) {
          setAdapters(
            adapterRes.data as unknown as { index: number; name: string }[],
          );
        }
      } catch (error) {
        console.error("Failed to load firewall state:", error);
      } finally {
        setIsLoading(false);
      }
    }
    fetchState();
  }, []);

  const handleSave = async () => {
    try {
      const payload = {
        ddos_activated: config.ddos_activated,
        incoming_ethernet_adapter: config.incoming_ethernet_adapter,
        output_ethernet_adapter: config.output_ethernet_adapter,
      };

      const { response } = await client.POST("/api/v1/config", {
        body: payload,
      });
      if (response.ok) {
        alert("Configuration applied to eBPF maps successfully.");
      }
    } catch (error) {
      console.error("Failed to update config:", error);
    }
  };

  if (isLoading) return <div className="p-6">Loading eBPF state...</div>;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">
          Firewall Configuration
        </h2>
        <p className="text-muted-foreground">
          Manage core eBPF parameters and hardware adapters.
        </p>
        {!hasModify && (
          <div className="mt-2 text-sm text-amber-600 font-medium">
            Read-only mode: You do not have permission to modify these settings.
          </div>
        )}
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Hardware Adapters Card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Network className="h-5 w-5" /> Network Adapters
            </CardTitle>
            <CardDescription>
              Bind the eBPF programs to specific interfaces.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Incoming Adapter (Ingress)</Label>
              <Select
                disabled={!hasModify}
                value={config?.incoming_ethernet_adapter?.toString()}
                onValueChange={(v) =>
                  setConfig({
                    ...config,
                    incoming_ethernet_adapter: parseInt(v),
                  })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select incoming adapter" />
                </SelectTrigger>
                <SelectContent>
                  {Array.isArray(adapters) &&
                    adapters.map((a) => (
                      <SelectItem key={a.index} value={a.index.toString()}>
                        {a.name} (idx: {a.index})
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Outgoing Adapter (Egress)</Label>
              <Select
                disabled={!hasModify}
                value={config?.output_ethernet_adapter?.toString()}
                onValueChange={(v) =>
                  setConfig({
                    ...config,
                    output_ethernet_adapter: parseInt(v),
                  })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select outgoing adapter" />
                </SelectTrigger>
                <SelectContent>
                  {Array.isArray(adapters) &&
                    adapters.map((a) => (
                      <SelectItem key={a.index} value={a.index.toString()}>
                        {a.name} (idx: {a.index})
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        {/* Threat Mitigation Card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" /> Threat Mitigation
            </CardTitle>
            <CardDescription>Global security policies.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between rounded-lg border p-4">
              <div className="space-y-0.5">
                <Label className="text-base">DDoS Protection</Label>
                <p className="text-sm text-muted-foreground">
                  Activate global rate limiting profiles.
                </p>
              </div>
              <Switch
                disabled={!hasModify}
                checked={config?.ddos_activated}
                onCheckedChange={(c) =>
                  setConfig({ ...config, ddos_activated: c })}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {hasModify && (
        <Button onClick={handleSave} className="w-full md:w-auto">
          Commit Configuration
        </Button>
      )}
    </div>
  );
}
