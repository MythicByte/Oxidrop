import { useEffect, useState } from "react";
import { Network, RefreshCw, ShieldCheck } from "lucide-react";
import { Card, CardContent } from "./ui/card.tsx";
import { Button } from "./ui/button.tsx";
import { client } from "./api.tsx";

type TrafficMap = "allow-v4" | "allow-v6" | "packets-v4" | "packets-v6";

async function readEntries(response: Response): Promise<unknown[]> {
  if (!response.ok) return [];
  try {
    const value: unknown = await response.json();
    if (Array.isArray(value)) return value;
    if (value && typeof value === "object") {
      return Object.entries(value).map(([key, state]) => ({ key, state }));
    }
  } catch {
    // An empty body is valid for an empty eBPF map.
  }
  return [];
}

export function AllowLists() {
  const [trafficMap, setTrafficMap] = useState<TrafficMap>("allow-v4");
  const [entries, setEntries] = useState<unknown[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [refreshToken, setRefreshToken] = useState(0);

  useEffect(() => {
    let active = true;
    setIsLoading(true);
    const load = async () => {
      try {
        const result = trafficMap === "allow-v4"
          ? await client.GET("/api/v1/config/allow_list/v4")
          : trafficMap === "allow-v6"
          ? await client.GET("/api/v1/config/allow_list/v6")
          : trafficMap === "packets-v4"
          ? await client.GET("/api/v1/config/packet_counts/v4")
          : await client.GET("/api/v1/config/packet_counts/v6");
        const nextEntries = await readEntries(result.response);
        if (active) setEntries(nextEntries);
      } catch (error) {
        console.error("Failed to load allow list:", error);
        if (active) setEntries([]);
      } finally {
        if (active) setIsLoading(false);
      }
    };
    void load();
    return () => {
      active = false;
    };
  }, [trafficMap, refreshToken]);

  const isPacketMap = trafficMap.startsWith("packets");
  const isIpv6 = trafficMap.endsWith("v6");
  const mapLabel = isPacketMap ? "Packet counts" : "Allow lists";

  return (
    <div className="space-y-8 p-4 sm:p-6 lg:p-8">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-primary">
            Traffic policy
          </p>
          <h1 className="text-3xl font-bold tracking-tight">{mapLabel}</h1>
          <p className="mt-2 text-muted-foreground">
            {isPacketMap
              ? "Inspect the IPv4 and IPv6 flows tracked by the firewall."
              : "Inspect the addresses and flows currently permitted by the firewall."}
          </p>
        </div>
        <Button
          variant="outline"
          onClick={() => setRefreshToken((token) => token + 1)}
        >
          <RefreshCw className="size-4" /> Refresh
        </Button>
      </div>
      <div className="max-w-full scroll-smooth overflow-x-auto rounded-xl border bg-background p-1 shadow-sm scrollbar-thin">
        <div className="flex w-max gap-2">
          {([
            ["allow-v4", "Allow list IPv4"],
            ["allow-v6", "Allow list IPv6"],
            ["packets-v4", "Packet counts IPv4"],
            ["packets-v6", "Packet counts IPv6"],
          ] as const).map(([value, label]) => (
            <button
              key={value}
              type="button"
              className={`shrink-0 rounded-lg px-4 py-2 text-sm font-medium transition-[background-color,color,transform,box-shadow] duration-300 ease-out ${
                trafficMap === value
                  ? "scale-[1.03] bg-primary text-primary-foreground shadow-sm"
                  : "text-muted-foreground hover:bg-muted"
              }`}
              onClick={() => setTrafficMap(value)}
            >
              {label}
              <span className="ml-1 text-xs opacity-70">
                {trafficMap === value ? `(${entries.length})` : ""}
              </span>
            </button>
          ))}
        </div>
      </div>
      <Card className="border-0 shadow-sm">
        <CardContent className="p-0">
          {isLoading
            ? (
              <div className="p-8 text-center text-sm text-muted-foreground">
                Reading eBPF map…
              </div>
            )
            : entries.length === 0
            ? (
              <div className="flex flex-col items-center p-12 text-center">
                <ShieldCheck className="size-10 text-primary/60" />
                <h2 className="mt-4 font-semibold">
                  No {isIpv6 ? "IPv6" : "IPv4"} entries
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  This {isPacketMap ? "packet-count map" : "allow list"}{" "}
                  is currently empty.
                </p>
              </div>
            )
            : (
              <div className="divide-y">
                {entries.map((entry, index) => (
                  <div
                    key={index}
                    className="flex items-center gap-3 px-5 py-4 text-sm"
                  >
                    <Network className="size-4 text-primary" />
                    <code className="font-mono text-xs">
                      {typeof entry === "string"
                        ? entry
                        : JSON.stringify(entry)}
                    </code>
                  </div>
                ))}
              </div>
            )}
        </CardContent>
      </Card>
    </div>
  );
}
