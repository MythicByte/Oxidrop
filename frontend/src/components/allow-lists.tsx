import { useEffect, useState } from "react";
import { Network, RefreshCw, ShieldCheck } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { client } from "./api";

type AddressFamily = "v4" | "v6";

async function readEntries(response: Response): Promise<unknown[]> {
  if (!response.ok) return [];
  try {
    const value: unknown = await response.json();
    if (Array.isArray(value)) return value;
    if (value && typeof value === "object") return Object.entries(value).map(([key, state]) => ({ key, state }));
  } catch {
    // An empty body is valid for an empty eBPF map.
  }
  return [];
}

export function AllowLists() {
  const [family, setFamily] = useState<AddressFamily>("v4");
  const [entries, setEntries] = useState<unknown[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [refreshToken, setRefreshToken] = useState(0);

  useEffect(() => {
    let active = true;
    setIsLoading(true);
    const load = async () => {
      try {
        const result = family === "v4"
          ? await client.GET("/api/v1/config/allow_list/v4")
          : await client.GET("/api/v1/config/allow_list/v6");
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
    return () => { active = false; };
  }, [family, refreshToken]);

  return (
    <div className="space-y-8 p-4 sm:p-6 lg:p-8">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div><p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-primary">Traffic policy</p><h1 className="text-3xl font-bold tracking-tight">Allow lists</h1><p className="mt-2 text-muted-foreground">Inspect the addresses and flows currently permitted by the firewall.</p></div>
        <Button variant="outline" onClick={() => setRefreshToken((token) => token + 1)}><RefreshCw className="size-4" /> Refresh</Button>
      </div>
      <div className="flex gap-2 rounded-xl border bg-background p-1 shadow-sm w-fit">
        {(["v4", "v6"] as const).map((value) => <button key={value} className={`rounded-lg px-4 py-2 text-sm font-medium ${family === value ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted"}`} onClick={() => setFamily(value)}>{value === "v4" ? "IPv4" : "IPv6"} <span className="ml-1 text-xs opacity-70">({value === family ? entries.length : "—"})</span></button>)}
      </div>
      <Card className="border-0 shadow-sm"><CardContent className="p-0">
        {isLoading ? <div className="p-8 text-center text-sm text-muted-foreground">Reading eBPF map…</div> : entries.length === 0 ? <div className="flex flex-col items-center p-12 text-center"><ShieldCheck className="size-10 text-primary/60" /><h2 className="mt-4 font-semibold">No {family === "v4" ? "IPv4" : "IPv6"} entries</h2><p className="mt-1 text-sm text-muted-foreground">This allow list is currently empty.</p></div> : <div className="divide-y">{entries.map((entry, index) => <div key={index} className="flex items-center gap-3 px-5 py-4 text-sm"><Network className="size-4 text-primary" /><code className="font-mono text-xs">{typeof entry === "string" ? entry : JSON.stringify(entry)}</code></div>)}</div>}
      </CardContent></Card>
    </div>
  );
}
