import { ScrollText, ShieldCheck } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export function Logs() {
  return (
    <div className="space-y-8 p-4 sm:p-6 lg:p-8">
      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-primary">
          Administrator tools
        </p>
        <h1 className="text-3xl font-bold tracking-tight">Logs</h1>
        <p className="mt-2 text-muted-foreground">
          Review security and policy events for this firewall.
        </p>
      </div>
      <Card className="border-0 shadow-sm">
        <CardContent className="flex flex-col items-center p-12 text-center">
          <div className="grid size-12 place-items-center rounded-2xl bg-primary/10 text-primary">
            <ScrollText className="size-6" />
          </div>
          <h2 className="mt-5 font-semibold">No log events available</h2>
          <p className="mt-2 max-w-md text-sm leading-relaxed text-muted-foreground">
            The current OpenAPI contract does not expose a log stream yet.
            This administrator-only view is ready for the backend audit endpoint.
          </p>
          <div className="mt-5 flex items-center gap-2 text-xs font-medium text-emerald-600">
            <ShieldCheck className="size-4" />
            Administrator access verified
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
