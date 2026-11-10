import { useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "./ui/alert";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "./ui/collapsible";
import { CopyButton } from "./CopyButton";
import {
  Activity,
  AlertCircle,
  ChevronRight,
  Code2,
  RefreshCw,
  Server,
} from "lucide-react";

interface SaasVerificationCardProps {
  saasData: any;
  isLoading: boolean;
  error: string | null;
  onRefresh: () => void;
}

export function SaasVerificationCard({
  saasData,
  isLoading,
  error,
  onRefresh,
}: SaasVerificationCardProps) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <Card>
      <CardHeader>
        <div>
          <div className="flex items-center gap-2">
            <Server className="size-4 text-primary" />
            <CardTitle className="text-sm font-semibold">
              Protected Backend Claim Verification
            </CardTitle>
          </div>
          <CardDescription className="text-xs">
            Validates token extraction, role validation, and session claims at{" "}
            <code className="font-mono text-[11px] bg-muted px-1 py-0.5">/api/saas/me</code>
          </CardDescription>
        </div>
        <CardAction>
          <Button
            variant="outline"
            size="sm"
            onClick={onRefresh}
            disabled={isLoading}
            className="gap-1.5 h-7 text-xs"
          >
            <RefreshCw className={`size-3 ${isLoading ? "animate-spin" : ""}`} />
            {isLoading ? "Validating..." : "Refresh /api/saas/me"}
          </Button>
        </CardAction>
      </CardHeader>

      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="size-4" />
            <AlertTitle className="text-xs font-semibold">
              Failed to query /api/saas/me
            </AlertTitle>
            <AlertDescription className="text-xs">{error}</AlertDescription>
          </Alert>
        )}

        {saasData ? (
          <div className="space-y-3.5">
            {/* Status summary grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 bg-muted/40 border border-border/60 p-3">
              <div className="space-y-1">
                <span className="text-[11px] text-muted-foreground uppercase tracking-wider block">
                  Transport
                </span>
                <Badge variant="outline" className="font-mono text-xs">
                  {saasData.transport || "Bearer"}
                </Badge>
              </div>

              <div className="space-y-1">
                <span className="text-[11px] text-muted-foreground uppercase tracking-wider block">
                  Status
                </span>
                <span className="font-semibold text-xs text-foreground block">
                  {saasData.status || "Authenticated"}
                </span>
              </div>

              <div className="space-y-1">
                <span className="text-[11px] text-muted-foreground uppercase tracking-wider block">
                  Email Verified
                </span>
                <span className="text-xs font-medium text-foreground block">
                  {saasData.user?.emailVerified ? "Yes" : "No"}
                </span>
              </div>

              <div className="space-y-1">
                <span className="text-[11px] text-muted-foreground uppercase tracking-wider block">
                  Session Expiry
                </span>
                <span className="text-xs font-mono text-muted-foreground block truncate">
                  {saasData.session?.expiresAt
                    ? new Date(saasData.session.expiresAt).toLocaleTimeString()
                    : "N/A"}
                </span>
              </div>
            </div>

            {/* Session ID display */}
            <div className="flex items-center justify-between text-xs bg-card border border-border/60 px-3 py-2">
              <span className="text-muted-foreground">Session Identifier:</span>
              <div className="flex items-center gap-1.5 font-mono text-[11px]">
                <span>{saasData.session?.id || "N/A"}</span>
                {saasData.session?.id && (
                  <CopyButton text={saasData.session.id} title="Copy full session ID" />
                )}
              </div>
            </div>

            {/* Collapsible raw JSON */}
            <Collapsible open={isOpen} onOpenChange={setIsOpen} className="border border-border/60">
              <CollapsibleTrigger render={
                <button
                  type="button"
                  className="w-full flex items-center justify-between p-2.5 text-xs text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
                />
              }>
                <div className="flex items-center gap-2 font-medium">
                  <ChevronRight
                    className={`size-3.5 transition-transform duration-200 ${
                      isOpen ? "rotate-90 text-foreground" : ""
                    }`}
                  />
                  <Code2 className="size-3.5 text-muted-foreground" />
                  <span>Inspect Raw JSON Response</span>
                </div>
                <Badge variant="secondary" className="text-[10px] px-1.5 py-0 h-4 font-mono">
                  JSON
                </Badge>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <div className="border-t border-border/60 bg-muted/50 p-3 relative">
                  <div className="absolute top-2 right-2">
                    <CopyButton
                      text={JSON.stringify(saasData, null, 2)}
                      title="Copy JSON Payload"
                    />
                  </div>
                  <pre className="overflow-x-auto font-mono text-[11px] leading-relaxed text-foreground/90 max-h-64 pr-8">
                    {JSON.stringify(saasData, null, 2)}
                  </pre>
                </div>
              </CollapsibleContent>
            </Collapsible>
          </div>
        ) : (
          !error && (
            <div className="py-6 text-center text-xs text-muted-foreground">
              {isLoading ? "Querying Axum endpoint..." : "No data available"}
            </div>
          )
        )}
      </CardContent>
    </Card>
  );
}
