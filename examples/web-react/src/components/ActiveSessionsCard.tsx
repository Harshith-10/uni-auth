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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./ui/table";
import { CopyButton } from "./CopyButton";
import {
  Globe,
  Laptop,
  RefreshCw,
  Shield,
  Smartphone,
  Trash2,
} from "lucide-react";

interface ActiveSessionsCardProps {
  sessions: any[];
  currentSessionId?: string;
  onRefresh: () => void;
  onRevokeSession: (token: string) => void;
  isLoading?: boolean;
}

export function ActiveSessionsCard({
  sessions,
  currentSessionId,
  onRefresh,
  onRevokeSession,
  isLoading = false,
}: ActiveSessionsCardProps) {
  // Helper to determine device type icon
  const getDeviceIcon = (ua?: string) => {
    if (!ua) return <Globe className="size-3.5 text-muted-foreground" />;
    const lower = ua.toLowerCase();
    if (lower.includes("mobile") || lower.includes("android") || lower.includes("iphone")) {
      return <Smartphone className="size-3.5 text-muted-foreground" />;
    }
    return <Laptop className="size-3.5 text-muted-foreground" />;
  };

  const formatUserAgent = (ua?: string) => {
    if (!ua) return "Web Browser";
    if (ua.includes("Chrome")) return "Google Chrome / Chromium";
    if (ua.includes("Firefox")) return "Mozilla Firefox";
    if (ua.includes("Safari")) return "Apple Safari";
    if (ua.includes("Edge")) return "Microsoft Edge";
    return ua.slice(0, 30) + (ua.length > 30 ? "..." : "");
  };

  return (
    <Card>
      <CardHeader>
        <div>
          <div className="flex items-center gap-2">
            <Laptop className="size-4 text-primary" />
            <CardTitle className="text-sm font-semibold">
              Active Sessions ({sessions.length})
            </CardTitle>
          </div>
          <CardDescription className="text-xs">
            Review and manage devices authorized to interact with your account
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
            Refresh Sessions
          </Button>
        </CardAction>
      </CardHeader>

      <CardContent>
        {sessions.length === 0 ? (
          <div className="py-8 text-center text-xs text-muted-foreground">
            No active sessions found.
          </div>
        ) : (
          <div className="border border-border/60 overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/40 text-xs">
                  <TableHead className="w-[180px]">Session ID</TableHead>
                  <TableHead>Client & User Agent</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((s, idx) => {
                  const isCurrent = s.id === currentSessionId;
                  const tokenToRevoke = s.token || s.id;
                  const expires = s.expiresAt ? new Date(s.expiresAt) : null;
                  const isExpired = expires ? expires.getTime() < Date.now() : false;

                  return (
                    <TableRow key={s.id || idx} className="text-xs">
                      <TableCell className="font-mono text-[11px]">
                        <div className="flex items-center gap-1.5">
                          <span className="truncate">{s.id?.slice(0, 12)}...</span>
                          {s.id && <CopyButton text={s.id} title="Copy session token" />}
                        </div>
                      </TableCell>

                      <TableCell>
                        <div className="flex items-center gap-2">
                          {getDeviceIcon(s.userAgent)}
                          <div className="space-y-0.5">
                            <span className="font-medium text-foreground block">
                              {formatUserAgent(s.userAgent)}
                            </span>
                            <span className="text-[10px] text-muted-foreground font-mono block truncate max-w-xs">
                              {s.ipAddress || "Local / Loopback"}
                            </span>
                          </div>
                        </div>
                      </TableCell>

                      <TableCell className="text-muted-foreground text-[11px]">
                        {expires ? (
                          <div className="space-y-0.5">
                            <span>{expires.toLocaleDateString()}</span>
                            <span className="block text-[10px] text-muted-foreground">
                              {expires.toLocaleTimeString()}
                            </span>
                          </div>
                        ) : (
                          "N/A"
                        )}
                      </TableCell>

                      <TableCell>
                        {isCurrent ? (
                          <Badge variant="default" className="text-[10px] px-1.5 py-0 h-4">
                            Current Device
                          </Badge>
                        ) : isExpired ? (
                          <Badge variant="destructive" className="text-[10px] px-1.5 py-0 h-4">
                            Expired
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4 text-emerald-600 dark:text-emerald-400 border-emerald-500/30">
                            Active
                          </Badge>
                        )}
                      </TableCell>

                      <TableCell className="text-right">
                        <Button
                          variant="outline"
                          size="xs"
                          onClick={() => onRevokeSession(tokenToRevoke)}
                          disabled={isCurrent}
                          className="text-xs text-destructive hover:bg-destructive/10 hover:text-destructive h-6 px-2 gap-1"
                          title={isCurrent ? "Cannot revoke active device here. Sign out instead." : "Revoke session token"}
                        >
                          <Trash2 className="size-3" />
                          Revoke
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
