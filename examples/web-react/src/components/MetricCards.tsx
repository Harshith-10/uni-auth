import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { CopyButton } from "./CopyButton";
import { User, Shield, KeyRound, Laptop, CheckCircle2, AlertCircle } from "lucide-react";
import { formatDateTime } from "../lib/utils";

interface MetricCardsProps {
  session: any;
  userRole: string;
  isAdmin: boolean;
  saasData: any;
  sessionsCount: number;
  onViewSessions: () => void;
}

export function MetricCards({
  session,
  userRole,
  isAdmin,
  saasData,
  sessionsCount,
  onViewSessions,
}: MetricCardsProps) {
  const user = session?.user;
  const emailVerified = user?.emailVerified || saasData?.user?.emailVerified;
  const sessionId = saasData?.session?.id || session?.session?.id;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
      {/* 1. USER IDENTITY */}
      <Card className="hover:border-foreground/20 transition-colors">
        <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
          <CardTitle className="text-xs font-medium text-muted-foreground">
            Account Identity
          </CardTitle>
          <div className="size-6 bg-muted flex items-center justify-center text-muted-foreground">
            <User className="size-3.5" />
          </div>
        </CardHeader>
        <CardContent className="space-y-1.5">
          <div className="flex items-center justify-between gap-1">
            <span className="font-semibold text-sm truncate">{user?.name || "User"}</span>
            {emailVerified ? (
              <Badge variant="outline" className="text-[10px] gap-1 border-emerald-500/30 text-emerald-600 dark:text-emerald-400 px-1 py-0 h-4">
                <CheckCircle2 className="size-2.5" />
                Verified
              </Badge>
            ) : (
              <Badge variant="outline" className="text-[10px] gap-1 text-muted-foreground px-1 py-0 h-4">
                <AlertCircle className="size-2.5" />
                Unverified
              </Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
          <div className="pt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground font-mono">
            <span className="truncate">UID: {user?.id?.slice(0, 10)}...</span>
            {user?.id && <CopyButton text={user.id} title="Copy User ID" />}
          </div>
        </CardContent>
      </Card>

      {/* 2. ROLE & PERMISSIONS */}
      <Card className="hover:border-foreground/20 transition-colors">
        <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
          <CardTitle className="text-xs font-medium text-muted-foreground">
            Role & Permissions
          </CardTitle>
          <div className="size-6 bg-muted flex items-center justify-center text-muted-foreground">
            <Shield className="size-3.5" />
          </div>
        </CardHeader>
        <CardContent className="space-y-1.5">
          <div className="flex items-center justify-between gap-1">
            <span className="font-semibold text-sm">
              {isAdmin ? "Administrator" : "Standard User"}
            </span>
            <Badge variant={isAdmin ? "default" : "secondary"} className="text-[10px] px-1.5 py-0 h-4">
              {userRole}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            {isAdmin ? "Full admin API privileges" : "Standard tenant permissions"}
          </p>
          <div className="pt-1 flex items-center gap-1 text-[11px] text-muted-foreground">
            <span>Access:</span>
            <span className="font-medium text-foreground">
              {isAdmin ? "Read/Write/Admin" : "Standard Profile"}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* 3. SESSION STATUS & TRANSPORT */}
      <Card className="hover:border-foreground/20 transition-colors">
        <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
          <CardTitle className="text-xs font-medium text-muted-foreground">
            Session Transport
          </CardTitle>
          <div className="size-6 bg-muted flex items-center justify-center text-muted-foreground">
            <KeyRound className="size-3.5" />
          </div>
        </CardHeader>
        <CardContent className="space-y-1.5">
          <div className="flex items-center justify-between gap-1">
            <span className="font-semibold text-sm">
              {saasData?.transport ? `${saasData.transport.toUpperCase()}` : "Active"}
            </span>
            <Badge variant="outline" className="text-[10px] font-mono px-1 py-0 h-4">
              {saasData?.status || "200 OK"}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground truncate">
            {(() => {
              const expiryRaw = saasData?.session?.expiresAt || session?.session?.expiresAt;
              const formatted = expiryRaw ? formatDateTime(expiryRaw) : null;
              return formatted && formatted !== "N/A"
                ? `Expires: ${formatted}`
                : "Active session";
            })()}
          </p>
          <div className="pt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground font-mono">
            <span className="truncate">SID: {sessionId ? `${sessionId.slice(0, 10)}...` : "Active"}</span>
            {sessionId && <CopyButton text={sessionId} title="Copy Session ID" />}
          </div>
        </CardContent>
      </Card>

      {/* 4. ACTIVE SESSIONS COUNT */}
      <Card className="hover:border-foreground/20 transition-colors">
        <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
          <CardTitle className="text-xs font-medium text-muted-foreground">
            Active Devices
          </CardTitle>
          <div className="size-6 bg-muted flex items-center justify-center text-muted-foreground">
            <Laptop className="size-3.5" />
          </div>
        </CardHeader>
        <CardContent className="space-y-1.5">
          <div className="flex items-center justify-between gap-1">
            <span className="font-semibold text-sm">
              {sessionsCount} {sessionsCount === 1 ? "Session" : "Sessions"}
            </span>
            <Badge variant="secondary" className="text-[10px] px-1.5 py-0 h-4 cursor-pointer" onClick={onViewSessions}>
              Manage
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            Connected across browser clients
          </p>
          <div className="pt-1 flex items-center gap-1 text-[11px] text-muted-foreground">
            <span className="size-1.5 rounded-full bg-emerald-500 inline-block" />
            <span>Current session active</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
