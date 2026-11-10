import { Badge } from "./ui/badge";
import {
  Card,
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
import { Code2, Terminal, CheckCircle2, ShieldCheck } from "lucide-react";

interface ApiDiagnosticsCardProps {
  token: string;
  userRole: string;
}

export function ApiDiagnosticsCard({ token, userRole }: ApiDiagnosticsCardProps) {
  const endpoints = [
    {
      method: "POST",
      path: "/api/auth/sign-in/email",
      desc: "Authenticates credentials and establishes session cookie/bearer token",
      auth: "Public",
    },
    {
      method: "POST",
      path: "/api/auth/sign-up/email",
      desc: "Registers new tenant account in SQLite/PostgreSQL storage",
      auth: "Public",
    },
    {
      method: "GET",
      path: "/api/auth/get-session",
      desc: "Retrieves active session and user claims via Better-Auth protocol",
      auth: "Session",
    },
    {
      method: "GET",
      path: "/api/auth/list-sessions",
      desc: "Lists all concurrent active sessions for the current authenticated user",
      auth: "Session",
    },
    {
      method: "POST",
      path: "/api/auth/revoke-session",
      desc: "Revokes a specific session token from the authentication store",
      auth: "Session",
    },
    {
      method: "GET",
      path: "/api/auth/admin/list-users",
      desc: "Queries paginated user directory with role and status filtering",
      auth: "Admin Role",
    },
    {
      method: "POST",
      path: "/api/auth/admin/impersonate-user",
      desc: "Issues scoped session claims impersonating a target user",
      auth: "Admin Role",
    },
    {
      method: "GET",
      path: "/api/saas/me",
      desc: "Axum SaaS route validating extracted Bearer token / Cookie claims",
      auth: "Session / Bearer",
    },
  ];

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Terminal className="size-4 text-primary" />
          <CardTitle className="text-sm font-semibold">
            Axum Architecture & API Protocol Diagnostics
          </CardTitle>
        </div>
        <CardDescription className="text-xs">
          Better-Auth protocol compatibility specification running against Rust backend
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Token Info Box */}
        <div className="bg-muted/40 border border-border/60 p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-foreground flex items-center gap-1.5">
              <ShieldCheck className="size-3.5 text-primary" />
              Client Authorization Context
            </span>
            <Badge variant="outline" className="font-mono text-[10px]">
              Role: {userRole}
            </Badge>
          </div>

          <div className="text-[11px] text-muted-foreground flex flex-col sm:flex-row sm:items-center justify-between gap-1 bg-card p-2 border border-border/50">
            <span className="font-mono text-muted-foreground">Bearer Token:</span>
            <div className="flex items-center gap-1 font-mono text-[11px]">
              <span className="truncate max-w-xs">
                {token ? `${token.slice(0, 24)}...` : "Cookie / Session Mode"}
              </span>
              {token && <CopyButton text={token} title="Copy Bearer Token" />}
            </div>
          </div>
        </div>

        {/* API Table */}
        <div className="border border-border/60 overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/40 text-xs">
                <TableHead className="w-20">Method</TableHead>
                <TableHead className="w-56">Endpoint Route</TableHead>
                <TableHead>Specification & Purpose</TableHead>
                <TableHead className="text-right">Access Level</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {endpoints.map((ep, i) => (
                <TableRow key={i} className="text-xs">
                  <TableCell>
                    <Badge
                      variant={ep.method === "POST" ? "default" : "secondary"}
                      className="font-mono text-[10px] px-1.5 py-0 h-4"
                    >
                      {ep.method}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-[11px] font-medium text-foreground">
                    {ep.path}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-[11px]">
                    {ep.desc}
                  </TableCell>
                  <TableCell className="text-right">
                    <Badge
                      variant={
                        ep.auth === "Admin Role"
                          ? "default"
                          : ep.auth === "Public"
                          ? "outline"
                          : "secondary"
                      }
                      className="text-[10px] px-1.5 py-0 h-4"
                    >
                      {ep.auth}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
