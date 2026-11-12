import { useState } from "react";
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "./ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./ui/table";
import { Avatar, AvatarFallback } from "./ui/avatar";
import { CopyButton } from "./CopyButton";
import {
  AlertCircle,
  CheckCircle2,
  KeyRound,
  Lock,
  Mail,
  MoreHorizontal,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Trash2,
  User,
  UserCheck,
  UserPlus,
  Users,
  UserX,
} from "lucide-react";

interface AdminConsoleCardProps {
  users: any[];
  totalUsers: number;
  currentUserId: string;
  search: string;
  onSearchChange: (query: string) => void;
  onRefresh: () => void;
  isLoading: boolean;
  onCreateUser: (user: {
    name: string;
    email: string;
    password: string;
    role: "user" | "admin";
  }) => Promise<void>;
  onToggleRole: (userId: string, currentRole?: string) => Promise<void>;
  onToggleBan: (userId: string, currentlyBanned?: boolean) => Promise<void>;
  onImpersonate: (userId: string) => Promise<void>;
  onDeleteUser: (userId: string) => Promise<void>;
}

export function AdminConsoleCard({
  users,
  totalUsers,
  currentUserId,
  search,
  onSearchChange,
  onRefresh,
  isLoading,
  onCreateUser,
  onToggleRole,
  onToggleBan,
  onImpersonate,
  onDeleteUser,
}: AdminConsoleCardProps) {
  // Dialog state for new user
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [newUserName, setNewUserName] = useState("");
  const [newUserEmail, setNewUserEmail] = useState("");
  const [newUserPassword, setNewUserPassword] = useState("");
  const [newUserRole, setNewUserRole] = useState<"user" | "admin">("user");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUserEmail.trim() || !newUserPassword) return;
    setIsSubmitting(true);
    try {
      await onCreateUser({
        name: newUserName.trim() || newUserEmail.split("@")[0],
        email: newUserEmail.trim(),
        password: newUserPassword,
        role: newUserRole,
      });
      setNewUserName("");
      setNewUserEmail("");
      setNewUserPassword("");
      setNewUserRole("user");
      setIsDialogOpen(false);
    } finally {
      setIsSubmitting(false);
    }
  };

  const getInitials = (name?: string, email?: string) => {
    if (name) {
      const parts = name.trim().split(" ");
      if (parts.length >= 2) return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
      return name.slice(0, 2).toUpperCase();
    }
    if (email) return email.slice(0, 2).toUpperCase();
    return "U";
  };

  const adminCount = users.filter((u) => u.role === "admin").length;
  const bannedCount = users.filter((u) => Boolean(u.banned)).length;
  const verifiedCount = users.filter((u) => Boolean(u.emailVerified)).length;

  return (
    <div className="space-y-4">
      {/* Stats Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-card border border-border/60 p-3">
          <div className="flex items-center justify-between text-muted-foreground mb-1">
            <span className="text-xs">Total Accounts</span>
            <Users className="size-3.5 text-primary" />
          </div>
          <span className="text-xl font-bold tracking-tight">{totalUsers}</span>
        </div>

        <div className="bg-card border border-border/60 p-3">
          <div className="flex items-center justify-between text-muted-foreground mb-1">
            <span className="text-xs">Administrators</span>
            <Shield className="size-3.5 text-primary" />
          </div>
          <span className="text-xl font-bold tracking-tight">{adminCount}</span>
        </div>

        <div className="bg-card border border-border/60 p-3">
          <div className="flex items-center justify-between text-muted-foreground mb-1">
            <span className="text-xs">Verified Emails</span>
            <CheckCircle2 className="size-3.5 text-emerald-500" />
          </div>
          <span className="text-xl font-bold tracking-tight">{verifiedCount}</span>
        </div>

        <div className="bg-card border border-border/60 p-3">
          <div className="flex items-center justify-between text-muted-foreground mb-1">
            <span className="text-xs">Suspended / Banned</span>
            <AlertCircle className="size-3.5 text-destructive" />
          </div>
          <span className="text-xl font-bold tracking-tight">{bannedCount}</span>
        </div>
      </div>

      {/* Main Directory Card */}
      <Card>
        <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Shield className="size-4 text-primary" />
              <CardTitle className="text-sm font-semibold">User Directory</CardTitle>
            </div>
            <CardDescription className="text-xs">
              Manage permissions, provision accounts, and impersonate sessions
            </CardDescription>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search Input */}
            <div className="relative w-48 sm:w-60">
              <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground pointer-events-none" />
              <Input
                placeholder="Search by email..."
                value={search}
                onChange={(e) => onSearchChange(e.target.value)}
                className="pl-8 text-xs h-8"
              />
            </div>

            {/* Refresh Button */}
            <Button
              variant="outline"
              size="sm"
              onClick={onRefresh}
              disabled={isLoading}
              className="gap-1.5 h-8 text-xs"
              title="Refresh users directory"
            >
              <RefreshCw className={`size-3 ${isLoading ? "animate-spin" : ""}`} />
              Refresh
            </Button>

            {/* Create User Dialog Trigger */}
            <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
              <DialogTrigger render={
                <Button size="sm" className="gap-1.5 h-8 text-xs">
                  <UserPlus className="size-3.5" />
                  New User
                </Button>
              } />
              <DialogContent className="sm:max-w-md">
                <form onSubmit={handleCreateSubmit}>
                  <DialogHeader className="space-y-1.5 pb-2">
                    <div className="flex items-center gap-2">
                      <div className="size-7 bg-primary text-primary-foreground flex items-center justify-center">
                        <UserPlus className="size-3.5" />
                      </div>
                      <div>
                        <DialogTitle className="text-sm font-semibold">Create New User</DialogTitle>
                        <DialogDescription className="text-xs">
                          Provision an account directly via Admin API
                        </DialogDescription>
                      </div>
                    </div>
                  </DialogHeader>

                  <div className="space-y-3 py-3">
                    <div className="space-y-1">
                      <Label htmlFor="admin-create-name" className="text-xs font-medium">
                        Full Name
                      </Label>
                      <div className="relative">
                        <User className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground pointer-events-none" />
                        <Input
                          id="admin-create-name"
                          placeholder="e.g. Marie Curie"
                          value={newUserName}
                          onChange={(e) => setNewUserName(e.target.value)}
                          className="pl-8 text-xs h-8"
                        />
                      </div>
                    </div>

                    <div className="space-y-1">
                      <Label htmlFor="admin-create-email" className="text-xs font-medium">
                        Email Address
                      </Label>
                      <div className="relative">
                        <Mail className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground pointer-events-none" />
                        <Input
                          id="admin-create-email"
                          type="email"
                          placeholder="marie@example.com"
                          value={newUserEmail}
                          onChange={(e) => setNewUserEmail(e.target.value)}
                          required
                          className="pl-8 text-xs h-8"
                        />
                      </div>
                    </div>

                    <div className="space-y-1">
                      <Label htmlFor="admin-create-password" className="text-xs font-medium">
                        Initial Password
                      </Label>
                      <div className="relative">
                        <Lock className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground pointer-events-none" />
                        <Input
                          id="admin-create-password"
                          type="password"
                          placeholder="••••••••"
                          value={newUserPassword}
                          onChange={(e) => setNewUserPassword(e.target.value)}
                          required
                          className="pl-8 text-xs h-8"
                        />
                      </div>
                    </div>

                    <div className="space-y-1">
                      <Label className="text-xs font-medium">Account Role</Label>
                      <Select
                        value={newUserRole}
                        onValueChange={(val) => {
                          if (val) setNewUserRole(val);
                        }}
                      >
                        <SelectTrigger className="w-full text-xs h-8">
                          <SelectValue placeholder="Select role" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="user">User (Standard)</SelectItem>
                          <SelectItem value="admin">Admin (Full privileges)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <DialogFooter className="pt-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => setIsDialogOpen(false)}
                      disabled={isSubmitting}
                      className="text-xs h-8"
                    >
                      Cancel
                    </Button>
                    <Button
                      type="submit"
                      size="sm"
                      disabled={isSubmitting}
                      className="text-xs h-8 gap-1.5"
                    >
                      {isSubmitting ? (
                        <>
                          <RefreshCw className="size-3 animate-spin" />
                          Creating...
                        </>
                      ) : (
                        <>
                          <UserPlus className="size-3" />
                          Create User
                        </>
                      )}
                    </Button>
                  </DialogFooter>
                </form>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>

        <CardContent>
          {users.length === 0 ? (
            <div className="py-8 text-center text-xs text-muted-foreground">
              {isLoading ? "Loading users directory..." : "No users matched your query."}
            </div>
          ) : (
            <div className="border border-border/60 overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/40 text-xs">
                    <TableHead>User</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="hidden md:table-cell">User ID</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((u) => {
                    const isSelf = u.id === currentUserId;
                    const uRole = u.role || "user";
                    const uBanned = Boolean(u.banned);

                    return (
                      <TableRow key={u.id} className="text-xs">
                        {/* User Identity */}
                        <TableCell>
                          <div className="flex items-center gap-2.5">
                            <Avatar size="sm">
                              <AvatarFallback className="bg-muted text-[10px] font-medium">
                                {getInitials(u.name, u.email)}
                              </AvatarFallback>
                            </Avatar>
                            <div className="space-y-0.5">
                              <div className="flex items-center gap-1.5">
                                <span className="font-medium text-foreground">{u.name}</span>
                                {isSelf && (
                                  <Badge variant="outline" className="text-[9px] px-1 py-0 h-3.5">
                                    You
                                  </Badge>
                                )}
                              </div>
                              <span className="text-[11px] text-muted-foreground block truncate">
                                {u.email}
                              </span>
                            </div>
                          </div>
                        </TableCell>

                        {/* Role */}
                        <TableCell>
                          <Badge
                            variant={uRole === "admin" ? "default" : "secondary"}
                            className="text-[10px] gap-1 px-1.5 py-0 h-4 font-mono"
                          >
                            {uRole === "admin" ? <Shield className="size-2.5" /> : <User className="size-2.5" />}
                            {uRole}
                          </Badge>
                        </TableCell>

                        {/* Status */}
                        <TableCell>
                          <div className="flex items-center gap-1.5 flex-wrap">
                            {uBanned ? (
                              <Badge variant="destructive" className="text-[10px] gap-1 px-1.5 py-0 h-4">
                                <UserX className="size-2.5" />
                                Banned
                              </Badge>
                            ) : (
                              <Badge variant="outline" className="text-[10px] gap-1 border-emerald-500/30 text-emerald-600 dark:text-emerald-400 px-1.5 py-0 h-4">
                                <CheckCircle2 className="size-2.5" />
                                Active
                              </Badge>
                            )}

                            {u.emailVerified && (
                              <Badge variant="secondary" className="text-[10px] px-1 py-0 h-4 hidden sm:inline-flex">
                                Verified
                              </Badge>
                            )}
                          </div>
                        </TableCell>

                        {/* User ID */}
                        <TableCell className="hidden md:table-cell font-mono text-[11px] text-muted-foreground">
                          <div className="flex items-center gap-1">
                            <span>{u.id.slice(0, 10)}...</span>
                            <CopyButton text={u.id} title="Copy User ID" />
                          </div>
                        </TableCell>

                        {/* Actions */}
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            {/* Impersonate quick button (only if not self and not banned) */}
                            {!isSelf && !uBanned && (
                              <Button
                                variant="secondary"
                                size="xs"
                                onClick={() => onImpersonate(u.id)}
                                className="h-6 px-2 text-[11px] gap-1 hidden sm:inline-flex"
                                title={`Impersonate ${u.name}`}
                              >
                                <KeyRound className="size-2.5" />
                                Impersonate
                              </Button>
                            )}

                            {/* Dropdown Menu for secondary or all actions */}
                            <DropdownMenu>
                              <DropdownMenuTrigger render={
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  className="size-7"
                                  title="Actions menu"
                                >
                                  <MoreHorizontal className="size-3.5" />
                                </Button>
                              } />
                              <DropdownMenuContent align="end" className="w-44">
                                <DropdownMenuLabel>User Actions</DropdownMenuLabel>
                                <DropdownMenuSeparator />

                                <DropdownMenuItem onClick={() => onToggleRole(u.id, uRole)}>
                                  <Shield className="size-3.5 mr-2" />
                                  {uRole === "admin" ? "Demote to User" : "Promote to Admin"}
                                </DropdownMenuItem>

                                {!isSelf && (
                                  <>
                                    {!uBanned && (
                                      <DropdownMenuItem onClick={() => onImpersonate(u.id)}>
                                        <KeyRound className="size-3.5 mr-2" />
                                        Impersonate User
                                      </DropdownMenuItem>
                                    )}

                                    <DropdownMenuItem onClick={() => onToggleBan(u.id, uBanned)}>
                                      {uBanned ? (
                                        <>
                                          <UserCheck className="size-3.5 mr-2 text-emerald-500" />
                                          Unban Account
                                        </>
                                      ) : (
                                        <>
                                          <UserX className="size-3.5 mr-2 text-amber-500" />
                                          Suspend / Ban
                                        </>
                                      )}
                                    </DropdownMenuItem>

                                    <DropdownMenuSeparator />

                                    <DropdownMenuItem
                                      variant="destructive"
                                      onClick={() => onDeleteUser(u.id)}
                                    >
                                      <Trash2 className="size-3.5 mr-2" />
                                      Delete User
                                    </DropdownMenuItem>
                                  </>
                                )}
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </div>
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
    </div>
  );
}
