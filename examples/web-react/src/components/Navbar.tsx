import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu";
import { Avatar, AvatarFallback } from "./ui/avatar";
import {
  ShieldCheck,
  ShieldAlert,
  Shield,
  User,
  LogOut,
  Sun,
  Moon,
  Laptop,
  Activity,
  KeyRound,
  ExternalLink,
} from "lucide-react";

interface NavbarProps {
  session: any;
  isAdmin: boolean;
  userRole: string;
  impersonatedBy?: string | null;
  theme: "dark" | "light";
  onToggleTheme: () => void;
  onSignOut: () => void;
  onStopImpersonating: () => void;
  onOpenAuthModal: () => void;
  onSelectTab: (tab: string) => void;
}

export function Navbar({
  session,
  isAdmin,
  userRole,
  impersonatedBy,
  theme,
  onToggleTheme,
  onSignOut,
  onStopImpersonating,
  onOpenAuthModal,
  onSelectTab,
}: NavbarProps) {
  const user = session?.user;

  // Generate user initials for avatar
  const getInitials = (name?: string, email?: string) => {
    if (name) {
      const parts = name.trim().split(" ");
      if (parts.length >= 2) {
        return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
      }
      return name.slice(0, 2).toUpperCase();
    }
    if (email) {
      return email.slice(0, 2).toUpperCase();
    }
    return "UA";
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b bg-background/95 backdrop-blur-md supports-backdrop-filter:bg-background/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between gap-4">
        {/* Brand / Logo */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center size-8 bg-primary text-primary-foreground shadow-xs">
            <ShieldCheck className="size-4" />
          </div>
          <div className="flex items-center gap-2">
            <span className="font-heading font-semibold text-sm tracking-tight">
              Uni-Auth
            </span>
            <Badge variant="outline" className="hidden sm:inline-flex text-[10px] font-mono px-1.5 py-0">
              Axum + Better-Auth
            </Badge>
          </div>
        </div>

        {/* Center / Status */}
        <div className="hidden md:flex items-center gap-2 text-xs text-muted-foreground border border-border/60 px-2.5 py-1">
          <span className="relative flex size-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full size-2 bg-emerald-500"></span>
          </span>
          <span className="font-mono text-[11px]">Backend: localhost:3000</span>
        </div>

        {/* Right Actions */}
        <div className="flex items-center gap-2">
          {/* Theme toggle */}
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={onToggleTheme}
            title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            aria-label="Toggle theme"
          >
            {theme === "dark" ? (
              <Sun className="size-4 text-muted-foreground hover:text-foreground transition-colors" />
            ) : (
              <Moon className="size-4 text-muted-foreground hover:text-foreground transition-colors" />
            )}
          </Button>

          {user ? (
            <div className="flex items-center gap-2">
              {impersonatedBy && (
                <div className="hidden sm:flex items-center gap-1.5 bg-amber-500/10 text-amber-900 dark:text-amber-200 border border-amber-500/30 px-2 py-0.5 text-xs">
                  <ShieldAlert className="size-3 text-amber-600 dark:text-amber-400" />
                  <span className="text-[11px] font-medium">Impersonating</span>
                  <Button
                    variant="ghost"
                    size="xs"
                    onClick={onStopImpersonating}
                    className="h-5 px-1.5 text-[10px] text-amber-700 dark:text-amber-300 hover:bg-amber-500/20"
                  >
                    Exit
                  </Button>
                </div>
              )}

              <Badge variant={isAdmin ? "default" : "secondary"} className="hidden sm:inline-flex gap-1 text-[11px]">
                {isAdmin ? <Shield className="size-3" /> : <User className="size-3" />}
                {userRole}
              </Badge>

              {/* User Dropdown */}
              <DropdownMenu>
                <DropdownMenuTrigger render={
                  <Button variant="ghost" className="relative p-0 size-8 overflow-hidden">
                    <Avatar size="sm">
                      <AvatarFallback className="bg-primary/10 text-primary font-medium text-xs">
                        {getInitials(user.name, user.email)}
                      </AvatarFallback>
                    </Avatar>
                  </Button>
                } />
                <DropdownMenuContent align="end" className="w-56">
                  <DropdownMenuLabel>
                    <div className="flex flex-col space-y-1">
                      <p className="text-xs font-medium leading-none text-foreground">{user.name}</p>
                      <p className="text-[11px] leading-none text-muted-foreground truncate">{user.email}</p>
                    </div>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuGroup>
                    <DropdownMenuItem onClick={() => onSelectTab("overview")}>
                      <Activity className="size-3.5 mr-2" />
                      Overview & Security
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => onSelectTab("sessions")}>
                      <Laptop className="size-3.5 mr-2" />
                      Active Sessions
                    </DropdownMenuItem>
                    {isAdmin && (
                      <DropdownMenuItem onClick={() => onSelectTab("admin")}>
                        <Shield className="size-3.5 mr-2" />
                        Admin Console
                      </DropdownMenuItem>
                    )}
                    <DropdownMenuItem onClick={() => onSelectTab("diagnostics")}>
                      <KeyRound className="size-3.5 mr-2" />
                      API Diagnostics
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                  <DropdownMenuSeparator />
                  {impersonatedBy && (
                    <>
                      <DropdownMenuItem onClick={onStopImpersonating} className="text-amber-600 dark:text-amber-400">
                        <ShieldAlert className="size-3.5 mr-2" />
                        Stop Impersonating
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                    </>
                  )}
                  <DropdownMenuItem variant="destructive" onClick={onSignOut}>
                    <LogOut className="size-3.5 mr-2" />
                    Sign Out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <Button size="sm" onClick={onOpenAuthModal} className="gap-1.5">
                <User className="size-3.5" />
                Sign In
              </Button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
