import { Alert, AlertDescription, AlertTitle } from "./ui/alert";
import { Button } from "./ui/button";
import { ShieldAlert, LogOut } from "lucide-react";

interface ImpersonationBannerProps {
  userName: string;
  userEmail: string;
  impersonatedBy: string;
  onStopImpersonating: () => void;
}

export function ImpersonationBanner({
  userName,
  userEmail,
  impersonatedBy,
  onStopImpersonating,
}: ImpersonationBannerProps) {
  return (
    <Alert className="border-amber-500/50 bg-amber-500/10 text-amber-950 dark:text-amber-200">
      <ShieldAlert className="size-4 text-amber-600 dark:text-amber-400" />
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 w-full">
        <div>
          <AlertTitle className="text-xs font-semibold tracking-tight text-amber-900 dark:text-amber-200">
            Active Impersonation: {userName} ({userEmail})
          </AlertTitle>
          <AlertDescription className="text-xs text-amber-800/80 dark:text-amber-300/80">
            You are operating under this user&apos;s identity. Initiating Admin ID: <code className="font-mono text-[11px] bg-amber-500/20 px-1 py-0.5">{impersonatedBy}</code>
          </AlertDescription>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={onStopImpersonating}
          className="shrink-0 border-amber-600/40 text-amber-900 dark:text-amber-100 hover:bg-amber-500/20 gap-1.5 h-7 text-xs"
        >
          <LogOut className="size-3" />
          Exit Impersonation
        </Button>
      </div>
    </Alert>
  );
}
