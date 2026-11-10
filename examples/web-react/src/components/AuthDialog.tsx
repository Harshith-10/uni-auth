import { Dialog, DialogContent } from "./ui/dialog";
import { AuthCard } from "./AuthCard";

interface AuthDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  authTab: string;
  setAuthTab: (tab: string) => void;
  email: string;
  setEmail: (email: string) => void;
  password: string;
  setPassword: (password: string) => void;
  name: string;
  setName: (name: string) => void;
  message: { type: "default" | "destructive"; text: string } | null;
  isLoading?: boolean;
  onSignIn: (e: React.FormEvent) => void;
  onSignUp: (e: React.FormEvent) => void;
  onSocialSignIn: (provider: "google" | "github") => void;
  onFillDemo: (email: string, password: string) => void;
}

export function AuthDialog({
  open,
  onOpenChange,
  ...authProps
}: AuthDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md p-6">
        <AuthCard {...authProps} isInDialog={true} />
      </DialogContent>
    </Dialog>
  );
}
