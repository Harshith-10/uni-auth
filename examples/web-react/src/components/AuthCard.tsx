import { useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "./ui/alert";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "./ui/card";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Separator } from "./ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import {
  AlertCircle,
  CheckCircle2,
  Eye,
  EyeOff,
  Lock,
  LogIn,
  Mail,
  ShieldCheck,
  Sparkles,
  User,
  UserPlus,
} from "lucide-react";

interface AuthCardProps {
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
  isInDialog?: boolean;
}

export function AuthCard({
  authTab,
  setAuthTab,
  email,
  setEmail,
  password,
  setPassword,
  name,
  setName,
  message,
  isLoading = false,
  onSignIn,
  onSignUp,
  onSocialSignIn,
  onFillDemo,
  isInDialog = false,
}: AuthCardProps) {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <Card className={isInDialog ? "border-0 shadow-none ring-0 p-0" : "w-full max-w-md mx-auto shadow-sm"}>
      <CardHeader className="space-y-1.5 pb-4">
        <div className="flex items-center gap-2">
          <div className="flex items-center justify-center size-7 bg-primary text-primary-foreground shadow-xs">
            <ShieldCheck className="size-4" />
          </div>
          <div>
            <CardTitle className="text-base font-semibold">Authentication</CardTitle>
            <CardDescription className="text-xs">
              Sign in with a demo account or register new credentials
            </CardDescription>
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {message && (
          <Alert variant={message.type} className="animate-in fade-in duration-200">
            {message.type === "destructive" ? (
              <AlertCircle className="size-4" />
            ) : (
              <CheckCircle2 className="size-4" />
            )}
            <AlertTitle className="text-xs font-semibold">
              {message.type === "destructive" ? "Notice" : "Status"}
            </AlertTitle>
            <AlertDescription className="text-xs">{message.text}</AlertDescription>
          </Alert>
        )}

        <Tabs value={authTab} onValueChange={setAuthTab} className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="signin" className="gap-1.5 text-xs">
              <LogIn className="size-3.5" />
              Sign In
            </TabsTrigger>
            <TabsTrigger value="signup" className="gap-1.5 text-xs">
              <UserPlus className="size-3.5" />
              Sign Up
            </TabsTrigger>
          </TabsList>

          {/* SIGN IN TAB */}
          <TabsContent value="signin" className="space-y-4 mt-4">
            <form onSubmit={onSignIn} className="space-y-3.5">
              <div className="space-y-1.5">
                <Label htmlFor="signin-email" className="text-xs font-medium">
                  Email Address
                </Label>
                <div className="relative">
                  <Mail className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground pointer-events-none" />
                  <Input
                    id="signin-email"
                    type="email"
                    placeholder="admin@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className="pl-8 text-xs h-8"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <Label htmlFor="signin-password" className="text-xs font-medium">
                    Password
                  </Label>
                </div>
                <div className="relative">
                  <Lock className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground pointer-events-none" />
                  <Input
                    id="signin-password"
                    type={showPassword ? "text" : "password"}
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="pl-8 pr-8 text-xs h-8"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-xs"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-1 top-1 text-muted-foreground hover:text-foreground"
                    title={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                  </Button>
                </div>
              </div>

              <Button type="submit" className="w-full h-8 text-xs" disabled={isLoading}>
                {isLoading ? (
                  <span className="flex items-center gap-1.5">
                    <span className="size-3 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
                    Authenticating...
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5">
                    <LogIn className="size-3.5" />
                    Sign In
                  </span>
                )}
              </Button>
            </form>
          </TabsContent>

          {/* SIGN UP TAB */}
          <TabsContent value="signup" className="space-y-4 mt-4">
            <form onSubmit={onSignUp} className="space-y-3.5">
              <div className="space-y-1.5">
                <Label htmlFor="signup-name" className="text-xs font-medium">
                  Full Name
                </Label>
                <div className="relative">
                  <User className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground pointer-events-none" />
                  <Input
                    id="signup-name"
                    type="text"
                    placeholder="Ada Lovelace"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                    className="pl-8 text-xs h-8"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="signup-email" className="text-xs font-medium">
                  Email Address
                </Label>
                <div className="relative">
                  <Mail className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground pointer-events-none" />
                  <Input
                    id="signup-email"
                    type="email"
                    placeholder="ada@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className="pl-8 text-xs h-8"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="signup-password" className="text-xs font-medium">
                  Password
                </Label>
                <div className="relative">
                  <Lock className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground pointer-events-none" />
                  <Input
                    id="signup-password"
                    type={showPassword ? "text" : "password"}
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="pl-8 pr-8 text-xs h-8"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-xs"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-1 top-1 text-muted-foreground hover:text-foreground"
                    title={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                  </Button>
                </div>
              </div>

              <Button type="submit" className="w-full h-8 text-xs" disabled={isLoading}>
                {isLoading ? (
                  <span className="flex items-center gap-1.5">
                    <span className="size-3 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
                    Registering...
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5">
                    <UserPlus className="size-3.5" />
                    Create Account
                  </span>
                )}
              </Button>
            </form>
          </TabsContent>
        </Tabs>

        <Separator />

        {/* SEEDED DEMO ACCOUNTS */}
        <div className="space-y-2.5 rounded-none border border-border/70 bg-muted/30 p-3">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-xs font-medium text-foreground">
              <Sparkles className="size-3 text-primary" />
              Seeded Demo Accounts
            </span>
            <span className="text-[10px] text-muted-foreground">Click to fill</span>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onFillDemo("admin@example.com", "admin12345")}
              className="h-auto flex-col items-start p-2 gap-1 text-left"
            >
              <div className="flex items-center justify-between w-full">
                <span className="font-medium text-xs">Admin</span>
                <Badge variant="default" className="text-[9px] px-1 py-0 h-4">
                  admin
                </Badge>
              </div>
              <span className="text-[10px] text-muted-foreground truncate w-full">
                admin@example.com
              </span>
            </Button>

            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onFillDemo("alice@example.com", "password123")}
              className="h-auto flex-col items-start p-2 gap-1 text-left"
            >
              <div className="flex items-center justify-between w-full">
                <span className="font-medium text-xs">Alice</span>
                <Badge variant="secondary" className="text-[9px] px-1 py-0 h-4">
                  user
                </Badge>
              </div>
              <span className="text-[10px] text-muted-foreground truncate w-full">
                alice@example.com
              </span>
            </Button>

            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onFillDemo("bob@example.com", "password123")}
              className="h-auto flex-col items-start p-2 gap-1 text-left"
            >
              <div className="flex items-center justify-between w-full">
                <span className="font-medium text-xs">Bob</span>
                <Badge variant="outline" className="text-[9px] px-1 py-0 h-4">
                  unverified
                </Badge>
              </div>
              <span className="text-[10px] text-muted-foreground truncate w-full">
                bob@example.com
              </span>
            </Button>

            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onFillDemo("banned@example.com", "password123")}
              className="h-auto flex-col items-start p-2 gap-1 text-left"
            >
              <div className="flex items-center justify-between w-full">
                <span className="font-medium text-xs">Banned</span>
                <Badge variant="destructive" className="text-[9px] px-1 py-0 h-4">
                  banned
                </Badge>
              </div>
              <span className="text-[10px] text-muted-foreground truncate w-full">
                banned@example.com
              </span>
            </Button>
          </div>
        </div>

        <Separator />

        {/* SOCIAL SIGN IN */}
        <div className="space-y-2">
          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t border-border/70" />
            </div>
            <div className="relative flex justify-center text-[10px] uppercase">
              <span className="bg-card px-2 text-muted-foreground">Or continue with</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onSocialSignIn("google")}
              className="gap-2 text-xs h-8"
            >
              <svg className="size-3.5" viewBox="0 0 24 24">
                <path
                  fill="currentColor"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="currentColor"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="currentColor"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="currentColor"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
              Google
            </Button>

            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onSocialSignIn("github")}
              className="gap-2 text-xs h-8"
            >
              <svg className="size-3.5" fill="currentColor" viewBox="0 0 24 24">
                <path
                  fillRule="evenodd"
                  clipRule="evenodd"
                  d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                />
              </svg>
              GitHub
            </Button>
          </div>
        </div>
      </CardContent>

      <CardFooter className="py-3 flex justify-center text-[10px] text-muted-foreground">
        <span>Powered by uni-auth</span>
      </CardFooter>
    </Card>
  );
}
