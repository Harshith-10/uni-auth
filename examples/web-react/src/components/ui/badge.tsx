import * as React from "react";
import { cn } from "../../lib/utils";

export type BadgeVariant = "default" | "secondary" | "destructive" | "outline";

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: BadgeVariant;
}

const badgeVariantClasses: Record<BadgeVariant, string> = {
  default:
    "border-transparent bg-primary text-primary-foreground shadow hover:bg-primary/90",
  secondary:
    "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
  destructive:
    "border-transparent bg-destructive text-destructive-foreground shadow hover:bg-destructive/90",
  outline: "text-foreground border",
};

export function badgeVariants({
  variant = "default",
  className,
}: {
  variant?: BadgeVariant;
  className?: string;
} = {}) {
  return cn(
    "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors",
    badgeVariantClasses[variant],
    className
  );
}

export function Badge({
  className,
  variant = "default",
  ...props
}: BadgeProps) {
  return (
    <div className={badgeVariants({ variant, className })} {...props} />
  );
}
