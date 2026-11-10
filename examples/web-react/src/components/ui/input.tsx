import * as React from "react";
import { cn } from "../../lib/utils";

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>;

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, ...props }, ref) => {
    return (
      <input
        type={type}
        ref={ref}
        className={cn(
          "flex h-9 w-full rounded-md border bg-transparent px-3 py-1 text-sm text-foreground shadow-sm transition-colors focus-visible:outline-none",
          className
        )}
        {...props}
      />
    );
  }
);
Input.displayName = "Input";
