import { useState } from "react";
import { Button } from "./ui/button";
import { Check, Copy } from "lucide-react";

interface CopyButtonProps {
  text: string;
  className?: string;
  title?: string;
}

export function CopyButton({ text, className, title = "Copy to clipboard" }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button
      variant="ghost"
      size="icon-xs"
      onClick={handleCopy}
      className={className}
      title={title}
      aria-label={title}
      type="button"
    >
      {copied ? (
        <Check className="size-3 text-emerald-500 animate-in fade-in zoom-in-75 duration-150" />
      ) : (
        <Copy className="size-3 text-muted-foreground hover:text-foreground transition-colors" />
      )}
    </Button>
  );
}
