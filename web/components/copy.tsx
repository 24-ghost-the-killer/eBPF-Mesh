// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { Check, Copy, Download } from "lucide-react";
import { useState } from "react";
import { Button } from "./ui/button";

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      size="sm"
      variant="outline"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {}
      }}
    >
      {done ? <Check /> : <Copy />}
      {done ? "Copied" : label}
    </Button>
  );
}

export function DownloadButton({ text, filename }: { text: string; filename: string }) {
  return (
    <Button
      size="sm"
      variant="outline"
      onClick={() => {
        const url = URL.createObjectURL(new Blob([text], { type: "text/x-shellscript" }));
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
      }}
    >
      <Download />
      Download
    </Button>
  );
}

export function CodeBlock({ code, label }: { code: string; label: string }) {
  return (
    <pre
      aria-label={label}
      tabIndex={0}
      data-testid="code-block"
      className="max-h-96 overflow-auto rounded-md border border-border bg-muted p-4 font-mono text-xs leading-relaxed"
    >
      <code>{code}</code>
    </pre>
  );
}
