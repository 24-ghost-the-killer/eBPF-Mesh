// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { Monitor, Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "./ui/button";

type Theme = "system" | "light" | "dark";
const ORDER: Theme[] = ["system", "light", "dark"];

/** Inline script (with the CSP nonce) that applies the stored theme before paint. */
export const THEME_SCRIPT = `try{var t=localStorage.getItem("theme");if(t==="light"||t==="dark")document.documentElement.classList.add(t)}catch(e){}`;

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>("system");
  useEffect(() => {
    try {
      const t = localStorage.getItem("theme");
      if (t === "light" || t === "dark") setTheme(t);
    } catch {}
  }, []);
  const next = ORDER[(ORDER.indexOf(theme) + 1) % ORDER.length]!;
  const apply = () => {
    const el = document.documentElement;
    el.classList.remove("light", "dark");
    if (next !== "system") el.classList.add(next);
    try {
      if (next === "system") localStorage.removeItem("theme");
      else localStorage.setItem("theme", next);
    } catch {}
    setTheme(next);
  };
  const Icon = theme === "dark" ? Moon : theme === "light" ? Sun : Monitor;
  return (
    <Button variant="ghost" size="icon" onClick={apply} aria-label={`Theme: ${theme}. Switch to ${next}.`} title={`Theme: ${theme}`}>
      <Icon />
    </Button>
  );
}
