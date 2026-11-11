// SPDX-License-Identifier: MIT OR Apache-2.0

/** 1234 -> "1.23 k", 1.5e9 -> "1.5 G" (SI, 3 significant digits). */
export function si(n: number, unit = ""): string {
  if (!Number.isFinite(n)) return "–";
  const abs = Math.abs(n);
  const steps: [number, string][] = [
    [1e12, "T"],
    [1e9, "G"],
    [1e6, "M"],
    [1e3, "k"],
  ];
  for (const [v, p] of steps) {
    if (abs >= v) return `${trim(n / v)} ${p}${unit}`;
  }
  return `${trim(n)}${unit ? " " + unit : ""}`;
}

function trim(n: number): string {
  const s = Math.abs(n) >= 100 ? n.toFixed(0) : Math.abs(n) >= 10 ? n.toFixed(1) : n.toFixed(2);
  return s.replace(/\.0+$/, "").replace(/(\.\d*[1-9])0+$/, "$1");
}

export const pps = (n: number) => si(n, "pps");
export const bps = (n: number) => si(n, "bps");

export function dateTime(ms: number | null | undefined): string {
  if (ms == null) return "–";
  return new Date(ms).toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

/** "in 2 h", "in 5 min", "expired". */
export function expiresIn(ms: number | null | undefined, now = Date.now()): string {
  if (ms == null) return "never";
  const s = Math.round((ms - now) / 1000);
  if (s <= 0) return "expired";
  if (s < 3600) return `in ${Math.max(1, Math.round(s / 60))} min`;
  if (s < 86400 * 2) return `in ${Math.round(s / 3600)} h`;
  return `in ${Math.round(s / 86400)} days`;
}

/** Protected IP without the /32. */
export function hostOf(prefix: string): string {
  return prefix.replace(/\/(32|128)$/, "");
}

/** "3 min 12 s", "1 h 5 min", "45 s". */
export function duration(fromMs: number, toMs: number): string {
  const s = Math.max(0, Math.round((toMs - fromMs) / 1000));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`;
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
}

const VECTORS: Record<string, string> = {
  syn_flood: "SYN flood",
  udp_flood: "UDP flood",
  icmp_flood: "ICMP flood",
  ack_flood: "ACK flood",
  volumetric: "Volumetric",
};

export function vectorName(v: string): string {
  return VECTORS[v] ?? v;
}
