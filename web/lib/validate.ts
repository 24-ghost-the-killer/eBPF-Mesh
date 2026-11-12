// SPDX-License-Identifier: MIT OR Apache-2.0
// Client-side checks for instant feedback. The API validates everything
// again; these only mirror its rules.

export function isIPv4(s: string): boolean {
  const parts = s.split(".");
  return (
    parts.length === 4 &&
    parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255)
  );
}

export function isIPv6(s: string): boolean {
  if (!/^[0-9a-fA-F:]+$/.test(s) || !s.includes(":")) return false;
  const dbl = s.split("::");
  if (dbl.length > 2) return false;
  const groups = s.split(":").filter((g) => g !== "");
  if (groups.some((g) => g.length > 4)) return false;
  return dbl.length === 2 ? groups.length < 8 : groups.length === 8;
}

/** A source address or prefix for an allow/block rule. */
export function checkRulePrefix(s: string, minV4 = 16, minV6 = 32): string | null {
  const [addr, len, extra] = s.trim().split("/");
  if (extra !== undefined || !addr) return "Enter an address or prefix, e.g. 203.0.113.7 or 203.0.113.0/24.";
  const v4 = isIPv4(addr);
  if (!v4 && !isIPv6(addr)) return "Not an IP address.";
  const max = v4 ? 32 : 128;
  const l = len === undefined ? max : Number(len);
  if (!Number.isInteger(l) || l < 0 || l > max || (len !== undefined && !/^\d+$/.test(len)))
    return "Invalid prefix length.";
  const min = v4 ? minV4 : minV6;
  if (l < min) return `Prefixes wider than /${min} are not allowed.`;
  return null;
}

export type Service = { proto: string; port?: number | null };


/** "tcp/80, tcp/443, udp/27015, icmp" -> services; throws a message. */
export function parseServices(s: string): Service[] {
  const out: Service[] = [];
  for (const raw of s.split(/[\s,]+/).filter(Boolean)) {
    const [proto, port, extra] = raw.toLowerCase().split("/");
    if (extra !== undefined) throw new Error(`"${raw}": use proto/port, e.g. tcp/443`);
    if (proto === "icmp" || proto === "icmpv6") {
      if (port !== undefined) throw new Error(`"${raw}": ${proto} has no ports`);
      out.push({ proto });
      continue;
    }
    if (proto !== "tcp" && proto !== "udp") throw new Error(`"${raw}": protocol must be tcp, udp or icmp`);
    if (port === undefined) {
      out.push({ proto }); // every port
      continue;
    }
    const n = Number(port);
    if (!/^\d+$/.test(port) || n < 1 || n > 65535) throw new Error(`"${raw}": port must be 1-65535`);
    out.push({ proto, port: n });
  }
  return out;
}

export function formatServices(s: Service[]): string {
  return s.map((x) => (x.port ? `${x.proto}/${x.port}` : x.proto)).join(", ");
}
