// SPDX-License-Identifier: MIT OR Apache-2.0
import { describe, expect, it } from "vitest";
import { safeNext } from "@/components/session";
import { duration, expiresIn, hostOf, si, vectorName } from "@/lib/format";
import { liveUrl, pushFrame, WINDOW } from "@/lib/live";
import { checkRulePrefix, formatServices, isIPv4, isIPv6, parseServices } from "@/lib/validate";
import { csp } from "@/proxy";

describe("format", () => {
  it("prints SI units", () => {
    expect(si(0, "pps")).toBe("0 pps");
    expect(si(999)).toBe("999");
    expect(si(1234, "pps")).toBe("1.23 kpps");
    expect(si(1.5e9, "bps")).toBe("1.5 Gbps");
    expect(si(12_000_000)).toBe("12 M");
    expect(si(Number.NaN)).toBe("–");
  });
  it("prints expiry", () => {
    const now = 1_000_000_000_000;
    expect(expiresIn(null, now)).toBe("never");
    expect(expiresIn(now - 1, now)).toBe("expired");
    expect(expiresIn(now + 5 * 60_000, now)).toBe("in 5 min");
    expect(expiresIn(now + 3 * 3600_000, now)).toBe("in 3 h");
    expect(expiresIn(now + 7 * 86400_000, now)).toBe("in 7 days");
  });
  it("prints durations and vectors", () => {
    expect(duration(0, 45_000)).toBe("45 s");
    expect(duration(0, 192_000)).toBe("3 min 12 s");
    expect(duration(0, 3_900_000)).toBe("1 h 5 min");
    expect(duration(10, 0)).toBe("0 s");
    expect(vectorName("udp_flood")).toBe("UDP flood");
    expect(vectorName("new_kind")).toBe("new_kind");
  });
  it("strips host prefix lengths", () => {
    expect(hostOf("198.51.100.2/32")).toBe("198.51.100.2");
    expect(hostOf("198.51.100.0/24")).toBe("198.51.100.0/24");
  });
});

describe("validation mirrors the API", () => {
  it("addresses", () => {
    expect(isIPv4("192.0.2.10")).toBe(true);
    for (const bad of ["192.0.2", "192.0.2.256", "01.2.3.4", "a.b.c.d", "1.2.3.4.5"]) expect(isIPv4(bad)).toBe(false);
    expect(isIPv6("2001:db8::1")).toBe(true);
    expect(isIPv6("2001:db8::1::2")).toBe(false);
  });
  it("rule prefixes: no world, nothing wider than the limit", () => {
    expect(checkRulePrefix("203.0.113.7")).toBeNull();
    expect(checkRulePrefix("203.0.113.0/24")).toBeNull();
    expect(checkRulePrefix("2001:db8::/48")).toBeNull();
    expect(checkRulePrefix("0.0.0.0/0")).toMatch(/wider/);
    expect(checkRulePrefix("::/0")).toMatch(/wider/);
    expect(checkRulePrefix("10.0.0.0/8")).toMatch(/wider/);
    expect(checkRulePrefix("203.0.113.0/33")).toMatch(/length/);
    expect(checkRulePrefix("203.0.113.0/2a")).toMatch(/length/);
    expect(checkRulePrefix("nope")).toMatch(/Not an IP/);
  });
  it("services", () => {
    expect(parseServices("tcp/80, tcp/443 udp/27015,icmp")).toEqual([
      { proto: "tcp", port: 80 },
      { proto: "tcp", port: 443 },
      { proto: "udp", port: 27015 },
      { proto: "icmp" },
    ]);
    expect(parseServices("")).toEqual([]);
    expect(parseServices("udp")).toEqual([{ proto: "udp" }]);
    expect(() => parseServices("tcp/0")).toThrow(/1-65535/);
    expect(() => parseServices("tcp/70000")).toThrow(/1-65535/);
    expect(() => parseServices("icmp/1")).toThrow(/no ports/);
    expect(() => parseServices("sctp/1")).toThrow(/protocol/);
    expect(formatServices([{ proto: "tcp", port: 443 }, { proto: "icmp" }])).toBe("tcp/443, icmp");
  });
});

describe("live view", () => {
  const frame = (ts: number, inPps: number) => ({
    ts,
    total: {
      in_pps: inPps,
      in_bps: inPps * 8000,
      filtered_pps: 1,
      filtered_bps: 8000,
      clean_pps: inPps - 1,
      clean_bps: (inPps - 1) * 8000,
      return_pps: 0,
      return_bps: 0,
    },
    pops: [],
    verdicts: [],
    attacks: [],
  });
  it("keeps a rolling window", () => {
    let s = pushFrame([], frame(1000, 5), "pps");
    expect(s).toEqual([{ t: 1000, in: 5, filtered: 1, clean: 4 }]);
    s = pushFrame(s, frame(1000, 7), "pps"); // same timestamp replaces
    expect(s).toHaveLength(1);
    for (let i = 1; i <= WINDOW + 10; i++) s = pushFrame(s, frame(1000 + i * 1000, i), "bps");
    expect(s).toHaveLength(WINDOW);
    expect(s[s.length - 1]!.in).toBe((WINDOW + 10) * 8000);
  });
  it("uses the page's origin", () => {
    expect(liveUrl(7, { protocol: "https:", host: "portal.example.org" })).toBe("wss://portal.example.org/api/v1/tenants/7/live");
    expect(liveUrl(7, { protocol: "http:", host: "localhost:3000" })).toBe("ws://localhost:3000/api/v1/tenants/7/live");
  });
});

describe("security", () => {
  it("never redirects off-site after login", () => {
    expect(safeNext("/t/3/rules")).toBe("/t/3/rules");
    for (const bad of ["//evil.test", "https://evil.test", "/\\evil.test", "", null, "javascript:alert(1)"])
      expect(safeNext(bad)).toBe("/t");
  });
  it("CSP: nonce scripts only, no framing", () => {
    const p = csp("abc", { dev: false, https: true });
    const script = p.split("; ").find((d) => d.startsWith("script-src"))!;
    expect(script).toContain("'nonce-abc'");
    expect(script).not.toContain("unsafe-inline");
    expect(script).not.toContain("unsafe-eval");
    expect(p).toContain("frame-ancestors 'none'");
    expect(p).toContain("object-src 'none'");
    expect(p).toContain("upgrade-insecure-requests");
    expect(csp("abc", { dev: false, https: false })).not.toContain("upgrade-insecure-requests");
  });
});

describe("traffic history", () => {
  it("pivots per-PoP series into chart rows", async () => {
    const { pivot } = await import("@/components/traffic-history");
    const rows = pivot([
      { pop: "pop-1", points: [{ ts: 60_000, in_pps: 5 }, { ts: 0, in_pps: 1 }] },
      { pop: "pop-2", points: [{ ts: 0, in_pps: 2 }] },
    ]);
    expect(rows).toEqual([
      { ts: 0, "pop-1": 1, "pop-2": 2 },
      { ts: 60_000, "pop-1": 5 },
    ]);
  });
});
