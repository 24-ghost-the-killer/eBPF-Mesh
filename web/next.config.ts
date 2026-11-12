// SPDX-License-Identifier: MIT OR Apache-2.0
import path from "node:path";
import type { NextConfig } from "next";

// Security headers that do not depend on the request. The CSP (with a
// per-request nonce) and HSTS are set in proxy.ts.
const config: NextConfig = {
  poweredByHeader: false,
  // Container images (deploy/docker/Dockerfile.portal) use the standalone server.
  ...(process.env.NEXT_OUTPUT === "standalone"
    ? { output: "standalone" as const, outputFileTracingRoot: path.join(process.cwd(), "..") }
    : {}),
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
        ],
      },
    ];
  },
};

export default config;
