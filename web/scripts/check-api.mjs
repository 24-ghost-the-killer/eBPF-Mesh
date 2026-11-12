// SPDX-License-Identifier: MIT OR Apache-2.0
// Fails when lib/api/schema.d.ts is not what docs/openapi.json generates
// (run `pnpm gen:api` after changing the API).
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "schema-"));
try {
  const out = join(dir, "schema.d.ts");
  execFileSync("pnpm", ["exec", "openapi-typescript", "../docs/openapi.json", "-o", out], { stdio: "ignore" });
  if (readFileSync(out, "utf8") !== readFileSync("lib/api/schema.d.ts", "utf8")) {
    console.error("lib/api/schema.d.ts is out of date: run `pnpm --filter web gen:api`");
    process.exit(1);
  }
  console.log("API client types match docs/openapi.json");
} finally {
  rmSync(dir, { recursive: true, force: true });
}
