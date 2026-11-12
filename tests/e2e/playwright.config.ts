// SPDX-License-Identifier: MIT OR Apache-2.0
// Browser tests against the running lab (tests/integration/portal_e2e.sh
// starts PostgreSQL, NATS, the PoP agent, the API, the web app and the edge
// proxy, then runs these with PORTAL_URL, MAIL_DIR and LAB_HOOK set).
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts/,
  timeout: 180_000,
  expect: { timeout: 15_000 },
  workers: 1,
  fullyParallel: false,
  retries: 0,
  reporter: [["list"]],
  outputDir: process.env.E2E_OUT ?? "test-results",
  use: {
    baseURL: process.env.PORTAL_URL ?? "http://localhost:3000",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
