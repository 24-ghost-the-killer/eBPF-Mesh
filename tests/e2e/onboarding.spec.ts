// SPDX-License-Identifier: MIT OR Apache-2.0
// Phase 6 "done when": the whole onboarding flow (spec 13.3) works in the
// browser, against the real lab: PostgreSQL, API, NATS, a PoP with XDP, and
// a customer server in its own network namespace.
import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { lab, labOk, logIn, signUp, tenantOf, uniqueEmail, virtualAuthenticator } from "./helpers";

const ORIGIN = process.env.LAB_ORIGIN ?? "192.0.2.10";
const CLIENT = process.env.LAB_CLIENT ?? "203.0.113.1";

test("onboarding: sign up, 2FA, protect a server, tunnel, live traffic, mitigate, rules", async ({ page }) => {
  const email = uniqueEmail("onboard");
  // Script errors fail the test; so do failed API calls, except the
  // documented 503 of /traffic when ClickHouse is not configured (this harness).
  const consoleErrors: string[] = [];
  page.on("console", (m) => m.type() === "error" && !m.text().startsWith("Failed to load resource") && consoleErrors.push(m.text()));
  const failedApi: string[] = [];
  page.on("response", (r) => {
    const u = new URL(r.url());
    if (!u.pathname.startsWith("/api/") || r.status() < 500) return;
    if (r.status() === 503 && u.pathname.endsWith("/traffic")) return;
    failedApi.push(`${r.status()} ${u.pathname}`);
  });

  // 1. Sign up and verify the email address.
  await signUp(page, email);
  await logIn(page, email);
  await expect(page).toHaveURL(/\/t\/\d+$/);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  const tid = tenantOf(page);

  // Mitigate is not possible yet: 2FA first (spec 10).
  await page.getByRole("navigation", { name: "Portal" }).getByRole("link", { name: "Rules" }).click();
  await expect(page.getByText("Add a protected IP first.")).toBeVisible();

  // 2. Enable 2FA with a passkey.
  await virtualAuthenticator(page);
  await page.getByRole("navigation", { name: "Portal" }).getByRole("link", { name: "Settings" }).click();
  await expect(page.getByText("No passkeys yet.")).toBeVisible();
  await page.getByLabel("Name for the new passkey").fill("Lab key");
  await page.getByRole("button", { name: "Add a passkey" }).click();
  await expect(page.getByText('Passkey "Lab key" added.')).toBeVisible();
  await expect(page.getByRole("cell", { name: "Lab key", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: /Two-factor authentication/ }).getByText("On")).toBeVisible();

  // 3. Add a server: origin IP and the ports that must stay open.
  await page.getByRole("navigation", { name: "Portal" }).getByRole("link", { name: "Protected IPs" }).click();
  await expect(page.getByText("No protected IPs yet.")).toBeVisible();
  await page.getByRole("link", { name: "Protect a server" }).click();
  await page.getByLabel("Server IP (origin)").fill("not-an-ip");
  await page.getByRole("button", { name: "Get a protected IP" }).click();
  await expect(page.getByText("Enter your server's public IPv4 address.")).toBeVisible();
  await page.getByLabel("Server IP (origin)").fill(ORIGIN);
  await page.getByLabel("Ports that must stay open").fill("tcp/80");
  await page.getByRole("button", { name: "Get a protected IP" }).click();

  // 4. The portal allocates a protected IP and shows the tunnel script.
  await expect(page).toHaveURL(new RegExp(`/t/${tid}/assets/\\d+\\?new=1$`));
  const ip = (await page.getByRole("heading", { level: 1 }).textContent())!.trim();
  expect(ip).toMatch(/^198\.51\.100\.\d+$/);
  await expect(page.getByTestId("pop-status")).toHaveText("Active on 1 of 1 PoP", { timeout: 20_000 });
  if (process.env.TUNNEL_DEV) await page.getByLabel("Existing tunnel device (optional)").fill(process.env.TUNNEL_DEV);
  const block = page.getByTestId("code-block");
  await expect(block).toContainText(ip);
  if (process.env.TUNNEL_DEV) await expect(block).toContainText(process.env.TUNNEL_DEV);
  const script = (await block.textContent())!;
  expect(script).toContain(ORIGIN);

  // Before the script runs, the tunnel test fails.
  await page.getByRole("button", { name: "Test the tunnel" }).click();
  await expect(page.getByTestId("tunnel-failed")).toBeVisible({ timeout: 20_000 });

  // 5. The customer runs the script; the portal tests the tunnel.
  const file = join(tmpdir(), `sentinel-tunnel-${Date.now()}.sh`);
  writeFileSync(file, script);
  lab("origin-up", file, ip);
  await page.waitForTimeout(5500); // one tunnel test per asset every 5 s
  await page.getByRole("button", { name: "Test the tunnel" }).click();
  await expect(page.getByTestId("tunnel-ok")).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole("cell", { name: "3/3 replies", exact: true })).toBeVisible();

  // 6. DNS points to the protected IP: clients reach the server through the
  // PoP, and the overview shows the traffic live (observe mode).
  expect(labOk("http-ok", ip)).toBe(true);
  lab("traffic", ip, "20");
  await page.getByRole("navigation", { name: "Portal" }).getByRole("link", { name: "Overview" }).click();
  await expect(page.getByText("Live", { exact: true })).toBeVisible();
  await expect(page.getByTestId("rate-in")).not.toHaveText(/^(–|0 pps)$/, { timeout: 20_000 });
  await expect(page.getByRole("cell", { name: "lab1", exact: true })).toBeVisible();
  await expect(page.getByText("Would drop (observe)").first()).toBeVisible();
  await expect(page.getByRole("figure", { name: "Live traffic in pps" }).locator("svg").first()).toBeVisible();

  // 7. Switch to mitigate with service filtering.
  await page.getByRole("navigation", { name: "Portal" }).getByRole("link", { name: "Rules" }).click();
  await page.getByRole("radio", { name: /Mitigate/ }).check();
  await page.getByLabel("Drop traffic to all other ports and protocols").check();
  await page.getByRole("button", { name: "Save protection settings" }).click();
  await expect(page.getByText("Saved. The PoPs apply it within seconds.")).toBeVisible();
  await page.getByRole("navigation", { name: "Portal" }).getByRole("link", { name: "Protected IPs" }).click();
  await expect(page.getByRole("row", { name: new RegExp(ip.replace(/\./g, "\\.")) }).getByText("Mitigate")).toBeVisible();
  await expect(page.getByTestId("pop-status")).toHaveText("Active on 1 of 1 PoP", { timeout: 20_000 });
  expect(labOk("http-ok", ip)).toBe(true);

  // Rules page: a block rule is enforced at the PoP, and lifted again.
  await page.getByRole("navigation", { name: "Portal" }).getByRole("link", { name: "Rules" }).click();
  await page.getByLabel("Source address or prefix").fill("0.0.0.0/0");
  await page.getByRole("button", { name: "Add rule" }).click();
  await expect(page.getByText("Prefixes wider than /16 are not allowed.")).toBeVisible();
  await page.getByLabel("Source address or prefix").fill(CLIENT);
  await page.getByLabel("Note (optional)").fill("e2e");
  await page.getByRole("button", { name: "Add rule" }).click();
  const row = page.getByRole("row", { name: new RegExp(`block\\s+${CLIENT.replace(/\./g, "\\.")}/32`) });
  await expect(row).toBeVisible();
  await expect.poll(() => labOk("http-ok", ip), { timeout: 15_000 }).toBe(false);
  await row.getByRole("button", { name: /Remove block rule/ }).click();
  await expect(page.getByText("No allow or block rules.")).toBeVisible();
  await expect.poll(() => labOk("http-ok", ip), { timeout: 15_000 }).toBe(true);

  // Log out; logging in again needs the passkey.
  await page.getByRole("button", { name: "Log out" }).first().click();
  await expect(page).toHaveURL(/\/login$/);
  await logIn(page, email);
  await expect(page).toHaveURL(/\/login\/2fa/);
  await page.getByRole("button", { name: "Use a passkey" }).click();
  await expect(page).toHaveURL(new RegExp(`/t/${tid}$`));

  expect(consoleErrors.filter((e) => !/favicon/.test(e))).toEqual([]);
  expect(failedApi).toEqual([]);
});
