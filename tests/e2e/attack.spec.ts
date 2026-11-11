// SPDX-License-Identifier: MIT OR Apache-2.0
// Phase 7 "done when": an attack is detected, mitigated and shown in the
// portal with no manual action. After the customer's normal setup, nothing
// is clicked: the worker detects the UDP flood from the PoP's telemetry,
// signs decisions, the agent blocks the bots in XDP, the API records the
// attack, the portal shows it and the customer's webhook is called.
import { createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { lab, labOk, logIn, signUp, tenantOf, uniqueEmail, virtualAuthenticator } from "./helpers";

const ORIGIN = process.env.LAB_ORIGIN ?? "192.0.2.10";
const SINK = "http://127.0.0.1:9999/hook";

type Delivery = { headers: Record<string, string>; body: string };

function deliveries(): Delivery[] {
  return lab("webhooks")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Delivery);
}

function events(secret: string, tenant: number): { event: string; attack?: { vector: string; id: number } }[] {
  return deliveries()
    .map((d) => {
      const ts = d.headers["x-sentinel-timestamp"];
      const want = "sha256=" + createHmac("sha256", secret).update(`${ts}.${d.body}`).digest("hex");
      return { d, ok: d.headers["x-sentinel-signature"] === want };
    })
    .filter((x) => x.ok)
    .map((x) => JSON.parse(x.d.body))
    .filter((e) => e.tenant === tenant);
}

const nav = (page: Page, name: string) => page.getByRole("navigation", { name: "Portal" }).getByRole("link", { name });

test("an attack is detected, mitigated and shown with no manual action", async ({ page }) => {
  test.setTimeout(240_000);
  // ---- the customer's normal setup -------------------------------------------------------
  const email = uniqueEmail("attack");
  await signUp(page, email);
  await logIn(page, email);
  await expect(page).toHaveURL(/\/t\/\d+$/);
  const tid = tenantOf(page);
  await virtualAuthenticator(page);
  await nav(page, "Settings").click();
  await page.getByRole("button", { name: "Add a passkey" }).click();
  await expect(page.getByText(/Passkey ".*" added\./)).toBeVisible();

  await page.getByLabel("Webhook URL").fill(SINK);
  await page.getByRole("button", { name: "Add", exact: true }).click();
  const secret = (await page.getByTestId("webhook-secret").textContent())!.trim();
  expect(secret).toMatch(/^whsec_/);
  await page.getByRole("button", { name: `Send a test to ${SINK}` }).click();
  await expect(page.getByText(/test ok: HTTP 200/)).toBeVisible();

  await page.goto(`/t/${tid}/assets/new`);
  await page.getByLabel("Server IP (origin)").fill(ORIGIN);
  await page.getByLabel("Ports that must stay open").fill("tcp/80, udp/27015");
  await page.getByRole("button", { name: "Get a protected IP" }).click();
  await expect(page.getByTestId("pop-status")).toHaveText("Active on 1 of 1 PoP", { timeout: 20_000 });
  const ip = (await page.getByRole("heading", { level: 1 }).textContent())!.trim();
  if (process.env.TUNNEL_DEV) await page.getByLabel("Existing tunnel device (optional)").fill(process.env.TUNNEL_DEV);
  await expect(page.getByTestId("code-block")).toContainText(process.env.TUNNEL_DEV || ip);
  const file = join(tmpdir(), `sentinel-attack-${Date.now()}.sh`);
  writeFileSync(file, (await page.getByTestId("code-block").textContent())!);
  lab("origin-up", file, ip);
  expect(labOk("http-ok", ip)).toBe(true);
  await nav(page, "Rules").click();
  await page.getByRole("radio", { name: /Mitigate/ }).check();
  await page.getByRole("button", { name: "Save protection settings" }).click();
  await expect(page.getByText("Saved. The PoPs apply it within seconds.")).toBeVisible();
  await page.waitForTimeout(3000); // the PoP applies mitigate mode
  await nav(page, "Overview").click();
  await expect(page.getByTestId("active-attack")).toHaveCount(0);

  // ---- the attack: from here on nobody touches anything --------------------------------------
  const drops0 = Number(lab("drops"));
  lab("flood", ip, "27015", "30");

  // Detected and shown live on the overview.
  const alert = page.getByTestId("active-attack");
  await expect(alert).toContainText("UDP flood in progress", { timeout: 30_000 });

  // Mitigated: the bots are blocked at the PoP, the server stops receiving
  // the flood, normal visitors still get through.
  await expect.poll(() => Number(lab("drops")) - drops0, { timeout: 20_000 }).toBeGreaterThan(1000);
  await page.waitForTimeout(2000);
  const rx1 = Number(lab("udp-rx"));
  await page.waitForTimeout(3000);
  const rx2 = Number(lab("udp-rx"));
  expect(rx2 - rx1, "flood packets still reaching the server in 3 s (4000 pps sent)").toBeLessThan(600);
  expect(labOk("http-ok", ip)).toBe(true);
  await expect(alert).toContainText(/(?:[1-9]\d?|100)% dropped at the PoPs/, { timeout: 15_000 });

  // Shown on the attacks pages, with the blocked bots.
  await alert.getByRole("link", { name: "Details" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(`UDP flood on ${ip}`);
  await expect(page.getByTestId("attack-active")).toBeVisible();
  const blocked = page.getByTestId("blocked-sources");
  await expect(blocked).toContainText("203.0.113.6", { timeout: 15_000 });
  await expect(blocked).toContainText("worker-1");

  // The customer's webhook got a signed "attack.started".
  await expect.poll(() => events(secret, tid).map((e) => e.event), { timeout: 15_000 }).toContain("attack.started");
  expect(events(secret, tid).find((e) => e.event === "attack.started")?.attack?.vector).toBe("udp_flood");

  // The flood stops; the attack ends on its own and the webhook hears it.
  await nav(page, "Attacks").click();
  const row = page.getByRole("row", { name: /UDP flood/ });
  await expect(row).toBeVisible();
  await expect(row.getByText("Ended")).toBeVisible({ timeout: 80_000 });
  await expect.poll(() => events(secret, tid).map((e) => e.event), { timeout: 15_000 }).toContain("attack.ended");
  await nav(page, "Overview").click();
  await expect(page.getByTestId("active-attack")).toHaveCount(0);
  expect(labOk("http-ok", ip)).toBe(true);
});
