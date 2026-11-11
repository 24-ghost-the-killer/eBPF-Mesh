// SPDX-License-Identifier: MIT OR Apache-2.0
// Phase 9 "done when": all public pages render, pass accessibility checks
// and link to signup; the separately hosted status page works, also when the
// platform cannot be reached.
import { expect, test } from "@playwright/test";
import { audit } from "./helpers";

const PAGES = [
  ["/", /DDoS protection that keeps your servers where they are/],
  ["/how-it-works", /How it works/],
  ["/pricing", /Pricing/],
  ["/status", /Status/],
  ["/contact", /Contact/],
] as const;

for (const scheme of ["light", "dark"] as const) {
  test(`public pages render, are accessible and link to signup (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    const errors: string[] = [];
    page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
    for (const [path, h1] of PAGES) {
      const resp = await page.goto(path);
      expect(resp!.status(), path).toBe(200);
      await expect(page.getByRole("heading", { level: 1 })).toHaveText(h1);
      await expect(page).toHaveTitle(/Sentinel-Edge/);
      const signup = page.locator('a[href="/signup"]');
      expect(await signup.count(), `${path} links to signup`).toBeGreaterThan(0);
      await audit(page, `${path} (${scheme})`);
    }
    expect(errors).toEqual([]);
  });
}

test("public pages work on a phone and lead to signup", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 });
  for (const [path] of PAGES) {
    await page.goto(path);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow, `${path} scrolls sideways on a phone`).toBeLessThanOrEqual(0);
  }
  await page.goto("/");
  await expect(page.getByRole("figure").getByText("lab1", { exact: true })).toBeVisible();
  await expect(page.getByText("1 of 1 PoPs up")).toBeVisible();
  await page.getByRole("link", { name: "Get started" }).first().click();
  await expect(page).toHaveURL(/\/signup$/);
  await expect(page.getByRole("heading", { name: "Create an account" })).toBeVisible();
  await page.goto("/status");
  await expect(page.getByTestId("status-summary")).toHaveText("All PoPs operational");
  await page.goto("/how-it-works");
  await page.getByText("Do I have to move my server?").click();
  await expect(page.getByText(/You keep your server and provider/)).toBeVisible();
});

test("the separately hosted status page shows the network and survives an outage", async ({ page }) => {
  const url = process.env.STATUS_PAGE_URL ?? "http://localhost:3100";
  await page.goto(url);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("All systems operational");
  await expect(page.getByRole("cell", { name: "lab1" })).toBeVisible();
  await expect(page.getByText("Lab maintenance")).toBeVisible();
  await audit(page, "status page");

  // The platform goes away: the page says so and keeps the last known state.
  await page.route("**/api/v1/status", (r) => r.abort());
  await page.reload();
  await expect(page.getByRole("alert")).toContainText("We cannot reach the platform right now");
  await expect(page.getByText(/Last known state from/)).toBeVisible();
  await expect(page.getByRole("cell", { name: "lab1" })).toBeVisible();
  await audit(page, "status page (outage)");
});
