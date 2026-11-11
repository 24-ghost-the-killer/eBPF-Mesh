// SPDX-License-Identifier: MIT OR Apache-2.0
// Accessibility (spec 13.5): no WCAG 2.1 A/AA violations axe can detect on
// the auth pages and every portal page, in light and dark mode, on desktop
// and phone widths.
import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import { logIn, signUp, tenantOf, uniqueEmail } from "./helpers";

async function audit(page: Page, label: string) {
  await page.waitForLoadState("networkidle");
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const found = r.violations.map((v) => `${label}: ${v.id} (${v.impact}) ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
  expect(found, found.join("\n")).toEqual([]);
}

for (const scheme of ["light", "dark"] as const) {
  test(`portal pages are accessible (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    for (const path of ["/login", "/signup", "/forgot-password"]) {
      await page.goto(path);
      await audit(page, path);
    }
    const email = uniqueEmail(`a11y-${scheme}`);
    await signUp(page, email);
    await logIn(page, email);
    await expect(page).toHaveURL(/\/t\/\d+$/);
    const t = tenantOf(page);
    await page.goto(`/t/${t}/assets/new`);
    await page.getByLabel("Server IP (origin)").fill("192.0.2.30");
    await page.getByRole("button", { name: "Get a protected IP" }).click();
    await expect(page).toHaveURL(/\/assets\/\d+\?new=1$/);
    const asset = page.url().replace(/\?.*$/, "");
    await expect(page.getByTestId("code-block")).toBeVisible();
    await audit(page, "asset");
    for (const path of [`/t/${t}`, `/t/${t}/assets`, `/t/${t}/assets/new`, `/t/${t}/rules`, `/t/${t}/settings`]) {
      await page.goto(path);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      await audit(page, path);
    }
    // Phone width: navigation stays usable, no horizontal page scroll.
    await page.setViewportSize({ width: 375, height: 800 });
    for (const path of [asset, `/t/${t}/rules`]) {
      await page.goto(path);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect(overflow, `${path} scrolls horizontally on a phone`).toBeLessThanOrEqual(0);
      await audit(page, `${path} (phone)`);
    }
  });
}
