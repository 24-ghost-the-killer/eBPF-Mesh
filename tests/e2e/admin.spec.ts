// SPDX-License-Identifier: MIT OR Apache-2.0
// Admin panel (phase 8): PoP health and drain, tenants, operator decisions,
// signing keys; refused to everyone else.
import { expect, test } from "@playwright/test";
import { audit, lab, logIn, signUp, uniqueEmail, virtualAuthenticator } from "./helpers";

test("platform admins drain PoPs, block sources and see trusted issuers", async ({ page, browser }) => {
  page.on("dialog", (d) => void d.accept());
  const email = uniqueEmail("ops");
  await signUp(page, email, "Operators");
  await logIn(page, email);
  await expect(page).toHaveURL(/\/t\/\d+$/);
  await virtualAuthenticator(page);
  await page.getByRole("navigation", { name: "Portal" }).getByRole("link", { name: "Settings" }).click();
  await page.getByRole("button", { name: "Add a passkey" }).click();
  await expect(page.getByText(/Passkey ".*" added\./)).toBeVisible();
  lab("promote", email);
  await page.reload();
  await page.getByRole("link", { name: "Platform admin" }).click();
  await expect(page.getByRole("heading", { name: "PoPs" })).toBeVisible();

  // PoP health and drain.
  const row = page.getByTestId("pop-lab1");
  await expect(row.getByText("up", { exact: true })).toBeVisible();
  await audit(page, "/admin");
  await row.getByRole("button", { name: "Drain lab1" }).click();
  await expect(page.getByText(/Draining lab1/)).toBeVisible();
  await expect(row.getByText("draining", { exact: true })).toBeVisible();
  await row.getByRole("button", { name: "Undrain lab1" }).click();
  await expect(row.getByText("up", { exact: true })).toBeVisible({ timeout: 10_000 });

  // Tenants.
  await page.getByRole("navigation", { name: "Admin" }).getByRole("link", { name: "Tenants" }).click();
  await expect(page.getByRole("cell", { name: "Operators", exact: true })).toBeVisible();
  await audit(page, "/admin/tenants");

  // An operator decision: signed by the API, verified and recorded.
  await page.getByRole("navigation", { name: "Admin" }).getByRole("link", { name: "Decisions" }).click();
  await page.getByLabel("Source address or prefix").fill("203.0.113.200");
  await page.getByRole("button", { name: "Block", exact: true }).click();
  await expect(page.getByText(/Block 203\.0\.113\.200\/32 signed and sent to every PoP/)).toBeVisible();
  await expect(page.getByRole("cell", { name: "203.0.113.200/32" })).toBeVisible({ timeout: 20_000 });
  await audit(page, "/admin/decisions");

  // Trusted issuers: the lab worker and the API itself.
  await page.getByRole("navigation", { name: "Admin" }).getByRole("link", { name: "Signing keys" }).click();
  await expect(page.getByRole("cell", { name: "worker-1", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "api", exact: true })).toBeVisible();
  await audit(page, "/admin/keys");

  // Anyone else: not found in the portal, 403 from the API.
  const other = await browser.newPage();
  const email2 = uniqueEmail("not-ops");
  await signUp(other, email2);
  await logIn(other, email2);
  await expect(other).toHaveURL(/\/t\/\d+$/);
  await other.goto("/admin");
  await expect(other.getByRole("heading", { name: "Page not found" })).toBeVisible();
  await expect(other.getByRole("link", { name: "Platform admin" })).toHaveCount(0);
  expect((await other.request.get("/api/v1/admin/pops")).status()).toBe(403);
});
