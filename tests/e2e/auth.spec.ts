// SPDX-License-Identifier: MIT OR Apache-2.0
// Login errors, TOTP as the second factor, security headers.
import { expect, test } from "@playwright/test";
import { logIn, PASSWORD, signUp, totpCode, uniqueEmail } from "./helpers";

test("login errors and unverified accounts", async ({ page }) => {
  const email = uniqueEmail("auth");
  await logIn(page, email);
  await expect(page.getByRole("main").getByRole("alert")).toHaveText("wrong email or password");

  await page.goto("/signup");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("short");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("main").getByRole("alert")).toHaveText("Use at least 12 characters for your password.");
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await logIn(page, email);
  await expect(page.getByRole("main").getByRole("alert")).toContainText("Verify your email address first");

  // Portal pages need a session.
  await page.context().clearCookies();
  await page.goto("/t/1/assets");
  await expect(page).toHaveURL(/\/login\?next=%2Ft%2F1%2Fassets$/);
});

test("TOTP: enable, then required at login", async ({ page }) => {
  const email = uniqueEmail("totp");
  await signUp(page, email);
  await logIn(page, email);
  await expect(page).toHaveURL(/\/t\/\d+$/);
  await page.getByRole("navigation", { name: "Portal" }).getByRole("link", { name: "Settings" }).click();
  await page.getByRole("button", { name: "Set up an authenticator app" }).click();
  await expect(page.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  const secret = (await page.getByTestId("totp-secret").textContent())!.trim();
  await page.getByLabel("Code from the app").fill("000000");
  await page.getByRole("button", { name: "Turn on" }).click();
  await expect(page.getByRole("main").getByRole("alert")).toContainText("wrong or expired code");
  await page.getByLabel("Code from the app").fill(totpCode(secret));
  await page.getByRole("button", { name: "Turn on" }).click();
  await expect(page.getByText("Authenticator app enabled.")).toBeVisible();

  await page.getByRole("button", { name: "Log out" }).first().click();
  await logIn(page, email);
  await expect(page).toHaveURL(/\/login\/2fa/);
  // A wrong code is rejected; the code used to enable 2FA cannot be replayed,
  // so wait for the next 30-second step (few attempts: failures are rate limited).
  await page.getByLabel("Authenticator code").fill("123456");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("main").getByRole("alert")).toContainText("wrong or already used code");
  await page.waitForTimeout(30_000 - (Date.now() % 30_000) + 1500);
  await page.getByLabel("Authenticator code").fill(totpCode(secret));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page).toHaveURL(/\/t\/\d+$/);
});

test("security headers", async ({ page }) => {
  const resp = await page.goto("/login");
  const h = resp!.headers();
  expect(h["content-security-policy"]).toMatch(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
  expect(h["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(h["x-frame-options"]).toBe("DENY");
  expect(h["x-content-type-options"]).toBe("nosniff");
  expect(h["referrer-policy"]).toBe("strict-origin-when-cross-origin");
  const api = await page.request.get("/api/v1/status");
  expect(api.headers()["cache-control"]).toBe("no-store");
});
