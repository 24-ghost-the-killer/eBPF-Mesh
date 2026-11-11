// SPDX-License-Identifier: MIT OR Apache-2.0
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, type Page } from "@playwright/test";
import * as OTPAuth from "otpauth";

export const PASSWORD = "correct horse battery staple";

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set: run these tests through tests/integration/portal_e2e.sh`);
  return v;
}

/** Runs a lab action (namespaces, traffic) through the harness's hook script. */
export function lab(...args: string[]): string {
  return execFileSync(env("LAB_HOOK"), args, { encoding: "utf8", timeout: 60_000 });
}

/** True when the lab action exits 0. */
export function labOk(...args: string[]): boolean {
  try {
    lab(...args);
    return true;
  } catch {
    return false;
  }
}

/** The link in the newest mail to `to` (the API writes mails as JSON files). */
export async function mailLink(to: string, path: "/verify-email" | "/reset-password"): Promise<string> {
  const dir = env("MAIL_DIR");
  for (let i = 0; i < 50; i++) {
    let files: string[] = [];
    try {
      files = readdirSync(dir).sort().reverse();
    } catch {}
    for (const f of files) {
      const m = JSON.parse(readFileSync(join(dir, f), "utf8")) as { to: string; body: string };
      if (m.to !== to) continue;
      const url = m.body.match(/https?:\/\/\S+/)?.[0];
      if (url && new URL(url).pathname === path) return url;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`no ${path} mail to ${to}`);
}

export function uniqueEmail(tag: string): string {
  return `${tag}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@e2e.test`;
}

/** Sign up and verify through the UI; returns nothing (log in next). */
export async function signUp(page: Page, email: string, company = "Example Ltd") {
  await page.goto("/signup");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByLabel("Company or project name").fill(company);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await page.goto(await mailLink(email, "/verify-email"));
  await expect(page.getByText("Your email address is verified.")).toBeVisible();
}

export async function logIn(page: Page, email: string) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Log in" }).click();
}

/** Tenant id from a /t/<id>/... URL. */
export function tenantOf(page: Page): number {
  const m = new URL(page.url()).pathname.match(/^\/t\/(\d+)/);
  if (!m) throw new Error(`not a tenant page: ${page.url()}`);
  return Number(m[1]);
}

/** A platform authenticator (passkey) for this page, via the DevTools protocol. */
export async function virtualAuthenticator(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, authenticatorId };
}

export function totpCode(secret: string): string {
  return new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret), digits: 6, period: 30 }).generate();
}
