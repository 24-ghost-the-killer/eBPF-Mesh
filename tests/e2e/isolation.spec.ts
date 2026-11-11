// SPDX-License-Identifier: MIT OR Apache-2.0
// Tenant isolation (spec 14): user A can never see tenant B.
import { expect, test } from "@playwright/test";
import { logIn, signUp, tenantOf, uniqueEmail } from "./helpers";

test("a customer cannot see another customer's tenant", async ({ browser }) => {
  // Customer B with a protected IP.
  const b = await browser.newPage();
  const emailB = uniqueEmail("iso-b");
  await signUp(b, emailB, "Tenant B");
  await logIn(b, emailB);
  await expect(b).toHaveURL(/\/t\/\d+$/);
  const tb = tenantOf(b);
  await b.goto(`/t/${tb}/assets/new`);
  await b.getByLabel("Server IP (origin)").fill("192.0.2.20");
  await b.getByRole("button", { name: "Get a protected IP" }).click();
  await expect(b).toHaveURL(/\/assets\/\d+\?new=1$/);
  const assetB = Number(new URL(b.url()).pathname.split("/").pop());
  const ipB = (await b.getByRole("heading", { level: 1 }).textContent())!.trim();

  // Customer A.
  const a = await browser.newPage();
  const emailA = uniqueEmail("iso-a");
  await signUp(a, emailA, "Tenant A");
  await logIn(a, emailA);
  await expect(a).toHaveURL(/\/t\/\d+$/);
  const ta = tenantOf(a);
  expect(ta).not.toBe(tb);

  // Pages of tenant B: not found, nothing of B rendered.
  for (const path of [`/t/${tb}`, `/t/${tb}/assets`, `/t/${tb}/assets/${assetB}`, `/t/${tb}/rules`, `/t/${tb}/settings`]) {
    await a.goto(path);
    await expect(a.getByRole("heading", { name: "Page not found" })).toBeVisible();
    await expect(a.locator("body")).not.toContainText(ipB);
    await expect(a.locator("body")).not.toContainText("Tenant B");
  }
  // Tenant B's asset under A's own tenant id: not found either.
  await a.goto(`/t/${ta}/assets/${assetB}`);
  await expect(a.getByRole("main").getByRole("alert")).toContainText("no such resource");
  await expect(a.locator("body")).not.toContainText(ipB);

  // The API with A's session: 404 for every tenant-B route.
  for (const path of [
    `/api/v1/tenants/${tb}/assets`,
    `/api/v1/tenants/${tb}/assets/${assetB}`,
    `/api/v1/tenants/${tb}/assets/${assetB}/tunnel`,
    `/api/v1/tenants/${tb}/assets/${assetB}/status`,
    `/api/v1/tenants/${tb}/rules`,
    `/api/v1/tenants/${ta}/assets/${assetB}`,
  ]) {
    const r = await a.request.get(path);
    expect(r.status(), path).toBe(404);
    expect(await r.text()).not.toContain(ipB);
  }
  // The live WebSocket for tenant B is refused.
  const closed = await a.evaluate(
    (tid) =>
      new Promise<string>((resolve) => {
        const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/v1/tenants/${tid}/live`);
        ws.onmessage = () => resolve("message");
        ws.onerror = () => resolve("error");
        ws.onclose = () => resolve("closed");
      }),
    tb,
  );
  expect(closed).not.toBe("message");

  // A's own tenant works and is empty.
  await a.goto(`/t/${ta}/assets`);
  await expect(a.getByText("No protected IPs yet.")).toBeVisible();
});
