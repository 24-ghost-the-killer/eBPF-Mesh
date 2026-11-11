// SPDX-License-Identifier: MIT OR Apache-2.0
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ModeBadge, PopStatusBadge } from "@/components/pop-status";
import { ErrorState, Loading } from "@/components/states";
import { Field, Input } from "@/components/ui/input";
import { ApiError } from "@/lib/api/client";

const status = (applied: number, total: number) => ({
  config_version: 3,
  pops_applied: applied,
  pops_total: total,
  pops: [],
});

describe("PopStatusBadge", () => {
  it("says on how many PoPs the config is active", () => {
    render(<PopStatusBadge status={status(1, 1)} />);
    expect(screen.getByText("Active on 1 of 1 PoP")).toBeTruthy();
  });
  it("plural and partial", () => {
    render(<PopStatusBadge status={status(2, 3)} />);
    const b = screen.getByText("Active on 2 of 3 PoPs");
    expect(b.className).toContain("text-warn");
  });
  it("no PoPs online", () => {
    render(<PopStatusBadge status={status(0, 0)} />);
    expect(screen.getByText("No PoP online")).toBeTruthy();
  });
  it("while loading", () => {
    render(<PopStatusBadge status={undefined} />);
    expect(screen.getByText("Checking PoPs…")).toBeTruthy();
  });
});

describe("ModeBadge", () => {
  it("names the mode", () => {
    render(
      <>
        <ModeBadge mode="observe" />
        <ModeBadge mode="mitigate" />
      </>,
    );
    expect(screen.getByText("Observe")).toBeTruthy();
    expect(screen.getByText("Mitigate")).toBeTruthy();
  });
});

describe("Field", () => {
  it("labels the control and announces errors", () => {
    render(
      <Field id="origin" label="Server IP" hint="Public IPv4" error="Not an IP address.">
        <Input />
      </Field>,
    );
    const input = screen.getByLabelText("Server IP");
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(input.getAttribute("aria-describedby")).toBe("origin-hint origin-error");
    expect(screen.getByRole("alert").textContent).toBe("Not an IP address.");
  });
  it("valid field has no error", () => {
    render(
      <Field id="x" label="X">
        <Input />
      </Field>,
    );
    expect(screen.getByLabelText("X").getAttribute("aria-invalid")).toBe("false");
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("states", () => {
  it("loading is announced", () => {
    render(<Loading label="Loading assets" />);
    expect(screen.getByRole("status").textContent).toContain("Loading assets");
  });
  it("errors show the API message", () => {
    render(<ErrorState error={new ApiError(404, "not_found", "no such resource")} retry={() => {}} />);
    expect(screen.getByRole("alert").textContent).toContain("no such resource");
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });
});
