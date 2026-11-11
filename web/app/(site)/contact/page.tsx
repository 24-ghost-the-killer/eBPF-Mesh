// SPDX-License-Identifier: MIT OR Apache-2.0
import type { Metadata } from "next";
import Link from "next/link";
import { CONTACT_EMAIL } from "@/lib/site";

export const metadata: Metadata = {
  title: "Contact",
  description: "Talk to us about plans, onboarding or an attack in progress.",
};

export default function Contact() {
  return (
    <>
      <h1 className="text-4xl font-bold tracking-tight">Contact</h1>
      <div className="mt-6 grid max-w-2xl gap-6 text-lg">
        {CONTACT_EMAIL ? (
          <p>
            Write to{" "}
            <a className="text-primary underline" href={`mailto:${CONTACT_EMAIL}`}>
              {CONTACT_EMAIL}
            </a>{" "}
            for plans, onboarding help or questions about the platform.
          </p>
        ) : (
          <p>Contact details are not configured for this installation.</p>
        )}
        <p className="text-base text-muted-fg">
          Under attack right now? You can protect a server yourself in a few minutes:{" "}
          <Link className="text-primary underline" href="/signup">
            create an account
          </Link>
          , add your server and run the tunnel script.
        </p>
      </div>
    </>
  );
}
