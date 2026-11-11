// SPDX-License-Identifier: MIT OR Apache-2.0
import Link from "next/link";

export default function NotFound() {
  return (
    <main id="main" className="mx-auto max-w-md p-10 text-center">
      <h1 className="text-xl font-semibold">Page not found</h1>
      <p className="mt-2 text-sm text-muted-fg">It may have moved, or you may not have access to it.</p>
      <Link href="/t" className="mt-4 inline-block text-sm text-primary underline">
        Go to the portal
      </Link>
    </main>
  );
}
