// SPDX-License-Identifier: MIT OR Apache-2.0
import { redirect } from "next/navigation";

// The public website arrives in phase 9; until then the root opens the portal.
export default function Home() {
  redirect("/t");
}
