// SPDX-License-Identifier: MIT OR Apache-2.0
import { errorMessage } from "./api/client";

/** Friendlier messages for the browser's WebAuthn errors. */
export function passkeyError(e: unknown): string {
  const name = e instanceof Error ? e.name : "";
  if (name === "NotAllowedError" || name === "AbortError") return "The passkey prompt was cancelled or timed out.";
  if (name === "InvalidStateError") return "This passkey is already registered.";
  if (name === "NotSupportedError") return "This browser or device does not support passkeys.";
  if (name === "SecurityError") return "Passkeys need the portal's own address (HTTPS or localhost).";
  return errorMessage(e);
}
