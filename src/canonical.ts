import crypto from "node:crypto";
import canonicalize from "canonicalize";

export function canonicalJson(value: unknown): string {
  const result = canonicalize(value);
  if (typeof result !== "string") {
    throw new TypeError("Value cannot be represented by RFC 8785 JSON Canonicalization Scheme.");
  }
  return result;
}

export function sha256Bytes(value: Uint8Array | string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function sha256Canonical(value: unknown): string {
  return sha256Bytes(canonicalJson(value));
}
