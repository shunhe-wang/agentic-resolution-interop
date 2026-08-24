import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair, GeneralSign } from "jose";
import { canonicalJson } from "../src/canonical.js";
import type { ResolutionAuthorizationClaims } from "../src/authorization.js";
import {
  catalogSha256,
  clauseId,
  providerId,
  rulesSha256,
  serviceId,
  termsSha256,
} from "../src/scenario.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "fixtures/core/valid");

const claims: ResolutionAuthorizationClaims = {
  schemaVersion: "resolution-authorization-v1",
  authorizationId: "authorization-neutral-001",
  transaction: {
    transactionId: "tx-neutral-001",
    orderId: "order-neutral-001",
    disputedLineItemIds: ["line-002"],
  },
  parties: [
    { principalId: "principal:buyer:001", role: "claimant", authorityRef: "authority:buyer:001" },
    { principalId: "principal:merchant:001", role: "respondent", authorityRef: "authority:merchant:001" },
  ],
  appointment: {
    administrator: "Synthetic Neutral Administrator",
    tribunal: "Synthetic Neutral Tribunal",
    caseMode: "evaluation",
    procedureProfile: "evaluation",
  },
  legalContext: {
    termsAtrHash: `0x${termsSha256}`,
    clauseId,
    rulesSha256,
    catalogSha256,
    providerId,
    serviceId,
  },
  claimScope: { claimType: "non_delivery", requestedRemedy: "refund" },
  remedyCeiling: { action: "refund", currency: "USD", amountMinorUnits: "5000" },
  issuedAt: "2026-08-24T15:00:00.000Z",
  expiresAt: "2027-08-24T15:00:00.000Z",
};

const principals = [
  { kid: "claimant-key-1", principalId: "principal:buyer:001", role: "claimant" as const },
  { kid: "respondent-key-1", principalId: "principal:merchant:001", role: "respondent" as const },
];
const sign = new GeneralSign(new TextEncoder().encode(canonicalJson(claims)));
const trustKeys = [];
for (const principal of principals) {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  trustKeys.push({ ...publicJwk, ...principal, alg: "EdDSA", use: "sig" });
  sign.addSignature(privateKey).setProtectedHeader({ alg: "EdDSA", kid: principal.kid, typ: "resolution-authorization-v1+jws" });
}
const jws = await sign.sign();
fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(OUT, "resolution-authorization-v1.json"), `${JSON.stringify(jws, null, 2)}\n`);
fs.writeFileSync(path.join(OUT, "resolution-authorization-public-keys.json"), `${JSON.stringify(trustKeys, null, 2)}\n`);
console.log("wrote signed bilateral authorization with public keys only");
