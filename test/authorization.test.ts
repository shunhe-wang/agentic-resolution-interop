import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { exportJWK, FlattenedSign, generateKeyPair } from "jose";
import type { AuthorizationTrustKey, GeneralJws } from "../src/authorization.js";
import { type ResolutionAuthorizationClaims, verifyBilateralAuthorization } from "../src/authorization.js";
import {
  FIXED_VERIFICATION_TIME,
  catalogSha256,
  clauseId,
  providerId,
  rulesSha256,
  serviceId,
  termsSha256,
} from "../src/scenario.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = <T>(name: string): T => JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures/core", name), "utf8")) as T;
const expected = {
  transactionId: "tx-neutral-001",
  orderId: "order-neutral-001",
  disputedLineItemIds: ["line-002"],
  termsAtrHash: `0x${termsSha256}`,
  clauseId,
  rulesSha256,
  catalogSha256,
  providerId,
  serviceId,
};

async function signAuthorization(
  claims: ResolutionAuthorizationClaims,
  principals: readonly [string, string],
): Promise<{ jws: GeneralJws; trustedKeys: AuthorizationTrustKey[] }> {
  const payloadBytes = Buffer.from(JSON.stringify(claims), "utf8");
  const jws: GeneralJws = { payload: payloadBytes.toString("base64url"), signatures: [] };
  const trustedKeys: AuthorizationTrustKey[] = [];
  for (const [index, role] of (["claimant", "respondent"] as const).entries()) {
    const kid = `generated-${role}-key`;
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const signature = await new FlattenedSign(payloadBytes).setProtectedHeader({ alg: "EdDSA", kid }).sign(privateKey);
    jws.signatures.push({ protected: signature.protected!, signature: signature.signature });
    trustedKeys.push({ ...(await exportJWK(publicKey)), kid, principalId: principals[index]!, role });
  }
  return { jws, trustedKeys };
}

function authorizationClaims(): ResolutionAuthorizationClaims {
  return {
    schemaVersion: "resolution-authorization-v1",
    authorizationId: "authorization-generated-001",
    transaction: {
      transactionId: expected.transactionId,
      orderId: expected.orderId,
      disputedLineItemIds: [...expected.disputedLineItemIds],
    },
    parties: [],
    appointment: {
      administrator: "Synthetic Neutral Administrator",
      tribunal: "Synthetic Neutral Tribunal",
      caseMode: "evaluation",
      procedureProfile: "evaluation",
    },
    legalContext: {
      termsAtrHash: expected.termsAtrHash,
      clauseId: expected.clauseId,
      rulesSha256: expected.rulesSha256,
      catalogSha256: expected.catalogSha256,
      providerId: expected.providerId,
      serviceId: expected.serviceId,
    },
    claimScope: { claimType: "non_delivery", requestedRemedy: "refund" },
    remedyCeiling: { action: "refund", currency: "USD", amountMinorUnits: "5000" },
    issuedAt: "2026-08-24T15:00:00.000Z",
    expiresAt: "2027-08-24T15:00:00.000Z",
  };
}

test("bilateral authorization verifies two distinct principal signatures and exact bindings", async () => {
  const result = await verifyBilateralAuthorization({
    jws: read<GeneralJws>("valid/resolution-authorization-v1.json"),
    trustedKeys: read<AuthorizationTrustKey[]>("valid/resolution-authorization-public-keys.json"),
    expected,
    now: new Date(FIXED_VERIFICATION_TIME),
  });
  assert.deepEqual(result.signerKids, ["claimant-key-1", "respondent-key-1"]);
  assert.equal(result.claims.appointment.tribunal, "Synthetic Neutral Tribunal");
});

test("one signature is not bilateral authority", async () => {
  const jws = read<GeneralJws>("negative/resolution-authorization-one-signature.json");
  await assert.rejects(
    verifyBilateralAuthorization({
      jws,
      trustedKeys: read<AuthorizationTrustKey[]>("valid/resolution-authorization-public-keys.json"),
      expected,
      now: new Date(FIXED_VERIFICATION_TIME),
    }),
    /Exactly two signatures/,
  );
});

test("one principal cannot satisfy both bilateral roles with separate keys", async () => {
  const claims = authorizationClaims();
  claims.parties = [
    { principalId: "principal:same:001", role: "claimant", authorityRef: "authority:claimant:001" },
    { principalId: "principal:same:001", role: "respondent", authorityRef: "authority:respondent:001" },
  ];
  const signed = await signAuthorization(claims, ["principal:same:001", "principal:same:001"]);

  await assert.rejects(
    verifyBilateralAuthorization({ ...signed, expected, now: new Date(FIXED_VERIFICATION_TIME) }),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "authorization_bilateral_missing",
  );
});

test("malformed authorization timestamps fail closed", async () => {
  const claims = authorizationClaims();
  claims.parties = [
    { principalId: "principal:claimant:001", role: "claimant", authorityRef: "authority:claimant:001" },
    { principalId: "principal:respondent:001", role: "respondent", authorityRef: "authority:respondent:001" },
  ];
  claims.issuedAt = "not-a-date";
  claims.expiresAt = "also-not-a-date";
  const signed = await signAuthorization(claims, ["principal:claimant:001", "principal:respondent:001"]);

  await assert.rejects(
    verifyBilateralAuthorization({ ...signed, expected, now: new Date(FIXED_VERIFICATION_TIME) }),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "authorization_time_invalid",
  );
});

test("authorization line bindings cannot collapse embedded delimiters", async () => {
  const claims = authorizationClaims();
  claims.parties = [
    { principalId: "principal:claimant:001", role: "claimant", authorityRef: "authority:claimant:001" },
    { principalId: "principal:respondent:001", role: "respondent", authorityRef: "authority:respondent:001" },
  ];
  claims.transaction.disputedLineItemIds = ["line-002\nline-extra"];
  const signed = await signAuthorization(claims, ["principal:claimant:001", "principal:respondent:001"]);

  await assert.rejects(
    verifyBilateralAuthorization({
      ...signed,
      expected: { ...expected, disputedLineItemIds: ["line-002", "line-extra"] },
      now: new Date(FIXED_VERIFICATION_TIME),
    }),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "authorization_binding_mismatch",
  );
});
