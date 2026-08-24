import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import type { AuthorizationTrustKey, GeneralJws } from "../src/authorization.js";
import { verifyBilateralAuthorization } from "../src/authorization.js";
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
const read = <T>(name: string): T => JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures/core/valid", name), "utf8")) as T;
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

test("bilateral authorization verifies two distinct principal signatures and exact bindings", async () => {
  const result = await verifyBilateralAuthorization({
    jws: read<GeneralJws>("resolution-authorization-v1.json"),
    trustedKeys: read<AuthorizationTrustKey[]>("resolution-authorization-public-keys.json"),
    expected,
    now: new Date(FIXED_VERIFICATION_TIME),
  });
  assert.deepEqual(result.signerKids, ["claimant-key-1", "respondent-key-1"]);
  assert.equal(result.claims.appointment.tribunal, "Synthetic Neutral Tribunal");
});

test("one signature is not bilateral authority", async () => {
  const jws = read<GeneralJws>("resolution-authorization-v1.json");
  jws.signatures.pop();
  await assert.rejects(
    verifyBilateralAuthorization({
      jws,
      trustedKeys: read<AuthorizationTrustKey[]>("resolution-authorization-public-keys.json"),
      expected,
      now: new Date(FIXED_VERIFICATION_TIME),
    }),
    /Exactly two signatures/,
  );
});
