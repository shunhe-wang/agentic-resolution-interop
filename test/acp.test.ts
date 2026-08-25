import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  ACP_ORDER_SCHEMA_URL,
  ACP_UPSTREAM_REVISION,
  validateAcpExternalResolutionFixture,
  type AcpExternalResolutionFixture,
} from "../src/acp.js";
import { sha256Canonical } from "../src/canonical.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = <T>(relative: string): T =>
  JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures", relative), "utf8")) as T;
const VALIDATION_TIME = new Date("2026-08-24T16:00:00.000Z");

test("ACP vector carries a pending dispute through external disposition and separate execution", () => {
  const fixture = read<AcpExternalResolutionFixture>("acp/valid/contested-external-resolution.json");
  const adjustment = fixture.source.order.adjustments?.find(
    (candidate) => candidate.id === fixture.mapping.contestedAdjustmentId,
  );
  const operative = fixture.lifecycle.dispositions.find(
    (disposition) => disposition.dispositionId === fixture.lifecycle.operativeDispositionId,
  );
  const execution = fixture.lifecycle.executions[0];

  assert.equal(fixture.source.upstreamRevision, ACP_UPSTREAM_REVISION);
  assert.equal(fixture.source.orderSchema, ACP_ORDER_SCHEMA_URL);
  assert.equal(fixture.source.verification.authenticity, "not_claimed");
  assert.equal(fixture.source.verification.canonicalization, "RFC8785");
  assert.equal(fixture.source.verification.digestAlgorithm, "SHA-256");
  assert.equal(fixture.source.verification.orderSha256, sha256Canonical(fixture.source.order));
  assert.equal(fixture.mapping.extensionPlacement, "not_asserted");
  assert.equal("external_resolution" in fixture.source.order, false);
  assert.equal("capabilities" in fixture.source.order, false);
  assert.equal(adjustment?.type, "dispute");
  assert.equal(adjustment?.status, "pending");
  assert.equal(fixture.lifecycle.handoff.nativeProtocol, "agentic_checkout_acp");
  assert.notEqual(
    fixture.lifecycle.handoff.roles.resolver,
    fixture.lifecycle.handoff.roles.recordIssuer,
  );
  assert.equal(operative?.reviewState, "final");
  assert.equal(execution?.status, "completed");
  assert.notEqual(operative?.signedArtifact.artifactRef, execution?.receiptProof?.artifactRef);
  assert.deepEqual(validateAcpExternalResolutionFixture(fixture, { now: VALIDATION_TIME }), []);
  assert.deepEqual(fixture.expected, { valid: true, reasonCodes: [] });
});

test("ACP dispute adjustment alone does not establish bilateral resolution authority", () => {
  const fixture = read<AcpExternalResolutionFixture>(
    "acp/negative/dispute-adjustment-without-bilateral-authority.json",
  );
  assert.equal(fixture.source.order.adjustments?.[0]?.type, "dispute");
  assert.equal(fixture.source.order.adjustments?.[0]?.status, "pending");
  assert.deepEqual(
    validateAcpExternalResolutionFixture(fixture, { now: VALIDATION_TIME }),
    fixture.expected.reasonCodes,
  );
  assert.deepEqual(fixture.expected.reasonCodes, [
    "acp_lifecycle_invalid",
    "acp_resolution_authority_missing",
  ]);
});

test("ACP disposition artifact cannot double as execution evidence", () => {
  const fixture = read<AcpExternalResolutionFixture>(
    "acp/negative/disposition-as-execution.json",
  );
  const operative = fixture.lifecycle.dispositions.find(
    (disposition) => disposition.dispositionId === fixture.lifecycle.operativeDispositionId,
  );
  assert.equal(
    fixture.lifecycle.executions[0]?.receiptProof?.artifactRef,
    operative?.signedArtifact.artifactRef,
  );
  assert.deepEqual(
    validateAcpExternalResolutionFixture(fixture, { now: VALIDATION_TIME }),
    fixture.expected.reasonCodes,
  );
  assert.deepEqual(fixture.expected.reasonCodes, [
    "acp_execution_not_separate",
    "acp_lifecycle_invalid",
  ]);
});
