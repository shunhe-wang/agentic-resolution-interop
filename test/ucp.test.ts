import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  projectUcpResolution,
  UCP_RESOLUTION_EXTENSION,
  UCP_RESOLUTION_EXTENSION_VERSION,
  UCP_RESOLUTION_SCHEMA_URL,
  validateUcpPressureTestPath,
  type UcpPressureTestFixture,
} from "../src/ucp.js";
import type { ResolutionLifecycle } from "../src/types.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = <T>(relative: string): T => JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures", relative), "utf8")) as T;
const readRoot = <T>(relative: string): T => JSON.parse(fs.readFileSync(path.join(ROOT, relative), "utf8")) as T;

test("UCP projection is pure and carries sibling lifecycle references", () => {
  const order = read<Record<string, unknown>>("ucp/source/order.json");
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  const before = JSON.stringify(order);
  const projected = projectUcpResolution(order, lifecycle);
  assert.equal(JSON.stringify(order), before);
  assert.ok((projected.ucp as any).capabilities[UCP_RESOLUTION_EXTENSION]);
  assert.equal(UCP_RESOLUTION_EXTENSION, "ai.peoplescourt.shopping.dispute_resolution");
  assert.equal(UCP_RESOLUTION_EXTENSION_VERSION, "2026-08-23");
  assert.equal(
    UCP_RESOLUTION_SCHEMA_URL,
    "https://peoplescourt.ai/standards/ucp/dispute-resolution/2026-08-23/schema.json",
  );
  assert.equal("execution_posture" in (projected.external_resolution as object), false);
  assert.equal((projected.external_resolution as any).dispositions.length, 2);
  assert.equal((projected.external_resolution as any).executions[0].status, "completed");
});

test("committed UCP paths distinguish escrow-held and post-settlement execution owners", () => {
  const escrow = read<UcpPressureTestFixture>("ucp/paths/escrow-held.json");
  const refund = read<UcpPressureTestFixture>("ucp/paths/post-settlement-merchant-refund.json");
  assert.equal(escrow.pressureTest.posture, "escrow_held");
  assert.equal(refund.pressureTest.posture, "post_settlement_merchant_refund");
  assert.notEqual(escrow.pressureTest.nativeReceiptKind, refund.pressureTest.nativeReceiptKind);
  assert.equal(escrow.executionEvidence.custodyAtHandoff.state, "held_by_escrow");
  assert.equal(refund.executionEvidence.custodyAtHandoff.state, "settled_to_merchant");
  assert.equal(escrow.executionEvidence.refundRequest, null);
  assert.equal(escrow.executionEvidence.merchantApproval, null);
  assert.ok(refund.executionEvidence.refundRequest);
  assert.ok(refund.executionEvidence.merchantApproval);
  assert.notEqual(escrow.lifecycle.handoff.roles.executor, refund.lifecycle.handoff.roles.executor);
  assert.notEqual(escrow.lifecycle.executions[0]!.providerRef, refund.lifecycle.executions[0]!.providerRef);
  assert.notEqual(
    escrow.lifecycle.executions[0]!.receiptProof!.artifactRef,
    refund.lifecycle.executions[0]!.receiptProof!.artifactRef,
  );
  assert.deepEqual(
    escrow.lifecycle.dispositions.map((item) => ({
      outcome: item.outcome,
      remedy: item.authorizedRemedy,
      state: item.reviewState,
      supersedes: item.supersedesDispositionId ?? null,
    })),
    refund.lifecycle.dispositions.map((item) => ({
      outcome: item.outcome,
      remedy: item.authorizedRemedy,
      state: item.reviewState,
      supersedes: item.supersedesDispositionId ?? null,
    })),
  );
  assert.deepEqual(escrow.lifecycle.handoff.remedyCeilings, refund.lifecycle.handoff.remedyCeilings);
  for (const fixture of [escrow, refund]) {
    const projectedUcp = fixture.order.ucp as any;
    const projectedResolution = fixture.order.external_resolution as any;
    assert.deepEqual(projectedUcp.capabilities[UCP_RESOLUTION_EXTENSION], [
      { version: UCP_RESOLUTION_EXTENSION_VERSION },
    ]);
    assert.equal(projectedResolution.extension, UCP_RESOLUTION_EXTENSION);
    assert.equal(projectedResolution.version, UCP_RESOLUTION_EXTENSION_VERSION);
    assert.equal("execution_posture" in projectedResolution, false);
    assert.equal(projectedResolution.handoffs[0].artifact_ref, "#/lifecycle/handoff");
    assert.equal(projectedResolution.executions[0].artifact_ref, "#/lifecycle/executions/0");
    assert.deepEqual(
      validateUcpPressureTestPath(fixture, { now: new Date("2026-08-27T00:00:00.000Z") }),
      [],
    );
  }
});

test("UCP negatives reject swapped executor, receipt, and custody evidence", () => {
  for (const id of ["swapped-executor", "swapped-receipt", "swapped-custody-evidence"]) {
    const vector = read<{
      expectedReasonCode: string;
      fixture: UcpPressureTestFixture;
    }>(`ucp/negative/${id}.json`);
    const reasons = validateUcpPressureTestPath(vector.fixture, { now: new Date("2026-08-27T00:00:00.000Z") });
    assert.ok(reasons.includes(vector.expectedReasonCode as any), `${id} did not produce ${vector.expectedReasonCode}`);
  }
});

test("UCP profile schema matches the governed namespace, version, and canonical host", () => {
  const schema = readRoot<any>("profiles/ucp/external-resolution.schema.json");
  assert.equal(schema.$id, UCP_RESOLUTION_SCHEMA_URL);
  assert.equal(schema.name, UCP_RESOLUTION_EXTENSION);
  assert.equal(schema.version, UCP_RESOLUTION_EXTENSION_VERSION);
  assert.equal(schema.$defs.externalResolution.properties.extension.const, UCP_RESOLUTION_EXTENSION);
  assert.equal(schema.$defs.externalResolution.properties.version.const, UCP_RESOLUTION_EXTENSION_VERSION);
  assert.equal("execution_posture" in schema.$defs.externalResolution.properties, false);
});
