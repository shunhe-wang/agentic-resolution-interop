import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { dispositionDigest, frozenRecordDigest, handoffDigest, validateLifecycle } from "../src/lifecycle.js";
import type { ResolutionLifecycle } from "../src/types.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = <T>(relative: string): T => JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures", relative), "utf8")) as T;
const manifest = read<any>("core/manifest.json");

test("valid lifecycle freezes the record and separates disposition from execution", () => {
  const lifecycle = read<ResolutionLifecycle>(manifest.validJourney.replace("valid/", "core/valid/"));
  const result = validateLifecycle(lifecycle, { now: new Date(manifest.validationTime) });
  assert.equal(result.ok, true);
  assert.equal(result.operativeDisposition?.reviewState, "final");
  assert.equal(result.latestExecution?.status, "completed");
  assert.notEqual(result.operativeDisposition?.signedArtifact.artifactRef, result.latestExecution?.receiptProof?.artifactRef);
});

test("committed advisory lifecycle is final without an executor or receipt", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/advisory-lifecycle.json");
  const result = validateLifecycle(lifecycle, { now: new Date(manifest.validationTime) });
  assert.equal(result.ok, true, result.reasonCodes.join(", "));
  assert.equal(result.operativeDisposition?.reviewState, "final");
  assert.equal(lifecycle.handoff.roles.executor, undefined);
  assert.deepEqual(lifecycle.executions, []);
  assert.equal(result.latestExecution, null);
});

test("completed executions cannot cumulatively exceed the operative disposition", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  const replay = structuredClone(lifecycle.executions[0]!);
  replay.executionId = "execution-neutral-002";
  replay.nativeTransactionReference = "refund:synthetic:002";
  replay.recordedAt = "2026-08-26T12:06:00.000Z";
  replay.receiptProof = {
    artifactRef: "synthetic-refund-receipt-002.json",
    sha256: "c".repeat(64),
    verificationStatus: "passed",
  };
  lifecycle.executions.push(replay);

  const result = validateLifecycle(lifecycle, { now: new Date(manifest.validationTime) });
  assert.equal(result.ok, false);
  assert.ok(result.reasonCodes.includes("execution_outside_authority"));
});

test("execution identities cannot be replayed", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  const replay = structuredClone(lifecycle.executions[0]!);
  replay.amountMinorUnits = "0";
  replay.recordedAt = "2026-08-26T12:06:00.000Z";
  lifecycle.executions.push(replay);

  const result = validateLifecycle(lifecycle, { now: new Date(manifest.validationTime) });
  assert.equal(result.ok, false);
  assert.ok(result.reasonCodes.includes("execution_id_duplicate"));
});

test("a completed native transaction reference cannot satisfy two executions", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  lifecycle.executions[0]!.amountMinorUnits = "1000";
  const replay = structuredClone(lifecycle.executions[0]!);
  replay.executionId = "execution-neutral-002";
  replay.recordedAt = "2026-08-26T12:06:00.000Z";
  lifecycle.executions.push(replay);

  const result = validateLifecycle(lifecycle, { now: new Date(manifest.validationTime) });
  assert.equal(result.ok, false);
  assert.ok(result.reasonCodes.includes("execution_reference_duplicate"));
});

test("not-attempted execution state does not require a fabricated failure", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  const execution = lifecycle.executions[0]!;
  execution.status = "not_attempted";
  execution.nativeTransactionReference = null;
  execution.receiptProof = null;
  delete execution.failureCode;

  const result = validateLifecycle(lifecycle, { now: new Date(manifest.validationTime) });
  assert.equal(result.ok, true, result.reasonCodes.join(", "));
});

test("an execution record requires a named executor", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  delete lifecycle.handoff.roles.executor;
  const digest = handoffDigest(lifecycle.handoff);
  for (const disposition of lifecycle.dispositions) {
    disposition.handoffDigest = digest;
    disposition.dispositionDigest = dispositionDigest(disposition);
  }
  lifecycle.executions[0]!.dispositionDigest = lifecycle.dispositions[1]!.dispositionDigest;

  const result = validateLifecycle(lifecycle, { now: new Date(manifest.validationTime) });
  assert.equal(result.ok, false);
  assert.ok(result.reasonCodes.includes("execution_executor_missing"));
});

test("duplicate disposition identities are rejected", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  lifecycle.dispositions.push(structuredClone(lifecycle.dispositions[0]!));

  const result = validateLifecycle(lifecycle, { now: new Date(manifest.validationTime) });
  assert.equal(result.ok, false);
  assert.ok(result.reasonCodes.includes("disposition_id_duplicate"));
});

test("a disposition cannot supersede a missing predecessor", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  const operative = lifecycle.dispositions[1]!;
  operative.supersedesDispositionId = "disposition-does-not-exist";
  operative.dispositionDigest = dispositionDigest(operative);
  lifecycle.executions[0]!.dispositionDigest = operative.dispositionDigest;

  const result = validateLifecycle(lifecycle, { now: new Date(manifest.validationTime) });
  assert.equal(result.ok, false);
  assert.ok(result.reasonCodes.includes("supersession_target_missing"));
});

test("all dispositions must belong to the operative supersession chain", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  const disconnected = structuredClone(lifecycle.dispositions[1]!);
  disconnected.dispositionId = "disposition-neutral-003";
  delete disconnected.supersedesDispositionId;
  disconnected.dispositionDigest = dispositionDigest(disconnected);
  lifecycle.dispositions.push(disconnected);

  const result = validateLifecycle(lifecycle, { now: new Date(manifest.validationTime) });
  assert.equal(result.ok, false);
  assert.ok(result.reasonCodes.includes("disposition_graph_disconnected"));
});

test("line-item identity comparison cannot collapse embedded delimiters", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  lifecycle.handoff.transaction.disputedLineItemIds = ["line-002\nline-extra"];
  lifecycle.handoff.frozenRecord.manifest.disputedLineItemIds = ["line-002", "line-extra"];
  lifecycle.expected.disputedLineItemIds = ["line-002", "line-extra"];
  lifecycle.handoff.frozenRecord.digest = frozenRecordDigest(lifecycle.handoff.frozenRecord.manifest);
  const digest = handoffDigest(lifecycle.handoff);
  for (const disposition of lifecycle.dispositions) {
    disposition.handoffDigest = digest;
    disposition.frozenRecordDigest = lifecycle.handoff.frozenRecord.digest;
    disposition.dispositionDigest = dispositionDigest(disposition);
  }
  lifecycle.executions[0]!.dispositionDigest = lifecycle.dispositions[1]!.dispositionDigest;

  const result = validateLifecycle(lifecycle, { now: new Date(manifest.validationTime) });
  assert.equal(result.ok, false);
  assert.ok(result.reasonCodes.includes("disputed_line_reference_mismatch"));
});

test("all stable negative vectors produce their declared reason code", () => {
  for (const vector of manifest.negatives) {
    const negative = read<{ expectedReasonCode: string; lifecycle: ResolutionLifecycle }>(`core/${vector.path}`);
    const result = validateLifecycle(negative.lifecycle, { now: new Date(manifest.validationTime) });
    assert.equal(result.ok, false, vector.id);
    assert.ok(result.reasonCodes.includes(negative.expectedReasonCode as never), `${vector.id}: ${result.reasonCodes.join(", ")}`);
  }
});

test("missing-party-authority vector isolates bilateral authority failure", () => {
  const negative = read<{ lifecycle: ResolutionLifecycle }>("core/negative/missing-party-authority.json");
  const result = validateLifecycle(negative.lifecycle, { now: new Date(manifest.validationTime) });
  assert.deepEqual(result.reasonCodes, ["party_authority_missing"]);
});

test("verifier-local observation metadata is outside stable handoff identity", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  const before = handoffDigest(lifecycle.handoff);
  lifecycle.handoff.nativeVerification = { verifierId: "local-test", verifiedAt: "2030-01-01T00:00:00.000Z" };
  assert.equal(handoffDigest(lifecycle.handoff), before);
});
