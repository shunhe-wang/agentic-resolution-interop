import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { handoffDigest, validateLifecycle } from "../src/lifecycle.js";
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

test("all stable negative vectors produce their declared reason code", () => {
  for (const vector of manifest.negatives) {
    const negative = read<{ expectedReasonCode: string; lifecycle: ResolutionLifecycle }>(`core/${vector.path}`);
    const result = validateLifecycle(negative.lifecycle, { now: new Date(manifest.validationTime) });
    assert.equal(result.ok, false, vector.id);
    assert.ok(result.reasonCodes.includes(negative.expectedReasonCode as never), `${vector.id}: ${result.reasonCodes.join(", ")}`);
  }
});

test("verifier-local observation metadata is outside stable handoff identity", () => {
  const lifecycle = read<ResolutionLifecycle>("core/valid/lifecycle.json");
  const before = handoffDigest(lifecycle.handoff);
  lifecycle.handoff.nativeVerification = { verifierId: "local-test", verifiedAt: "2030-01-01T00:00:00.000Z" };
  assert.equal(handoffDigest(lifecycle.handoff), before);
});
