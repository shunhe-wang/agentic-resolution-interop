import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  reconcileAcpOrderObservation,
  type AcpGetOrderReconciliationMatrix,
  type AcpOrderSnapshot,
} from "../src/acp-reconciliation.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const readMatrix = (): AcpGetOrderReconciliationMatrix =>
  JSON.parse(
    fs.readFileSync(path.join(ROOT, "fixtures/acp/get-order/reconciliation-matrix.json"), "utf8"),
  ) as AcpGetOrderReconciliationMatrix;

test("ACP GET Order matrix reconciles webhook and pull snapshots without regression", () => {
  const matrix = readMatrix();
  assert.equal(matrix.coverage, "ordering_and_cache_only");
  assert.equal(matrix.orderingPlacement, "not_asserted");
  assert.equal(matrix.etagSemantics, "cache_validation_not_cross_channel_ordering");
  assert.equal(matrix.cases.length, 7);

  for (const vector of matrix.cases) {
    const currentObservation = vector.current ? matrix.observations[vector.current] : null;
    const incoming = matrix.observations[vector.incoming];
    assert.ok(incoming, `${vector.id}: incoming observation exists`);
    assert.ok(
      currentObservation === null || currentObservation?.kind === "snapshot",
      `${vector.id}: current observation is a snapshot`,
    );
    const result = reconcileAcpOrderObservation(
      currentObservation as AcpOrderSnapshot | null,
      incoming,
    );
    assert.deepEqual(
      { action: result.action, reason: result.reason },
      vector.expected,
      vector.id,
    );
  }
});

test("ACP GET Order reconciliation rejects a snapshot whose declared digest changed", () => {
  const matrix = readMatrix();
  const current = structuredClone(matrix.observations.webhook8) as AcpOrderSnapshot;
  const incoming = structuredClone(matrix.observations.get9) as AcpOrderSnapshot;
  incoming.order.totals = [{ type: "total", display_text: "Total", amount: 1 }];

  const result = reconcileAcpOrderObservation(current, incoming);
  assert.deepEqual(
    { action: result.action, reason: result.reason },
    { action: "conflict", reason: "snapshot_digest_mismatch" },
  );
  assert.equal(result.state?.revision, 8);
});

test("ACP GET Order reconciliation drops persisted state whose declared digest is corrupt", () => {
  const matrix = readMatrix();
  const current = structuredClone(matrix.observations.get9) as AcpOrderSnapshot;
  const incoming = structuredClone(matrix.observations.webhook8) as AcpOrderSnapshot;
  current.order.totals = [{ type: "total", display_text: "Total", amount: 1 }];

  const result = reconcileAcpOrderObservation(current, incoming);
  assert.deepEqual(
    { action: result.action, reason: result.reason },
    { action: "conflict", reason: "snapshot_digest_mismatch" },
  );
  assert.equal(result.state, null);
});
