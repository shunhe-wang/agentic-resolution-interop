import { sha256Canonical } from "./canonical.js";
import type { AcpSourceOrder } from "./acp.js";

export type AcpOrderSnapshot = {
  kind: "snapshot";
  merchantScope: string;
  source: "webhook" | "get";
  revision: number;
  etag?: string;
  orderSha256: string;
  order: AcpSourceOrder;
};

export type AcpOrderNotModified = {
  kind: "not_modified";
  merchantScope: string;
  source: "get";
  orderId: string;
  etag: string;
};

export type AcpOrderObservation = AcpOrderSnapshot | AcpOrderNotModified;

export type AcpOrderReconciliationAction =
  | "initialize"
  | "advance"
  | "replay"
  | "ignore_stale"
  | "not_modified"
  | "conflict";

export type AcpOrderReconciliationReason =
  | "first_snapshot"
  | "newer_revision"
  | "same_revision_same_digest"
  | "older_revision"
  | "etag_not_modified"
  | "same_revision_different_digest"
  | "order_identity_mismatch"
  | "snapshot_digest_mismatch"
  | "revision_invalid"
  | "not_modified_without_state"
  | "etag_mismatch";

export type AcpOrderReconciliationDecision = {
  action: AcpOrderReconciliationAction;
  reason: AcpOrderReconciliationReason;
  state: AcpOrderSnapshot | null;
};

export type AcpOrderReconciliationCase = {
  id: string;
  description: string;
  current: string | null;
  incoming: string;
  expected: Pick<AcpOrderReconciliationDecision, "action" | "reason">;
};

export type AcpGetOrderReconciliationMatrix = {
  schemaVersion: "acp-get-order-reconciliation-matrix-v1";
  synthetic: true;
  informative: true;
  relatedProposal: "agentic-commerce-protocol/agentic-commerce-protocol#234";
  coverage: "ordering_and_cache_only";
  orderingPlacement: "not_asserted";
  revisionSemantics: "merchant_scoped_monotonic_external_envelope";
  etagSemantics: "cache_validation_not_cross_channel_ordering";
  observations: Record<string, AcpOrderObservation>;
  cases: AcpOrderReconciliationCase[];
};

function conflict(
  reason: AcpOrderReconciliationReason,
  current: AcpOrderSnapshot | null,
): AcpOrderReconciliationDecision {
  return { action: "conflict", reason, state: current };
}

function validSnapshot(snapshot: AcpOrderSnapshot): AcpOrderReconciliationReason | null {
  if (!Number.isSafeInteger(snapshot.revision) || snapshot.revision < 0) return "revision_invalid";
  if (snapshot.orderSha256 !== sha256Canonical(snapshot.order)) return "snapshot_digest_mismatch";
  return null;
}

export function reconcileAcpOrderObservation(
  current: AcpOrderSnapshot | null,
  incoming: AcpOrderObservation,
): AcpOrderReconciliationDecision {
  if (!current) {
    if (incoming.kind === "not_modified") return conflict("not_modified_without_state", null);
    const invalid = validSnapshot(incoming);
    if (invalid) return conflict(invalid, null);
    return { action: "initialize", reason: "first_snapshot", state: incoming };
  }

  const invalidCurrent = validSnapshot(current);
  if (invalidCurrent) return conflict(invalidCurrent, null);

  const incomingOrderId = incoming.kind === "snapshot" ? incoming.order.id : incoming.orderId;
  if (
    incoming.merchantScope !== current.merchantScope ||
    incomingOrderId !== current.order.id
  ) return conflict("order_identity_mismatch", current);

  if (incoming.kind === "not_modified") {
    if (!current.etag || incoming.etag !== current.etag) return conflict("etag_mismatch", current);
    return { action: "not_modified", reason: "etag_not_modified", state: current };
  }

  const invalid = validSnapshot(incoming);
  if (invalid) return conflict(invalid, current);

  if (incoming.revision > current.revision) {
    return { action: "advance", reason: "newer_revision", state: incoming };
  }
  if (incoming.revision < current.revision) {
    return { action: "ignore_stale", reason: "older_revision", state: current };
  }
  if (incoming.orderSha256 === current.orderSha256) {
    return { action: "replay", reason: "same_revision_same_digest", state: current };
  }
  return conflict("same_revision_different_digest", current);
}
