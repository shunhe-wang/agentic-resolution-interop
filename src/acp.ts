import { sha256Canonical } from "./canonical.js";
import { dispositionDigest, frozenRecordDigest, handoffDigest, validateLifecycle } from "./lifecycle.js";
import type { ResolutionLifecycle } from "./types.js";

export const ACP_UPSTREAM_REVISION = "7fdd78df677a94dce04c770644b0fbbb1401272b";
export const ACP_ORDER_SCHEMA_URL =
  `https://raw.githubusercontent.com/agentic-commerce-protocol/agentic-commerce-protocol/${ACP_UPSTREAM_REVISION}/spec/unreleased/json-schema/schema.agentic_checkout.json#/$defs/Order`;

export type AcpOrderAdjustment = {
  id: string;
  type: string;
  occurred_at: string;
  status: string;
  line_items?: Array<{ id: string; quantity: number }>;
  amount?: number;
  currency?: string;
  description?: string;
  reason?: string;
};

export type AcpSourceOrder = {
  type?: "order";
  id: string;
  checkout_session_id: string;
  permalink_url: string;
  status?: string;
  line_items?: Array<{
    id: string;
    title: string;
    quantity: { ordered: number; current: number; fulfilled?: number };
    unit_price?: number;
    subtotal?: number;
    status?: string;
  }>;
  fulfillments?: Array<Record<string, unknown>>;
  adjustments?: AcpOrderAdjustment[];
  totals?: Array<Record<string, unknown>>;
};

export type AcpSourceVerification = {
  schemaVersion: "synthetic-acp-record-verification-v1";
  upstreamRevision: typeof ACP_UPSTREAM_REVISION;
  orderSchema: typeof ACP_ORDER_SCHEMA_URL;
  canonicalization: "RFC8785";
  digestAlgorithm: "SHA-256";
  orderSha256: string;
  validationScope: "pinned-order-fields-exercised-by-this-vector";
  authenticity: "not_claimed";
};

export type AcpExternalResolutionFixture = {
  schemaVersion: "acp-external-resolution-test-vector-v1";
  synthetic: true;
  informative: true;
  source: {
    protocol: "agentic_checkout_acp";
    upstreamRevision: typeof ACP_UPSTREAM_REVISION;
    orderSchema: typeof ACP_ORDER_SCHEMA_URL;
    verification: AcpSourceVerification;
    order: AcpSourceOrder;
  };
  mapping: {
    contestedAdjustmentId: string;
    lifecycleArtifactRef: "#/lifecycle";
    extensionPlacement: "not_asserted";
  };
  lifecycle: ResolutionLifecycle;
  expected: {
    valid: boolean;
    reasonCodes: AcpExternalResolutionReasonCode[];
  };
};

export type AcpExternalResolutionReasonCode =
  | "acp_source_order_invalid"
  | "acp_contested_adjustment_missing"
  | "acp_order_binding_mismatch"
  | "acp_external_resolver_missing"
  | "acp_resolution_authority_missing"
  | "acp_execution_not_separate"
  | "acp_lifecycle_order_invalid"
  | "acp_lifecycle_invalid";

const sameStrings = (left: readonly string[], right: readonly string[]): boolean =>
  [...left].sort().join("\n") === [...right].sort().join("\n");

const validDate = (value: string): number | null => {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
};

export function sealAcpExternalResolutionLifecycle(
  source: ResolutionLifecycle,
  order: AcpSourceOrder,
  verification: AcpSourceVerification,
): ResolutionLifecycle {
  const lifecycle = structuredClone(source);
  lifecycle.handoff.nativeProtocol = "agentic_checkout_acp";
  lifecycle.handoff.transaction.orderId = order.id;
  lifecycle.handoff.transaction.checkoutId = order.checkout_session_id;
  const orderArtifact = {
    artifactId: "acp-order.json",
    sha256: sha256Canonical(order),
    mediaType: "application/json",
    source: "synthetic-acp-order",
  };
  const verificationArtifact = {
    artifactId: "acp-record-verification.json",
    sha256: sha256Canonical(verification),
    mediaType: "application/json",
    source: "synthetic-pinned-acp-order-check",
  };
  lifecycle.handoff.frozenRecord.manifest.includedArtifacts = [
    orderArtifact,
    verificationArtifact,
    ...lifecycle.handoff.frozenRecord.manifest.includedArtifacts.filter(
      (artifact) => artifact.artifactId !== "ucp-order.json",
    ),
  ];
  lifecycle.handoff.nativeProof = {
    artifactRef: "#/source/verification",
    sha256: verificationArtifact.sha256,
    verificationMethod: "synthetic-pinned-acp-order-structure-and-binding-check",
  };
  lifecycle.handoff.frozenRecord.digest = frozenRecordDigest(lifecycle.handoff.frozenRecord.manifest);
  const stableHandoffDigest = handoffDigest(lifecycle.handoff);
  for (const disposition of lifecycle.dispositions) {
    disposition.handoffDigest = stableHandoffDigest;
    disposition.frozenRecordDigest = lifecycle.handoff.frozenRecord.digest;
    disposition.dispositionDigest = dispositionDigest(disposition);
  }
  const operative = lifecycle.dispositions.find(
    (disposition) => disposition.dispositionId === lifecycle.operativeDispositionId,
  );
  for (const execution of lifecycle.executions) {
    if (operative && execution.dispositionId === operative.dispositionId) {
      execution.dispositionDigest = operative.dispositionDigest;
    }
  }
  return lifecycle;
}

export function validateAcpExternalResolutionFixture(
  fixture: AcpExternalResolutionFixture,
  options: { now: Date },
): AcpExternalResolutionReasonCode[] {
  const reasons = new Set<AcpExternalResolutionReasonCode>();
  const { order, verification } = fixture.source;
  const adjustment = order.adjustments?.find(
    (candidate) => candidate.id === fixture.mapping.contestedAdjustmentId,
  );

  if (
    fixture.source.protocol !== "agentic_checkout_acp" ||
    fixture.source.upstreamRevision !== ACP_UPSTREAM_REVISION ||
    fixture.source.orderSchema !== ACP_ORDER_SCHEMA_URL ||
    order.type !== "order" ||
    !order.id ||
    !order.checkout_session_id ||
    !order.permalink_url.startsWith("https://") ||
    verification.upstreamRevision !== ACP_UPSTREAM_REVISION ||
    verification.orderSchema !== ACP_ORDER_SCHEMA_URL ||
    verification.canonicalization !== "RFC8785" ||
    verification.digestAlgorithm !== "SHA-256" ||
    verification.validationScope !== "pinned-order-fields-exercised-by-this-vector" ||
    verification.authenticity !== "not_claimed" ||
    verification.orderSha256 !== sha256Canonical(order)
  ) reasons.add("acp_source_order_invalid");

  if (
    !adjustment ||
    adjustment.type !== "dispute" ||
    adjustment.status !== "pending" ||
    !adjustment.line_items?.length
  ) reasons.add("acp_contested_adjustment_missing");

  const disputedLineIds = adjustment?.line_items?.map((item) => item.id) ?? [];
  const handoff = fixture.lifecycle.handoff;
  const orderArtifact = handoff.frozenRecord.manifest.includedArtifacts.find(
    (artifact) => artifact.artifactId === "acp-order.json",
  );
  const verificationArtifact = handoff.frozenRecord.manifest.includedArtifacts.find(
    (artifact) => artifact.artifactId === "acp-record-verification.json",
  );
  if (
    handoff.nativeProtocol !== "agentic_checkout_acp" ||
    handoff.transaction.orderId !== order.id ||
    handoff.transaction.checkoutId !== order.checkout_session_id ||
    !sameStrings(handoff.transaction.disputedLineItemIds, disputedLineIds) ||
    orderArtifact?.sha256 !== sha256Canonical(order) ||
    verificationArtifact?.sha256 !== sha256Canonical(verification) ||
    handoff.nativeProof.artifactRef !== "#/source/verification" ||
    handoff.nativeProof.sha256 !== sha256Canonical(verification)
  ) reasons.add("acp_order_binding_mismatch");

  if (
    handoff.roles.resolver !== handoff.resolver.resolverId ||
    [handoff.roles.claimant, handoff.roles.respondent, handoff.roles.recordIssuer].includes(
      handoff.roles.resolver,
    )
  ) reasons.add("acp_external_resolver_missing");

  const lifecycleResult = validateLifecycle(fixture.lifecycle, options);
  if (lifecycleResult.reasonCodes.includes("party_authority_missing")) {
    reasons.add("acp_resolution_authority_missing");
  }
  if (lifecycleResult.reasonCodes.includes("decision_not_execution")) {
    reasons.add("acp_execution_not_separate");
  }
  if (!lifecycleResult.ok) reasons.add("acp_lifecycle_invalid");

  const contestedAt = adjustment ? validDate(adjustment.occurred_at) : null;
  const handedOffAt = validDate(handoff.createdAt);
  const operativeIssuedAt = lifecycleResult.operativeDisposition
    ? validDate(lifecycleResult.operativeDisposition.issuedAt)
    : null;
  const executedAt = lifecycleResult.latestExecution
    ? validDate(lifecycleResult.latestExecution.recordedAt)
    : null;
  if (
    contestedAt === null ||
    handedOffAt === null ||
    operativeIssuedAt === null ||
    executedAt === null ||
    contestedAt > handedOffAt ||
    handedOffAt > operativeIssuedAt ||
    operativeIssuedAt > executedAt
  ) reasons.add("acp_lifecycle_order_invalid");

  return [...reasons].sort();
}
