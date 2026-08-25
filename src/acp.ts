import { createHmac, timingSafeEqual } from "node:crypto";
import { sha256Bytes, sha256Canonical } from "./canonical.js";
import { dispositionDigest, frozenRecordDigest, handoffDigest, validateLifecycle } from "./lifecycle.js";
import type { ResolutionLifecycle } from "./types.js";

export const ACP_UPSTREAM_REVISION = "7fdd78df677a94dce04c770644b0fbbb1401272b";
export const ACP_ORDER_SCHEMA_URL =
  `https://raw.githubusercontent.com/agentic-commerce-protocol/agentic-commerce-protocol/${ACP_UPSTREAM_REVISION}/spec/unreleased/json-schema/schema.agentic_checkout.json#/$defs/Order`;
export const ACP_WEBHOOK_SPEC_URL =
  `https://raw.githubusercontent.com/agentic-commerce-protocol/agentic-commerce-protocol/${ACP_UPSTREAM_REVISION}/spec/unreleased/openapi/openapi.agentic_checkout_webhook.yaml`;
export const ACP_WEBHOOK_SIGNATURE_TOLERANCE_SECONDS = 300;

// Public deterministic test material. This is intentionally not a credential and proves
// ACP webhook verification mechanics only, never merchant identity or production trust.
export const ACP_SYNTHETIC_WEBHOOK_TEST_KEY = Buffer.from(
  "agentic-resolution-interop/acp/synthetic-webhook-test-key/v1",
  "utf8",
);

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

export type AcpWebhookEvent = {
  type: "order_update";
  data: AcpSourceOrder;
};

export type AcpWebhookRequest = {
  endpoint: "/agentic_checkout/webhooks/order_events";
  contentType: "application/json";
  rawBody: string;
  merchantSignature: string;
};

export type AcpSourceVerification = {
  schemaVersion: "synthetic-acp-webhook-verification-v1";
  upstreamRevision: typeof ACP_UPSTREAM_REVISION;
  orderSchema: typeof ACP_ORDER_SCHEMA_URL;
  webhookSpec: typeof ACP_WEBHOOK_SPEC_URL;
  signatureAlgorithm: "HMAC-SHA256";
  signedPayload: "timestamp.raw_body";
  signatureToleranceSeconds: typeof ACP_WEBHOOK_SIGNATURE_TOLERANCE_SECONDS;
  canonicalization: "RFC8785";
  digestAlgorithm: "SHA-256";
  orderSha256: string;
  rawBodySha256: string;
  merchantSignatureSha256: string;
  validationScope: "manual-order-field-subset-exercised-by-this-vector";
  verificationStatus: "passed";
  authenticity: "synthetic_test_key_only";
};

export type AcpExternalResolutionFixture = {
  schemaVersion: "acp-external-resolution-test-vector-v1";
  synthetic: true;
  informative: true;
  source: {
    protocol: "agentic_checkout_acp";
    upstreamRevision: typeof ACP_UPSTREAM_REVISION;
    orderSchema: typeof ACP_ORDER_SCHEMA_URL;
    webhook: AcpWebhookRequest;
    verification: AcpSourceVerification;
    order: AcpSourceOrder;
  };
  mapping: {
    contestedAdjustmentId: string;
    lifecycleArtifactRef: "#/lifecycle";
    extensionPlacement: "not_asserted";
    nativeTransactionBinding: "not_available_in_pinned_order";
    acpFacingExecutionState: "deferred_not_asserted";
    contestedAmountBinding: "adjustment_amount_and_currency";
  };
  lifecycle: ResolutionLifecycle;
  expected: {
    valid: boolean;
    reasonCodes: AcpExternalResolutionReasonCode[];
  };
};

export type AcpExternalResolutionReasonCode =
  | "acp_source_order_invalid"
  | "acp_webhook_payload_mismatch"
  | "acp_webhook_signature_invalid"
  | "acp_webhook_timestamp_invalid"
  | "acp_contested_adjustment_missing"
  | "acp_contested_amount_mismatch"
  | "acp_order_binding_mismatch"
  | "acp_external_resolver_missing"
  | "acp_resolution_authority_missing"
  | "acp_execution_not_separate"
  | "acp_lifecycle_order_invalid"
  | "acp_lifecycle_invalid";

export const sameAcpIdentifierMultiset = (
  left: readonly string[],
  right: readonly string[],
): boolean => {
  if (left.length !== right.length) return false;
  const sortedLeft = [...left].sort();
  const sortedRight = [...right].sort();
  return sortedLeft.every((value, index) => value === sortedRight[index]);
};

const validDate = (value: string): number | null => {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
};

export function signAcpWebhook(
  rawBody: string,
  timestamp: number,
  sharedKey: Uint8Array,
): string {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new TypeError("ACP webhook timestamp must be a non-negative safe integer.");
  }
  const signature = acpWebhookSignatureHex(rawBody, timestamp, sharedKey);
  return `t=${timestamp},v1=${signature}`;
}

function acpWebhookSignatureHex(
  rawBody: string,
  timestamp: number,
  sharedKey: Uint8Array,
): string {
  return createHmac("sha256", sharedKey)
    .update(`${timestamp}.${rawBody}`, "utf8")
    .digest("hex");
}

export function verifyAcpWebhook(
  request: AcpWebhookRequest,
  options: { now: Date; sharedKey: Uint8Array },
): AcpExternalResolutionReasonCode[] {
  const reasons = new Set<AcpExternalResolutionReasonCode>();
  const match = /^t=(\d+),v1=([a-fA-F0-9]{64})$/.exec(request.merchantSignature);
  if (!match) return ["acp_webhook_signature_invalid"];

  const timestamp = Number(match[1]);
  const nowSeconds = Math.floor(options.now.getTime() / 1000);
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    return ["acp_webhook_timestamp_invalid"];
  }
  if (
    !Number.isSafeInteger(nowSeconds) ||
    Math.abs(nowSeconds - timestamp) > ACP_WEBHOOK_SIGNATURE_TOLERANCE_SECONDS
  ) reasons.add("acp_webhook_timestamp_invalid");

  const expected = acpWebhookSignatureHex(request.rawBody, timestamp, options.sharedKey);
  const supplied = match[2]!.toLowerCase();
  const expectedBytes = Buffer.from(expected, "hex");
  const suppliedBytes = Buffer.from(supplied, "hex");
  if (expectedBytes.length !== suppliedBytes.length || !timingSafeEqual(expectedBytes, suppliedBytes)) {
    reasons.add("acp_webhook_signature_invalid");
  }
  return [...reasons].sort();
}

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
    source: "synthetic-manual-acp-order-field-check",
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
    verificationMethod: "synthetic-manual-acp-order-field-and-binding-check",
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
  options: { now: Date; webhookSharedKey: Uint8Array },
): AcpExternalResolutionReasonCode[] {
  const reasons = new Set<AcpExternalResolutionReasonCode>();
  const { order, verification, webhook } = fixture.source;
  const adjustment = order.adjustments?.find(
    (candidate) => candidate.id === fixture.mapping.contestedAdjustmentId,
  );

  if (
    fixture.source.protocol !== "agentic_checkout_acp" ||
    fixture.source.upstreamRevision !== ACP_UPSTREAM_REVISION ||
    fixture.source.orderSchema !== ACP_ORDER_SCHEMA_URL ||
    verification.schemaVersion !== "synthetic-acp-webhook-verification-v1" ||
    verification.webhookSpec !== ACP_WEBHOOK_SPEC_URL ||
    verification.signatureAlgorithm !== "HMAC-SHA256" ||
    verification.signedPayload !== "timestamp.raw_body" ||
    verification.signatureToleranceSeconds !== ACP_WEBHOOK_SIGNATURE_TOLERANCE_SECONDS ||
    order.type !== "order" ||
    !order.id ||
    !order.checkout_session_id ||
    !order.permalink_url.startsWith("https://") ||
    verification.upstreamRevision !== ACP_UPSTREAM_REVISION ||
    verification.orderSchema !== ACP_ORDER_SCHEMA_URL ||
    verification.canonicalization !== "RFC8785" ||
    verification.digestAlgorithm !== "SHA-256" ||
    verification.validationScope !== "manual-order-field-subset-exercised-by-this-vector" ||
    verification.verificationStatus !== "passed" ||
    verification.authenticity !== "synthetic_test_key_only" ||
    verification.orderSha256 !== sha256Canonical(order)
  ) reasons.add("acp_source_order_invalid");

  if (verification.rawBodySha256 !== sha256Bytes(webhook.rawBody)) {
    reasons.add("acp_webhook_payload_mismatch");
  }
  if (verification.merchantSignatureSha256 !== sha256Bytes(webhook.merchantSignature)) {
    reasons.add("acp_webhook_signature_invalid");
  }

  let webhookEvent: AcpWebhookEvent | null = null;
  try {
    webhookEvent = JSON.parse(webhook.rawBody) as AcpWebhookEvent;
  } catch {
    reasons.add("acp_webhook_payload_mismatch");
  }
  if (
    webhook.endpoint !== "/agentic_checkout/webhooks/order_events" ||
    webhook.contentType !== "application/json" ||
    webhookEvent?.type !== "order_update" ||
    !webhookEvent.data ||
    sha256Canonical(webhookEvent.data) !== sha256Canonical(order)
  ) reasons.add("acp_webhook_payload_mismatch");
  for (const reason of verifyAcpWebhook(webhook, {
    now: options.now,
    sharedKey: options.webhookSharedKey,
  })) reasons.add(reason);

  if (
    !adjustment ||
    adjustment.type !== "dispute" ||
    adjustment.status !== "pending" ||
    !adjustment.line_items?.length
  ) reasons.add("acp_contested_adjustment_missing");

  const handoff = fixture.lifecycle.handoff;
  const lifecycleResult = validateLifecycle(fixture.lifecycle, options);
  const operative = lifecycleResult.operativeDisposition;
  const adjustmentAmount = adjustment?.amount;
  const adjustmentCurrency = adjustment?.currency?.toUpperCase();
  const downstreamMoney = [
    ...(operative ? [operative.authorizedRemedy] : []),
    ...fixture.lifecycle.executions,
  ];
  const validDownstreamMoney =
    typeof adjustmentAmount === "number" &&
    Number.isSafeInteger(adjustmentAmount) &&
    adjustmentAmount >= 0 &&
    downstreamMoney.every(
      (money) =>
        /^(0|[1-9][0-9]*)$/.test(money.amountMinorUnits) &&
        BigInt(money.amountMinorUnits) <= BigInt(adjustmentAmount) &&
        money.currency.toUpperCase() === adjustmentCurrency,
    );
  if (
    fixture.mapping.nativeTransactionBinding !== "not_available_in_pinned_order" ||
    fixture.mapping.acpFacingExecutionState !== "deferred_not_asserted" ||
    fixture.mapping.contestedAmountBinding !== "adjustment_amount_and_currency" ||
    typeof adjustmentAmount !== "number" ||
    !Number.isSafeInteger(adjustmentAmount) ||
    adjustmentAmount < 0 ||
    !adjustmentCurrency ||
    handoff.requestedRemedy.amountMinorUnits !== String(adjustmentAmount) ||
    handoff.requestedRemedy.currency.toUpperCase() !== adjustmentCurrency ||
    !validDownstreamMoney
  ) reasons.add("acp_contested_amount_mismatch");

  const disputedLineIds = adjustment?.line_items?.map((item) => item.id) ?? [];
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
    !sameAcpIdentifierMultiset(handoff.transaction.disputedLineItemIds, disputedLineIds) ||
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
