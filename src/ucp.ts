import { sha256Canonical } from "./canonical.js";
import { dispositionDigest, frozenRecordDigest, handoffDigest, validateLifecycle } from "./lifecycle.js";
import type { ResolutionExecutionReceipt, ResolutionLifecycle } from "./types.js";

export const UCP_RESOLUTION_EXTENSION = "ai.peoplescourt.shopping.dispute_resolution";
export const UCP_RESOLUTION_EXTENSION_VERSION = "2026-08-23";
export const UCP_RESOLUTION_SCHEMA_URL =
  "https://peoplescourt.ai/standards/ucp/dispute-resolution/2026-08-23/schema.json";

export type UcpExecutionPosture = "escrow_held" | "post_settlement_merchant_refund";

export type UcpFundsStateEvidence = {
  schemaVersion: "neutral-funds-state-evidence-v1";
  evidenceId: string;
  posture: UcpExecutionPosture;
  transactionId: string;
  orderId: string;
  state: "held_by_escrow" | "settled_to_merchant";
  custodyOwner: string;
  railId: string;
  currency: string;
  amountMinorUnits: string;
  observedAt: string;
  proof: { artifactRef: string; sha256: string; verificationStatus: "passed" };
};

export type UcpRefundRequest = {
  schemaVersion: "neutral-refund-request-v1";
  requestId: string;
  requestDigest: string;
  dispositionId: string;
  dispositionDigest: string;
  railId: string;
  currency: string;
  amountMinorUnits: string;
  requestedFrom: string;
  requestedAt: string;
};

export type UcpMerchantApproval = {
  schemaVersion: "neutral-merchant-refund-approval-v1";
  approvalId: string;
  approvalDigest: string;
  requestId: string;
  requestDigest: string;
  approver: string;
  approved: true;
  railId: string;
  currency: string;
  amountMinorUnits: string;
  approvedAt: string;
};

export type UcpReceiptBinding = {
  executionId: string;
  receiptDigest: string;
  nativeTransactionReference: string;
  dispositionDigest: string;
  custodyEvidenceDigest: string;
  refundRequestDigest: string | null;
  merchantApprovalDigest: string | null;
  railId: string;
};

export type UcpPressureTestFixture = {
  schemaVersion: "ucp-resolution-pressure-test-v1";
  synthetic: true;
  neutralFixtureShape: true;
  pressureTest: {
    posture: UcpExecutionPosture;
    executorExpectation: string;
    nativeReceiptKind: string;
    westonMappingRequired: string[];
  };
  executionEvidence: {
    custodyAtHandoff: UcpFundsStateEvidence;
    refundRequest: UcpRefundRequest | null;
    merchantApproval: UcpMerchantApproval | null;
    receiptBinding: UcpReceiptBinding;
  };
  lifecycle: ResolutionLifecycle;
  order: Record<string, unknown>;
};

export type UcpPressureTestReasonCode =
  | "ucp_path_lifecycle_invalid"
  | "ucp_path_custody_evidence_mismatch"
  | "ucp_path_executor_mismatch"
  | "ucp_path_receipt_mismatch"
  | "ucp_path_refund_chain_mismatch";

function digestWithoutField<T extends Record<string, unknown>>(value: T, field: keyof T): string {
  const copy = structuredClone(value);
  delete copy[field];
  return sha256Canonical(copy);
}

export function sealUcpPathLifecycle(
  source: ResolutionLifecycle,
  custodyAtHandoff: UcpFundsStateEvidence,
  executor: string,
  execution: ResolutionExecutionReceipt,
): ResolutionLifecycle {
  const lifecycle = structuredClone(source);
  lifecycle.handoff.roles.executor = executor;
  lifecycle.handoff.frozenRecord.manifest.includedArtifacts.push({
    artifactId: custodyAtHandoff.evidenceId,
    sha256: sha256Canonical(custodyAtHandoff),
    mediaType: "application/json",
    source: "synthetic-funds-state-evidence",
  });
  lifecycle.handoff.frozenRecord.digest = frozenRecordDigest(lifecycle.handoff.frozenRecord.manifest);
  const stableHandoffDigest = handoffDigest(lifecycle.handoff);
  for (const disposition of lifecycle.dispositions) {
    disposition.handoffDigest = stableHandoffDigest;
    disposition.frozenRecordDigest = lifecycle.handoff.frozenRecord.digest;
    disposition.dispositionDigest = dispositionDigest(disposition);
  }
  execution.dispositionId = lifecycle.operativeDispositionId;
  execution.dispositionDigest = lifecycle.dispositions.find(
    (item) => item.dispositionId === lifecycle.operativeDispositionId,
  )!.dispositionDigest;
  lifecycle.executions = [execution];
  return lifecycle;
}

export function validateUcpPressureTestPath(
  fixture: UcpPressureTestFixture,
  options: { now: Date },
): UcpPressureTestReasonCode[] {
  const reasons = new Set<UcpPressureTestReasonCode>();
  const lifecycleResult = validateLifecycle(fixture.lifecycle, options);
  if (!lifecycleResult.ok) reasons.add("ucp_path_lifecycle_invalid");

  const { posture } = fixture.pressureTest;
  const { custodyAtHandoff, refundRequest, merchantApproval, receiptBinding } = fixture.executionEvidence;
  const execution = fixture.lifecycle.executions[0];
  const custodyDigest = sha256Canonical(custodyAtHandoff);
  const frozenCustody = fixture.lifecycle.handoff.frozenRecord.manifest.includedArtifacts.find(
    (item) => item.artifactId === custodyAtHandoff.evidenceId,
  );
  const expectedExecutor = posture === "escrow_held"
    ? "executor:synthetic-escrow-controller"
    : "executor:synthetic-merchant-refund-service";
  const expectedCustodyState = posture === "escrow_held" ? "held_by_escrow" : "settled_to_merchant";
  const expectedCustodyOwner = posture === "escrow_held"
    ? "custodian:synthetic-escrow"
    : "principal:merchant:001";

  if (
    custodyAtHandoff.posture !== posture ||
    custodyAtHandoff.transactionId !== fixture.lifecycle.handoff.transaction.transactionId ||
    custodyAtHandoff.orderId !== fixture.lifecycle.handoff.transaction.orderId ||
    custodyAtHandoff.state !== expectedCustodyState ||
    custodyAtHandoff.custodyOwner !== expectedCustodyOwner ||
    !frozenCustody ||
    frozenCustody.sha256 !== custodyDigest
  ) reasons.add("ucp_path_custody_evidence_mismatch");

  if (
    !execution ||
    fixture.lifecycle.handoff.roles.executor !== expectedExecutor ||
    execution.providerRef !== expectedExecutor
  ) reasons.add("ucp_path_executor_mismatch");

  if (execution) {
    const expectedReceiptMarker = posture === "escrow_held" ? "escrow-controller" : "merchant-same-rail-refund";
    if (
      execution.status !== "completed" ||
      !execution.receiptProof?.artifactRef.includes(expectedReceiptMarker) ||
      receiptBinding.executionId !== execution.executionId ||
      receiptBinding.receiptDigest !== sha256Canonical(execution) ||
      receiptBinding.nativeTransactionReference !== execution.nativeTransactionReference ||
      receiptBinding.dispositionDigest !== execution.dispositionDigest ||
      receiptBinding.custodyEvidenceDigest !== custodyDigest ||
      receiptBinding.railId !== custodyAtHandoff.railId
    ) reasons.add("ucp_path_receipt_mismatch");
  }

  if (posture === "escrow_held") {
    if (
      refundRequest !== null ||
      merchantApproval !== null ||
      receiptBinding.refundRequestDigest !== null ||
      receiptBinding.merchantApprovalDigest !== null
    ) reasons.add("ucp_path_refund_chain_mismatch");
  } else if (
    !refundRequest ||
    !merchantApproval ||
    refundRequest.requestDigest !== digestWithoutField(refundRequest, "requestDigest") ||
    merchantApproval.approvalDigest !== digestWithoutField(merchantApproval, "approvalDigest") ||
    merchantApproval.requestId !== refundRequest.requestId ||
    merchantApproval.requestDigest !== refundRequest.requestDigest ||
    refundRequest.dispositionId !== execution?.dispositionId ||
    refundRequest.dispositionDigest !== execution?.dispositionDigest ||
    refundRequest.railId !== custodyAtHandoff.railId ||
    merchantApproval.railId !== custodyAtHandoff.railId ||
    execution?.source !== "merchant:synthetic-settlement-account" ||
    receiptBinding.refundRequestDigest !== refundRequest.requestDigest ||
    receiptBinding.merchantApprovalDigest !== merchantApproval.approvalDigest
  ) reasons.add("ucp_path_refund_chain_mismatch");

  return [...reasons].sort();
}

export function projectUcpResolution(
  order: Record<string, unknown>,
  lifecycle: ResolutionLifecycle,
  lifecycleArtifactRef = "../../core/valid/lifecycle.json",
): Record<string, unknown> {
  const artifactRef = (pointer: string): string => lifecycleArtifactRef.startsWith("#")
    ? `${lifecycleArtifactRef}${pointer}`
    : `${lifecycleArtifactRef}#${pointer}`;
  const before = JSON.stringify(order);
  const projected = structuredClone(order);
  const capabilities = ((projected.ucp as Record<string, unknown> | undefined)?.capabilities ?? {}) as Record<string, unknown>;
  projected.ucp = {
    ...((projected.ucp as Record<string, unknown> | undefined) ?? {}),
    capabilities: {
      ...capabilities,
      [UCP_RESOLUTION_EXTENSION]: [{ version: UCP_RESOLUTION_EXTENSION_VERSION }],
    },
  };
  projected.external_resolution = {
    extension: UCP_RESOLUTION_EXTENSION,
    version: UCP_RESOLUTION_EXTENSION_VERSION,
    handoffs: [{
      handoff_id: lifecycle.handoff.handoffId,
      artifact_ref: artifactRef("/handoff"),
      sha256: sha256Canonical(lifecycle.handoff),
    }],
    dispositions: lifecycle.dispositions.map((item) => ({
      disposition_id: item.dispositionId,
      artifact_ref: artifactRef(`/dispositions/${lifecycle.dispositions.indexOf(item)}`),
      sha256: item.dispositionDigest,
      review_state: item.reviewState,
    })),
    executions: lifecycle.executions.map((item) => ({
      execution_id: item.executionId,
      disposition_id: item.dispositionId,
      artifact_ref: artifactRef(`/executions/${lifecycle.executions.indexOf(item)}`),
      sha256: sha256Canonical(item),
      status: item.status,
    })),
  };
  if (JSON.stringify(order) !== before) throw new Error("ucp_projection_mutated_input");
  return projected;
}
