import { sha256Canonical } from "./canonical.js";
import type {
  FrozenRecordManifest,
  LifecycleReasonCode,
  ResolutionDisposition,
  ResolutionExecutionReceipt,
  ResolutionHandoff,
  ResolutionLifecycle,
} from "./types.js";

const SHA256 = /^[a-f0-9]{64}$/;
const MINOR_UNITS = /^(0|[1-9][0-9]*)$/;

export function frozenRecordDigest(manifest: FrozenRecordManifest): string {
  return sha256Canonical(manifest);
}

export function handoffDigest(handoff: ResolutionHandoff): string {
  const { nativeVerification: _local, ...stable } = handoff;
  return sha256Canonical(stable);
}

export function dispositionDigest(
  disposition: Omit<ResolutionDisposition, "dispositionDigest"> & Partial<Pick<ResolutionDisposition, "dispositionDigest">>,
): string {
  const { dispositionDigest: _digest, ...stable } = disposition;
  return sha256Canonical(stable);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return [...left].sort().join("\n") === [...right].sort().join("\n");
}

function minorUnits(value: string): bigint | null {
  if (!MINOR_UNITS.test(value)) return null;
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

function exceedsCeiling(
  remedy: { action: string; currency: string; amountMinorUnits: string },
  handoff: ResolutionHandoff,
): boolean {
  const amount = minorUnits(remedy.amountMinorUnits);
  const ceiling = handoff.remedyCeilings.find(
    (candidate) => candidate.action === remedy.action && candidate.currency === remedy.currency,
  );
  const ceilingAmount = ceiling ? minorUnits(ceiling.amountMinorUnits) : null;
  return amount === null || ceilingAmount === null || amount > ceilingAmount;
}

export type LifecycleValidation = {
  ok: boolean;
  reasonCodes: LifecycleReasonCode[];
  handoffDigest: string;
  operativeDisposition: ResolutionDisposition | null;
  latestExecution: ResolutionExecutionReceipt | null;
};

export function validateLifecycle(
  input: ResolutionLifecycle,
  options: { now: Date },
): LifecycleValidation {
  const reasons = new Set<LifecycleReasonCode>();
  const { handoff } = input;
  const manifest = handoff.frozenRecord.manifest;
  const stableHandoffDigest = handoffDigest(handoff);

  if (
    handoff.schemaVersion !== "resolution-handoff-v1" ||
    manifest.schemaVersion !== "resolution-frozen-record-manifest-v1"
  ) reasons.add("handoff_schema_invalid");

  if (!Number.isFinite(Date.parse(handoff.expiresAt)) || Date.parse(handoff.expiresAt) <= options.now.getTime()) {
    reasons.add("handoff_expired");
  }

  if (!handoff.frozenRecord.digest) reasons.add("frozen_record_digest_missing");
  if (!SHA256.test(handoff.frozenRecord.digest) || handoff.frozenRecord.digest !== frozenRecordDigest(manifest)) {
    reasons.add("frozen_record_digest_mismatch");
  }

  if (
    handoff.transaction.transactionId !== manifest.transactionId ||
    handoff.transaction.orderId !== manifest.orderId ||
    handoff.transaction.transactionId !== input.expected.transactionId ||
    handoff.transaction.orderId !== input.expected.orderId
  ) reasons.add("transaction_reference_mismatch");

  if (
    !sameStrings(handoff.transaction.disputedLineItemIds, manifest.disputedLineItemIds) ||
    !sameStrings(handoff.transaction.disputedLineItemIds, input.expected.disputedLineItemIds)
  ) reasons.add("disputed_line_reference_mismatch");

  if (handoff.policy.digest !== manifest.policyDigest || handoff.policy.digest !== input.expected.currentPolicyDigest) {
    reasons.add("policy_digest_stale");
  }

  if (handoff.terms.digest !== manifest.termsDigest || handoff.terms.digest !== input.expected.currentTermsDigest) {
    reasons.add("terms_digest_stale");
  }

  if (
    handoff.authority.bilateral !== true ||
    !handoff.authority.claimantAuthorityRef ||
    !handoff.authority.respondentAuthorityRef ||
    !manifest.authorityRefs.includes(handoff.authority.claimantAuthorityRef) ||
    !manifest.authorityRefs.includes(handoff.authority.respondentAuthorityRef) ||
    !SHA256.test(handoff.authority.authorizationArtifactHash)
  ) reasons.add("party_authority_missing");

  if (!handoff.nativeProof.artifactRef || !SHA256.test(handoff.nativeProof.sha256) || !handoff.nativeProof.verificationMethod) {
    reasons.add("native_proof_missing");
  }

  if (exceedsCeiling(handoff.requestedRemedy, handoff)) reasons.add("remedy_above_ceiling");

  const byId = new Map<string, ResolutionDisposition>();
  const childCount = new Map<string, number>();
  for (const disposition of input.dispositions) {
    byId.set(disposition.dispositionId, disposition);
    if (disposition.dispositionDigest !== dispositionDigest(disposition)) reasons.add("disposition_digest_mismatch");
    if (disposition.handoffDigest !== stableHandoffDigest) reasons.add("disposition_handoff_mismatch");
    if (
      disposition.transactionId !== handoff.transaction.transactionId ||
      disposition.frozenRecordDigest !== handoff.frozenRecord.digest
    ) reasons.add("disposition_record_mismatch");
    if (exceedsCeiling(disposition.authorizedRemedy, handoff)) reasons.add("remedy_above_ceiling");
    if (disposition.supersedesDispositionId) {
      childCount.set(
        disposition.supersedesDispositionId,
        (childCount.get(disposition.supersedesDispositionId) ?? 0) + 1,
      );
    }
  }

  if ([...childCount.values()].some((count) => count > 1)) reasons.add("supersession_fork");
  for (const start of input.dispositions) {
    const seen = new Set<string>();
    let current: ResolutionDisposition | undefined = start;
    while (current?.supersedesDispositionId) {
      if (seen.has(current.dispositionId)) {
        reasons.add("supersession_cycle");
        break;
      }
      seen.add(current.dispositionId);
      current = byId.get(current.supersedesDispositionId);
    }
  }

  const operative = byId.get(input.operativeDispositionId) ?? null;
  if (!operative) reasons.add("operative_disposition_missing");
  if (
    operative &&
    (operative.reviewState === "superseded" ||
      operative.reviewState === "vacated" ||
      input.dispositions.some((candidate) => candidate.supersedesDispositionId === operative.dispositionId))
  ) reasons.add("superseded_disposition_operative");

  let latestExecution: ResolutionExecutionReceipt | null = null;
  if (operative) {
    const authorizedAmount = minorUnits(operative.authorizedRemedy.amountMinorUnits);
    for (const execution of input.executions) {
      if (
        execution.dispositionId !== operative.dispositionId ||
        execution.dispositionDigest !== operative.dispositionDigest
      ) {
        reasons.add("execution_disposition_mismatch");
        continue;
      }
      latestExecution = execution;
      const executedAmount = minorUnits(execution.amountMinorUnits);
      if (
        executedAmount === null ||
        authorizedAmount === null ||
        execution.action !== operative.authorizedRemedy.action ||
        execution.currency !== operative.authorizedRemedy.currency ||
        executedAmount > authorizedAmount
      ) reasons.add("execution_outside_authority");

      if (execution.status === "completed") {
        if (
          !execution.nativeTransactionReference ||
          !execution.receiptProof ||
          execution.receiptProof.verificationStatus !== "passed" ||
          !SHA256.test(execution.receiptProof.sha256)
        ) reasons.add("execution_receipt_missing");

        if (
          execution.receiptProof &&
          input.dispositions.some(
            (candidate) =>
              candidate.signedArtifact.artifactRef === execution.receiptProof?.artifactRef ||
              candidate.signedArtifact.sha256 === execution.receiptProof?.sha256,
          )
        ) reasons.add("decision_not_execution");
      } else if (execution.status !== "pending" && !execution.failureCode) {
        reasons.add("execution_failure_code_missing");
      }
    }
  }

  return {
    ok: reasons.size === 0,
    reasonCodes: [...reasons].sort(),
    handoffDigest: stableHandoffDigest,
    operativeDisposition: operative,
    latestExecution,
  };
}
