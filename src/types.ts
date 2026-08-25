export type ProtocolId = "ucp" | "ap2" | "x402" | "a2a" | "agentic_checkout_acp" | "virtuals_acp" | "custom";
export type ResolutionAction = "refund" | "release_to_claimant" | "release_to_respondent" | "allocate_by_award" | "replace_product" | "none";

export type Money = {
  currency: string;
  amountMinorUnits: string;
};

export type FrozenRecordManifest = {
  schemaVersion: "resolution-frozen-record-manifest-v1";
  transactionId: string;
  orderId: string;
  disputedLineItemIds: string[];
  policyDigest: string;
  termsDigest: string;
  authorityRefs: string[];
  includedArtifacts: Array<{
    artifactId: string;
    sha256: string;
    mediaType: string;
    source: string;
  }>;
  excludedArtifacts: Array<{
    artifactId: string;
    reason: "verifier_local_metadata" | "outside_claim_scope" | "duplicate";
  }>;
};

export type ResolutionHandoff = {
  schemaVersion: "resolution-handoff-v1";
  handoffId: string;
  disputeId: string;
  nativeProtocol: ProtocolId;
  transaction: {
    transactionId: string;
    orderId: string;
    checkoutId?: string;
    disputedLineItemIds: string[];
  };
  roles: {
    claimant: string;
    respondent: string;
    recordIssuer: string;
    resolver: string;
    executor?: string;
  };
  claim: {
    claimId: string;
    claimType: string;
    artifactRef: string;
    artifactHash: string;
  };
  merchantResponse: {
    response: "accepted" | "partially_accepted" | "denied" | "no_response";
    artifactRef: string;
    artifactHash: string;
  };
  requestedRemedy: Money & { action: ResolutionAction };
  authority: {
    bilateral: true;
    claimantAuthorityRef: string;
    respondentAuthorityRef: string;
    authorizationArtifactHash: string;
  };
  policy: { version: string; digest: string };
  terms: { version: string; digest: string };
  frozenRecord: {
    canonicalization: "RFC8785";
    digestAlgorithm: "SHA-256";
    manifest: FrozenRecordManifest;
    digest: string;
  };
  remedyCeilings: Array<Money & { action: ResolutionAction }>;
  resolver: { resolverId: string; rulesetId: string; rulesVersion: string };
  createdAt: string;
  expiresAt: string;
  nativeProof: { artifactRef: string; sha256: string; verificationMethod: string };
  nativeVerification?: { verifierId: string; verifiedAt: string; fetchMetadata?: Record<string, unknown> };
};

export type ResolutionDisposition = {
  schemaVersion: "resolution-disposition-v1";
  dispositionId: string;
  dispositionDigest: string;
  handoffDigest: string;
  transactionId: string;
  frozenRecordDigest: string;
  outcome: string;
  authorizedRemedy: Money & { action: ResolutionAction };
  issuedAt: string;
  issuerRef: string;
  reviewState: "draft" | "served" | "final" | "superseded" | "vacated";
  supersedesDispositionId?: string;
  signedArtifact: { artifactRef: string; sha256: string };
};

export type ResolutionExecutionReceipt = {
  schemaVersion: "resolution-execution-receipt-v1";
  executionId: string;
  dispositionId: string;
  dispositionDigest: string;
  action: ResolutionAction;
  currency: string;
  amountMinorUnits: string;
  source: string;
  destination: string;
  nativeTransactionReference: string | null;
  status: "not_attempted" | "pending" | "completed" | "failed" | "blocked" | "unknown_outcome";
  providerRef: string;
  recordedAt: string;
  receiptProof: { artifactRef: string; sha256: string; verificationStatus: "passed" | "failed" } | null;
  failureCode?: string;
};

export type ResolutionLifecycle = {
  handoff: ResolutionHandoff;
  dispositions: ResolutionDisposition[];
  operativeDispositionId: string;
  executions: ResolutionExecutionReceipt[];
  expected: {
    transactionId: string;
    orderId: string;
    disputedLineItemIds: string[];
    currentPolicyDigest: string;
    currentTermsDigest: string;
  };
};

export type LifecycleReasonCode =
  | "handoff_schema_invalid"
  | "handoff_expired"
  | "frozen_record_digest_missing"
  | "frozen_record_digest_mismatch"
  | "transaction_reference_mismatch"
  | "disputed_line_reference_mismatch"
  | "policy_digest_stale"
  | "terms_digest_stale"
  | "party_authority_missing"
  | "native_proof_missing"
  | "disposition_digest_mismatch"
  | "remedy_above_ceiling"
  | "disposition_handoff_mismatch"
  | "disposition_record_mismatch"
  | "disposition_id_duplicate"
  | "disposition_graph_disconnected"
  | "operative_disposition_missing"
  | "superseded_disposition_operative"
  | "supersession_target_missing"
  | "supersession_cycle"
  | "supersession_fork"
  | "execution_disposition_mismatch"
  | "execution_executor_missing"
  | "execution_id_duplicate"
  | "execution_reference_duplicate"
  | "execution_outside_authority"
  | "execution_receipt_missing"
  | "execution_failure_code_missing"
  | "decision_not_execution";
