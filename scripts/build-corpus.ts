import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AuthorizationTrustKey, GeneralJws } from "../src/authorization.js";
import { verifyBilateralAuthorization } from "../src/authorization.js";
import { canonicalJson, sha256Bytes, sha256Canonical } from "../src/canonical.js";
import { verifyLcpBundle } from "../src/lcp.js";
import { dispositionDigest, frozenRecordDigest, handoffDigest, validateLifecycle } from "../src/lifecycle.js";
import {
  CATALOG,
  CLAUSE_TEXT,
  DISCOVERY,
  FIXED_VERIFICATION_TIME,
  RULES_TEXT,
  TERMS_TEXT,
  URLS,
  catalogSha256,
  catalogText,
  clauseId,
  discoveryText,
  providerId,
  rulesSha256,
  serviceId,
  termsSha256,
} from "../src/scenario.js";
import type { ResolutionDisposition, ResolutionExecutionReceipt, ResolutionLifecycle } from "../src/types.js";
import {
  projectUcpResolution,
  sealUcpPathLifecycle,
  validateUcpPressureTestPath,
  type UcpExecutionPosture,
  type UcpFundsStateEvidence,
  type UcpMerchantApproval,
  type UcpPressureTestFixture,
  type UcpRefundRequest,
} from "../src/ucp.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURES = path.join(ROOT, "fixtures");
const utf8 = (value: string): Uint8Array => Buffer.from(value, "utf8");
const clone = <T>(value: T): T => structuredClone(value);
const writeText = (relative: string, value: string): void => {
  const target = path.join(FIXTURES, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, value);
};
const writeJson = (relative: string, value: unknown): void => writeText(relative, `${JSON.stringify(value, null, 2)}\n`);
const readJson = <T>(relative: string): T => JSON.parse(fs.readFileSync(path.join(FIXTURES, relative), "utf8")) as T;

writeText("lcp/artifacts/terms.md", TERMS_TEXT);
writeText("lcp/artifacts/dispute-clause.md", CLAUSE_TEXT);
writeText("lcp/artifacts/rules.md", RULES_TEXT);
writeText("lcp/artifacts/legal-context.json", discoveryText);
writeText("lcp/artifacts/dispute-services.json", catalogText);

const verifiedLcp = verifyLcpBundle({
  legalContext: { url: URLS.discovery, bytes: utf8(discoveryText), mediaType: "application/json" },
  terms: { url: URLS.terms, bytes: utf8(TERMS_TEXT), mediaType: "text/markdown; charset=utf-8" },
  clause: { url: URLS.clause, bytes: utf8(CLAUSE_TEXT), mediaType: "text/markdown; charset=utf-8" },
  rules: { url: URLS.rules, bytes: utf8(RULES_TEXT), mediaType: "text/markdown; charset=utf-8" },
  catalog: { url: URLS.catalog, bytes: utf8(catalogText), mediaType: "application/json", serviceId },
});
writeJson("lcp/valid/verified-binding.json", verifiedLcp);

const authorizationJws = readJson<GeneralJws>("core/valid/resolution-authorization-v1.json");
const authorizationKeys = readJson<AuthorizationTrustKey[]>("core/valid/resolution-authorization-public-keys.json");
const authorization = await verifyBilateralAuthorization({
  jws: authorizationJws,
  trustedKeys: authorizationKeys,
  expected: {
    transactionId: "tx-neutral-001",
    orderId: "order-neutral-001",
    disputedLineItemIds: ["line-002"],
    termsAtrHash: `0x${termsSha256}`,
    clauseId,
    rulesSha256,
    catalogSha256,
    providerId,
    serviceId,
  },
  now: new Date(FIXED_VERIFICATION_TIME),
});

const manifest = {
  schemaVersion: "resolution-frozen-record-manifest-v1" as const,
  transactionId: "tx-neutral-001",
  orderId: "order-neutral-001",
  disputedLineItemIds: ["line-002"],
  policyDigest: rulesSha256,
  termsDigest: termsSha256,
  authorityRefs: ["authority:buyer:001", "authority:merchant:001"],
  includedArtifacts: [
    { artifactId: "ucp-order.json", sha256: "3".repeat(64), mediaType: "application/json", source: "synthetic-commerce-order" },
    { artifactId: "claim.json", sha256: "4".repeat(64), mediaType: "application/json", source: "synthetic-buyer-record" },
    { artifactId: "merchant-response.json", sha256: "5".repeat(64), mediaType: "application/json", source: "synthetic-merchant-record" },
    { artifactId: "legal-context.json", sha256: verifiedLcp.legalContext.sha256, mediaType: "application/json", source: "lcp-exact-bytes" },
    { artifactId: "terms.md", sha256: termsSha256, mediaType: "text/markdown", source: "lcp-exact-bytes" },
    { artifactId: "dispute-clause.md", sha256: verifiedLcp.clause.sha256, mediaType: "text/markdown", source: "lcp-exact-bytes" },
    { artifactId: "rules.md", sha256: rulesSha256, mediaType: "text/markdown", source: "lcp-exact-bytes" },
    { artifactId: "dispute-services.json", sha256: catalogSha256, mediaType: "application/json", source: "lcp-exact-bytes" },
  ],
  excludedArtifacts: [{ artifactId: "verifier-observation.json", reason: "verifier_local_metadata" as const }],
};

const handoff = {
  schemaVersion: "resolution-handoff-v1" as const,
  handoffId: "handoff-neutral-001",
  disputeId: "dispute-neutral-001",
  nativeProtocol: "ucp" as const,
  transaction: {
    transactionId: manifest.transactionId,
    orderId: manifest.orderId,
    checkoutId: "checkout-neutral-001",
    disputedLineItemIds: [...manifest.disputedLineItemIds],
  },
  roles: {
    claimant: "principal:buyer:001",
    respondent: "principal:merchant:001",
    recordIssuer: "issuer:synthetic-merchant-ledger",
    resolver: providerId,
    executor: "executor:synthetic-refund-service",
  },
  claim: { claimId: "claim-neutral-001", claimType: "non_delivery", artifactRef: "claim.json", artifactHash: "4".repeat(64) },
  merchantResponse: { response: "denied" as const, artifactRef: "merchant-response.json", artifactHash: "5".repeat(64) },
  requestedRemedy: { action: "refund" as const, currency: "USD", amountMinorUnits: "2500" },
  authority: {
    bilateral: true as const,
    claimantAuthorityRef: "authority:buyer:001",
    respondentAuthorityRef: "authority:merchant:001",
    authorizationArtifactHash: authorization.artifactHash,
  },
  policy: { version: "1.0.0", digest: rulesSha256 },
  terms: { version: "lcp-0.1.38", digest: termsSha256 },
  frozenRecord: { canonicalization: "RFC8785" as const, digestAlgorithm: "SHA-256" as const, manifest, digest: frozenRecordDigest(manifest) },
  remedyCeilings: [{ action: "refund" as const, currency: "USD", amountMinorUnits: "5000" }],
  resolver: { resolverId: providerId, rulesetId: CATALOG.services[0].rules.id, rulesVersion: CATALOG.services[0].rules.version },
  createdAt: "2026-08-24T16:00:00.000Z",
  expiresAt: "2027-08-24T16:00:00.000Z",
  nativeProof: { artifactRef: "ucp-order-signature.json", sha256: "6".repeat(64), verificationMethod: "upstream-protocol-verification-receipt" },
};

const first: ResolutionDisposition = {
  schemaVersion: "resolution-disposition-v1",
  dispositionId: "disposition-neutral-001",
  dispositionDigest: "",
  handoffDigest: handoffDigest(handoff),
  transactionId: manifest.transactionId,
  frozenRecordDigest: handoff.frozenRecord.digest,
  outcome: "claim_granted",
  authorizedRemedy: { action: "refund", currency: "USD", amountMinorUnits: "2500" },
  issuedAt: "2026-08-25T12:00:00.000Z",
  issuerRef: "tribunal:synthetic-neutral",
  reviewState: "superseded",
  signedArtifact: { artifactRef: "award-revision-1.json", sha256: "7".repeat(64) },
};
first.dispositionDigest = dispositionDigest(first);
const correction: ResolutionDisposition = {
  ...clone(first),
  dispositionId: "disposition-neutral-002",
  dispositionDigest: "",
  outcome: "claim_partially_granted",
  authorizedRemedy: { action: "refund", currency: "USD", amountMinorUnits: "2000" },
  issuedAt: "2026-08-26T12:00:00.000Z",
  reviewState: "final",
  supersedesDispositionId: first.dispositionId,
  signedArtifact: { artifactRef: "award-revision-2.json", sha256: "8".repeat(64) },
};
correction.dispositionDigest = dispositionDigest(correction);

const lifecycle: ResolutionLifecycle = {
  handoff,
  dispositions: [first, correction],
  operativeDispositionId: correction.dispositionId,
  executions: [{
    schemaVersion: "resolution-execution-receipt-v1",
    executionId: "execution-neutral-001",
    dispositionId: correction.dispositionId,
    dispositionDigest: correction.dispositionDigest,
    action: "refund",
    currency: "USD",
    amountMinorUnits: "2000",
    source: "merchant:synthetic-refund-ledger",
    destination: "buyer:synthetic-account",
    nativeTransactionReference: "refund:synthetic:001",
    status: "completed",
    providerRef: "provider:synthetic-refund-service",
    recordedAt: "2026-08-26T12:05:00.000Z",
    receiptProof: { artifactRef: "synthetic-refund-receipt.json", sha256: "9".repeat(64), verificationStatus: "passed" },
  }],
  expected: {
    transactionId: manifest.transactionId,
    orderId: manifest.orderId,
    disputedLineItemIds: [...manifest.disputedLineItemIds],
    currentPolicyDigest: manifest.policyDigest,
    currentTermsDigest: manifest.termsDigest,
  },
};
const valid = validateLifecycle(lifecycle, { now: new Date(FIXED_VERIFICATION_TIME) });
if (!valid.ok) throw new Error(`valid lifecycle failed: ${valid.reasonCodes.join(", ")}`);
writeJson("core/valid/lifecycle.json", lifecycle);
writeJson("core/valid/expected-digests.json", {
  frozenRecordDigest: handoff.frozenRecord.digest,
  handoffDigest: valid.handoffDigest,
  dispositionDigests: Object.fromEntries(lifecycle.dispositions.map((item) => [item.dispositionId, item.dispositionDigest])),
  authorizationArtifactHash: authorization.artifactHash,
});

const advisoryLifecycle = clone(lifecycle);
advisoryLifecycle.handoff.handoffId = "handoff-neutral-advisory-001";
advisoryLifecycle.handoff.disputeId = "dispute-neutral-advisory-001";
delete advisoryLifecycle.handoff.roles.executor;
advisoryLifecycle.executions = [];
const advisoryHandoffDigest = handoffDigest(advisoryLifecycle.handoff);
const advisoryFirst = advisoryLifecycle.dispositions[0]!;
advisoryFirst.dispositionId = "disposition-neutral-advisory-001";
advisoryFirst.handoffDigest = advisoryHandoffDigest;
advisoryFirst.signedArtifact = { artifactRef: "advisory-ruling-revision-1.json", sha256: "a".repeat(64) };
advisoryFirst.dispositionDigest = dispositionDigest(advisoryFirst);
const advisoryFinal = advisoryLifecycle.dispositions[1]!;
advisoryFinal.dispositionId = "disposition-neutral-advisory-002";
advisoryFinal.handoffDigest = advisoryHandoffDigest;
advisoryFinal.supersedesDispositionId = advisoryFirst.dispositionId;
advisoryFinal.signedArtifact = { artifactRef: "advisory-ruling-revision-2.json", sha256: "b".repeat(64) };
advisoryFinal.dispositionDigest = dispositionDigest(advisoryFinal);
advisoryLifecycle.operativeDispositionId = advisoryFinal.dispositionId;
const validAdvisory = validateLifecycle(advisoryLifecycle, { now: new Date(FIXED_VERIFICATION_TIME) });
if (!validAdvisory.ok) throw new Error(`valid advisory lifecycle failed: ${validAdvisory.reasonCodes.join(", ")}`);
writeJson("core/valid/advisory-lifecycle.json", advisoryLifecycle);

const unilateralAuthorization = clone(authorizationJws);
unilateralAuthorization.signatures = unilateralAuthorization.signatures.slice(0, 1);
writeJson("core/negative/resolution-authorization-one-signature.json", unilateralAuthorization);

function resealLifecycle(value: ResolutionLifecycle): void {
  value.handoff.frozenRecord.digest = frozenRecordDigest(value.handoff.frozenRecord.manifest);
  const digest = handoffDigest(value.handoff);
  for (const disposition of value.dispositions) {
    disposition.handoffDigest = digest;
    disposition.frozenRecordDigest = value.handoff.frozenRecord.digest;
    disposition.dispositionDigest = dispositionDigest(disposition);
  }
  const operative = value.dispositions.find((disposition) => disposition.dispositionId === value.operativeDispositionId);
  if (operative) {
    for (const execution of value.executions) {
      if (execution.dispositionId === operative.dispositionId) execution.dispositionDigest = operative.dispositionDigest;
    }
  }
}

const mutations: Array<{ id: string; code: string; mutate: (value: ResolutionLifecycle) => void }> = [
  { id: "missing-frozen-record-digest", code: "frozen_record_digest_missing", mutate: (v) => { v.handoff.frozenRecord.digest = ""; } },
  { id: "changed-frozen-record", code: "frozen_record_digest_mismatch", mutate: (v) => { v.handoff.frozenRecord.manifest.includedArtifacts[0]!.sha256 = "a".repeat(64); } },
  { id: "wrong-order-reference", code: "transaction_reference_mismatch", mutate: (v) => { v.handoff.transaction.orderId = "order-other"; } },
  { id: "wrong-line-item", code: "disputed_line_reference_mismatch", mutate: (v) => { v.handoff.transaction.disputedLineItemIds = ["line-001"]; } },
  { id: "stale-policy", code: "policy_digest_stale", mutate: (v) => { v.handoff.policy.digest = "a".repeat(64); } },
  { id: "stale-terms", code: "terms_digest_stale", mutate: (v) => { v.handoff.terms.digest = "b".repeat(64); } },
  {
    id: "missing-party-authority",
    code: "party_authority_missing",
    mutate: (v) => {
      v.handoff.authority.respondentAuthorityRef = "";
      v.handoff.authority.authorizationArtifactHash = sha256Canonical(unilateralAuthorization);
      v.handoff.frozenRecord.manifest.authorityRefs = [v.handoff.authority.claimantAuthorityRef];
      resealLifecycle(v);
    },
  },
  { id: "remedy-above-ceiling", code: "remedy_above_ceiling", mutate: (v) => { v.dispositions[1]!.authorizedRemedy.amountMinorUnits = "5001"; } },
  { id: "disposition-other-record", code: "disposition_record_mismatch", mutate: (v) => { v.dispositions[1]!.frozenRecordDigest = "c".repeat(64); } },
  { id: "superseded-operative", code: "superseded_disposition_operative", mutate: (v) => { v.operativeDispositionId = v.dispositions[0]!.dispositionId; } },
  { id: "supersession-cycle", code: "supersession_cycle", mutate: (v) => { v.dispositions[0]!.supersedesDispositionId = v.dispositions[1]!.dispositionId; } },
  { id: "supersession-fork", code: "supersession_fork", mutate: (v) => { const third = clone(v.dispositions[1]!); third.dispositionId = "disposition-neutral-003"; third.dispositionDigest = dispositionDigest(third); v.dispositions.push(third); } },
  { id: "duplicate-disposition-id", code: "disposition_id_duplicate", mutate: (v) => { v.dispositions.push(clone(v.dispositions[0]!)); } },
  {
    id: "missing-supersession-target",
    code: "supersession_target_missing",
    mutate: (v) => {
      v.dispositions[1]!.supersedesDispositionId = "disposition-does-not-exist";
      resealLifecycle(v);
    },
  },
  {
    id: "disconnected-disposition-graph",
    code: "disposition_graph_disconnected",
    mutate: (v) => {
      const disconnected = clone(v.dispositions[1]!);
      disconnected.dispositionId = "disposition-neutral-003";
      delete disconnected.supersedesDispositionId;
      disconnected.dispositionDigest = dispositionDigest(disconnected);
      v.dispositions.push(disconnected);
    },
  },
  { id: "execution-other-disposition", code: "execution_disposition_mismatch", mutate: (v) => { v.executions[0]!.dispositionId = v.dispositions[0]!.dispositionId; } },
  {
    id: "execution-without-executor",
    code: "execution_executor_missing",
    mutate: (v) => {
      delete v.handoff.roles.executor;
      resealLifecycle(v);
    },
  },
  { id: "execution-outside-authorization", code: "execution_outside_authority", mutate: (v) => { v.executions[0]!.amountMinorUnits = "2001"; } },
  {
    id: "duplicate-execution-id",
    code: "execution_id_duplicate",
    mutate: (v) => {
      const replay = clone(v.executions[0]!);
      replay.status = "pending";
      replay.amountMinorUnits = "0";
      replay.nativeTransactionReference = null;
      replay.receiptProof = null;
      replay.recordedAt = "2026-08-26T12:06:00.000Z";
      v.executions.push(replay);
    },
  },
  {
    id: "duplicate-execution-reference",
    code: "execution_reference_duplicate",
    mutate: (v) => {
      v.executions[0]!.amountMinorUnits = "1000";
      const replay = clone(v.executions[0]!);
      replay.executionId = "execution-neutral-002";
      replay.recordedAt = "2026-08-26T12:06:00.000Z";
      replay.receiptProof = {
        artifactRef: "synthetic-refund-receipt-002.json",
        sha256: "c".repeat(64),
        verificationStatus: "passed",
      };
      v.executions.push(replay);
    },
  },
  {
    id: "cumulative-execution-overrun",
    code: "execution_outside_authority",
    mutate: (v) => {
      const replay = clone(v.executions[0]!);
      replay.executionId = "execution-neutral-002";
      replay.nativeTransactionReference = "refund:synthetic:002";
      replay.recordedAt = "2026-08-26T12:06:00.000Z";
      replay.receiptProof = {
        artifactRef: "synthetic-refund-receipt-002.json",
        sha256: "c".repeat(64),
        verificationStatus: "passed",
      };
      v.executions.push(replay);
    },
  },
  { id: "completed-without-receipt", code: "execution_receipt_missing", mutate: (v) => { v.executions[0]!.receiptProof = null; } },
  { id: "decision-as-execution", code: "decision_not_execution", mutate: (v) => { v.executions[0]!.receiptProof = { ...v.dispositions[1]!.signedArtifact, verificationStatus: "passed" }; } },
  {
    id: "line-item-delimiter-collision",
    code: "disputed_line_reference_mismatch",
    mutate: (v) => {
      v.handoff.transaction.disputedLineItemIds = ["line-002\nline-extra"];
      v.handoff.frozenRecord.manifest.disputedLineItemIds = ["line-002", "line-extra"];
      v.expected.disputedLineItemIds = ["line-002", "line-extra"];
      resealLifecycle(v);
    },
  },
];
const negativeIndex = [];
for (const mutation of mutations) {
  const candidate = clone(lifecycle);
  mutation.mutate(candidate);
  const result = validateLifecycle(candidate, { now: new Date(FIXED_VERIFICATION_TIME) });
  if (!result.reasonCodes.includes(mutation.code as never)) throw new Error(`${mutation.id} did not produce ${mutation.code}`);
  const relative = `core/negative/${mutation.id}.json`;
  writeJson(relative, { id: mutation.id, expectedReasonCode: mutation.code, lifecycle: candidate });
  negativeIndex.push({ id: mutation.id, path: relative.replace("core/", ""), expectedReasonCode: mutation.code });
}

const order = {
  ucp: {
    version: "2026-04-08",
    status: "success",
    capabilities: { "dev.ucp.shopping.order": [{ version: "2026-04-08" }] },
  },
  id: "order-neutral-001",
  checkout_id: "checkout-neutral-001",
  permalink_url: "https://merchant.example.test/orders/order-neutral-001",
  line_items: [{
    id: "line-002",
    item: { id: "item-002", title: "Undelivered synthetic item", price: 2500 },
    quantity: { original: 1, total: 1, fulfilled: 0 },
    totals: [{ type: "total", amount: 2500 }],
    status: "processing",
  }],
  currency: "USD",
  totals: [{ type: "total", amount: 2500 }],
};
writeJson("ucp/source/order.json", order);

function buildUcpPath(posture: UcpExecutionPosture): UcpPressureTestFixture {
  const escrowHeld = posture === "escrow_held";
  const railId = "rail:synthetic-original-payment";
  const executor = escrowHeld
    ? "executor:synthetic-escrow-controller"
    : "executor:synthetic-merchant-refund-service";
  const custodyAtHandoff: UcpFundsStateEvidence = {
    schemaVersion: "neutral-funds-state-evidence-v1",
    evidenceId: escrowHeld ? "funds-state-escrow-held-001" : "funds-state-merchant-settled-001",
    posture,
    transactionId: lifecycle.handoff.transaction.transactionId,
    orderId: lifecycle.handoff.transaction.orderId,
    state: escrowHeld ? "held_by_escrow" : "settled_to_merchant",
    custodyOwner: escrowHeld ? "custodian:synthetic-escrow" : "principal:merchant:001",
    railId,
    currency: "USD",
    amountMinorUnits: "2500",
    observedAt: "2026-08-24T15:59:00.000Z",
    proof: {
      artifactRef: escrowHeld ? "synthetic-escrow-hold-proof.json" : "synthetic-merchant-settlement-release-proof.json",
      sha256: escrowHeld ? "a".repeat(64) : "b".repeat(64),
      verificationStatus: "passed",
    },
  };
  const execution: ResolutionExecutionReceipt = {
    schemaVersion: "resolution-execution-receipt-v1",
    executionId: escrowHeld ? "execution-escrow-held-001" : "execution-merchant-refund-001",
    dispositionId: "",
    dispositionDigest: "",
    action: "refund",
    currency: "USD",
    amountMinorUnits: "2000",
    source: escrowHeld ? "escrow:synthetic-custody-account" : "merchant:synthetic-settlement-account",
    destination: "buyer:synthetic-original-payment-account",
    nativeTransactionReference: escrowHeld ? "escrow-refund:synthetic:001" : "refund:same-rail:synthetic:001",
    status: "completed",
    providerRef: executor,
    recordedAt: "2026-08-26T12:05:00.000Z",
    receiptProof: {
      artifactRef: escrowHeld
        ? "synthetic-escrow-controller-receipt.json"
        : "synthetic-merchant-same-rail-refund-receipt.json",
      sha256: escrowHeld ? "c".repeat(64) : "d".repeat(64),
      verificationStatus: "passed",
    },
  };
  const pathLifecycle = sealUcpPathLifecycle(lifecycle, custodyAtHandoff, executor, execution);
  const operative = pathLifecycle.dispositions.find((item) => item.dispositionId === pathLifecycle.operativeDispositionId)!;
  const requestBase = escrowHeld ? null : {
    schemaVersion: "neutral-refund-request-v1" as const,
    requestId: "refund-request-merchant-001",
    dispositionId: operative.dispositionId,
    dispositionDigest: operative.dispositionDigest,
    railId,
    currency: operative.authorizedRemedy.currency,
    amountMinorUnits: operative.authorizedRemedy.amountMinorUnits,
    requestedFrom: "principal:merchant:001",
    requestedAt: "2026-08-26T12:01:00.000Z",
  };
  const refundRequest: UcpRefundRequest | null = requestBase
    ? { ...requestBase, requestDigest: sha256Canonical(requestBase) }
    : null;
  const approvalBase = refundRequest ? {
    schemaVersion: "neutral-merchant-refund-approval-v1" as const,
    approvalId: "merchant-refund-approval-001",
    requestId: refundRequest.requestId,
    requestDigest: refundRequest.requestDigest,
    approver: "principal:merchant:001",
    approved: true as const,
    railId,
    currency: refundRequest.currency,
    amountMinorUnits: refundRequest.amountMinorUnits,
    approvedAt: "2026-08-26T12:03:00.000Z",
  } : null;
  const merchantApproval: UcpMerchantApproval | null = approvalBase
    ? { ...approvalBase, approvalDigest: sha256Canonical(approvalBase) }
    : null;
  const pathExecution = pathLifecycle.executions[0]!;
  const fixture: UcpPressureTestFixture = {
    schemaVersion: "ucp-resolution-pressure-test-v1",
    synthetic: true,
    neutralFixtureShape: true,
    pressureTest: escrowHeld
      ? {
          posture,
          executorExpectation: "Frozen hold evidence identifies the escrow custodian; only the named escrow controller executes the bounded refund and returns a distinct receipt.",
          nativeReceiptKind: "escrow-controller-release-or-refund-receipt",
          westonMappingRequired: [
            "Map the neutral custody evidence to the implementation's actual escrow hold proof.",
            "Map the neutral execution receipt to the escrow controller's native receipt without treating the disposition as execution.",
          ],
        }
      : {
          posture,
          executorExpectation: "Frozen settlement evidence proves prior release to the merchant; a disposition-bound request, merchant approval, and same-rail send-back receipt remain separate artifacts.",
          nativeReceiptKind: "merchant-same-rail-refund-receipt",
          westonMappingRequired: [
            "Map the neutral settlement evidence to the implementation's actual merchant-settlement or release proof.",
            "Map request, approval, and receipt digests to native fields while preserving their separate identities and same-rail relationship.",
          ],
        },
    executionEvidence: {
      custodyAtHandoff,
      refundRequest,
      merchantApproval,
      receiptBinding: {
        executionId: pathExecution.executionId,
        receiptDigest: sha256Canonical(pathExecution),
        nativeTransactionReference: pathExecution.nativeTransactionReference!,
        dispositionDigest: pathExecution.dispositionDigest,
        custodyEvidenceDigest: sha256Canonical(custodyAtHandoff),
        refundRequestDigest: refundRequest?.requestDigest ?? null,
        merchantApprovalDigest: merchantApproval?.approvalDigest ?? null,
        railId,
      },
    },
    lifecycle: pathLifecycle,
    order: projectUcpResolution(order, pathLifecycle, "#/lifecycle"),
  };
  const reasons = validateUcpPressureTestPath(fixture, { now: new Date(FIXED_VERIFICATION_TIME) });
  if (reasons.length > 0) throw new Error(`${posture} UCP path failed: ${reasons.join(", ")}`);
  return fixture;
}

const escrowPath = buildUcpPath("escrow_held");
const merchantRefundPath = buildUcpPath("post_settlement_merchant_refund");
writeJson("ucp/paths/escrow-held.json", escrowPath);
writeJson("ucp/paths/post-settlement-merchant-refund.json", merchantRefundPath);

const ucpNegativeVectors = [
  {
    id: "swapped-executor",
    expectedReasonCode: "ucp_path_executor_mismatch",
    fixture: (() => {
      const value = clone(escrowPath);
      value.lifecycle.executions[0]!.providerRef = "executor:synthetic-merchant-refund-service";
      return value;
    })(),
  },
  {
    id: "swapped-receipt",
    expectedReasonCode: "ucp_path_receipt_mismatch",
    fixture: (() => {
      const value = clone(escrowPath);
      value.lifecycle.executions[0]!.receiptProof = clone(merchantRefundPath.lifecycle.executions[0]!.receiptProof);
      return value;
    })(),
  },
  {
    id: "swapped-custody-evidence",
    expectedReasonCode: "ucp_path_custody_evidence_mismatch",
    fixture: (() => {
      const value = clone(escrowPath);
      value.executionEvidence.custodyAtHandoff = clone(merchantRefundPath.executionEvidence.custodyAtHandoff);
      return value;
    })(),
  },
];
for (const vector of ucpNegativeVectors) {
  const reasons = validateUcpPressureTestPath(vector.fixture, { now: new Date(FIXED_VERIFICATION_TIME) });
  if (!reasons.includes(vector.expectedReasonCode as never)) {
    throw new Error(`${vector.id} UCP vector did not produce ${vector.expectedReasonCode}`);
  }
  writeJson(`ucp/negative/${vector.id}.json`, vector);
}

const opaqueMandate = "synthetic.ap2.mandate.bytes.must.remain.identical";
writeJson("lcp/protocols/placement-input.json", {
  ref: { type: "sha256", value: `0x${termsSha256}` },
  legalContextUrl: URLS.discovery,
  ap2Mandate: opaqueMandate,
});
writeJson("lcp/protocols/input/ap2.json", {
  kind: "message",
  messageId: "message-neutral-001",
  parts: [{ kind: "data", data: { "ap2.mandates.CheckoutMandateSdJwt": opaqueMandate } }],
});
writeJson("lcp/protocols/input/ucp.json", { id: "checkout-neutral-001", policies: [{ type: "example.existing", description: { plain: "Preserve this policy." } }] });
writeJson("lcp/protocols/input/x402.json", {
  x402Version: 2,
  accepts: [{ scheme: "exact", network: "base-sepolia", maxAmountRequired: "5000", extra: { asset: "synthetic-usdc" } }],
  extensions: { exampleSibling: { preserved: true } },
});

writeJson("core/manifest.json", {
  schemaVersion: "agentic-resolution-interop-corpus-v1",
  corpusVersion: "0.1.1",
  synthetic: true,
  validationTime: FIXED_VERIFICATION_TIME,
  validJourney: "valid/lifecycle.json",
  advisoryJourney: "valid/advisory-lifecycle.json",
  authorization: {
    jws: "valid/resolution-authorization-v1.json",
    publicKeys: "valid/resolution-authorization-public-keys.json",
  },
  lcpProfile: "../lcp/valid/verified-binding.json",
  ucpPressureTests: [
    "../ucp/paths/escrow-held.json",
    "../ucp/paths/post-settlement-merchant-refund.json",
  ],
  ucpNegativeTests: ucpNegativeVectors.map((vector) => ({
    id: vector.id,
    path: `../ucp/negative/${vector.id}.json`,
    expectedReasonCode: vector.expectedReasonCode,
  })),
  negatives: negativeIndex,
  identityInvariants: [
    "Verifier-local observation metadata is excluded from stable handoff identity.",
    "A superseding disposition does not overwrite its predecessor.",
    "A disposition never proves execution.",
    "A final advisory disposition does not require an executor, execution attempt, or receipt.",
    "RFC 8785 preserves distinct Unicode code-point sequences without NFC normalization.",
  ],
  contentDigest: sha256Canonical({ lifecycle, advisoryLifecycle, negativeIndex }),
});

console.log(`built two valid core lifecycles, ${mutations.length} stable lifecycle negatives, two UCP paths, and ${ucpNegativeVectors.length} UCP negatives`);
