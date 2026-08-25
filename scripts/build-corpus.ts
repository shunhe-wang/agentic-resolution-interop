import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildBundle, type Artifact } from "@integraledger/lcp-evidence";
import { serializeReport, type VerificationReport } from "@integraledger/lcp-verify";
import {
  ACP_ORDER_SCHEMA_URL,
  ACP_UPSTREAM_REVISION,
  sealAcpExternalResolutionLifecycle,
  validateAcpExternalResolutionFixture,
  type AcpExternalResolutionFixture,
  type AcpSourceOrder,
  type AcpSourceVerification,
} from "../src/acp.js";
import type { AuthorizationTrustKey, GeneralJws } from "../src/authorization.js";
import { verifyBilateralAuthorization } from "../src/authorization.js";
import { canonicalJson, sha256Bytes, sha256Canonical } from "../src/canonical.js";
import { buildIntegraResolutionHandoff } from "../src/integra-adapter.js";
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
const writeBytes = (relative: string, value: Uint8Array): void => {
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

const integraReport: VerificationReport = {
  verified: true,
  assurance: "legal-party",
  claimedClass: "TC-3",
  supportedClass: "TC-3",
  asOf: FIXED_VERIFICATION_TIME,
  steps: [
    { name: "atr-fingerprint", outcome: { status: "proved" } },
    { name: "settlement-enumeration", outcome: { status: "proved" } },
    { name: "buyer-acceptance", outcome: { status: "proved" } },
    { name: "authority-attenuation", outcome: { status: "proved" } },
    { name: "commitment-vs-leaf", outcome: { status: "proved" } },
    { name: "recourse-elections", outcome: { status: "proved" } },
    { name: "resolve-party", outcome: { status: "proved" } },
  ],
  coverage: { ports: ["synthetic-mechanical-verifier"], bindings: ["ucp"] },
  settlements: { found: [{ transactionId: manifest.transactionId }], multiplySettled: false },
};
const integraArtifacts: Artifact[] = [
  { role: "atr", bytes: utf8('{"lcp":"0.3","recourse":{"forum":"Synthetic Neutral Tribunal","governingLaw":"US-NY"}}') },
  { role: "signed acceptance", bytes: utf8("synthetic signed acceptance") },
  { role: "authority chain", bytes: utf8("synthetic authority chain") },
  { role: "spend artifact", bytes: utf8("synthetic spend authorization") },
  { role: "attestation", bytes: utf8("synthetic identity attestation") },
  { role: "settlement", bytes: utf8("synthetic settlement") },
  { role: "weld", bytes: utf8("synthetic transaction weld") },
  { role: "timestamp", bytes: utf8(FIXED_VERIFICATION_TIME) },
];
const integraEvidenceBundle = await buildBundle(integraArtifacts);
const {
  authority: _authority,
  frozenRecord: _frozenRecord,
  remedyCeilings: _remedyCeilings,
  createdAt: _createdAt,
  expiresAt: _expiresAt,
  nativeProof: _nativeProof,
  ...integraDraft
} = handoff;
const integraLegalContext = {
  legalContextSha256: verifiedLcp.legalContext.sha256,
  termsAtrHash: `0x${termsSha256}`,
  clauseId,
  rulesSha256,
  catalogSha256,
  providerId,
  serviceId,
};
const integraHandoff = await buildIntegraResolutionHandoff({
  draft: integraDraft,
  verificationReport: integraReport,
  reportProvenance: { verifierId: "verifier:synthetic-mechanical" },
  evidenceBundle: integraEvidenceBundle,
  authorization: { jws: authorizationJws, trustedKeys: authorizationKeys },
  legalContext: integraLegalContext,
  includedArtifacts: manifest.includedArtifacts,
  excludedArtifacts: manifest.excludedArtifacts,
  now: new Date(FIXED_VERIFICATION_TIME),
});
const integraNegativeVectors = [
  { id: "unverified-report", mutation: "Set verificationReport.verified to false.", expectedErrorCode: "integra_report_unverified" },
  { id: "malformed-report", mutation: "Replace the report with an object that omits its required runtime shape.", expectedErrorCode: "integra_report_shape_invalid" },
  { id: "missing-evidence-role", mutation: "Rebuild the CAR without the authority chain role.", expectedErrorCode: "integra_evidence_roles_missing" },
  { id: "bundle-root-mismatch", mutation: "Replace evidenceBundle.root without changing the CAR.", expectedErrorCode: "integra_evidence_root_mismatch" },
  { id: "one-signature-authorization", mutation: "Remove either signature from the bilateral JWS.", expectedErrorCode: "authorization_signatures_invalid" },
  { id: "changed-terms", mutation: "Change draft.terms.digest without changing the signed authorization.", expectedErrorCode: "handoff_binding_mismatch" },
  { id: "missing-legal-artifact", mutation: "Remove the exact catalog artifact from includedArtifacts.", expectedErrorCode: "handoff_legal_artifact_missing" },
  { id: "remedy-above-authorization", mutation: "Set requestedRemedy.amountMinorUnits to 5001.", expectedErrorCode: "remedy_outside_authorization" },
];
writeBytes("lcp/integra/artifacts/integra-verification-report.json", serializeReport(integraReport));
writeBytes("lcp/integra/artifacts/integra-evidence-bundle.car", integraEvidenceBundle.car);
writeText("lcp/integra/artifacts/resolution-authorization-v1.jws.json", canonicalJson(authorizationJws));
writeJson("lcp/integra/valid/resolution-handoff.json", integraHandoff);
writeJson("lcp/integra/valid/adapter-input.json", {
  schemaVersion: "integra-resolution-handoff-input-fixture-v1",
  synthetic: true,
  draft: integraDraft,
  verificationReport: "../artifacts/integra-verification-report.json",
  reportProvenance: { verifierId: "verifier:synthetic-mechanical" },
  evidenceBundle: {
    car: "../artifacts/integra-evidence-bundle.car",
    root: integraEvidenceBundle.root,
  },
  authorization: {
    jws: "../artifacts/resolution-authorization-v1.jws.json",
    trustedKeys: "../../../core/valid/resolution-authorization-public-keys.json",
  },
  legalContext: integraLegalContext,
  includedArtifacts: manifest.includedArtifacts,
  excludedArtifacts: manifest.excludedArtifacts,
  now: FIXED_VERIFICATION_TIME,
  expectedOutput: "resolution-handoff.json",
  expectedOutputSha256: sha256Canonical(integraHandoff),
});
writeJson("lcp/integra/negative-vectors.json", {
  schemaVersion: "integra-resolution-handoff-negative-vectors-v1",
  baseInput: "valid/adapter-input.json",
  vectors: integraNegativeVectors,
});

const mutations: Array<{ id: string; code: string; mutate: (value: ResolutionLifecycle) => void }> = [
  { id: "missing-frozen-record-digest", code: "frozen_record_digest_missing", mutate: (v) => { v.handoff.frozenRecord.digest = ""; } },
  { id: "changed-frozen-record", code: "frozen_record_digest_mismatch", mutate: (v) => { v.handoff.frozenRecord.manifest.includedArtifacts[0]!.sha256 = "a".repeat(64); } },
  { id: "wrong-order-reference", code: "transaction_reference_mismatch", mutate: (v) => { v.handoff.transaction.orderId = "order-other"; } },
  { id: "wrong-line-item", code: "disputed_line_reference_mismatch", mutate: (v) => { v.handoff.transaction.disputedLineItemIds = ["line-001"]; } },
  { id: "stale-policy", code: "policy_digest_stale", mutate: (v) => { v.handoff.policy.digest = "a".repeat(64); } },
  { id: "stale-terms", code: "terms_digest_stale", mutate: (v) => { v.handoff.terms.digest = "b".repeat(64); } },
  { id: "missing-party-authority", code: "party_authority_missing", mutate: (v) => { v.handoff.authority.respondentAuthorityRef = ""; } },
  { id: "remedy-above-ceiling", code: "remedy_above_ceiling", mutate: (v) => { v.dispositions[1]!.authorizedRemedy.amountMinorUnits = "5001"; } },
  { id: "disposition-other-record", code: "disposition_record_mismatch", mutate: (v) => { v.dispositions[1]!.frozenRecordDigest = "c".repeat(64); } },
  { id: "superseded-operative", code: "superseded_disposition_operative", mutate: (v) => { v.operativeDispositionId = v.dispositions[0]!.dispositionId; } },
  { id: "supersession-cycle", code: "supersession_cycle", mutate: (v) => { v.dispositions[0]!.supersedesDispositionId = v.dispositions[1]!.dispositionId; } },
  { id: "supersession-fork", code: "supersession_fork", mutate: (v) => { const third = clone(v.dispositions[1]!); third.dispositionId = "disposition-neutral-003"; third.dispositionDigest = dispositionDigest(third); v.dispositions.push(third); } },
  { id: "execution-other-disposition", code: "execution_disposition_mismatch", mutate: (v) => { v.executions[0]!.dispositionId = v.dispositions[0]!.dispositionId; } },
  { id: "execution-outside-authorization", code: "execution_outside_authority", mutate: (v) => { v.executions[0]!.amountMinorUnits = "2001"; } },
  { id: "completed-without-receipt", code: "execution_receipt_missing", mutate: (v) => { v.executions[0]!.receiptProof = null; } },
  { id: "decision-as-execution", code: "decision_not_execution", mutate: (v) => { v.executions[0]!.receiptProof = { ...v.dispositions[1]!.signedArtifact, verificationStatus: "passed" }; } },
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

const acpOrder: AcpSourceOrder = {
  type: "order",
  id: "order-neutral-001",
  checkout_session_id: "checkout-neutral-001",
  permalink_url: "https://merchant.example.test/orders/order-neutral-001",
  status: "processing",
  line_items: [{
    id: "line-002",
    title: "Undelivered synthetic item",
    quantity: { ordered: 1, current: 1, fulfilled: 0 },
    unit_price: 2500,
    subtotal: 2500,
    status: "processing",
  }],
  adjustments: [{
    id: "adjustment-dispute-001",
    type: "dispute",
    occurred_at: "2026-08-24T15:55:00.000Z",
    status: "pending",
    line_items: [{ id: "line-002", quantity: 1 }],
    amount: 2500,
    currency: "usd",
    description: "Buyer contests non-delivery of one synthetic item.",
    reason: "non_delivery",
  }],
  totals: [
    { type: "total", display_text: "Total", amount: 2500 },
    { type: "amount_refunded", display_text: "Refunded", amount: 0 },
  ],
};
const acpVerification: AcpSourceVerification = {
  schemaVersion: "synthetic-acp-record-verification-v1",
  upstreamRevision: ACP_UPSTREAM_REVISION,
  orderSchema: ACP_ORDER_SCHEMA_URL,
  canonicalization: "RFC8785",
  digestAlgorithm: "SHA-256",
  orderSha256: sha256Canonical(acpOrder),
  validationScope: "pinned-order-fields-exercised-by-this-vector",
  authenticity: "not_claimed",
};
const acpLifecycle = sealAcpExternalResolutionLifecycle(lifecycle, acpOrder, acpVerification);
const validAcpFixture: AcpExternalResolutionFixture = {
  schemaVersion: "acp-external-resolution-test-vector-v1",
  synthetic: true,
  informative: true,
  source: {
    protocol: "agentic_checkout_acp",
    upstreamRevision: ACP_UPSTREAM_REVISION,
    orderSchema: ACP_ORDER_SCHEMA_URL,
    verification: acpVerification,
    order: acpOrder,
  },
  mapping: {
    contestedAdjustmentId: "adjustment-dispute-001",
    lifecycleArtifactRef: "#/lifecycle",
    extensionPlacement: "not_asserted",
  },
  lifecycle: acpLifecycle,
  expected: { valid: true, reasonCodes: [] },
};
const validAcpReasons = validateAcpExternalResolutionFixture(validAcpFixture, {
  now: new Date(FIXED_VERIFICATION_TIME),
});
if (validAcpReasons.length > 0) throw new Error(`valid ACP vector failed: ${validAcpReasons.join(", ")}`);
writeJson("acp/valid/contested-external-resolution.json", validAcpFixture);

const resealAcpMutation = (fixture: AcpExternalResolutionFixture): void => {
  const lifecycle = fixture.lifecycle;
  const stableHandoffDigest = handoffDigest(lifecycle.handoff);
  for (const disposition of lifecycle.dispositions) {
    disposition.handoffDigest = stableHandoffDigest;
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
};

const acpNegativeVectors: Array<{
  id: string;
  fixture: AcpExternalResolutionFixture;
}> = [
  {
    id: "dispute-adjustment-without-bilateral-authority",
    fixture: (() => {
      const value = clone(validAcpFixture);
      value.lifecycle.handoff.authority.respondentAuthorityRef = "";
      resealAcpMutation(value);
      value.expected = {
        valid: false,
        reasonCodes: ["acp_lifecycle_invalid", "acp_resolution_authority_missing"],
      };
      return value;
    })(),
  },
  {
    id: "disposition-as-execution",
    fixture: (() => {
      const value = clone(validAcpFixture);
      const operative = value.lifecycle.dispositions.find(
        (disposition) => disposition.dispositionId === value.lifecycle.operativeDispositionId,
      )!;
      value.lifecycle.executions[0]!.receiptProof = {
        ...operative.signedArtifact,
        verificationStatus: "passed",
      };
      value.expected = {
        valid: false,
        reasonCodes: ["acp_execution_not_separate", "acp_lifecycle_invalid"],
      };
      return value;
    })(),
  },
];
for (const vector of acpNegativeVectors) {
  const reasons = validateAcpExternalResolutionFixture(vector.fixture, {
    now: new Date(FIXED_VERIFICATION_TIME),
  });
  if (JSON.stringify(reasons) !== JSON.stringify(vector.fixture.expected.reasonCodes)) {
    throw new Error(`${vector.id} ACP vector produced ${reasons.join(", ")}`);
  }
  writeJson(`acp/negative/${vector.id}.json`, vector.fixture);
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
  corpusVersion: "0.2.0",
  synthetic: true,
  validationTime: FIXED_VERIFICATION_TIME,
  validJourney: "valid/lifecycle.json",
  authorization: {
    jws: "valid/resolution-authorization-v1.json",
    publicKeys: "valid/resolution-authorization-public-keys.json",
  },
  lcpProfile: "../lcp/valid/verified-binding.json",
  integraResolutionHandoff: {
    input: "../lcp/integra/valid/adapter-input.json",
    output: "../lcp/integra/valid/resolution-handoff.json",
    negativeVectors: "../lcp/integra/negative-vectors.json",
  },
  ucpPressureTests: [
    "../ucp/paths/escrow-held.json",
    "../ucp/paths/post-settlement-merchant-refund.json",
  ],
  ucpNegativeTests: ucpNegativeVectors.map((vector) => ({
    id: vector.id,
    path: `../ucp/negative/${vector.id}.json`,
    expectedReasonCode: vector.expectedReasonCode,
  })),
  acpTestVectors: {
    valid: "../acp/valid/contested-external-resolution.json",
    negatives: acpNegativeVectors.map((vector) => ({
      id: vector.id,
      path: `../acp/negative/${vector.id}.json`,
      expectedReasonCodes: vector.fixture.expected.reasonCodes,
    })),
  },
  negatives: negativeIndex,
  identityInvariants: [
    "Verifier-local observation metadata is excluded from stable handoff identity.",
    "A superseding disposition does not overwrite its predecessor.",
    "A disposition never proves execution.",
    "The exact bilateral JWS, Integra report, and evidence CAR are jointly bound by the frozen-record digest.",
    "A supplied verification report is frozen but its producer identity remains an application trust decision.",
    "RFC 8785 preserves distinct Unicode code-point sequences without NFC normalization.",
  ],
  contentDigest: sha256Canonical({
    lifecycle,
    negativeIndex,
    integraHandoff,
    integraNegativeVectors,
    validAcpFixture,
    acpNegativeVectors,
  }),
});

console.log(`built ${mutations.length} stable lifecycle negatives, ${integraNegativeVectors.length} Integra adapter negatives, two UCP paths, ${ucpNegativeVectors.length} UCP negatives, and three ACP resolution vectors`);
