import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair, GeneralSign } from "jose";
import {
  verifyBilateralAuthorization,
  type AuthorizationTrustKey,
  type GeneralJws,
  type ResolutionAuthorizationClaims,
} from "../src/authorization.js";
import { canonicalJson, sha256Canonical } from "../src/canonical.js";
import { dispositionDigest, frozenRecordDigest, handoffDigest, validateLifecycle } from "../src/lifecycle.js";
import type { ResolutionExecutionReceipt, ResolutionLifecycle } from "../src/types.js";
import { validateUcpPressureTestPath, type UcpPressureTestFixture } from "../src/ucp.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = <T>(relative: string): T => JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures", relative), "utf8")) as T;
const NOW = new Date("2026-08-27T00:00:00.000Z");
const lifecycle = (): ResolutionLifecycle => read("core/valid/lifecycle.json");
const refundPath = (): UcpPressureTestFixture => read("ucp/paths/post-settlement-merchant-refund.json");

function completedResult(source: ResolutionLifecycle, suffix: string, amount: string): ResolutionExecutionReceipt {
  const result = structuredClone(source.executions[0]!);
  return {
    ...result,
    executionId: `execution-${suffix}`,
    nativeTransactionReference: `native-refund-${suffix}`,
    amountMinorUnits: amount,
    receiptProof: {
      ...result.receiptProof!,
      artifactRef: `receipt-${suffix}.json`,
      sha256: sha256Canonical({ syntheticReceiptId: suffix, amountMinorUnits: amount }),
    },
  };
}

for (const [name, amounts, accepted] of [
  ["below", ["900", "1000"], true],
  ["at", ["1000", "1000"], true],
  ["above", ["1000", "1001"], false],
] as const) {
  test(`completed executions ${name} the aggregate authority ceiling`, () => {
    const input = lifecycle();
    assert.equal(validateLifecycle(input, { now: NOW }).ok, true);
    assert.equal(input.dispositions.find((item) => item.dispositionId === input.operativeDispositionId)!.authorizedRemedy.amountMinorUnits, "2000");
    input.executions = amounts.map((amount, index) => completedResult(input, String(index), amount));
    const result = validateLifecycle(input, { now: NOW });
    assert.equal(result.ok, accepted);
    assert.deepEqual(result.reasonCodes, accepted ? [] : ["execution_outside_authority"]);
  });
}

for (const identity of ["execution ID", "provider/native transaction tuple"] as const) {
  test(`duplicate completed ${identity} is rejected without exceeding the ceiling`, () => {
    const input = lifecycle();
    input.executions = [completedResult(input, "one", "500"), completedResult(input, "two", "500")];
    assert.equal(validateLifecycle(input, { now: NOW }).ok, true);
    const [first, second] = input.executions;
    if (identity === "execution ID") second!.executionId = first!.executionId;
    else second!.nativeTransactionReference = first!.nativeTransactionReference;
    assert.deepEqual(validateLifecycle(input, { now: NOW }).reasonCodes, ["execution_identity_duplicate"]);
  });
}

test("distinct provider/native transaction tuples cannot collide through delimiters", () => {
  const input = lifecycle();
  input.executions = [completedResult(input, "one", "500"), completedResult(input, "two", "500")];
  input.executions[0]!.providerRef = "provider:a";
  input.executions[0]!.nativeTransactionReference = "b\nc";
  input.executions[1]!.providerRef = "provider:a\nb";
  input.executions[1]!.nativeTransactionReference = "c";
  assert.deepEqual(validateLifecycle(input, { now: NOW }).reasonCodes, []);
});

for (const status of ["pending", "failed"] as const) {
  test(`${status} attempts and their completed result are not double-counted`, () => {
    const input = lifecycle();
    const attempt = structuredClone(input.executions[0]!);
    attempt.status = status;
    attempt.receiptProof = null;
    if (status === "failed") attempt.failureCode = "native_attempt_failed";
    input.executions.unshift(attempt);
    assert.deepEqual(validateLifecycle(input, { now: NOW }).reasonCodes, []);
  });
}

test("core lifecycle rejects numeric JSON execution amounts", () => {
  const input = lifecycle();
  assert.deepEqual(validateLifecycle(input, { now: NOW }).reasonCodes, []);
  Object.assign(input.executions[0]!, { amountMinorUnits: 2000 });
  assert.deepEqual(validateLifecycle(input, { now: NOW }).reasonCodes, ["execution_outside_authority"]);
});

function reboundRefundDigests(fixture: UcpPressureTestFixture): void {
  const { refundRequest, merchantApproval, receiptBinding } = fixture.executionEvidence;
  const { requestDigest: _requestDigest, ...requestBody } = refundRequest!;
  refundRequest!.requestDigest = sha256Canonical(requestBody);
  merchantApproval!.requestDigest = refundRequest!.requestDigest;
  const { approvalDigest: _approvalDigest, ...approvalBody } = merchantApproval!;
  merchantApproval!.approvalDigest = sha256Canonical(approvalBody);
  receiptBinding.refundRequestDigest = refundRequest!.requestDigest;
  receiptBinding.merchantApprovalDigest = merchantApproval!.approvalDigest;
}

const refundMutations: Array<[string, (fixture: UcpPressureTestFixture) => void]> = [
  ["explicit denial", (input) => Object.assign(input.executionEvidence.merchantApproval!, { approved: false })],
  ["unrelated approver", (input) => { input.executionEvidence.merchantApproval!.approver = "principal:unrelated"; }],
  ["unrelated request recipient", (input) => { input.executionEvidence.refundRequest!.requestedFrom = "principal:unrelated"; }],
  ["request currency", (input) => { input.executionEvidence.refundRequest!.currency = "EUR"; }],
  ["approval currency", (input) => { input.executionEvidence.merchantApproval!.currency = "EUR"; }],
  ["request amount", (input) => { input.executionEvidence.refundRequest!.amountMinorUnits = "1999"; }],
  ["approval amount", (input) => { input.executionEvidence.merchantApproval!.amountMinorUnits = "1999"; }],
  ["noncanonical request amount", (input) => { input.executionEvidence.refundRequest!.amountMinorUnits = "02000"; }],
  ["noncanonical approval amount", (input) => { input.executionEvidence.merchantApproval!.amountMinorUnits = "02000"; }],
];
for (const [name, mutate] of refundMutations) {
  test(`UCP refund rejects ${name} despite valid digest links`, () => {
    const input = refundPath();
    assert.deepEqual(validateUcpPressureTestPath(input, { now: NOW }), []);
    mutate(input);
    reboundRefundDigests(input);
    assert.equal(validateLifecycle(input.lifecycle, { now: NOW }).ok, true);
    assert.deepEqual(validateUcpPressureTestPath(input, { now: NOW }), ["ucp_path_refund_chain_mismatch"]);
  });
}

test("UCP refund rejects matching numeric JSON amounts despite valid digest links", () => {
  const input = refundPath();
  assert.deepEqual(validateUcpPressureTestPath(input, { now: NOW }), []);
  Object.assign(input.executionEvidence.refundRequest!, { amountMinorUnits: 2000 });
  Object.assign(input.executionEvidence.merchantApproval!, { amountMinorUnits: 2000 });
  Object.assign(input.lifecycle.executions[0]!, { amountMinorUnits: 2000 });
  reboundRefundDigests(input);
  input.executionEvidence.receiptBinding.receiptDigest = sha256Canonical(input.lifecycle.executions[0]!);
  assert.deepEqual(validateUcpPressureTestPath(input, { now: NOW }), ["ucp_path_lifecycle_invalid", "ucp_path_refund_chain_mismatch"]);
});

function resealLifecycle(input: ResolutionLifecycle): void {
  input.handoff.frozenRecord.digest = frozenRecordDigest(input.handoff.frozenRecord.manifest);
  for (const disposition of input.dispositions) {
    disposition.handoffDigest = handoffDigest(input.handoff);
    disposition.frozenRecordDigest = input.handoff.frozenRecord.digest;
    disposition.dispositionDigest = dispositionDigest(disposition);
  }
  const operative = input.dispositions.find((item) => item.dispositionId === input.operativeDispositionId)!;
  for (const execution of input.executions) execution.dispositionDigest = operative.dispositionDigest;
}

test("UCP refund identities remain bound to frozen merchant custody after consistent role substitution", () => {
  const input = refundPath();
  assert.deepEqual(validateUcpPressureTestPath(input, { now: NOW }), []);
  const frozenCustodyDigest = sha256Canonical(input.executionEvidence.custodyAtHandoff);
  input.lifecycle.handoff.roles.respondent = "principal:unrelated";
  input.executionEvidence.refundRequest!.requestedFrom = "principal:unrelated";
  input.executionEvidence.merchantApproval!.approver = "principal:unrelated";
  resealLifecycle(input.lifecycle);
  const execution = input.lifecycle.executions[0]!;
  input.executionEvidence.refundRequest!.dispositionDigest = execution.dispositionDigest;
  input.executionEvidence.receiptBinding.dispositionDigest = execution.dispositionDigest;
  input.executionEvidence.receiptBinding.receiptDigest = sha256Canonical(execution);
  reboundRefundDigests(input);
  assert.equal(sha256Canonical(input.executionEvidence.custodyAtHandoff), frozenCustodyDigest);
  assert.equal(validateLifecycle(input.lifecycle, { now: NOW }).ok, true);
  assert.deepEqual(validateUcpPressureTestPath(input, { now: NOW }), ["ucp_path_refund_chain_mismatch"]);
});

test("core lifecycle rejects line-list delimiter substitution", () => {
  const input = lifecycle();
  input.handoff.transaction.disputedLineItemIds = ["line:a\nline:b"];
  input.handoff.frozenRecord.manifest.disputedLineItemIds = ["line:a\nline:b"];
  input.expected.disputedLineItemIds = ["line:a\nline:b"];
  resealLifecycle(input);
  assert.deepEqual(validateLifecycle(input, { now: NOW }).reasonCodes, []);
  input.expected.disputedLineItemIds = ["line:a", "line:b"];
  assert.deepEqual(validateLifecycle(input, { now: NOW }).reasonCodes, ["disputed_line_reference_mismatch"]);
});

test("core lifecycle preserves exact line identifiers independently of ordering", () => {
  const input = lifecycle();
  input.handoff.transaction.disputedLineItemIds = ["line:a\nline:b", "line:c"];
  input.handoff.frozenRecord.manifest.disputedLineItemIds = ["line:c", "line:a\nline:b"];
  input.expected.disputedLineItemIds = ["line:c", "line:a\nline:b"];
  resealLifecycle(input);
  assert.deepEqual(validateLifecycle(input, { now: NOW }).reasonCodes, []);
});

const originalJws = read<GeneralJws>("core/valid/resolution-authorization-v1.json");
const claims = (): ResolutionAuthorizationClaims => JSON.parse(Buffer.from(originalJws.payload, "base64url").toString("utf8")) as ResolutionAuthorizationClaims;
const expected = { ...claims().transaction, ...claims().legalContext };
type Principal = Pick<AuthorizationTrustKey, "kid" | "principalId" | "role">;

async function signedClaims(candidate: ResolutionAuthorizationClaims, principals?: Principal[]): Promise<{
  jws: GeneralJws;
  trustedKeys: AuthorizationTrustKey[];
}> {
  const keyPrincipals = principals ?? claims().parties.map((party, index) => ({ kid: `scratch-key-${index}`, principalId: party.principalId, role: party.role }));
  const sign = new GeneralSign(new TextEncoder().encode(canonicalJson(candidate)));
  const trustedKeys: AuthorizationTrustKey[] = [];
  for (const principal of keyPrincipals) {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });
    trustedKeys.push({ ...await exportJWK(publicKey), ...principal });
    sign.addSignature(privateKey).setProtectedHeader({ alg: "EdDSA", kid: principal.kid });
  }
  const signed = await sign.sign();
  const signatures = signed.signatures.map((signature) => {
    assert.equal(typeof signature.protected, "string");
    return { protected: signature.protected!, signature: signature.signature };
  });
  return { jws: { payload: signed.payload, signatures }, trustedKeys };
}

const hasCode = (code: string) => (error: unknown): boolean =>
  typeof error === "object" && error !== null && "code" in error && error.code === code;

test("bilateral signature verification rejects line-list delimiter substitution", async () => {
  const candidate = claims();
  candidate.transaction.disputedLineItemIds = ["line:a\nline:b"];
  const signed = await signedClaims(candidate);
  await verifyBilateralAuthorization({ ...signed, expected: { ...expected, disputedLineItemIds: candidate.transaction.disputedLineItemIds }, now: NOW });
  await assert.rejects(
    verifyBilateralAuthorization({ ...signed, expected: { ...expected, disputedLineItemIds: ["line:a", "line:b"] }, now: NOW }),
    hasCode("authorization_binding_mismatch"),
  );
});

test("bilateral signature verification preserves line identity and cardinality", async () => {
  const candidate = claims();
  candidate.transaction.disputedLineItemIds = ["line:a\nline:b", "line:c"];
  const signed = await signedClaims(candidate);
  await verifyBilateralAuthorization({ ...signed, expected: { ...expected, disputedLineItemIds: ["line:c", "line:a\nline:b"] }, now: NOW });
  await assert.rejects(
    verifyBilateralAuthorization({ ...signed, expected: { ...expected, disputedLineItemIds: ["line:c", "line:a\nline:b", "line:c"] }, now: NOW }),
    hasCode("authorization_binding_mismatch"),
  );
});

test("principal/role tuples cannot collide while retaining both party roles", async () => {
  const principals: Principal[] = [
    { kid: "claimant", principalId: "principal:a", role: "claimant" },
    { kid: "respondent", principalId: "principal:b:claimant\nprincipal:c", role: "respondent" },
  ];
  const positive = claims();
  positive.parties.forEach((party, index) => { party.principalId = principals[index]!.principalId; });
  await verifyBilateralAuthorization({ ...await signedClaims(positive, principals), expected, now: NOW });
  const substituted = structuredClone(positive);
  substituted.parties[0]!.principalId = "principal:a:claimant\nprincipal:b";
  substituted.parties[1]!.principalId = "principal:c";
  await assert.rejects(
    verifyBilateralAuthorization({ ...await signedClaims(substituted, principals), expected, now: NOW }),
    hasCode("authorization_principal_mismatch"),
  );
});

const timeCases: Array<[string, (candidate: ResolutionAuthorizationClaims) => void, Date]> = [
  ["invalid issuance", (candidate) => { candidate.issuedAt = "not-a-date"; }, NOW],
  ["invalid expiry", (candidate) => { candidate.expiresAt = "not-a-date"; }, NOW],
  ["invalid observation time", () => {}, new Date("not-a-date")],
  ["empty interval", (candidate) => { candidate.issuedAt = candidate.expiresAt; }, NOW],
  ["reversed interval", (candidate) => { candidate.issuedAt = "2028-08-24T15:00:00.000Z"; }, NOW],
  ["before issuance", () => {}, new Date("2026-08-24T14:59:59.999Z")],
  ["at expiry", () => {}, new Date("2027-08-24T15:00:00.000Z")],
];
for (const [name, mutate, now] of timeCases) {
  test(`signed authorization rejects ${name}`, async () => {
    const candidate = claims();
    mutate(candidate);
    await assert.rejects(
      verifyBilateralAuthorization({ ...await signedClaims(candidate), expected, now }),
      hasCode("authorization_time_invalid"),
    );
  });
}

for (const now of [new Date("2026-08-24T15:00:00.000Z"), new Date("2027-08-24T14:59:59.999Z")]) {
  test(`signed authorization remains active at ${now.toISOString()}`, async () => {
    await verifyBilateralAuthorization({ ...await signedClaims(claims()), expected, now });
  });
}
