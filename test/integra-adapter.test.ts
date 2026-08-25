import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildBundle, type Artifact, type EvidenceBundle } from "@integraledger/lcp-evidence";
import type { VerificationReport } from "@integraledger/lcp-verify";
import type { AuthorizationTrustKey, GeneralJws } from "../src/authorization.js";
import {
  buildIntegraResolutionHandoff,
  type IntegraResolutionHandoffDraft,
  type IntegraResolutionHandoffInput,
} from "../src/integra-adapter.js";
import { sha256Bytes, sha256Canonical } from "../src/canonical.js";
import { frozenRecordDigest } from "../src/lifecycle.js";
import {
  FIXED_VERIFICATION_TIME,
  catalogSha256,
  clauseId,
  discoveryText,
  providerId,
  rulesSha256,
  serviceId,
  termsSha256,
} from "../src/scenario.js";
import type { ResolutionHandoff, ResolutionLifecycle } from "../src/types.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = <T>(relative: string): T =>
  JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures", relative), "utf8")) as T;

const report = (): VerificationReport => ({
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
  settlements: { found: [{ transactionId: "tx-neutral-001" }], multiplySettled: false },
});

const bundle = async (excludedRole?: Artifact["role"]): Promise<EvidenceBundle> => {
  const allArtifacts: Artifact[] = [
    { role: "atr", bytes: new TextEncoder().encode('{"lcp":"0.3","recourse":{"forum":"Synthetic Neutral Tribunal","governingLaw":"US-NY"}}') },
    { role: "signed acceptance", bytes: new TextEncoder().encode("synthetic signed acceptance") },
    { role: "authority chain", bytes: new TextEncoder().encode("synthetic authority chain") },
    { role: "spend artifact", bytes: new TextEncoder().encode("synthetic spend authorization") },
    { role: "attestation", bytes: new TextEncoder().encode("synthetic identity attestation") },
    { role: "settlement", bytes: new TextEncoder().encode("synthetic settlement") },
    { role: "weld", bytes: new TextEncoder().encode("synthetic transaction weld") },
    { role: "timestamp", bytes: new TextEncoder().encode(FIXED_VERIFICATION_TIME) },
  ];
  const artifacts = allArtifacts.filter((artifact) => artifact.role !== excludedRole);
  return buildBundle(artifacts);
};

const input = async (): Promise<IntegraResolutionHandoffInput> => {
  const source = read<ResolutionLifecycle>("core/valid/lifecycle.json").handoff;
  const {
    authority: _authority,
    frozenRecord: _frozenRecord,
    remedyCeilings: _remedyCeilings,
    createdAt: _createdAt,
    expiresAt: _expiresAt,
    nativeProof: _nativeProof,
    nativeVerification: _nativeVerification,
    ...draft
  } = source;
  return {
    draft,
    verificationReport: report(),
    reportProvenance: { verifierId: "verifier:synthetic-mechanical" },
    evidenceBundle: await bundle(),
    authorization: {
      jws: read<GeneralJws>("core/valid/resolution-authorization-v1.json"),
      trustedKeys: read<AuthorizationTrustKey[]>("core/valid/resolution-authorization-public-keys.json"),
    },
    legalContext: {
      legalContextSha256: sha256Bytes(discoveryText),
      termsAtrHash: `0x${termsSha256}`,
      clauseId,
      rulesSha256,
      catalogSha256,
      providerId,
      serviceId,
    },
    includedArtifacts: source.frozenRecord.manifest.includedArtifacts,
    excludedArtifacts: source.frozenRecord.manifest.excludedArtifacts,
    now: new Date(FIXED_VERIFICATION_TIME),
  };
};

const expectCode = async (candidate: IntegraResolutionHandoffInput, code: string): Promise<void> => {
  await assert.rejects(
    buildIntegraResolutionHandoff(candidate),
    (error: unknown) => typeof error === "object" && error !== null && "code" in error && error.code === code,
  );
};

test("verified Integra report and evidence bundle produce a frozen bilateral handoff", async () => {
  const result: ResolutionHandoff = await buildIntegraResolutionHandoff(await input());

  assert.equal(result.schemaVersion, "resolution-handoff-v1");
  assert.equal(result.createdAt, FIXED_VERIFICATION_TIME);
  assert.equal(result.expiresAt, "2027-08-24T15:00:00.000Z");
  assert.equal(result.authority.bilateral, true);
  assert.equal(result.authority.claimantAuthorityRef, "authority:buyer:001");
  assert.equal(result.authority.respondentAuthorityRef, "authority:merchant:001");
  assert.equal(result.frozenRecord.digest, frozenRecordDigest(result.frozenRecord.manifest));
  assert.equal(result.nativeProof.verificationMethod, "integra-verification-report/mechanical");
  assert.equal(result.nativeVerification?.verifierId, "verifier:synthetic-mechanical");
  assert.ok(result.frozenRecord.manifest.includedArtifacts.some((artifact) =>
    artifact.artifactId === "resolution-authorization-v1.jws.json" &&
    artifact.sha256 === result.authority.authorizationArtifactHash
  ));
  assert.ok(result.frozenRecord.manifest.includedArtifacts.some((artifact) => artifact.artifactId === "integra-verification-report.json"));
  assert.ok(result.frozenRecord.manifest.includedArtifacts.some((artifact) => artifact.artifactId === "integra-evidence-bundle.car"));
});

test("the committed Integra input fixture reproduces the exact frozen handoff", async () => {
  const base = path.join(ROOT, "fixtures", "lcp", "integra", "valid");
  const fixture = JSON.parse(fs.readFileSync(path.join(base, "adapter-input.json"), "utf8")) as {
    draft: IntegraResolutionHandoffDraft;
    verificationReport: string;
    reportProvenance: { verifierId: string };
    evidenceBundle: { car: string; root: string };
    authorization: { jws: string; trustedKeys: string };
    legalContext: IntegraResolutionHandoffInput["legalContext"];
    includedArtifacts: IntegraResolutionHandoffInput["includedArtifacts"];
    excludedArtifacts: IntegraResolutionHandoffInput["excludedArtifacts"];
    now: string;
    expectedOutput: string;
    expectedOutputSha256: string;
  };
  const resolve = (relative: string): string => path.resolve(base, relative);
  const result = await buildIntegraResolutionHandoff({
    draft: fixture.draft,
    verificationReport: JSON.parse(fs.readFileSync(resolve(fixture.verificationReport), "utf8")) as VerificationReport,
    reportProvenance: fixture.reportProvenance,
    evidenceBundle: {
      root: fixture.evidenceBundle.root,
      car: fs.readFileSync(resolve(fixture.evidenceBundle.car)),
    },
    authorization: {
      jws: JSON.parse(fs.readFileSync(resolve(fixture.authorization.jws), "utf8")) as GeneralJws,
      trustedKeys: JSON.parse(fs.readFileSync(resolve(fixture.authorization.trustedKeys), "utf8")) as AuthorizationTrustKey[],
    },
    legalContext: fixture.legalContext,
    includedArtifacts: fixture.includedArtifacts,
    excludedArtifacts: fixture.excludedArtifacts,
    now: new Date(fixture.now),
  });
  const expected = JSON.parse(fs.readFileSync(resolve(fixture.expectedOutput), "utf8")) as ResolutionHandoff;
  assert.deepEqual(result, expected);
  assert.equal(sha256Canonical(result), fixture.expectedOutputSha256);
});

test("an unverified Integra report cannot cross the resolver handoff boundary", async () => {
  const candidate = await input();
  candidate.verificationReport.verified = false;
  await expectCode(candidate, "integra_report_unverified");
});

test("a malformed Integra report fails with a stable adapter code", async () => {
  const candidate = await input();
  candidate.verificationReport = { verified: true } as VerificationReport;
  await expectCode(candidate, "integra_report_shape_invalid");
});

test("an incomplete Integra evidence bundle cannot cross the resolver handoff boundary", async () => {
  const candidate = await input();
  candidate.evidenceBundle = await bundle("authority chain");
  await expectCode(candidate, "integra_evidence_roles_missing");
});

test("a declared Integra bundle root must match the verified CAR root", async () => {
  const candidate = await input();
  candidate.evidenceBundle = { ...candidate.evidenceBundle, root: "bafy-synthetic-mismatched-root" };
  await expectCode(candidate, "integra_evidence_root_mismatch");
});

test("one signature cannot appoint the resolver", async () => {
  const candidate = await input();
  candidate.authorization.jws = {
    ...candidate.authorization.jws,
    signatures: candidate.authorization.jws.signatures.slice(0, 1),
  };
  await expectCode(candidate, "authorization_signatures_invalid");
});

test("a draft with changed legal terms cannot reuse the signed authorization", async () => {
  const candidate = await input();
  candidate.draft.terms.digest = "a".repeat(64);
  await expectCode(candidate, "handoff_binding_mismatch");
});

test("the frozen handoff must retain every exact legal-context artifact", async () => {
  const candidate = await input();
  candidate.includedArtifacts = candidate.includedArtifacts.filter((artifact) => artifact.sha256 !== catalogSha256);
  await expectCode(candidate, "handoff_legal_artifact_missing");
});

test("a requested remedy above the bilateral ceiling is rejected", async () => {
  const candidate = await input();
  candidate.draft.requestedRemedy.amountMinorUnits = "5001";
  await expectCode(candidate, "remedy_outside_authorization");
});
