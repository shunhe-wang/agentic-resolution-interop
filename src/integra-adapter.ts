import {
  decodeCar,
  type EvidenceBundle,
  verifyBundle,
} from "@integraledger/lcp-evidence";
import {
  RCS4_REQUIRED_ROLES,
  serializeReport,
  type VerificationReport,
} from "@integraledger/lcp-verify";
import {
  type AuthorizationTrustKey,
  type GeneralJws,
  verifyBilateralAuthorization,
} from "./authorization.js";
import { sha256Bytes } from "./canonical.js";
import { frozenRecordDigest } from "./lifecycle.js";
import type {
  FrozenRecordManifest,
  ResolutionAction,
  ResolutionHandoff,
} from "./types.js";

const INTEGRA_VERSION = "0.12.1";
const SHA256 = /^[a-f0-9]{64}$/;
const RESOLUTION_ACTIONS = new Set<string>([
  "refund",
  "release_to_claimant",
  "release_to_respondent",
  "allocate_by_award",
  "replace_product",
  "none",
]);

type DerivedHandoffFields =
  | "authority"
  | "frozenRecord"
  | "remedyCeilings"
  | "createdAt"
  | "expiresAt"
  | "nativeProof"
  | "nativeVerification";

export type IntegraResolutionHandoffDraft = Omit<
  ResolutionHandoff,
  DerivedHandoffFields
>;

export type IntegraResolutionHandoffInput = {
  draft: IntegraResolutionHandoffDraft;
  verificationReport: VerificationReport;
  reportProvenance: { verifierId: string };
  evidenceBundle: Pick<EvidenceBundle, "root" | "car">;
  authorization: {
    jws: GeneralJws;
    trustedKeys: AuthorizationTrustKey[];
  };
  legalContext: {
    legalContextSha256: string;
    termsAtrHash: string;
    clauseId: string;
    rulesSha256: string;
    catalogSha256: string;
    providerId: string;
    serviceId: string;
  };
  includedArtifacts: FrozenRecordManifest["includedArtifacts"];
  excludedArtifacts: FrozenRecordManifest["excludedArtifacts"];
  now: Date;
};

export class IntegraHandoffAdapterError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "IntegraHandoffAdapterError";
  }
}

function fail(code: string, message: string): never {
  throw new IntegraHandoffAdapterError(code, message);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}

function validDate(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function validateReport(report: VerificationReport, now: Date): Uint8Array {
  const candidate = report as unknown;
  if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) {
    fail("integra_report_shape_invalid", "Integra verification report is not an object.");
  }
  const value = candidate as Record<string, unknown>;
  const coverage = value.coverage as Record<string, unknown> | undefined;
  const settlements = value.settlements as Record<string, unknown> | undefined;
  const steps = value.steps;
  const scalarShapeValid =
    typeof value.verified === "boolean" &&
    typeof value.assurance === "string" &&
    typeof value.claimedClass === "string" &&
    typeof value.supportedClass === "string" &&
    typeof value.asOf === "string";
  const coverageShapeValid =
    typeof coverage === "object" && coverage !== null && !Array.isArray(coverage) &&
    Array.isArray(coverage.ports) && coverage.ports.every((item) => typeof item === "string") &&
    Array.isArray(coverage.bindings) && coverage.bindings.every((item) => typeof item === "string");
  const settlementShapeValid =
    typeof settlements === "object" && settlements !== null && !Array.isArray(settlements) &&
    Array.isArray(settlements.found) && typeof settlements.multiplySettled === "boolean";
  const stepShapeValid = Array.isArray(steps) && steps.every((step) => {
    if (typeof step !== "object" || step === null || Array.isArray(step)) return false;
    const item = step as Record<string, unknown>;
    const outcome = item.outcome;
    return typeof item.name === "string" && typeof outcome === "object" && outcome !== null &&
      !Array.isArray(outcome) && typeof (outcome as Record<string, unknown>).status === "string";
  });
  if (!scalarShapeValid || !coverageShapeValid || !settlementShapeValid || !stepShapeValid) {
    fail("integra_report_shape_invalid", "Integra verification report has an invalid runtime shape.");
  }
  if (report.verified !== true) {
    fail("integra_report_unverified", "Integra verification report is not mechanically verified.");
  }
  if (report.supportedClass !== "TC-3" && report.supportedClass !== "TC-4") {
    fail("integra_report_class_insufficient", "Resolver handoff requires an Integra TC-3 or TC-4 report.");
  }
  if (report.steps.some((step) => step.outcome.status === "failed")) {
    fail("integra_report_failed_step", "Integra verification report contains a failed step.");
  }
  const requiredSteps = [
    "atr-fingerprint",
    "settlement-enumeration",
    "buyer-acceptance",
    "authority-attenuation",
    "commitment-vs-leaf",
    "recourse-elections",
    "resolve-party",
  ];
  for (const name of requiredSteps) {
    if (report.steps.find((step) => step.name === name)?.outcome.status !== "proved") {
      fail("integra_report_required_step_missing", `Integra verification step ${name} is not proved.`);
    }
  }
  if (report.coverage.ports.length === 0 || report.coverage.bindings.length === 0) {
    fail("integra_report_coverage_missing", "Integra verification report does not identify its live ports and bindings.");
  }
  const asOf = validDate(report.asOf);
  if (asOf === null || asOf > now.getTime()) {
    fail("integra_report_time_invalid", "Integra verification report has an invalid or future as-of time.");
  }
  try {
    return serializeReport(report);
  } catch {
    fail("integra_report_shape_invalid", "Integra verification report is not canonically serializable JSON.");
  }
}

async function validateEvidenceBundle(bundle: Pick<EvidenceBundle, "root" | "car">): Promise<{
  carDigest: string;
  root: string;
}> {
  const verified = await verifyBundle(bundle.car);
  if (!verified.ok) {
    fail("integra_evidence_invalid", verified.reason ?? "Integra evidence bundle failed verification.");
  }
  let decoded: ReturnType<typeof decodeCar>;
  try {
    decoded = decodeCar(bundle.car);
  } catch {
    fail("integra_evidence_invalid", "Integra evidence bundle is not a decodable CAR.");
  }
  const root = decoded.roots[0];
  if (!root || root !== bundle.root) {
    fail("integra_evidence_root_mismatch", "Integra evidence bundle root does not match the verified CAR root.");
  }
  const roles = new Set<string>(verified.entries.map((entry) => entry.role));
  const missing = RCS4_REQUIRED_ROLES.filter((role) => !roles.has(role));
  if (missing.length > 0) {
    fail("integra_evidence_roles_missing", `Integra evidence bundle is missing required roles: ${missing.join(", ")}.`);
  }
  return { carDigest: sha256Bytes(bundle.car), root };
}

function assertDraftBindings(
  input: IntegraResolutionHandoffInput,
  claims: Awaited<ReturnType<typeof verifyBilateralAuthorization>>["claims"],
): void {
  const { draft, legalContext } = input;
  const claimant = claims.parties.find((party) => party.role === "claimant");
  const respondent = claims.parties.find((party) => party.role === "respondent");
  const termsDigest = legalContext.termsAtrHash.startsWith("0x")
    ? legalContext.termsAtrHash.slice(2)
    : legalContext.termsAtrHash;
  const transactionMatches =
    draft.transaction.transactionId === claims.transaction.transactionId &&
    draft.transaction.orderId === claims.transaction.orderId &&
    sameStrings(draft.transaction.disputedLineItemIds, claims.transaction.disputedLineItemIds);
  const partyMatches =
    claimant !== undefined &&
    respondent !== undefined &&
    draft.roles.claimant === claimant.principalId &&
    draft.roles.respondent === respondent.principalId;
  const legalMatches =
    draft.terms.digest === termsDigest &&
    draft.policy.digest === legalContext.rulesSha256 &&
    draft.roles.resolver === legalContext.providerId &&
    draft.resolver.resolverId === legalContext.providerId;
  const claimMatches =
    draft.claim.claimType === claims.claimScope.claimType &&
    draft.requestedRemedy.action === claims.claimScope.requestedRemedy;
  if (!transactionMatches || !partyMatches || !legalMatches || !claimMatches) {
    fail("handoff_binding_mismatch", "Handoff draft does not match the verified transaction, parties, legal context, or claim scope.");
  }
  if (
    draft.requestedRemedy.action !== claims.remedyCeiling.action ||
    draft.requestedRemedy.currency !== claims.remedyCeiling.currency ||
    !/^(0|[1-9][0-9]*)$/.test(draft.requestedRemedy.amountMinorUnits) ||
    !/^(0|[1-9][0-9]*)$/.test(claims.remedyCeiling.amountMinorUnits) ||
    BigInt(draft.requestedRemedy.amountMinorUnits) > BigInt(claims.remedyCeiling.amountMinorUnits)
  ) {
    fail("remedy_outside_authorization", "Requested remedy exceeds or differs from the bilateral authorization.");
  }
}

function checkedArtifacts(
  input: IntegraResolutionHandoffInput,
  reportDigest: string,
  evidence: { carDigest: string; root: string },
  authorizationDigest: string,
): FrozenRecordManifest["includedArtifacts"] {
  const generated: FrozenRecordManifest["includedArtifacts"] = [
    {
      artifactId: "integra-verification-report.json",
      sha256: reportDigest,
      mediaType: "application/json",
      source: `@integraledger/lcp-verify@${INTEGRA_VERSION}/canonical-report-format`,
    },
    {
      artifactId: "integra-evidence-bundle.car",
      sha256: evidence.carDigest,
      mediaType: "application/vnd.ipld.car",
      source: `@integraledger/lcp-evidence@${INTEGRA_VERSION}:${evidence.root}`,
    },
    {
      artifactId: "resolution-authorization-v1.jws.json",
      sha256: authorizationDigest,
      mediaType: "application/jose+json",
      source: "verified-bilateral-resolution-authorization",
    },
  ];
  const artifacts = [...input.includedArtifacts, ...generated].sort((a, b) =>
    a.artifactId.localeCompare(b.artifactId),
  );
  const ids = new Set<string>();
  for (const artifact of artifacts) {
    if (ids.has(artifact.artifactId) || !SHA256.test(artifact.sha256)) {
      fail("handoff_artifact_invalid", "Handoff artifacts require unique identifiers and lowercase SHA-256 digests.");
    }
    ids.add(artifact.artifactId);
  }
  const required = [
    [input.draft.claim.artifactRef, input.draft.claim.artifactHash],
    [input.draft.merchantResponse.artifactRef, input.draft.merchantResponse.artifactHash],
  ] as const;
  for (const [artifactId, digest] of required) {
    if (!artifacts.some((artifact) => artifact.artifactId === artifactId && artifact.sha256 === digest)) {
      fail("handoff_artifact_binding_missing", `Handoff artifact ${artifactId} is absent or has the wrong digest.`);
    }
  }
  if (!artifacts.some((artifact) => artifact.sha256 === input.draft.terms.digest)) {
    fail("handoff_terms_artifact_missing", "Handoff does not include the exact terms artifact.");
  }
  if (!artifacts.some((artifact) => artifact.sha256 === input.draft.policy.digest)) {
    fail("handoff_policy_artifact_missing", "Handoff does not include the exact policy or rules artifact.");
  }
  const clauseMatch = /^sha256:0x([a-f0-9]{64})$/i.exec(input.legalContext.clauseId);
  const legalDigests = [
    input.legalContext.legalContextSha256,
    input.draft.terms.digest,
    input.legalContext.rulesSha256,
    input.legalContext.catalogSha256,
    clauseMatch?.[1]?.toLowerCase(),
  ];
  if (legalDigests.some((digest) => digest === undefined || !SHA256.test(digest)) ||
    legalDigests.some((digest) => !artifacts.some((artifact) => artifact.sha256 === digest))) {
    fail("handoff_legal_artifact_missing", "Handoff does not include every exact legal-context artifact digest.");
  }
  return artifacts;
}

export async function buildIntegraResolutionHandoff(
  input: IntegraResolutionHandoffInput,
): Promise<ResolutionHandoff> {
  if (!Number.isFinite(input.now.getTime())) {
    fail("handoff_time_invalid", "Resolver handoff requires a valid observation time.");
  }
  const verifierId = input.reportProvenance?.verifierId;
  if (typeof verifierId !== "string" || verifierId.trim().length === 0 || verifierId.length > 200) {
    fail("integra_report_provenance_invalid", "Integra report provenance requires a bounded caller-declared verifier identifier.");
  }
  const reportBytes = validateReport(input.verificationReport, input.now);
  const reportDigest = sha256Bytes(reportBytes);
  const evidence = await validateEvidenceBundle(input.evidenceBundle);
  const authorization = await verifyBilateralAuthorization({
    jws: input.authorization.jws,
    trustedKeys: input.authorization.trustedKeys,
    expected: {
      transactionId: input.draft.transaction.transactionId,
      orderId: input.draft.transaction.orderId,
      disputedLineItemIds: input.draft.transaction.disputedLineItemIds,
      termsAtrHash: input.legalContext.termsAtrHash,
      clauseId: input.legalContext.clauseId,
      rulesSha256: input.legalContext.rulesSha256,
      catalogSha256: input.legalContext.catalogSha256,
      providerId: input.legalContext.providerId,
      serviceId: input.legalContext.serviceId,
    },
    now: input.now,
  });
  assertDraftBindings(input, authorization.claims);

  const claimant = authorization.claims.parties.find((party) => party.role === "claimant");
  const respondent = authorization.claims.parties.find((party) => party.role === "respondent");
  if (!claimant || !respondent) {
    fail("authorization_bilateral_missing", "Authorization does not contain both appointed parties.");
  }
  const includedArtifacts = checkedArtifacts(input, reportDigest, evidence, authorization.artifactHash);
  if (!RESOLUTION_ACTIONS.has(authorization.claims.remedyCeiling.action)) {
    fail("remedy_outside_authorization", "Authorization names an unsupported resolution action.");
  }
  const remedyAction = authorization.claims.remedyCeiling.action as ResolutionAction;
  const manifest: FrozenRecordManifest = {
    schemaVersion: "resolution-frozen-record-manifest-v1",
    transactionId: input.draft.transaction.transactionId,
    orderId: input.draft.transaction.orderId,
    disputedLineItemIds: [...input.draft.transaction.disputedLineItemIds].sort(),
    policyDigest: input.draft.policy.digest,
    termsDigest: input.draft.terms.digest,
    authorityRefs: [claimant.authorityRef, respondent.authorityRef].sort(),
    includedArtifacts,
    excludedArtifacts: [...input.excludedArtifacts].sort((a, b) =>
      a.artifactId.localeCompare(b.artifactId),
    ),
  };

  return {
    ...input.draft,
    authority: {
      bilateral: true,
      claimantAuthorityRef: claimant.authorityRef,
      respondentAuthorityRef: respondent.authorityRef,
      authorizationArtifactHash: authorization.artifactHash,
    },
    frozenRecord: {
      canonicalization: "RFC8785",
      digestAlgorithm: "SHA-256",
      manifest,
      digest: frozenRecordDigest(manifest),
    },
    remedyCeilings: [{ ...authorization.claims.remedyCeiling, action: remedyAction }],
    createdAt: input.now.toISOString(),
    expiresAt: authorization.claims.expiresAt,
    nativeProof: {
      artifactRef: "integra-verification-report.json",
      sha256: reportDigest,
      verificationMethod: "integra-verification-report/mechanical",
    },
    nativeVerification: {
      verifierId,
      verifiedAt: input.verificationReport.asOf,
    },
  };
}
