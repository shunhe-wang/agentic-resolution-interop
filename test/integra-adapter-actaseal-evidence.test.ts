/**
 * Adds the ActaSeal disputed_agent_purchase receipt
 * (~/a/lcp-fork/proposals/actaseal.lcp-binding.v1/examples/disputed_agent_purchase/receipt.json)
 * as one `includedArtifacts` evidence item on top of the existing
 * neutral-001 Integra scenario, using only fields
 * resolution-frozen-record-manifest-v1.schema.json already defines:
 * `artifactId`, `sha256`, `mediaType`, `source`. No new fields, no
 * schema change.
 *
 * `source` is a free-text string in the schema (same as
 * "lcp-exact-bytes" / "synthetic-buyer-record" / the
 * "@integraledger/lcp-evidence@0.12.1:<root>" convention the adapter's
 * own generated entries use) -- it carries `terms_hash` as a compact
 * tag (`actaseal.lcp-binding.v1:terms_hash=<64-hex>`), the one
 * ActaSeal-specific fact this schema has a field able to carry at all.
 *
 * What did NOT fit, and was deliberately not forced into an invented
 * field:
 *   - the receipt's `decision`/`action_hash`/`ledger_entry_hash`/
 *     `signature`/`receipt_public_key_hex` -- the schema's evidence-item
 *     shape has no slot for any of this; a reader who needs it must
 *     open the underlying receipt.json (referenced by artifactId) and
 *     re-derive it themselves, the same way this repo's own
 *     `nativeProof`/`nativeVerification` point at an external artifact
 *     rather than inlining its contents.
 *   - the LCP binding record itself (lcp_record.json) and terms.txt --
 *     out of scope for "the receipt is an evidence item" as asked; a
 *     real integration would presumably add those as their own
 *     `includedArtifacts` entries too, but that is a scope decision for
 *     whoever wires this for real, not invented here.
 *
 * Why NO fixture in this file is a "terms-swapped" or
 * "receipt-without-terms_hash" negative vector: traced through
 * src/integra-adapter.ts's `checkedArtifacts`, a caller-supplied
 * `includedArtifacts` entry's `sha256` is NEVER independently
 * re-hashed against real bytes -- it is trusted at face value. The
 * only sha256 cross-checks this adapter performs are against a fixed
 * set of OTHER declared digests already inside the same JSON document
 * (`draft.terms.digest`, `draft.policy.digest`, the claim/merchant-
 * response artifactRefs, and the legalContext digest set) -- none of
 * which the ActaSeal evidence item participates in, and `terms_hash`
 * itself is not a concept this schema is aware of at all (it lives
 * only inside the opaque receipt.json content this schema treats as a
 * single artifactId+sha256+mediaType+source tuple). Concretely:
 *   - "terms-swapped" (the ATR hash a signed receipt commits to
 *     disagreeing with the actual terms bytes) can only be detected by
 *     something that re-hashes the real terms document -- this schema
 *     never does that for a caller-declared evidence item, so there is
 *     no adapter-level failure to trigger. Mutating the ActaSeal
 *     entry's declared `sha256` to any other 64-hex value here
 *     succeeds silently (confirmed by hand before writing this file:
 *     it is accepted, not rejected).
 *   - "receipt-without-terms_hash" is even less expressible:
 *     `terms_hash` presence/absence is invisible to this schema
 *     entirely; it is not, and cannot honestly be made, a field this
 *     adapter inspects.
 * The two vectors below instead exercise the ONE integrity check this
 * schema DOES apply to every `includedArtifacts` entry, including a
 * newly added one: `handoff_artifact_invalid` on a malformed digest
 * shape or a duplicate `artifactId`. These are real, already-defined
 * failure modes -- not relabeled ActaSeal-specific ones.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import type { VerificationReport } from "@integraledger/lcp-verify";
import type { AuthorizationTrustKey, GeneralJws } from "../src/authorization.js";
import {
  buildIntegraResolutionHandoff,
  type IntegraResolutionHandoffDraft,
  type IntegraResolutionHandoffInput,
} from "../src/integra-adapter.js";
import { sha256Canonical } from "../src/canonical.js";
import type { ResolutionHandoff } from "../src/types.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BASE = path.join(ROOT, "fixtures", "lcp", "integra", "valid");
const resolve = (relative: string): string => path.resolve(BASE, relative);

type FixtureFile = {
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

const readFixture = (): FixtureFile =>
  JSON.parse(fs.readFileSync(path.join(BASE, "adapter-input-actaseal-evidence.json"), "utf8")) as FixtureFile;

const toInput = (fixture: FixtureFile): Omit<IntegraResolutionHandoffInput, "now"> & { now: Date } => ({
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

const ACTASEAL_ARTIFACT_ID = "actaseal-disputed-purchase-receipt.json";

test("the ActaSeal disputed-purchase receipt fixture reproduces the exact frozen handoff", async () => {
  const fixture = readFixture();
  const result = await buildIntegraResolutionHandoff(toInput(fixture));
  const expected = JSON.parse(fs.readFileSync(resolve(fixture.expectedOutput), "utf8")) as ResolutionHandoff;
  assert.deepEqual(result, expected);
  assert.equal(sha256Canonical(result), fixture.expectedOutputSha256);
});

test("the ActaSeal receipt evidence item carries only schema-defined fields", async () => {
  const fixture = readFixture();
  const result = await buildIntegraResolutionHandoff(toInput(fixture));
  const artifact = result.frozenRecord.manifest.includedArtifacts.find(
    (entry) => entry.artifactId === ACTASEAL_ARTIFACT_ID,
  );
  assert.ok(artifact, "ActaSeal receipt evidence item is missing from the frozen manifest");
  assert.deepEqual(Object.keys(artifact!).sort(), ["artifactId", "mediaType", "sha256", "source"]);
  assert.match(artifact!.sha256, /^[a-f0-9]{64}$/);
  assert.equal(artifact!.mediaType, "application/json");
  assert.match(artifact!.source, /^actaseal\.lcp-binding\.v1:terms_hash=[a-f0-9]{64}$/);
});

test("a malformed ActaSeal evidence-item digest fails handoff_artifact_invalid (not a terms-swap check)", async () => {
  const fixture = readFixture();
  const candidate = toInput(fixture);
  candidate.includedArtifacts = candidate.includedArtifacts.map((artifact) =>
    artifact.artifactId === ACTASEAL_ARTIFACT_ID ? { ...artifact, sha256: "not-a-valid-sha256" } : artifact,
  );
  await assert.rejects(
    buildIntegraResolutionHandoff(candidate),
    (error: unknown) => typeof error === "object" && error !== null && "code" in error && error.code === "handoff_artifact_invalid",
  );
});

test("a duplicate ActaSeal artifactId fails handoff_artifact_invalid", async () => {
  const fixture = readFixture();
  const candidate = toInput(fixture);
  const actaseal = candidate.includedArtifacts.find((artifact) => artifact.artifactId === ACTASEAL_ARTIFACT_ID)!;
  candidate.includedArtifacts = [...candidate.includedArtifacts, { ...actaseal }];
  await assert.rejects(
    buildIntegraResolutionHandoff(candidate),
    (error: unknown) => typeof error === "object" && error !== null && "code" in error && error.code === "handoff_artifact_invalid",
  );
});

test("swapping the ActaSeal evidence item's declared digest is NOT detected by this schema (documents a real gap, not a false claim)", async () => {
  // Confirms the module docstring's claim above by construction: an
  // arbitrary, well-formed-but-wrong sha256 on the ActaSeal artifact
  // (standing in for "the terms document bytes were swapped, so the
  // ActaSeal-signed terms_hash no longer matches what's really behind
  // this evidence item") is silently ACCEPTED by this adapter, because
  // includedArtifacts entries are caller-declared and never
  // content-verified. Detecting that swap is entirely
  // lcp_actaseal_binding's job (LCP_TERMS_HASH_MISMATCH), operating on
  // the receipt's own signed terms_hash field -- a layer this schema
  // does not see into.
  const fixture = readFixture();
  const candidate = toInput(fixture);
  candidate.includedArtifacts = candidate.includedArtifacts.map((artifact) =>
    artifact.artifactId === ACTASEAL_ARTIFACT_ID ? { ...artifact, sha256: "0".repeat(64) } : artifact,
  );
  const result = await buildIntegraResolutionHandoff(candidate);
  const artifact = result.frozenRecord.manifest.includedArtifacts.find(
    (entry) => entry.artifactId === ACTASEAL_ARTIFACT_ID,
  );
  assert.equal(artifact?.sha256, "0".repeat(64));
});
