import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseLegalContextJson } from "@integraledger/lcp-discovery";
import { LCP_SPEC_VERSION, atrHashEquals, hashAtr } from "@integraledger/lcp-kernel";
import { ap2Placement } from "@integraledger/lcp-placement-ap2";
import { ucpPlacement } from "@integraledger/lcp-placement-ucp";
import { x402Placement } from "@integraledger/lcp-placement-x402";
import { strictExtractX402LegalContext } from "../dist/src/lcp.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURES = path.join(ROOT, "fixtures/lcp");
const writeMode = process.argv.includes("--write");
const read = (relative) => JSON.parse(fs.readFileSync(path.join(FIXTURES, relative), "utf8"));
const write = (relative, value) => {
  const target = path.join(FIXTURES, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
};

const listing = parseLegalContextJson(read("artifacts/legal-context.json"));
const termsBytes = fs.readFileSync(path.join(FIXTURES, "artifacts/terms.md"));
const servedAtrHash = await hashAtr(termsBytes);
assert.equal(atrHashEquals(servedAtrHash, listing.atrHash), true);

const placementInput = read("protocols/placement-input.json");
const advertisement = { ref: placementInput.ref, termsUrl: placementInput.legalContextUrl };

const ap2Input = read("protocols/input/ap2.json");
const ap2Before = JSON.stringify(ap2Input);
const ap2 = ap2Placement.place({ ref: advertisement.ref }, ap2Input);
assert.equal("refused" in ap2, false);
assert.equal(JSON.stringify(ap2Input), ap2Before, "AP2 placement must not mutate its input");
assert.equal(ap2.value.parts[0].data["ap2.mandates.CheckoutMandateSdJwt"], placementInput.ap2Mandate);
assert.deepEqual(ap2Placement.extract(ap2.value).value.ref, advertisement.ref);

const ucpInput = read("protocols/input/ucp.json");
const ucp = ucpPlacement.place(advertisement, ucpInput);
assert.equal("refused" in ucp, false);
assert.deepEqual(ucpPlacement.extract(ucp.value).value.ref, advertisement.ref);
assert.equal(ucp.value.policies[0].type, "example.existing");

const x402Input = read("protocols/input/x402.json");
const x402 = x402Placement.place(advertisement, x402Input);
assert.equal("refused" in x402, false);
assert.deepEqual(x402Placement.extract(x402.value).value.ref, advertisement.ref);
assert.equal(x402.value.extensions.exampleSibling.preserved, true);
assert.equal(x402.value.accepts[0].extra.asset, "synthetic-usdc");

const conflict = structuredClone(x402.value);
conflict.accepts[0].extra.atrHash = `0x${"f".repeat(64)}`;
assert.equal("refused" in x402Placement.extract(conflict), false, "official reader currently gives canonical extension precedence");
assert.throws(() => strictExtractX402LegalContext(conflict), /conflict/);
const urlOnlyConflict = structuredClone(x402.value);
delete urlOnlyConflict.accepts[0].extra.atrHash;
urlOnlyConflict.accepts[0].extra.legalContextUrl = "https://attacker.example/legal-context.json";
assert.throws(() => strictExtractX402LegalContext(urlOnlyConflict), /conflict/);

const results = {
  schemaVersion: "official-integra-placement-results-v1",
  integraPackageVersion: "0.12.1",
  lcpSpecVersion: LCP_SPEC_VERSION,
  nodeEngine: ">=24",
  termsAtrHash: servedAtrHash,
  ap2: { roundtrip: true, inputPure: true, mandateByteIdentical: true },
  ucp: { roundtrip: true, existingPolicyPreserved: true },
  x402: {
    roundtrip: true,
    siblingExtensionPreserved: true,
    existingExtraPreserved: true,
    officialCanonicalReferencePrecedenceObserved: true,
    experimentalStrictReaderRejectedConflicts: true,
  },
};

if (writeMode) {
  write("protocols/placed/ap2.json", ap2.value);
  write("protocols/placed/ucp.json", ucp.value);
  write("protocols/placed/x402.json", x402.value);
  write("protocols/negative/x402-reference-conflict.json", conflict);
  write("protocols/official-results.json", results);
} else {
  assert.deepEqual(read("protocols/placed/ap2.json"), ap2.value);
  assert.deepEqual(read("protocols/placed/ucp.json"), ucp.value);
  assert.deepEqual(read("protocols/placed/x402.json"), x402.value);
  assert.deepEqual(read("protocols/official-results.json"), results);
}

console.log("official Integra AP2, UCP, and x402 placement checks passed");
