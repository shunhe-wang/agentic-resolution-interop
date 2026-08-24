import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "../dist/src/canonical.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURES = path.join(ROOT, "fixtures");
const MANIFEST = path.join(FIXTURES, "manifest.json");
const EXPECTED = path.join(FIXTURES, "expected-seal.txt");
const writeMode = process.argv.includes("--write");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) return walk(absolute);
    if (absolute === MANIFEST || absolute === EXPECTED) return [];
    return [absolute];
  });
}

const files = walk(FIXTURES)
  .map((absolute) => ({
    path: path.relative(FIXTURES, absolute).split(path.sep).join("/"),
    sha256: sha256(fs.readFileSync(absolute)),
    bytes: fs.statSync(absolute).size,
  }))
  .sort((left, right) => left.path.localeCompare(right.path));
const manifest = {
  schemaVersion: "agentic-resolution-interop-seal-v1",
  hashAlgorithm: "SHA-256",
  canonicalization: "RFC8785",
  synthetic: true,
  files,
};
const seal = sha256(canonicalJson(manifest));

if (writeMode) {
  fs.writeFileSync(MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`);
  fs.writeFileSync(EXPECTED, `${seal}\n`);
} else {
  assert.deepEqual(JSON.parse(fs.readFileSync(MANIFEST, "utf8")), manifest);
  assert.equal(fs.readFileSync(EXPECTED, "utf8").trim(), seal);
}

console.log(`${writeMode ? "sealed" : "verified"} ${files.length} fixture files as ${seal}`);
