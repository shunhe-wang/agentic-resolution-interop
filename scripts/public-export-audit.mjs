import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURES = path.join(ROOT, "fixtures");
const TEXT_EXTENSIONS = new Set([".json", ".md", ".ts", ".mjs", ".yml", ".yaml", ".txt"]);

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if ([".git", "node_modules", "dist"].includes(entry.name)) return [];
    const absolute = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(absolute) : [absolute];
  });
}

for (const file of walk(FIXTURES)) {
  if (!TEXT_EXTENSIONS.has(path.extname(file))) continue;
  const text = fs.readFileSync(file, "utf8");
  const relative = path.relative(ROOT, file);
  const textWithoutGovernedUcpNamespace = text.replaceAll("ai.peoplescourt.shopping.dispute_resolution", "");
  assert.doesNotMatch(
    textWithoutGovernedUcpNamespace,
    /people'?s[ -]?court|peoples-court|facet/i,
    `${relative} contains a provider identifier outside the governed UCP namespace`,
  );
  if (relative.startsWith(`fixtures${path.sep}core${path.sep}`) || relative.startsWith(`fixtures${path.sep}lcp${path.sep}`)) {
    assert.doesNotMatch(text, /ai\.peoplescourt\./i, `${relative} must remain protocol/provider-neutral`);
  }
  assert.doesNotMatch(text, /"d"\s*:/, `${path.relative(ROOT, file)} contains private JWK material`);
  assert.doesNotMatch(text, /\/Users\/|[A-Za-z]:\\Users\\/, `${path.relative(ROOT, file)} contains a local absolute path`);
}

for (const file of walk(ROOT)) {
  if (!TEXT_EXTENSIONS.has(path.extname(file))) continue;
  const text = fs.readFileSync(file, "utf8");
  assert.doesNotMatch(text, /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, `${path.relative(ROOT, file)} contains a private key block`);
  assert.doesNotMatch(text, /(?:gho|ghp|github_pat)_[A-Za-z0-9_]{20,}/, `${path.relative(ROOT, file)} contains a GitHub token shape`);
}

const coreManifest = JSON.parse(fs.readFileSync(path.join(FIXTURES, "core/manifest.json"), "utf8"));
assert.equal(coreManifest.synthetic, true);
console.log("public export audit passed: neutral core/LCP fixtures, governed UCP namespace only, and no private JWKs, tokens, private-key blocks, or local paths");
