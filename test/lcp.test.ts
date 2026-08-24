import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { assertJsonWithoutDuplicateKeys, verifyLcpBundle, type LcpBundle } from "../src/lcp.js";
import { URLS, serviceId } from "../src/scenario.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const artifact = (name: string, url: string, mediaType: string) => ({
  url,
  bytes: fs.readFileSync(path.join(ROOT, "fixtures/lcp/artifacts", name)),
  mediaType,
});
const bundle = (): LcpBundle => ({
  legalContext: artifact("legal-context.json", URLS.discovery, "application/json"),
  terms: artifact("terms.md", URLS.terms, "text/markdown"),
  clause: artifact("dispute-clause.md", URLS.clause, "text/markdown"),
  rules: artifact("rules.md", URLS.rules, "text/markdown"),
  catalog: { ...artifact("dispute-services.json", URLS.catalog, "application/json"), serviceId },
});

test("exact caller-supplied LCP artifacts verify without remote fetching", () => {
  const verified = verifyLcpBundle(bundle());
  assert.equal(verified.catalog.providerId, "urn:example:agentic-resolution:resolver");
  assert.equal(verified.catalog.profile, "experimental-lcp-dispute-services-v0.1");
  const committed = JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures/lcp/valid/verified-binding.json"), "utf8"));
  assert.deepEqual(verified, committed);
});

test("changed terms bytes fail the ATR binding", () => {
  const changed = bundle();
  changed.terms.bytes = Buffer.concat([changed.terms.bytes, Buffer.from("changed")]);
  assert.throws(() => verifyLcpBundle(changed), /ATR hash/);
});

test("duplicate keys, excessive nesting, and invalid UTF-8 fail closed", () => {
  assert.throws(() => assertJsonWithoutDuplicateKeys('{"a":1,"a":2}'), /duplicate/);
  assert.throws(() => assertJsonWithoutDuplicateKeys(`${"[".repeat(66)}0${"]".repeat(66)}`), /nesting limit/);
  const invalid = bundle();
  invalid.legalContext.bytes = Uint8Array.from([0xff, 0xfe]);
  assert.throws(() => verifyLcpBundle(invalid), /valid UTF-8/);
});
