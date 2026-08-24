import assert from "node:assert/strict";
import test from "node:test";
import { canonicalJson, sha256Canonical } from "../src/canonical.js";

test("RFC 8785 does not NFC-normalize string values", () => {
  const composed = { value: "é" };
  const decomposed = { value: "e\u0301" };
  assert.notEqual(canonicalJson(composed), canonicalJson(decomposed));
  assert.notEqual(sha256Canonical(composed), sha256Canonical(decomposed));
});

test("canonically equivalent Unicode keys remain distinct keys", () => {
  const value = { "é": 1, "e\u0301": 2 };
  const encoded = canonicalJson(value);
  assert.match(encoded, /"é":1/);
  assert.match(encoded, /"é":2/);
  assert.equal(Object.keys(JSON.parse(encoded)).length, 2);
});
