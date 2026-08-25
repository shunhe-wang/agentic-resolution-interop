import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { Ajv2020, type ErrorObject } from "ajv/dist/2020.js";
import formatsModule from "ajv-formats";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMAS = [
  "resolution-frozen-record-manifest-v1.schema.json",
  "resolution-handoff-v1.schema.json",
  "resolution-disposition-v1.schema.json",
  "resolution-execution-receipt-v1.schema.json",
  "resolution-lifecycle-v1.schema.json",
] as const;
const addFormats = formatsModule as unknown as (ajv: Ajv2020) => Ajv2020;

const readJson = <T>(relative: string): T =>
  JSON.parse(fs.readFileSync(path.join(ROOT, relative), "utf8")) as T;

function lifecycleValidator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  for (const name of SCHEMAS) ajv.addSchema(readJson(path.join("schemas", name)));
  return ajv.getSchema("resolution-lifecycle-v1.schema.json")!;
}

test("committed execution and advisory lifecycles conform to the portable schema", () => {
  const validate = lifecycleValidator();
  for (const relative of ["fixtures/core/valid/lifecycle.json", "fixtures/core/valid/advisory-lifecycle.json"]) {
    assert.equal(validate(readJson(relative)), true, `${relative}: ${JSON.stringify(validate.errors)}`);
  }
});

test("schema requires an executor when execution records exist", () => {
  const lifecycle = readJson<any>("fixtures/core/valid/lifecycle.json");
  delete lifecycle.handoff.roles.executor;
  const validate = lifecycleValidator();
  assert.equal(validate(lifecycle), false);
  assert.ok(validate.errors?.some((error: ErrorObject) => error.instancePath === "/handoff/roles" && error.params.missingProperty === "executor"));
});

test("schema identities and references remain relative to the retrieved pinned bundle", () => {
  for (const name of SCHEMAS) {
    const schema = readJson<any>(path.join("schemas", name));
    assert.equal(schema.$id, name);
    const serialized = JSON.stringify(schema);
    assert.doesNotMatch(serialized, /raw\.githubusercontent\.com|\/main\/schemas\//);
  }
});
