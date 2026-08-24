import { LCP_SPEC_VERSION } from "@integraledger/lcp-kernel";
import { sha256Bytes } from "./canonical.js";

const UTF8_FATAL = new TextDecoder("utf-8", { fatal: true });
const SHA256 = /^[a-f0-9]{64}$/;
const ATR = /^0x[a-f0-9]{64}$/;
const CLAUSE_ID = /^sha256:0x[a-f0-9]{64}$/;
const MAX_JSON_BYTES = 256 * 1024;
const MAX_TEXT_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 64;

export type ExactArtifact = { url: string; bytes: Uint8Array; mediaType: string };
export type LcpBundle = {
  legalContext: ExactArtifact;
  terms: ExactArtifact;
  clause: ExactArtifact;
  rules: ExactArtifact;
  catalog: ExactArtifact & { serviceId: string };
};

export type VerifiedLcpBundle = {
  schemaVersion: "experimental-agentic-resolution-lcp-binding-v1";
  lcpSpecVersion: string;
  legalContext: { url: string; sha256: string; byteLength: number };
  terms: { url: string; atrHash: string; sha256: string; byteLength: number };
  clause: { url: string; clauseId: string; sha256: string; byteLength: number };
  rules: { id: string; version: string; url: string; sha256: string; byteLength: number };
  catalog: {
    url: string;
    sha256: string;
    byteLength: number;
    providerId: string;
    serviceId: string;
    profile: "experimental-lcp-dispute-services-v0.1";
  };
  disputeResolution: { method: string; jurisdiction: string; contact: string };
  api: string;
};

export class LcpBundleError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "LcpBundleError";
  }
}

function fail(code: string, message: string): never {
  throw new LcpBundleError(code, message);
}

function httpsUrl(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.startsWith("https://") || /\s/.test(value)) {
    fail("url_invalid", `${label} must be an absolute lowercase HTTPS URL without whitespace.`);
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    fail("url_invalid", `${label} is not a valid URL.`);
  }
  if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || parsed.hash) {
    fail("url_invalid", `${label} must not contain credentials or a fragment.`);
  }
  return value;
}

function decode(artifact: ExactArtifact, limit: number, label: string): string {
  if (artifact.bytes.byteLength === 0 || artifact.bytes.byteLength > limit) {
    fail("artifact_size_invalid", `${label} must contain 1-${limit} bytes.`);
  }
  try {
    return UTF8_FATAL.decode(artifact.bytes);
  } catch {
    fail("artifact_not_utf8", `${label} must be valid UTF-8.`);
  }
}

export function assertJsonWithoutDuplicateKeys(text: string, label = "JSON"): void {
  let cursor = 0;
  const invalid = (): never => fail("json_invalid", `${label} is not valid JSON.`);
  const whitespace = (): void => {
    while (/\s/u.test(text[cursor] ?? "")) cursor += 1;
  };
  const readString = (): string => {
    if (text[cursor] !== '"') invalid();
    const start = cursor++;
    while (cursor < text.length) {
      if (text[cursor] === "\\") {
        cursor += 2;
        continue;
      }
      if (text[cursor] === '"') {
        cursor += 1;
        try {
          return JSON.parse(text.slice(start, cursor)) as string;
        } catch {
          invalid();
        }
      }
      cursor += 1;
    }
    return invalid();
  };
  const readValue = (depth: number): void => {
    if (depth > MAX_JSON_DEPTH) fail("json_depth_exceeded", `${label} exceeds the ${MAX_JSON_DEPTH}-level nesting limit.`);
    whitespace();
    if (text[cursor] === "{") {
      cursor += 1;
      whitespace();
      const keys = new Set<string>();
      if (text[cursor] === "}") {
        cursor += 1;
        return;
      }
      while (cursor < text.length) {
        whitespace();
        const key = readString();
        if (keys.has(key)) fail("json_duplicate_key", `${label} contains duplicate object key ${JSON.stringify(key)}.`);
        keys.add(key);
        whitespace();
        if (text[cursor] !== ":") invalid();
        cursor += 1;
        readValue(depth + 1);
        whitespace();
        if (text[cursor] === "}") {
          cursor += 1;
          return;
        }
        if (text[cursor] !== ",") invalid();
        cursor += 1;
      }
      invalid();
    }
    if (text[cursor] === "[") {
      cursor += 1;
      whitespace();
      if (text[cursor] === "]") {
        cursor += 1;
        return;
      }
      while (cursor < text.length) {
        readValue(depth + 1);
        whitespace();
        if (text[cursor] === "]") {
          cursor += 1;
          return;
        }
        if (text[cursor] !== ",") invalid();
        cursor += 1;
      }
      invalid();
    }
    if (text[cursor] === '"') {
      readString();
      return;
    }
    const token = text.slice(cursor).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u)?.[0];
    if (!token) return invalid();
    cursor += token.length;
  };
  readValue(0);
  whitespace();
  if (cursor !== text.length) invalid();
}

function jsonObject(artifact: ExactArtifact, label: string): Record<string, unknown> {
  const text = decode(artifact, MAX_JSON_BYTES, label);
  assertJsonWithoutDuplicateKeys(text, label);
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    fail("json_invalid", `${label} is not valid JSON.`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("json_invalid", `${label} must be an object.`);
  return value as Record<string, unknown>;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("catalog_invalid", `${label} must be an object.`);
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() === "") fail("catalog_invalid", `${label} must be non-blank.`);
  return value;
}

function strings(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string" || item.trim() === "")) {
    fail("catalog_invalid", `${label} must be a non-empty string array.`);
  }
  const result = value as string[];
  if (new Set(result).size !== result.length) fail("catalog_invalid", `${label} must be unique.`);
  return result;
}

export function verifyLcpBundle(bundle: LcpBundle): VerifiedLcpBundle {
  for (const [label, artifact] of Object.entries(bundle)) {
    if (label !== "serviceId") httpsUrl((artifact as ExactArtifact).url, `${label} URL`);
  }
  const listing = jsonObject(bundle.legalContext, "legal-context.json");
  const catalog = jsonObject(bundle.catalog, "dispute-services.json");
  decode(bundle.terms, MAX_TEXT_BYTES, "terms");
  decode(bundle.clause, MAX_TEXT_BYTES, "clause");
  decode(bundle.rules, MAX_TEXT_BYTES, "rules");

  const termsUrl = httpsUrl(listing.terms, "terms URL");
  const api = httpsUrl(listing.api, "resolver API URL");
  const atrHash = string(listing.atrHash, "atrHash").toLowerCase();
  const dispute = object(listing.disputeResolution, "disputeResolution");
  const clauseUrl = httpsUrl(dispute.source, "clause URL");
  const catalogUrl = httpsUrl(dispute.catalog, "catalog URL");
  const clauseId = string(dispute.clauseId, "clauseId").toLowerCase();
  const method = string(dispute.method, "method");
  const jurisdiction = string(dispute.jurisdiction, "jurisdiction");
  const contact = string(dispute.contact, "contact");

  if (listing.acceptanceRequired !== true || listing.termsFormat !== "markdown") {
    fail("legal_context_invalid", "This profile requires markdown terms and explicit acceptance.");
  }
  if (termsUrl !== bundle.terms.url || clauseUrl !== bundle.clause.url || catalogUrl !== bundle.catalog.url) {
    fail("artifact_reference_mismatch", "Legal-context URLs do not identify the supplied exact artifacts.");
  }
  const termsHash = sha256Bytes(bundle.terms.bytes);
  const clauseHash = sha256Bytes(bundle.clause.bytes);
  const rulesHash = sha256Bytes(bundle.rules.bytes);
  if (!ATR.test(atrHash) || atrHash !== `0x${termsHash}`) fail("atr_hash_mismatch", "ATR hash does not match exact terms bytes.");
  if (!CLAUSE_ID.test(clauseId) || clauseId !== `sha256:0x${clauseHash}`) fail("clause_hash_mismatch", "Clause id does not match exact clause bytes.");

  if (catalog.schemaVersion !== "experimental-lcp-dispute-services-v0.1") {
    fail("catalog_invalid", "Unsupported experimental catalog profile.");
  }
  const provider = object(catalog.provider, "catalog.provider");
  if (!Array.isArray(catalog.services)) fail("catalog_invalid", "Catalog services must be an array.");
  const service = catalog.services.map((item) => object(item, "catalog service")).find((item) => item.serviceId === bundle.catalog.serviceId);
  if (!service) fail("service_not_found", "Selected service is absent from the catalog.");
  const clause = object(service.clause, "service.clause");
  const terms = object(service.terms, "service.terms");
  const rules = object(service.rules, "service.rules");
  const intake = object(service.intake, "service.intake");
  const result = object(service.result, "service.result");
  const evidence = object(service.evidence, "service.evidence");
  if (!strings(service.methods, "service.methods").includes(method)) fail("method_not_supported", "Service does not support the selected method.");
  if (!strings(service.jurisdictions, "service.jurisdictions").includes(jurisdiction)) fail("jurisdiction_not_supported", "Service does not support the selected jurisdiction.");
  if (
    clause.id !== clauseId ||
    clause.url !== clauseUrl ||
    clause.sha256 !== clauseHash ||
    terms.url !== termsUrl ||
    terms.sha256 !== termsHash ||
    rules.url !== bundle.rules.url ||
    rules.sha256 !== rulesHash ||
    intake.url !== api ||
    result.dispositionSeparateFromExecution !== true ||
    evidence.candidateUntilAdopted !== true
  ) fail("catalog_binding_mismatch", "Catalog service does not bind the supplied artifacts and resolver boundary.");
  if (!SHA256.test(string(rules.sha256, "rules hash"))) fail("catalog_invalid", "Rules hash must be SHA-256.");

  return {
    schemaVersion: "experimental-agentic-resolution-lcp-binding-v1",
    lcpSpecVersion: LCP_SPEC_VERSION,
    legalContext: { url: bundle.legalContext.url, sha256: sha256Bytes(bundle.legalContext.bytes), byteLength: bundle.legalContext.bytes.byteLength },
    terms: { url: termsUrl, atrHash, sha256: termsHash, byteLength: bundle.terms.bytes.byteLength },
    clause: { url: clauseUrl, clauseId, sha256: clauseHash, byteLength: bundle.clause.bytes.byteLength },
    rules: {
      id: string(rules.id, "rules id"),
      version: string(rules.version, "rules version"),
      url: string(rules.url, "rules URL"),
      sha256: rulesHash,
      byteLength: bundle.rules.bytes.byteLength,
    },
    catalog: {
      url: catalogUrl,
      sha256: sha256Bytes(bundle.catalog.bytes),
      byteLength: bundle.catalog.bytes.byteLength,
      providerId: string(provider.id, "provider id"),
      serviceId: string(service.serviceId, "service id"),
      profile: "experimental-lcp-dispute-services-v0.1",
    },
    disputeResolution: { method, jurisdiction, contact },
    api,
  };
}

export function strictExtractX402LegalContext(input: Record<string, any>): { ref: { type: string; value: string }; termsUrl: string } {
  const canonical = input.extensions?.legalContext?.info;
  if (!canonical || canonical.type !== "sha256" || typeof canonical.value !== "string") {
    fail("x402_legal_context_missing", "Canonical x402 legalContext extension is missing.");
  }
  for (const accepted of input.accepts ?? []) {
    const extra = accepted?.extra;
    const hasHash = extra && Object.hasOwn(extra, "atrHash");
    const hasUrl = extra && Object.hasOwn(extra, "legalContextUrl");
    if (!hasHash && !hasUrl) continue;
    if (
      !hasHash ||
      !hasUrl ||
      !/^0x[a-f0-9]{64}$/.test(extra.atrHash) ||
      typeof extra.legalContextUrl !== "string" ||
      extra.atrHash !== canonical.value ||
      extra.legalContextUrl !== canonical.legalContextUrl
    ) fail("x402_legal_context_conflict", "Legacy x402 legal-context fields conflict with the canonical reference.");
  }
  return { ref: { type: canonical.type, value: canonical.value }, termsUrl: canonical.legalContextUrl };
}
