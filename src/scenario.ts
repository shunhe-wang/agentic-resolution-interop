import { canonicalJson, sha256Bytes } from "./canonical.js";

export const FIXED_VERIFICATION_TIME = "2026-08-24T16:00:00.000Z";

export const URLS = {
  discovery: "https://resolver.example/.well-known/legal-context.json",
  terms: "https://resolver.example/legal/terms.md",
  clause: "https://resolver.example/legal/dispute-clause.md",
  rules: "https://resolver.example/legal/rules.md",
  catalog: "https://resolver.example/.well-known/dispute-services.json",
  intake: "https://resolver.example/v1/resolution-requests",
  result: "https://resolver.example/v1/resolution-results/{caseId}",
} as const;

export const TERMS_TEXT = [
  "# Synthetic agent-commerce terms",
  "",
  "These terms govern a synthetic two-line-item transaction.",
  "The second line item must be delivered by the stated deadline.",
  "An LCP reference identifies exact terms bytes but does not itself appoint a resolver or establish resolution authority.",
  "",
].join("\n");

export const CLAUSE_TEXT = [
  "# Synthetic dispute clause",
  "",
  "A dispute may be submitted to the selected synthetic service only when both principals separately sign an authorization for the transaction, claim scope, legal artifacts, and remedy ceiling.",
  "Transaction or payment authority is not resolution authority.",
  "A disposition is not proof that a remedy was executed.",
  "",
].join("\n");

export const RULES_TEXT = [
  "# Synthetic resolver rules",
  "",
  "The resolver considers only the frozen record identified in the handoff.",
  "A correction supersedes but does not overwrite an earlier disposition.",
  "Execution requires a separate receipt tied to the operative disposition digest.",
  "",
].join("\n");

export const termsSha256 = sha256Bytes(TERMS_TEXT);
export const clauseSha256 = sha256Bytes(CLAUSE_TEXT);
export const rulesSha256 = sha256Bytes(RULES_TEXT);
export const clauseId = `sha256:0x${clauseSha256}`;
export const providerId = "urn:example:agentic-resolution:resolver";
export const serviceId = "urn:example:agentic-resolution:service:v1";

export const CATALOG = {
  schemaVersion: "experimental-lcp-dispute-services-v0.1",
  provider: {
    id: providerId,
    name: "Synthetic Neutral Resolver",
    contact: "mailto:resolver@example.invalid",
  },
  services: [{
    serviceId,
    name: "Synthetic bounded transaction resolution",
    methods: ["arbitration"],
    jurisdictions: ["US-NY"],
    clause: { id: clauseId, url: URLS.clause, sha256: clauseSha256 },
    terms: { url: URLS.terms, sha256: termsSha256 },
    rules: { id: "urn:example:agentic-resolution:rules:v1", version: "1.0.0", url: URLS.rules, sha256: rulesSha256 },
    eligibility: { currencies: ["USD"], maximumAmountMinorUnits: { USD: "5000" } },
    intake: {
      url: URLS.intake,
      method: "POST",
      mediaType: "application/vnd.agentic-resolution.handoff-v1+json",
      authSchemes: ["bilateral-jws"],
    },
    evidence: { profile: "resolution-frozen-record-manifest-v1", candidateUntilAdopted: true },
    result: {
      urlTemplate: URLS.result,
      mediaType: "application/vnd.agentic-resolution.result-v1+json",
      dispositionSeparateFromExecution: true,
    },
  }],
} as const;

export const DISCOVERY = {
  acceptanceRequired: true,
  api: URLS.intake,
  atrHash: `0x${termsSha256}`,
  disputeResolution: {
    catalog: URLS.catalog,
    clauseId,
    contact: "mailto:resolver@example.invalid",
    jurisdiction: "US-NY",
    method: "arbitration",
    source: URLS.clause,
  },
  terms: URLS.terms,
  termsFormat: "markdown",
} as const;

export const catalogText = canonicalJson(CATALOG);
export const discoveryText = canonicalJson(DISCOVERY);
export const catalogSha256 = sha256Bytes(catalogText);
