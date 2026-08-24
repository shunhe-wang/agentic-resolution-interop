# Agentic Resolution Interop

This repository is a provider-neutral, executable conformance corpus for the seam between agentic commerce and external dispute resolution.

It gives UCP, LCP, AP2, x402, checkout, escrow, merchant-refund, and resolver implementers the same synthetic lifecycle to pressure-test.

The lifecycle keeps five things distinct: a verified commerce record, bilateral resolution authority, a frozen dispute record, a disposition or Award reference, and a separate execution receipt.

People's Court is the initial maintainer and one intended implementation. The core and LCP fixtures contain no People's Court or vendor-specific resolver identifiers. The UCP projection is explicitly a People's Court-governed vendor profile over the same neutral lifecycle.

## Reproduce it

Use Node.js 24 or later.

```bash
npm ci
npm run check
```

The check builds the TypeScript, runs the lifecycle and security vectors, verifies official Integra LCP placement behavior for UCP, AP2, and x402, checks the corpus seal, and audits the public export boundary.

Expected result: 14 tests pass, 16 negative lifecycle vectors and three UCP path negatives produce their declared reason codes, both UCP pressure-test paths remain distinct, and 42 fixture files match the committed seal.

## Start with these public fixtures

- [Protocol-neutral valid lifecycle](fixtures/core/valid/lifecycle.json)
- [Runner-neutral corpus manifest](fixtures/core/manifest.json)
- [Escrow-held UCP path](fixtures/ucp/paths/escrow-held.json)
- [Post-settlement merchant-refund UCP path](fixtures/ucp/paths/post-settlement-merchant-refund.json)
- [Verified LCP legal-context binding](fixtures/lcp/valid/verified-binding.json)
- [Official Integra placement results](fixtures/lcp/protocols/official-results.json)
- [Portable JSON Schemas](schemas/resolution-lifecycle-v1.schema.json)
- [Whole-corpus seal](fixtures/expected-seal.txt)

Each file is synthetic and contains no live transaction, case, personal, payment, or production-key data.

## What the valid journey covers

```text
verified host transaction
        +
exact LCP legal artifacts
        +
bilateral resolution authorization
        |
        v
frozen resolution handoff
        |
        v
disposition 1 <- superseded by disposition 2
        |
        v
separate bounded execution receipt
```

The valid transaction has two line items, one disputed line, a USD 50.00 remedy ceiling, an initial disposition, a correcting final disposition, and a USD 20.00 completed refund receipt.

The committed authorization is a two-signature EdDSA JWS from distinct synthetic claimant and respondent principals.

Only public verification keys are committed.

## Protocol profiles

The core lifecycle is protocol-neutral.

The UCP projection is the first operational profile because it exposes both execution postures requested for pressure testing.

Its namespace is `ai.peoplescourt.shopping.dispute_resolution`. Namespace ownership identifies the extension publisher; it does not make the synthetic resolver, parties, disposition, or executor People's Court-specific. The execution posture remains fixture-only metadata outside the negotiated extension.

The escrow-held and post-settlement fixtures embed separate frozen funds-state evidence and separate execution receipts. The post-settlement fixture additionally separates the disposition-bound refund request, merchant approval, and same-rail refund receipt. The shapes are deliberately neutral; implementers must map them to native evidence and receipt fields rather than treating them as Facet or other vendor-native objects.

The LCP profile verifies exact caller-supplied terms, clause, rules, catalog, and discovery bytes without remote fetching.

It uses the official Integra packages to exercise AP2, UCP, and x402 placement and extraction.

The AP2 check proves that adding the LCP carrier leaves the opaque mandate bytes identical, not that the native AP2 mandate is itself valid.

The x402 strict reader is an experimental fail-closed rule for conflicting duplicate legal-context references, not current official Integra behavior.

The existing [`@peoples-court/x402-disputes`](https://github.com/shunhe-wang/peoples-court-x402-disputes) repository remains the separate usable x402 SDK and extension.

This repository does not duplicate it.

## Status

| Surface | Version or status |
|---|---|
| Repository | `0.1.0` |
| Corpus schema | `agentic-resolution-interop-corpus-v1` |
| LCP specification reported by Integra | `0.1.38` |
| Integra packages | `0.12.1` |
| Node.js | `>=24` |
| Corpus seal | See [`fixtures/expected-seal.txt`](fixtures/expected-seal.txt) |
| Package publication | Disabled with `"private": true` |

## What this does not claim

This is an informative reference implementation and test corpus.

It is not an adopted UCP, LCP, AP2, x402, ACP, or other protocol standard.

It does not certify a resolver, decide merits, create consent, establish enforceability, verify a host protocol's native transaction by itself, move funds, or prove that a remedy executed merely because a disposition exists.

See [CONFORMANCE.md](CONFORMANCE.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [SECURITY.md](SECURITY.md) before integrating it.

## Contributing

Independent protocol, wallet, commerce, resolver, escrow, and merchant-refund implementations are invited to run the corpus and contribute failing vectors.

The most valuable report identifies the exact field, digest, role, amount bound, supersession rule, or receipt status that cannot be represented without loss.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md).
