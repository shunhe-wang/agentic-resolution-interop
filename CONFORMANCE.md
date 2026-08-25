# Conformance

Conformance in this repository means that an implementation can consume the committed synthetic corpus and reproduce each declared acceptance or rejection result.

It is not certification, endorsement, production readiness, or legal validity.

## Required behavior

A conforming core runner must:

1. compute stable JSON identities with RFC 8785 and SHA-256;
2. bind the handoff to the exact transaction, order, disputed line items, policy, terms, authorities, artifacts, and native proof reference;
3. enforce the requested and authorized remedy ceilings in canonical minor units;
4. retain superseded dispositions and reject cycles or forks;
5. select no superseded or vacated disposition as operative;
6. require a separate receipt for completed execution;
7. bind every execution to the operative disposition id and digest; and
8. produce the stable reason code declared by each negative vector.

An implementation may produce additional reason codes for a vector.

It must include the declared reason code.

## LCP profile behavior

An LCP-profile runner must verify caller-supplied exact bytes and reject changed ATR, clause, rules, catalog, service, method, jurisdiction, or intake bindings.

It must reject duplicate JSON keys, invalid UTF-8, excessive artifact sizes, excessive JSON nesting, malformed URLs, and legal-context substitution.

It must not infer resolution authority from the presence of an LCP reference.

## Integra adapter behavior

A conforming Integra resolver-handoff adapter must:

1. reject an unverified, insufficient-class, failed, incomplete, or future-dated mechanical report;
2. verify the supplied evidence CAR, require its declared root to match, and require every RCS-4 evidence role;
3. verify two distinct claimant and respondent signatures over the exact transaction and legal context;
4. reject draft parties, terms, policy, claim scope, or remedy amounts outside that authorization;
5. include the canonical report, exact CAR, exact bilateral JWS, and every declared legal-context artifact digest in the frozen manifest; and
6. reproduce the committed handoff and the declared adapter error codes.

Report-producer authentication and live-port execution are preconditions, not claims of adapter conformance.

## Official placement behavior

The committed placement outputs are reproduced by Integra packages `0.12.1` under Node.js 24.

The results cover official AP2, UCP, and x402 placement and extraction APIs.

The strict x402 conflict rejection is an additional experimental consumer rule.

## UCP execution-path behavior

A conforming UCP pressure-test runner must verify that the funds-state evidence is frozen into the path-specific handoff and matches the declared execution posture.

For escrow-held execution, the named escrow controller and its receipt must remain distinct from a merchant-refund executor and receipt.

For post-settlement execution, the prior merchant-settlement evidence, disposition-bound refund request, merchant approval, and same-rail receipt must remain separately identifiable and digest-linked.

The committed UCP negative vectors must reject swapped executor, receipt, and custody evidence with their declared reason codes. The fixture objects are neutral comparison shapes, not upstream- or vendor-native schemas.

## Reproduction

```bash
npm ci
npm run check
```

The authoritative corpus index is [`fixtures/core/manifest.json`](fixtures/core/manifest.json).

The whole-corpus byte inventory is [`fixtures/manifest.json`](fixtures/manifest.json).

The expected seal is [`fixtures/expected-seal.txt`](fixtures/expected-seal.txt).
