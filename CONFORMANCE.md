# Conformance

Conformance in this repository means that an implementation can consume the committed synthetic corpus and reproduce each declared acceptance or rejection result.

It is not certification, endorsement, production readiness, or legal validity.

## Required behavior

A conforming core runner must:

1. compute stable JSON identities with RFC 8785 and SHA-256;
2. bind the handoff to the exact transaction, order, disputed line items, policy, terms, authorities, artifacts, and native proof reference;
3. enforce the requested and authorized remedy ceilings in canonical minor units;
4. retain superseded dispositions and reject cycles or forks;
5. reject duplicate disposition ids, missing supersession targets, and dispositions outside the operative supersession chain;
6. select no superseded or vacated disposition as operative;
7. permit a final advisory disposition with no executor, execution attempt, or receipt;
8. require a named executor whenever an execution record exists;
9. require a separate receipt for completed execution;
10. bind every execution to the operative disposition id and digest;
11. reject duplicate execution ids and duplicate completed native transaction references;
12. enforce the authorized remedy ceiling across the cumulative completed amount, not only one receipt at a time; and
13. produce the stable reason code declared by each negative vector.

An implementation may produce additional reason codes for a vector.

It must include the declared reason code.

The committed missing-party-authority vector is re-sealed around a one-signature authorization artifact and therefore isolates `party_authority_missing` without relying on a stale downstream handoff digest.

## Advisory lifecycle behavior

The advisory positive has a final operative disposition and an empty `executions` array.

It does not name an executor.

An implementation must not fabricate a completed execution receipt, failure, or native transaction reference to represent that state.

If an implementation emits an explicit `not_attempted` execution-state record, the state does not require a failure code or receipt proof.

Any later enforcement or execution artifact remains outside the disposition and must bind back to the operative disposition if it is added.

## LCP profile behavior

An LCP-profile runner must verify caller-supplied exact bytes and reject changed ATR, clause, rules, catalog, service, method, jurisdiction, or intake bindings.

It must reject duplicate JSON keys, invalid UTF-8, excessive artifact sizes, excessive JSON nesting, malformed URLs, and legal-context substitution.

It must not infer resolution authority from the presence of an LCP reference.

## Official placement behavior

The committed placement outputs are reproduced by Integra packages `0.12.1` under Node.js 24.

The results cover official AP2, UCP, and x402 placement and extraction APIs.

The strict x402 conflict rejection is an additional experimental consumer rule.

## Portable schema behavior

The JSON Schemas use retrieval-relative `$id` and `$ref` values.

A consumer that retrieves the lifecycle schema from a commit-pinned URL will therefore resolve sibling schemas from that same pinned commit.

`npm run check` compiles every schema under Draft 2020-12 and validates both committed core positive lifecycles.

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
