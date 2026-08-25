# Integra resolution-handoff adapter

This adapter turns already-verified Integra legal-context evidence into the protocol-neutral `resolution-handoff-v1` boundary.

It is resolver-side glue, not a replacement for Integra's verification walk or a dispute-resolution standard.

## Public seam

```ts
buildIntegraResolutionHandoff(input) -> Promise<ResolutionHandoff>
```

The caller supplies:

- an Integra mechanical `VerificationReport` obtained from a trusted verification process;
- the caller-declared identifier of that verification process;
- an Integra evidence CAR and its declared root;
- the exact bilateral resolution-authorization JWS and pinned public verification keys;
- the exact legal-context bindings;
- a proposed neutral handoff draft and its included and excluded artifacts; and
- the observation time used for authorization and report checks.

The adapter:

1. requires a verified TC-3 or TC-4 report with all resolver-required steps proved;
2. re-verifies the CAR, its root, and the RCS-4 evidence-role floor;
3. verifies distinct claimant and respondent signatures;
4. matches the signed transaction, parties, legal context, claim, and remedy ceiling to the draft; and
5. emits a frozen handoff that binds the report, CAR, authorization, and dispute record together.

Start with the [complete synthetic input](../../fixtures/lcp/integra/valid/adapter-input.json) and its [expected handoff](../../fixtures/lcp/integra/valid/resolution-handoff.json).

## Trust boundary

The adapter serializes and freezes the supplied report with Integra's canonical report serializer. The emitted verifier identifier is caller-declared: the adapter does not authenticate the report producer and does not rerun live verification ports.

The application must establish that trust before calling the adapter.

The CAR integrity check proves content-addressed package integrity and required-role presence. It does not decide whether evidence is true, persuasive, admissible, or sufficient on the merits.

An LCP reference and an Integra report do not appoint a resolver. Appointment comes only from the separately verified two-signature authorization.

## Stable negative cases

The [negative-vector manifest](../../fixtures/lcp/integra/negative-vectors.json) covers:

- an unverified report;
- a malformed report;
- a missing RCS-4 evidence role;
- a CAR root mismatch;
- a one-signature authorization;
- changed legal terms;
- a missing exact legal-context artifact; and
- a requested remedy above the bilateral ceiling.

Run all vectors under Node.js 24 or later:

```bash
npm ci
npm run check
```
