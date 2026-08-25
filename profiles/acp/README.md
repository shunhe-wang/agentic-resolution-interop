# Informative ACP external-resolution test vector

This profile exercises the seam discussed in [ACP Discussion #298](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/discussions/298).

It is a test vector, not an ACP extension proposal.

The source `Order` is pinned to ACP commit `7fdd78df677a94dce04c770644b0fbbb1401272b` and its unreleased `Order` schema.

The source order has one `dispute` adjustment in `pending` state for one undelivered line item.

The fixture then carries the same order, checkout, and line-item identifiers into a provider-neutral resolution lifecycle with four distinct stages:

1. contested transaction;
2. bilateral handoff to an external resolver;
3. final disposition; and
4. separate execution receipt.

## Boundary under test

An ACP `dispute` adjustment records that a transaction is contested.

It does not by itself appoint a resolver, establish bilateral resolution authority, prove a disposition, or prove that a remedy executed.

The valid vector therefore requires separate claimant and respondent authority references.

It also requires the execution receipt to identify the operative disposition while remaining a distinct artifact.

The source ACP `Order` is preserved without added extension fields.

The surrounding corpus wrapper declares `extensionPlacement: "not_asserted"` because ACP extension placement is unsettled.

## Vectors

- [Valid contested transaction to external resolution](../../fixtures/acp/valid/contested-external-resolution.json)
- [Invalid: dispute adjustment without bilateral authority](../../fixtures/acp/negative/dispute-adjustment-without-bilateral-authority.json)
- [Invalid: disposition reused as execution evidence](../../fixtures/acp/negative/disposition-as-execution.json)

Each file is synthetic and deterministic.

The pinned structural check covers only the ACP `Order` fields exercised by this vector.

It explicitly records `authenticity: "not_claimed"` and does not claim to authenticate a merchant, verify an ACP-native signature, establish legal consent, decide a dispute, or execute a refund.

## Reproduce

```bash
npm ci
npm run check
```
