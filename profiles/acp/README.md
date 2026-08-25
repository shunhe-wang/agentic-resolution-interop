# Informative ACP external-resolution test vector

This profile exercises the seam discussed in [ACP Discussion #298](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/discussions/298).

It is a test vector, not an ACP extension proposal.

The source `Order` and webhook contract are pinned to ACP commit `7fdd78df677a94dce04c770644b0fbbb1401272b`.

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

The source ACP `Order` is preserved without added extension fields inside an exact `order_update` webhook body.

The profile recomputes ACP's native `Merchant-Signature` rule: HMAC-SHA256 over `timestamp + "." + raw_body` with the recommended 300-second tolerance.

The committed key is public deterministic test material, not a credential.

Passing this check proves the native signing and replay-window mechanics for the exact synthetic bytes.

It does not authenticate a real merchant or establish production trust.

The surrounding corpus wrapper declares `extensionPlacement: "not_asserted"` because ACP extension placement is unsettled.

## Vectors

- [Valid contested transaction to external resolution](../../fixtures/acp/valid/contested-external-resolution.json)
- [Invalid: changed webhook signature](../../fixtures/acp/negative/webhook-signature-mismatch.json)
- [Invalid: contested amount differs from the requested remedy](../../fixtures/acp/negative/contested-amount-mismatch.json)
- [Invalid: dispute adjustment without bilateral authority](../../fixtures/acp/negative/dispute-adjustment-without-bilateral-authority.json)
- [Invalid: disposition reused as execution evidence](../../fixtures/acp/negative/disposition-as-execution.json)

The separate [GET Order reconciliation matrix](get-order-reconciliation.md) covers missed-webhook recovery and cross-channel ordering without asserting that revision metadata already exists in ACP.

Each file is synthetic and deterministic.

The source check is a manual subset over the ACP `Order` fields exercised by this vector. The pinned schema URL is review context, not a claim of full JSON Schema validation.

The native verifier records `authenticity: "synthetic_test_key_only"` and does not claim to authenticate a real merchant, establish legal consent, decide a dispute, or execute a refund.

## Reproduce

```bash
npm ci
npm run check
```
