# People's Court experimental UCP external-resolution profile

Namespace: `ai.peoplescourt.shopping.dispute_resolution`

Version: `2026-08-23`

Canonical schema URL: `https://peoplescourt.ai/standards/ucp/dispute-resolution/2026-08-23/schema.json`

People's Court governs this vendor-extension namespace. The referenced lifecycle, fixture parties, resolver, and execution roles remain provider-neutral.

The canonical schema URL was not live when this corpus revision was published. Implementations must not advertise or negotiate this capability until that exact schema is served from the namespace-authority domain and independently verified.

This experimental profile attaches references to an externally resolved dispute lifecycle without redefining UCP order semantics.

It is not adopted by the UCP project.

## Required invariants

The UCP order and its native verification establish commerce-record provenance only.

They do not establish bilateral resolution authority.

An implementation must preserve the exact received order, separately verify claimant and respondent authority, freeze the transaction and dispute artifacts into one handoff, retain disposition revisions through supersession, and represent execution through a distinct receipt.

The extension arrays are append-oriented references.

The fixture-level `pressureTest.posture` value identifies who is expected to return a native receipt.

It is pressure-test metadata outside the negotiated extension and does not prove that the identified executor acted.

Each path embeds its own frozen handoff, dispositions, execution evidence, and receipt. The escrow-held path freezes a neutral custody/hold proof and names a separate escrow-controller receipt. The post-settlement path freezes prior merchant-settlement evidence and then carries distinct disposition-bound refund-request, merchant-approval, and same-rail refund-receipt bindings.

These are neutral fixture shapes, not invented Facet-native fields. The `westonMappingRequired` notes identify the exact evidence and receipt relationships an escrow or merchant-refund implementation must map without loss.

## Pressure-test fixtures

- [Funds still held in escrow](../../fixtures/ucp/paths/escrow-held.json)
- [Funds already settled and merchant or PSP refund required](../../fixtures/ucp/paths/post-settlement-merchant-refund.json)

Negative vectors reject a swapped executor, a receipt from the wrong execution path, and custody evidence from the wrong posture:

- [Swapped executor](../../fixtures/ucp/negative/swapped-executor.json)
- [Swapped receipt](../../fixtures/ucp/negative/swapped-receipt.json)
- [Swapped custody evidence](../../fixtures/ucp/negative/swapped-custody-evidence.json)

Independent implementers should report any field or lifecycle edge that cannot be represented exactly in both paths.
