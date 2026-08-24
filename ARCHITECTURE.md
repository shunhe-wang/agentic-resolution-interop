# Architecture

The repository tests boundaries, not a universal dispute protocol.

## Protocol-neutral core

The core defines four artifacts.

1. `resolution-handoff-v1` binds the transaction, disputed lines, bilateral authority references, exact policy and terms digests, evidence manifest, resolver, and remedy ceilings.
2. `resolution-disposition-v1` binds an outcome and bounded remedy to the frozen handoff and supports append-only supersession.
3. `resolution-execution-receipt-v1` identifies the exact operative disposition and records a separate execution attempt or result.
4. `resolution-authorization-v1` demonstrates distinct claimant and respondent signatures over the transaction, legal context, claim scope, appointment, and ceiling.

Verifier-local observation time and fetch metadata do not change stable handoff identity.

The stable identity recipe is RFC 8785 JSON Canonicalization Scheme followed by SHA-256.

The included Unicode tests prove that composed and decomposed strings remain distinct, as RFC 8785 requires.

## Native protocol boundary

Each protocol adapter starts after the native transaction verifier succeeds.

The adapter records a native verification receipt or proof reference in the frozen handoff.

This repository does not replace UCP business-profile trust, AP2 mandate verification, x402 settlement verification, checkout authentication, or rail-specific receipt verification.

## LCP profile

The LCP profile binds exact supplied bytes for discovery, terms, clause, rules, and an experimental dispute-services catalog.

No verifier function performs a remote fetch.

Callers own transport, SSRF prevention, redirect policy, caching, timeout, and trust-anchor selection before supplying bytes.

The experimental catalog is namespaced to avoid implying LCP adoption.

## UCP paths

The UCP extension is append-oriented and keeps lifecycle artifacts as sibling references on the order. People's Court owns the vendor namespace `ai.peoplescourt.shopping.dispute_resolution`; the referenced core lifecycle remains provider-neutral.

Execution posture is pressure-test metadata outside the negotiated extension. Both paths therefore exercise the same extension payload while varying the expected execution owner and native receipt.

The escrow-held path expects the escrow controller to return a rail-specific receipt.

The post-settlement path expects the merchant or PSP to return a refund receipt.

Both receipts must identify the exact operative disposition and remain distinct from the Award or other disposition artifact.

Each path freezes the funds state observed at handoff into its own manifest. The escrow path binds hold evidence to the escrow custodian and controller. The post-settlement path binds prior merchant settlement, then links a later refund request and merchant approval to a separate same-rail receipt. These are corpus-level neutral shapes; native implementations must supply their own field mapping.

## AP2 and x402 placement checks

The official Integra AP2 check adds `metadata.legalContext` without changing the opaque mandate bytes.

The official UCP check preserves an existing policy.

The official x402 check preserves an existing extension and `accepts[].extra` field.

An additional strict x402 reader rejects conflicting legacy legal-context copies even where the current official reader gives the canonical extension precedence.
