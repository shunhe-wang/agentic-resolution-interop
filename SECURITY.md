# Security and trust boundaries

This repository is a public reference implementation and synthetic conformance corpus.

It is not a deployed resolver, escrow, payment service, production-money system, or professional security audit.

## Fail-closed boundaries

The LCP verifier accepts caller-supplied bytes and performs no remote fetching.

It rejects invalid UTF-8, oversized artifacts, duplicate JSON keys, excessive nesting, unsafe URLs, changed exact-byte hashes, unsupported method or jurisdiction, and catalog substitution.

The lifecycle verifier rejects missing bilateral authority references, transaction or line-item drift, stale policy or terms, changed frozen records, excessive remedies, invalid supersession, and unproved or mismatched execution.

The authorization verifier requires distinct claimant and respondent EdDSA signatures from pinned public keys.

Applications still own signer authorization, revocation, key rotation, principal identity, native protocol verification, and legal validity.

## Supplied Integra report boundary

The Integra adapter validates the contents and canonical bytes of a supplied mechanical verification report, but a report is not signed by this adapter and its producer identity is not authenticated here.

Only call the adapter after obtaining the report from a trusted verification process. Freezing its digest proves which report was used; it does not prove who ran the verifier or that the adapter reran the report's live ports.

The evidence CAR is independently checked for content integrity, declared-root agreement, and the required RCS-4 roles. That check establishes package integrity and completeness at the declared role level, not the truth, legal weight, or admissibility of each artifact.

## Canonicalization

Stable JSON identities use RFC 8785 through the Apache-2.0 `canonicalize` package and SHA-256.

RFC 8785 does not normalize Unicode.

Composed and decomposed strings can therefore have different canonical bytes and hashes.

## Placement limitations

Official Integra placement checks prove placement and extraction behavior only.

The AP2 check proves byte preservation of an opaque synthetic mandate and does not verify that mandate.

The LCP reference does not itself prove bilateral resolution consent.

The x402 strict conflict rule is experimental and additional to official package behavior.

## Sensitive data

All committed fixtures are synthetic.

Only public JWK material is committed.

Do not place private keys, bearer credentials, unrestricted URLs, personal data, live payment artifacts, or confidential case records in an issue or fixture.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use [GitHub Security Advisories](https://github.com/shunhe-wang/agentic-resolution-interop/security/advisories/new) for private reporting after repository creation.
