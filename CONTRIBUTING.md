# Contributing

Issues, independent runner results, and focused pull requests are welcome.

Do not include secrets, personal data, live case material, confidential transaction records, or suspected vulnerabilities in a public issue.

Report vulnerabilities through the process in [SECURITY.md](SECURITY.md).

## High-value contributions

The highest-value contribution is a stable vector that exposes an interoperability loss across a real protocol or execution path.

Please identify the exact field, digest, role, amount, authority, supersession edge, or receipt status at issue.

UCP escrow-held and post-settlement merchant-refund reports are especially useful for the initial profile.

ACP reports should identify whether a pending `dispute` adjustment can be carried into a bilateral external handoff without inventing extension placement or conflating disposition with execution.

LCP legal-context, AP2 placement, and x402 conflict cases are also in scope.

## Pull requests

Contributions are licensed under Apache License 2.0 and require a Developer Certificate of Origin sign-off in every commit.

Use `git commit -s` to add:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Before opening a pull request:

1. run `npm ci` under Node.js 24 or later;
2. run `npm run check`;
3. describe the protocol, trust-boundary, or security effect;
4. add or update a mechanically executed vector; and
5. update claim-bearing documentation when behavior changes.

Changes that weaken bilateral authority, transaction binding, exact-byte integrity, remedy limits, append-only supersession, or the disposition-execution boundary will not be accepted without an explicit versioned design decision.
