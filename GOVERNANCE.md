# Governance

This repository begins as a maintainer-led interoperability project with open technical participation.

The initial maintainer is People's Court.

The core lifecycle, LCP profile, fixture parties, synthetic resolver, and execution roles remain provider-neutral.

Protocol projections may use an explicitly identified vendor namespace where the protocol requires an accountable namespace authority. The UCP extension is governed by People's Court under `ai.peoplescourt.shopping.dispute_resolution`; that ownership does not imply that People's Court is the resolver or executor in the neutral fixtures.

## Decision process

Minor fixes and new noncontroversial vectors use ordinary pull-request review.

Changes to artifact identity, authority semantics, remedy bounds, supersession, finality, execution meaning, reason codes, or protocol namespaces require a public design issue before implementation.

The issue must state the compatibility effect, alternatives considered, migration path, and whether a new corpus version is required.

## Compatibility

Existing valid and negative vectors are stable within a corpus major version.

Breaking changes require a new versioned directory or schema id.

No maintainer may describe an experimental profile as adopted by an upstream protocol without a link to the upstream decision.

## Working groups

Protocol-focused discussion may be organized into informal working groups when at least two independent implementations participate.

Any future Dispute Resolution Working Group proposal should begin with tested cross-implementation vectors and a written scope.

It should not claim authority from this repository alone.

## Maintainer expansion

Sustained contributors may be added as reviewers or maintainers based on demonstrated technical work, careful trust-boundary reasoning, and constructive cross-project collaboration.

Maintainer status is documented in [MAINTAINERS.md](MAINTAINERS.md).
