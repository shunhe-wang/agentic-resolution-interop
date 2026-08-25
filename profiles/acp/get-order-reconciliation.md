# Informative GET Order reconciliation matrix

This matrix exercises the recovery path proposed in [ACP issue #234](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/issues/234).

It is runnable evidence, not proposed ACP schema.

## Boundary under test

A GET endpoint can recover current order state after a missed webhook, but a consumer also needs to decide whether each webhook or GET snapshot is newer, stale, a replay, or contradictory.

An ETag can avoid retransmitting an unchanged representation.

An ETag does not by itself order webhook and GET observations across channels.

The fixture therefore places a merchant-scoped monotonic revision in an informative external envelope while leaving its eventual ACP location unasserted.

The source `Order` remains unchanged.

## Acceptance matrix

| Current observation | Incoming observation | Expected result |
|---|---|---|
| Webhook revision 8 | Duplicate webhook revision 8, same digest | Replay |
| Webhook revision 8 | Delayed webhook revision 7 | Ignore stale |
| Webhook revision 8 | GET revision 9 | Advance |
| GET revision 9 | Delayed webhook revision 8 | Ignore stale |
| GET revision 9 | GET revision 9, different digest | Conflict |
| Webhook revision 7 | GET revision 9 after a missed webhook | Advance and recover |
| GET revision 9 | Matching ETag / 304 observation | No state change |

Every full snapshot carries a SHA-256 digest over RFC 8785 canonical JSON.

The reducer rejects a declared digest that does not match the supplied `Order` bytes.

## Reproduce

The authoritative fixture is [fixtures/acp/get-order/reconciliation-matrix.json](../../fixtures/acp/get-order/reconciliation-matrix.json).

```bash
npm ci
npm run check
```
