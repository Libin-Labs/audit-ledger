# @lp-labs/audit-ledger

An append-only in-memory chain of bounded canonical JSON records hashed with SHA-256 through the
standard Web Crypto API. No custom cryptography or third-party runtime dependency is used.

## Install

```sh
npm install @lp-labs/audit-ledger
```

## Quick start

```js
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createAuditLedger, verifyAuditLedger } from '@lp-labs/audit-ledger';

const ledger = createAuditLedger({ crypto: webcrypto });
await ledger.append({ action: 'record-created', subject: 'user:42' });
await ledger.append({ action: 'record-read', subject: 'user:42' });
const entries = ledger.entries();
assert.equal((await ledger.verify()).valid, true);
assert.equal((await verifyAuditLedger(entries, { crypto: webcrypto })).valid, true);
```

## API and types

- `createAuditLedger(options?): AuditLedger` requires `SubtleCrypto.digest`; supply `crypto` as a
  platform `Crypto` or `SubtleCrypto` object when `globalThis.crypto.subtle` is not available.
- `AuditLedger.append(record): Promise<LedgerEntry>` queues appends in call order. Records must be
  strict JSON values; each entry records its zero-based `sequence`, `previousHash`, frozen `record`,
  and lowercase SHA-256 `hash`.
- `AuditLedger.entries(): readonly LedgerEntry[]` returns an immutable snapshot.
- `AuditLedger.verify(): Promise<LedgerVerification>` independently recalculates the current chain.
- `verifyAuditLedger(entries, options?): Promise<LedgerVerification>` verifies a copied/exported chain
  without relying on a ledger instance.
- `JsonPrimitive` and `JsonValue` describe accepted strict JSON data. `LedgerEntry` describes a link,
  `LedgerOptions` defines crypto and limits, and `LedgerVerification` reports `valid`, verified
  `entries`, and for invalid chains the first failing `index` and `reason`.

## Canonicalization and limits

Object keys are sorted recursively before hashing. Strings, booleans, null, and finite numbers are
accepted. Arrays, plain records, and null-prototype records are supported; undefined, accessors,
functions, symbols, bigints, cycles, non-plain objects, and non-finite numbers fail. Defaults are
10,000 entries, 65,536 UTF-8 bytes per record, 20,000 JSON nodes, 20,000 items per array, and depth 32. `maxEntries` accepts 1–1,000,000 and `maxRecordBytes` accepts 1–10,000,000. Hashing uses the
platform's `SHA-256` implementation through `SubtleCrypto.digest`.

## Errors and verification results

Malformed options, unavailable Web Crypto, and unsupported JSON values throw `TypeError`; exhausted
limits and oversized or deeply nested records throw `RangeError`; provider failures reject append or
verification promises. `verifyAuditLedger` reports structural, sequence, link, record, and digest
mismatches as `{ valid: false, index, reason }` rather than treating an incomplete chain as valid.

## Important security boundary

This ledger is in-memory and its hashes alone do not provide tamper evidence against an actor who can
rewrite the entire ledger and recompute its hashes. Persist entries durably and anchor a trusted latest
hash outside the ledger (for example, in independently controlled storage) to detect truncation or full
rewrites. Verification proves consistency with a supplied chain, not authenticity, author identity,
delivery, completeness, access control, or external timestamping. Protect the injected crypto provider
and your anchoring process.

## Support

If this library is useful to you, consider supporting its maintenance with a [donation via PayPal](https://www.paypal.me/LibinPrasanth).

## Author

Created by [Libin Prasanth](https://www.linkedin.com/in/libinprasanth/). Connect on LinkedIn for updates and discussion.
