import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createAuditLedger, verifyAuditLedger } from '../dist/esm/index.js';

const options = { crypto: webcrypto };

test('canonicalizes record key order and independently verifies appended chain', async () => {
  const ledger = createAuditLedger(options);
  const first = await ledger.append({ z: 2, a: { y: true, x: 1 } });
  const second = await ledger.append({ action: 'update', id: 4 });
  assert.equal(first.sequence, 0);
  assert.equal(second.previousHash, first.hash);
  assert.equal((await ledger.verify()).valid, true);
  assert.equal((await verifyAuditLedger(ledger.entries(), options)).valid, true);
  const reordered = await createAuditLedger(options).append({ a: { x: 1, y: true }, z: 2 });
  assert.equal(first.hash, reordered.hash);
});

test('serializes concurrent appends in call order', async () => {
  const ledger = createAuditLedger(options);
  const entries = await Promise.all([ledger.append({ id: 1 }), ledger.append({ id: 2 })]);
  assert.deepEqual(
    entries.map(({ sequence }) => sequence),
    [0, 1],
  );
  assert.equal((await ledger.verify()).valid, true);
});

test('detects changed records, hashes, sequence, and linkage', async () => {
  const ledger = createAuditLedger(options);
  await ledger.append({ value: 'original' });
  await ledger.append({ value: 'next' });
  const entries = ledger.entries();
  const changed = structuredClone(entries);
  changed[0].record.value = 'changed';
  assert.equal((await verifyAuditLedger(changed, options)).reason, 'hash-mismatch');
  const brokenLink = structuredClone(entries);
  brokenLink[1].previousHash = '0'.repeat(64);
  assert.equal((await verifyAuditLedger(brokenLink, options)).reason, 'previous-hash-mismatch');
  const brokenOrder = structuredClone(entries);
  brokenOrder[1].sequence = 8;
  assert.equal((await verifyAuditLedger(brokenOrder, options)).reason, 'sequence-mismatch');
  const badShape = [{ nope: true }];
  assert.equal((await verifyAuditLedger(badShape, options)).reason, 'malformed-entry');
});

test('copies and freezes caller records to prevent post-append mutation', async () => {
  const record = { nested: { value: 1 } };
  const ledger = createAuditLedger(options);
  const entry = await ledger.append(record);
  record.nested.value = 99;
  assert.equal(entry.record.nested.value, 1);
  assert.equal(Object.isFrozen(entry.record.nested), true);
  assert.equal((await ledger.verify()).valid, true);
});

test('rejects unsupported, cyclic, over-deep, and over-budget JSON', async () => {
  const ledger = createAuditLedger({ ...options, maxRecordBytes: 16 });
  await assert.rejects(ledger.append({ x: undefined }), /strict JSON/);
  await assert.rejects(ledger.append([, 1]), /holes/);
  const cyclic = {};
  cyclic.self = cyclic;
  await assert.rejects(ledger.append(cyclic), /Cyclic/);
  await assert.rejects(ledger.append({ text: 'this string is too long' }), /exceeds 16 bytes/);
  const deep = {};
  let cursor = deep;
  for (let index = 0; index < 34; index++) cursor = cursor.next = {};
  await assert.rejects(ledger.append(deep), /depth exceeds 32/);
  await assert.rejects(ledger.append(new Date()), /plain records/);
});

test('enforces finite capacity and reports malformed API input explicitly', async () => {
  const ledger = createAuditLedger({ ...options, maxEntries: 1 });
  await ledger.append({ id: 1 });
  await assert.rejects(ledger.append({ id: 2 }), /capacity exceeded/);
  await assert.rejects(verifyAuditLedger({}, options), /must be an array/);
  assert.throws(() => createAuditLedger({ crypto: {} }), /SubtleCrypto.digest/);
  assert.throws(() => createAuditLedger({ maxEntries: 0, ...options }), /maxEntries/);
});

test('rejects accessor-backed records rather than invoking property getters', async () => {
  const record = {};
  Object.defineProperty(record, 'secret', {
    enumerable: true,
    get() {
      throw new Error('called');
    },
  });
  await assert.rejects(createAuditLedger(options).append(record), /accessor properties/);
});
