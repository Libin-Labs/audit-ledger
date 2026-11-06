export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };
export interface LedgerEntry {
  readonly sequence: number;
  readonly previousHash: string;
  readonly record: JsonValue;
  readonly hash: string;
}
export interface LedgerOptions {
  readonly crypto?: Crypto | SubtleCrypto;
  readonly maxEntries?: number;
  readonly maxRecordBytes?: number;
}
export interface LedgerVerification {
  readonly valid: boolean;
  readonly entries: number;
  readonly index?: number;
  readonly reason?: string;
}
export interface AuditLedger {
  append(record: JsonValue): Promise<LedgerEntry>;
  entries(): readonly LedgerEntry[];
  verify(): Promise<LedgerVerification>;
}

const integerLimit = (value: number, name: string, max: number): void => {
  if (!Number.isSafeInteger(value) || value < 1 || value > max)
    throw new RangeError(`${name} must be an integer from 1 to ${max}.`);
};
const subtleFor = (provider?: Crypto | SubtleCrypto): SubtleCrypto => {
  const candidate =
    provider === undefined
      ? globalThis.crypto?.subtle
      : 'subtle' in provider
        ? provider.subtle
        : provider;
  if (!candidate || typeof candidate.digest !== 'function')
    throw new TypeError(
      'Web Crypto SubtleCrypto.digest is required; provide it explicitly when unavailable.',
    );
  return candidate;
};
const encode = (value: string): BufferSource => new TextEncoder().encode(value) as BufferSource;
const digest = async (value: string, crypto: SubtleCrypto): Promise<string> => {
  const result = await crypto.digest('SHA-256', encode(value));
  return Array.from(new Uint8Array(result), (byte) => byte.toString(16).padStart(2, '0')).join('');
};

function canonicalJson(value: unknown, maxBytes: number): string {
  let nodes = 0;
  const ancestors = new WeakSet<object>();
  const normalize = (input: unknown, depth: number): unknown => {
    nodes++;
    if (nodes > 20_000) throw new RangeError('JSON node limit exceeded.');
    if (depth > 32) throw new RangeError('JSON nesting depth exceeds 32.');
    if (input === null || typeof input === 'string' || typeof input === 'boolean') return input;
    if (typeof input === 'number') {
      if (!Number.isFinite(input)) throw new TypeError('JSON numbers must be finite.');
      return input;
    }
    if (typeof input !== 'object')
      throw new TypeError('Records must contain strict JSON values only.');
    if (ancestors.has(input)) throw new TypeError('Cyclic records are not valid JSON.');
    ancestors.add(input);
    let output: unknown;
    if (Array.isArray(input)) {
      if (input.length > 20_000) throw new RangeError('JSON array exceeds 20,000 items.');
      const keys = Reflect.ownKeys(input);
      if (
        keys.some(
          (key) => typeof key === 'symbol' || (key !== 'length' && !/^(0|[1-9]\d*)$/.test(key)),
        )
      )
        throw new TypeError('JSON arrays cannot contain named or symbol properties.');
      if (Object.keys(input).length !== input.length)
        throw new TypeError('JSON arrays must not contain holes.');
      const result: unknown[] = [];
      for (let index = 0; index < input.length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
        if (!descriptor || !('value' in descriptor))
          throw new TypeError('JSON arrays cannot contain accessor properties.');
        result.push(normalize(descriptor.value, depth + 1));
      }
      output = result;
    } else {
      const prototype = Object.getPrototypeOf(input);
      if (prototype !== Object.prototype && prototype !== null)
        throw new TypeError('JSON objects must be plain records.');
      if (Reflect.ownKeys(input).some((key) => typeof key === 'symbol'))
        throw new TypeError('JSON objects cannot contain symbol properties.');
      const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      for (const key of Object.keys(input).sort()) {
        const descriptor = Object.getOwnPropertyDescriptor(input, key);
        if (!descriptor || !('value' in descriptor))
          throw new TypeError('JSON objects cannot contain accessor properties.');
        result[key] = normalize(descriptor.value, depth + 1);
      }
      output = result;
    }
    ancestors.delete(input);
    return output;
  };
  const normalized = normalize(value, 0);
  const serialize = (item: unknown): string => {
    if (item === null || typeof item !== 'object') {
      const primitive = JSON.stringify(item);
      if (primitive === undefined) throw new TypeError('Expected a JSON value.');
      return primitive;
    }
    if (Array.isArray(item)) return `[${item.map(serialize).join(',')}]`;
    const record = item as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${serialize(record[key])}`)
      .join(',')}}`;
  };
  const serialized = serialize(normalized);
  if (new TextEncoder().encode(serialized).byteLength > maxBytes)
    throw new RangeError(`Canonical JSON exceeds ${maxBytes} bytes.`);
  return serialized;
}
const immutableJson = (canonical: string): JsonValue => {
  const parsed = JSON.parse(canonical) as JsonValue;
  const freeze = (value: JsonValue): JsonValue => {
    if (value && typeof value === 'object') {
      if (Array.isArray(value)) value.forEach((item) => freeze(item));
      else Object.values(value).forEach((item) => freeze(item));
      Object.freeze(value);
    }
    return value;
  };
  return freeze(parsed);
};
const envelope = (sequence: number, previousHash: string, canonicalRecord: string): string =>
  `{"previousHash":${JSON.stringify(previousHash)},"record":${canonicalRecord},"sequence":${sequence}}`;
const isEntry = (value: unknown): value is LedgerEntry => {
  if (!value || typeof value !== 'object') return false;
  const entry = value as Partial<LedgerEntry>;
  return (
    Number.isSafeInteger(entry.sequence) &&
    typeof entry.previousHash === 'string' &&
    typeof entry.hash === 'string' &&
    /^[a-f0-9]{64}$/.test(entry.hash) &&
    Object.hasOwn(value, 'record')
  );
};

export function createAuditLedger(options: LedgerOptions = {}): AuditLedger {
  if (!options || typeof options !== 'object') throw new TypeError('Options must be an object.');
  const maxEntries = options.maxEntries ?? 10_000;
  const maxRecordBytes = options.maxRecordBytes ?? 64 * 1024;
  integerLimit(maxEntries, 'maxEntries', 1_000_000);
  integerLimit(maxRecordBytes, 'maxRecordBytes', 10_000_000);
  const crypto = subtleFor(options.crypto);
  const ledger: LedgerEntry[] = [];
  let tail = Promise.resolve();
  const append = (record: JsonValue): Promise<LedgerEntry> => {
    const operation = tail.then(async () => {
      if (ledger.length >= maxEntries) throw new RangeError('Ledger entry capacity exceeded.');
      const canonical = canonicalJson(record, maxRecordBytes);
      const safeRecord = immutableJson(canonical);
      const sequence = ledger.length;
      const previousHash = ledger.at(-1)?.hash ?? '';
      const hash = await digest(envelope(sequence, previousHash, canonical), crypto);
      const entry = Object.freeze({ sequence, previousHash, record: safeRecord, hash });
      ledger.push(entry);
      return entry;
    });
    tail = operation.then(
      () => undefined,
      () => undefined,
    );
    return operation;
  };
  return {
    append,
    entries: () => Object.freeze([...ledger]),
    verify: async () => verifyAuditLedger(ledger, { crypto, maxEntries, maxRecordBytes }),
  };
}

export async function verifyAuditLedger(
  entries: readonly unknown[],
  options: LedgerOptions = {},
): Promise<LedgerVerification> {
  if (!Array.isArray(entries)) throw new TypeError('Ledger entries must be an array.');
  const maxEntries = options.maxEntries ?? 10_000;
  const maxRecordBytes = options.maxRecordBytes ?? 64 * 1024;
  integerLimit(maxEntries, 'maxEntries', 1_000_000);
  integerLimit(maxRecordBytes, 'maxRecordBytes', 10_000_000);
  const crypto = subtleFor(options.crypto);
  if (entries.length > maxEntries) throw new RangeError('Ledger entry capacity exceeded.');
  let previousHash = '';
  for (let index = 0; index < entries.length; index++) {
    const item = entries[index];
    if (!isEntry(item))
      return Object.freeze({ valid: false, entries: index, index, reason: 'malformed-entry' });
    if (item.sequence !== index)
      return Object.freeze({ valid: false, entries: index, index, reason: 'sequence-mismatch' });
    if (item.previousHash !== previousHash)
      return Object.freeze({
        valid: false,
        entries: index,
        index,
        reason: 'previous-hash-mismatch',
      });
    let canonical: string;
    try {
      canonical = canonicalJson(item.record, maxRecordBytes);
    } catch {
      return Object.freeze({ valid: false, entries: index, index, reason: 'invalid-record' });
    }
    const expected = await digest(envelope(index, previousHash, canonical), crypto);
    if (item.hash !== expected)
      return Object.freeze({ valid: false, entries: index, index, reason: 'hash-mismatch' });
    previousHash = item.hash;
  }
  return Object.freeze({ valid: true, entries: entries.length });
}
