import { createAuditLedger, verifyAuditLedger, type JsonValue } from '@lp-labs/audit-ledger';

const input: JsonValue = { action: 'updated', subject: 'user:1' };
const provider: Crypto = globalThis.crypto;
const ledger = createAuditLedger({ crypto: provider });
const entry = await ledger.append(input);
const verified = await verifyAuditLedger([entry], { crypto: provider });
if (!verified.valid) throw new Error('Ledger verification failed');
