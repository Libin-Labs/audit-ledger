import audit = require('@lp-labs/audit-ledger');

async function run(): Promise<void> {
  const provider: Crypto = globalThis.crypto;
  const ledger = audit.createAuditLedger({ crypto: provider });
  await ledger.append({ action: 'created' });
  const verified = await ledger.verify();
  if (!verified.valid) throw new Error('Ledger verification failed');
}
void run();
