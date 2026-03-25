/**
 * Submit a receipt commitment to the Midnight audit-claims contract.
 *
 * Reads receipt.json produced by the receipt-builder tool and submits
 * the roots and hashes as a public commitment on Midnight.
 *
 * Usage:
 *   tsx src/submitCommitment.ts <path-to-receipt.json> [--contract-address <addr>]
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { hexToBytes } from './utils.js';
import { getProviders } from './providers.js';

interface ReceiptJson {
  receiptId: string;
  contentHash: string;
  baseRootSha256: string;
  zkRootPoseidon: string | null;
  baseManifestHash: string;
  monitorConfigHash: string;
  schemaHash: string;
  observedAtMillis: number;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.error('Usage: tsx src/submitCommitment.ts <receipt.json> [--contract-address <addr>]');
    process.exit(1);
  }

  const receiptPath = args[0];
  const receipt: ReceiptJson = JSON.parse(
    fs.readFileSync(path.resolve(receiptPath), 'utf-8')
  );

  console.log('=== Submit Commitment to Midnight ===');
  console.log(`Receipt ID:    ${receipt.receiptId}`);
  console.log(`Content Hash:  ${receipt.contentHash}`);
  console.log(`Base Root:     ${receipt.baseRootSha256}`);
  console.log(`ZK Root:       ${receipt.zkRootPoseidon ?? '(none)'}`);
  console.log(`Config Hash:   ${receipt.monitorConfigHash}`);
  console.log(`Schema Hash:   ${receipt.schemaHash}`);
  console.log(`Timestamp:     ${receipt.observedAtMillis}`);
  console.log('');

  // Convert to byte arrays for the contract
  const receiptId = hexToBytes(receipt.receiptId);
  const zkRoot = receipt.zkRootPoseidon
    ? hexToBytes(receipt.zkRootPoseidon)
    : new Uint8Array(32); // zero bytes if no ZK root
  const baseRoot = hexToBytes(receipt.baseRootSha256);
  const configHash = hexToBytes(receipt.monitorConfigHash);
  const schemaHash = hexToBytes(receipt.schemaHash);
  const timestamp = BigInt(receipt.observedAtMillis);

  const providers = getProviders();

  // TODO: Replace with actual Midnight SDK calls when API stabilizes
  //
  // Expected flow:
  // 1. Connect to proof server at providers.proofServerUrl
  // 2. Load contract at deployed address (or deploy if --deploy flag)
  // 3. Build the submitCommitment transaction:
  //    const tx = await contract.callCircuit('submitCommitment', {
  //      receiptId,
  //      zkRoot,
  //      baseRoot,
  //      configHash,
  //      schemaHash,
  //      ts: timestamp,
  //    });
  // 4. Submit and wait for confirmation
  // 5. Log transaction hash

  console.log('TODO: Midnight SDK integration pending');
  console.log(`Would call submitCommitment on ${providers.proofServerUrl}`);
  console.log('Commitment data prepared successfully.');
}

main().catch(console.error);
