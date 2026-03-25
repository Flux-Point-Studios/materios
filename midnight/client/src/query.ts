/**
 * Query an audit commitment and risk proofs from the Midnight audit-claims contract.
 *
 * Looks up a commitment by its receiptId and returns the stored baseRoot,
 * plus checks for any verified risk threshold proofs. This can be used to
 * verify that a specific audit receipt has been anchored on-chain and to
 * confirm that ZK-proven claims exist for it.
 *
 * Usage:
 *   pnpm query -- <receiptId>
 *
 * Arguments:
 *   receiptId - 32-byte hex identifier of the commitment to look up
 *
 * Example:
 *   pnpm query -- 0xabc...123
 *
 * Required environment variables:
 *   - MIDNIGHT_PROOF_SERVER_URL (or default localhost:6300)
 *   - MIDNIGHT_CONTRACT_ADDRESS (deployed audit-claims address)
 */

import { getProviders } from './providers.js';
import { hexToBytes, bytesToHex, assertEnv } from './utils.js';

async function main(): Promise<void> {
  // -------------------------------------------------------------------------
  // 1. Parse command-line arguments
  // -------------------------------------------------------------------------
  const receiptIdHex = process.argv[2];

  if (!receiptIdHex) {
    console.error('Usage: pnpm query -- <receiptId>');
    process.exit(1);
  }

  const receiptIdBytes = hexToBytes(receiptIdHex);

  console.log(`Querying commitment for receiptId: ${receiptIdHex}`);

  // -------------------------------------------------------------------------
  // 2. Connect to the deployed contract
  // -------------------------------------------------------------------------
  const providers = getProviders();
  // const contractAddress = assertEnv('MIDNIGHT_CONTRACT_ADDRESS');

  // TODO: Connect to the deployed contract instance
  //
  //   import { Contract } from '@midnight-ntwrk/compact-runtime';
  //   const contract = await Contract.connect(contractAddress, {
  //     providers,
  //     wallet,
  //   });

  // -------------------------------------------------------------------------
  // 3. Call the lookupCommitment circuit
  // -------------------------------------------------------------------------

  // TODO: Invoke the lookupCommitment circuit
  //
  //   const result = await contract.call.lookupCommitment(receiptIdBytes);
  //
  //   // The circuit returns the baseRoot as Bytes<32>
  //   const baseRootHex = bytesToHex(result);
  //   console.log(`Commitment found.`);
  //   console.log(`  baseRoot: 0x${baseRootHex}`);
  //
  // Note: If the commitment does not exist, the contract will throw
  // an assertion error: "Commitment not found".

  // -------------------------------------------------------------------------
  // 4. Optionally read additional ledger state
  // -------------------------------------------------------------------------

  // TODO: Query additional fields from the contract ledger
  //
  // The contract stores multiple maps keyed by receiptId:
  //   - zk_roots:      ZK-friendly Merkle root
  //   - base_roots:    Base audit Merkle root
  //   - config_hashes: Hash of the audit configuration
  //   - schema_hashes: Hash of the data schema
  //   - timestamps:    Unix timestamp of the commitment
  //
  // These can be read via the contract's ledger state API:
  //
  //   const ledger = await contract.ledger();
  //   const zkRoot = await ledger.zk_roots.get(receiptIdBytes);
  //   const configHash = await ledger.config_hashes.get(receiptIdBytes);
  //   const schemaHash = await ledger.schema_hashes.get(receiptIdBytes);
  //   const timestamp = await ledger.timestamps.get(receiptIdBytes);
  //
  //   console.log(`  zkRoot:     0x${bytesToHex(zkRoot)}`);
  //   console.log(`  configHash: 0x${bytesToHex(configHash)}`);
  //   console.log(`  schemaHash: 0x${bytesToHex(schemaHash)}`);
  //   console.log(`  timestamp:  ${timestamp}`);

  // -------------------------------------------------------------------------
  // 5. Query risk threshold proofs
  // -------------------------------------------------------------------------

  // TODO: Check if a risk proof exists for this receipt:
  //
  //   const hasProof = await contract.call.hasRiskProof(receiptIdBytes);
  //   console.log(`  risk_proof: ${hasProof}`);
  //
  //   if (hasProof) {
  //     console.log('');
  //     console.log('  A verified ZK proof exists for this receipt.');
  //     console.log('  The risk score was proven to meet the committed threshold');
  //     console.log('  without revealing the actual score value.');
  //   } else {
  //     console.log('');
  //     console.log('  No risk threshold proof found for this receipt.');
  //     console.log('  Use proveRiskThreshold to generate one.');
  //   }

  console.log('');
  console.log('query scaffold complete.');
  console.log(
    'Replace the TODO sections with actual Midnight SDK calls ' +
      'once the contract is deployed and the SDK version is finalized.'
  );
}

main().catch((err) => {
  console.error('Query failed:', err);
  process.exit(1);
});
