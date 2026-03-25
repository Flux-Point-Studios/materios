/**
 * Submit a claim against an existing audit commitment on the Midnight
 * audit-claims contract.
 *
 * A claim asserts a boolean result (pass/fail) for a specific claim key,
 * linked to a previously anchored commitment (identified by receiptId).
 * The contract verifies that the commitment exists before recording the claim.
 *
 * Usage:
 *   pnpm submit-claim -- <receiptId> <claimKey> <true|false>
 *
 * Arguments:
 *   receiptId  - 32-byte hex identifier of the existing commitment
 *   claimKey   - 32-byte hex key identifying this specific claim
 *   result     - Boolean claim result: "true" or "false"
 *
 * Example:
 *   pnpm submit-claim -- 0xabc...123 0xdef...456 true
 *
 * Required environment variables:
 *   - MIDNIGHT_PROOF_SERVER_URL (or default localhost:6300)
 *   - MIDNIGHT_CONTRACT_ADDRESS (deployed audit-claims address)
 */

import { getProviders } from './providers.js';
import { hexToBytes, assertEnv } from './utils.js';

async function main(): Promise<void> {
  // -------------------------------------------------------------------------
  // 1. Parse command-line arguments
  // -------------------------------------------------------------------------
  const [receiptIdHex, claimKeyHex, resultStr] = process.argv.slice(2);

  if (!receiptIdHex || !claimKeyHex || !resultStr) {
    console.error(
      'Usage: pnpm submit-claim -- <receiptId> <claimKey> <true|false>'
    );
    process.exit(1);
  }

  if (resultStr !== 'true' && resultStr !== 'false') {
    console.error('Claim result must be "true" or "false"');
    process.exit(1);
  }

  const receiptIdBytes = hexToBytes(receiptIdHex);
  const claimKeyBytes = hexToBytes(claimKeyHex);
  const claimResult = resultStr === 'true';

  console.log('Submitting claim:');
  console.log(`  receiptId:   ${receiptIdHex}`);
  console.log(`  claimKey:    ${claimKeyHex}`);
  console.log(`  claimResult: ${claimResult}`);

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
  // 3. Call the submitClaim circuit
  // -------------------------------------------------------------------------

  // TODO: Invoke the submitClaim circuit
  //
  //   const tx = await contract.call.submitClaim(
  //     receiptIdBytes,
  //     claimKeyBytes,
  //     claimResult
  //   );
  //
  //   console.log(`Transaction hash: ${tx.txHash}`);
  //   console.log(`Claim recorded on-chain successfully.`);
  //
  // Note: The contract will assert that a commitment with the given receiptId
  // exists before allowing the claim to be recorded. If the commitment does
  // not exist, the transaction will fail with "Commitment must exist".

  console.log('');
  console.log('submitClaim scaffold complete.');
  console.log(
    'Replace the TODO sections with actual Midnight SDK calls ' +
      'once the contract is deployed and the SDK version is finalized.'
  );
}

main().catch((err) => {
  console.error('submitClaim failed:', err);
  process.exit(1);
});
