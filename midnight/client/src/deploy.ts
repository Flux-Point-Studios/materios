/**
 * Deploy the audit-claims Compact contract to the Midnight network.
 *
 * This script:
 *   1. Connects to the Midnight network via configured providers
 *   2. Loads the compiled contract artifacts from contracts/managed/
 *   3. Deploys the audit-claims contract
 *   4. Logs the deployed contract address
 *
 * Usage:
 *   pnpm deploy
 *
 * Required environment variables:
 *   - MIDNIGHT_PROOF_SERVER_URL (or default localhost:6300)
 *   - MIDNIGHT_NODE_URL
 *   - MIDNIGHT_WALLET_SEED (for signing the deploy transaction)
 */

import { getProviders } from './providers.js';

async function main(): Promise<void> {
  const providers = getProviders();

  console.log('Connecting to Midnight network...');
  console.log(`  Proof server: ${providers.proofServerUrl}`);
  console.log(`  Node:         ${providers.nodeUrl}`);
  console.log(`  Indexer:      ${providers.indexerUrl}`);

  // ---------------------------------------------------------------------------
  // TODO: Load compiled contract artifacts
  //
  // The Compact compiler (compactc) produces a managed contract directory
  // containing the circuit keys, verification keys, and ABI. Load them here:
  //
  //   import { Contract } from '@midnight-ntwrk/compact-runtime';
  //   const contractArtifacts = await Contract.load(
  //     'contracts/managed/audit-claims'
  //   );
  //
  // The exact API depends on the version of @midnight-ntwrk/compact-runtime.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // TODO: Create a wallet / signer
  //
  // The Midnight SDK provides wallet abstractions for signing transactions.
  // This will use the MIDNIGHT_WALLET_SEED env var or a keyfile.
  //
  //   import { Wallet } from '@midnight-ntwrk/midnight-js-types';
  //   const wallet = await Wallet.fromSeed(process.env.MIDNIGHT_WALLET_SEED);
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // TODO: Deploy the contract
  //
  // Use the contract artifacts + wallet to deploy:
  //
  //   const deployTx = await contractArtifacts.deploy({
  //     providers,
  //     wallet,
  //   });
  //   const contractAddress = deployTx.contractAddress;
  //   console.log(`Contract deployed at: ${contractAddress}`);
  //
  // Store the contract address in a local file or environment for later use
  // by submitCommitment, submitClaim, and query scripts.
  // ---------------------------------------------------------------------------

  console.log('');
  console.log('Deploy scaffold complete.');
  console.log(
    'Replace the TODO sections above with actual Midnight SDK calls ' +
      'once the contract is compiled and the SDK version is finalized.'
  );
}

main().catch((err) => {
  console.error('Deploy failed:', err);
  process.exit(1);
});
