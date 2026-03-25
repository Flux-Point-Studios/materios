/**
 * Prove that a receipt's risk score meets a threshold WITHOUT revealing the score.
 *
 * This is the core ZK privacy demonstration for Materios:
 * - The actual risk score is provided as a private witness
 * - The monitor config hash is verified against the on-chain commitment
 * - Only the Boolean result (pass/fail) is visible on-chain
 *
 * Usage:
 *   tsx src/proveRiskThreshold.ts <receipt-id> <threshold> <actual-score> <config-hash>
 *
 * Example:
 *   tsx src/proveRiskThreshold.ts \
 *     0xaabb...  \       # receipt ID (committed on-chain)
 *     75         \       # threshold (public: "score must be >= 75")
 *     92         \       # actual score (PRIVATE: never revealed)
 *     0xccdd...          # config hash (must match committed config)
 */

import { hexToBytes, bytesToHex } from './utils.js';
import { getProviders } from './providers.js';

interface ProofInputs {
  receiptId: Uint8Array;
  threshold: bigint;
  // Private witness inputs — these are NEVER sent to the contract directly.
  // They are provided to the proof server which generates a ZK proof.
  privateScore: bigint;
  privateConfigHash: Uint8Array;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 4) {
    console.error(
      'Usage: tsx src/proveRiskThreshold.ts <receipt-id> <threshold> <actual-score> <config-hash>'
    );
    console.error('');
    console.error('  receipt-id:   hex-encoded receipt ID (must have been committed)');
    console.error('  threshold:    minimum risk score (public, visible on-chain)');
    console.error('  actual-score: real risk score (PRIVATE, only used in proof generation)');
    console.error('  config-hash:  hex-encoded monitor config hash (must match commitment)');
    process.exit(1);
  }

  const [receiptIdHex, thresholdStr, actualScoreStr, configHashHex] = args;

  const inputs: ProofInputs = {
    receiptId: hexToBytes(receiptIdHex),
    threshold: BigInt(thresholdStr),
    privateScore: BigInt(actualScoreStr),
    privateConfigHash: hexToBytes(configHashHex),
  };

  console.log('=== Prove Risk Threshold (ZK) ===');
  console.log(`Receipt ID:     ${receiptIdHex}`);
  console.log(`Threshold:      ${inputs.threshold} (PUBLIC -- visible on-chain)`);
  console.log(`Actual Score:   ${inputs.privateScore} (PRIVATE -- never revealed)`);
  console.log(`Config Hash:    ${configHashHex}`);
  console.log('');

  // Pre-flight check: would the proof succeed?
  if (inputs.privateScore < inputs.threshold) {
    console.error('ERROR: Actual score is below threshold. Proof would fail.');
    console.error(`  ${inputs.privateScore} < ${inputs.threshold}`);
    process.exit(1);
  }

  console.log(`Pre-flight: score ${inputs.privateScore} >= ${inputs.threshold} -- PASS`);
  console.log('');

  const providers = getProviders();

  // TODO: Replace with actual Midnight SDK calls when API stabilizes
  //
  // Expected flow:
  //
  // 1. Connect to proof server
  //    The proof server generates the ZK proof locally. The private inputs
  //    (actualScore, configHash) are provided as witnesses and NEVER leave
  //    the proof server.
  //
  // 2. Set up witnesses:
  //    contract.setWitness('local_risk_score', () => inputs.privateScore);
  //    contract.setWitness('local_config_hash', () => inputs.privateConfigHash);
  //
  // 3. Call the proveRiskThreshold circuit:
  //    const tx = await contract.callCircuit('proveRiskThreshold', {
  //      receiptId: inputs.receiptId,
  //      threshold: inputs.threshold,
  //    });
  //    // Note: only receiptId and threshold are public inputs.
  //    // The proof server uses the witnesses internally.
  //
  // 4. Submit proof transaction to Midnight network
  //    const result = await tx.submit();
  //
  // 5. Verify the claim was stored:
  //    const hasProof = await contract.callCircuit('hasRiskProof', {
  //      receiptId: inputs.receiptId,
  //    });
  //    assert(hasProof === true);
  //
  // What an observer sees on-chain:
  //   - receiptId (public)
  //   - threshold value (public)
  //   - Boolean result: true (the proof passed)
  //   - The ZK proof itself (verifiable by anyone)
  //
  // What is NOT revealed:
  //   - The actual risk score
  //   - The raw trace data
  //   - The monitor configuration details

  console.log('TODO: Midnight SDK integration pending');
  console.log(`Would call proveRiskThreshold on ${providers.proofServerUrl}`);
  console.log('');
  console.log('When integrated, the flow will be:');
  console.log('  1. Proof server receives private inputs as witnesses');
  console.log('  2. ZK proof generated locally (score never leaves machine)');
  console.log('  3. Only the proof + public inputs submitted to Midnight');
  console.log('  4. Anyone can verify the claim without seeing the score');
  console.log('');
  console.log('Proof inputs prepared successfully.');
}

main().catch(console.error);
