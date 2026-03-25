/**
 * Midnight network provider configuration.
 *
 * Connects to the Midnight proof server and indexer.
 * Configured via environment variables:
 * - MIDNIGHT_PROOF_SERVER_URL (default: http://localhost:6300)
 * - MIDNIGHT_INDEXER_URL
 * - MIDNIGHT_NODE_URL
 */

export interface MidnightProviders {
  proofServerUrl: string;
  indexerUrl: string;
  nodeUrl: string;
}

export function getProviders(): MidnightProviders {
  return {
    proofServerUrl: process.env.MIDNIGHT_PROOF_SERVER_URL ?? 'http://localhost:6300',
    indexerUrl: process.env.MIDNIGHT_INDEXER_URL ?? 'http://localhost:6301',
    nodeUrl: process.env.MIDNIGHT_NODE_URL ?? 'http://localhost:6302',
  };
}
