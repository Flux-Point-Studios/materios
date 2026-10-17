# Public Sapling corpus

`provenance.json` pins nine Zcash mainnet block fixtures at Zebra commit
`2c3930dacd4ddfb4cf605a216d4bd20eda99725c`. They came from public GitHub files,
never an authenticated node. The block filenames supply the source network and
height; the parser computes each v4 txid from the full transaction bytes.

`vectors.py` parses these Sapling-era v4 blocks and computes their ZIP-243
shielded signature digest. The public block bytes, transaction bytes, spend/output
actions and digest are kept together. `vectors.py --check` verifies every source
hash and regenerates every byte of bundles.json, actions.bin and bundles.bin
before the Wasm verification run. It refuses stale or altered derived data.

The corpus contains 23 transactions / 42 proofs, including five complete
1-spend/2-output bundles. A valid signature over each transaction digest is an
independent check on the parser and ZIP-243 digest construction.

The Sapling verification keys are the uncompressed Bellman VK prefix of the
official Zcash parameter files from https://download.z.cash/downloads/ . The
complete 47,958,396-byte spend and 3,592,860-byte output files were checked against
the upstream librustzcash BLAKE2b-512 pins before extracting the prefixes. The
prefix includes six curve points, the big-endian IC count, then IC G1 points:
`868 + 96 * count` bytes (1,636 spend; 1,444 output). Both parameter hashes and VK
SHA-256 hashes are in provenance.json. The setup ceremony and Sapling relation
are unchanged; no new trusted setup is generated.

Sources:

- [Zebra public vectors](https://github.com/ZcashFoundation/zebra/tree/2c3930dacd4ddfb4cf605a216d4bd20eda99725c/zebra-test/src/vectors)
- [ZIP-243](https://zips.z.cash/zip-0243)
- [Official parameter identities](https://github.com/zcash/librustzcash/blob/17667fb4a33789ecb71fc8418dc320b358ce81b0/zcash_proofs/src/lib.rs)
- [Sapling 0.5.0 public-input construction](https://github.com/zcash/sapling-crypto/blob/0.5.0/src/verifier.rs)

The initial download-only script used the explicit one-off scratch-script TDD
exception. The committed parser, provenance verifier and cryptographic adapter
have behavioral regression tests; the scratch download script has no production
caller. Fixture origin is reviewable and is not itself a proof of verification.
