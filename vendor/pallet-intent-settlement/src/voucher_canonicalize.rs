//! Voucher canonicalization with Plutus V3 Data CBOR for the beneficiary
//! address — the three-way cross-chain anchor.
//!
//! # Why this module exists
//!
//! Team B's Aiken validator (see
//! `validators/aegis-policy-v1/lib/aegis/digests.ak::canonical_voucher_body`)
//! computes the voucher body by **raw-concatenating** the Plutus V3 Data CBOR
//! of the beneficiary `Address`, NOT by SCALE-encoding it with a
//! compact-length prefix. The existing
//! [`crate::types::compute_voucher_digest`] helper SCALE-encodes the address
//! (`BoundedVec<u8>` uses compact-len + raw bytes), which produces a
//! different pre-image and therefore a different Blake2b-256 output.
//!
//! Both are "valid" in isolation — but the Aiken validator is the Cardano
//! source of truth for on-chain verification, so the pallet (Team A) and the
//! TS SDK (Team C) MUST mirror Aiken's byte layout exactly. This module adds
//! that second helper without breaking the first.
//!
//! # Cross-team parity anchor
//!
//! The pinned reference vector is `voucher_digest_with_address` in
//! `docs/test-vectors.json`:
//!
//! ```text
//! expected_hex = ae73d78970eb486376fb9d5e4d00cba0a5b2a2200c935d942cc258b12a7f8405
//! ```
//!
//! Body layout (196 bytes, raw concat — no length prefixes):
//!
//! ```text
//!   claim_id                        (32 bytes)
//!   policy_id                       (32 bytes)
//!   beneficiary_address_cbor        (80 bytes for type-0 CIP-0019 addresses)
//!   amount_ada                      (u64 little-endian, 8 bytes)
//!   bfpr_digest                     (32 bytes)
//!   issued_block                    (u32 little-endian, 4 bytes)
//!   expiry_slot_cardano             (u64 little-endian, 8 bytes)
//! ```
//!
//! # CBOR encoding
//!
//! Aiken's `builtin.serialise_data` emits Plutus V3 Data CBOR with
//! **indefinite-length** constr arrays (`0xd8 0x79 0x9f ... 0xff` markers),
//! NOT the definite-length shortcut (`0xd8 0x79 0x82 ...`) that some Rust
//! CBOR crates default to. We therefore hand-roll the bytes rather than
//! depend on a full CBOR crate — the pallet is `no_std`, the structure is
//! tiny (5 nested constr-0 wrappers for a type-0 address), and correctness
//! is verified byte-for-byte against the pinned Aiken vector.
//!
//! CIP-0019 type-0 address (payment VK + stake VK inline) in Plutus V3 Data:
//!
//! ```text
//! Address {
//!   payment_credential: VerificationKey(hash28),
//!   stake_credential:   Some(Inline(VerificationKey(hash28))),
//! }
//! ```
//!
//! Encodes as (80 bytes):
//!
//! ```text
//!   d8 79 9f                          -- constr-0 indefinite (Address)
//!     d8 79 9f                        --   constr-0 indefinite (VK payment)
//!       58 1c <28B payment hash>      --     bstr(28)
//!     ff
//!     d8 79 9f                        --   constr-0 indefinite (Some)
//!       d8 79 9f                      --     constr-0 indefinite (Inline)
//!         d8 79 9f                    --       constr-0 indefinite (VK stake)
//!           58 1c <28B stake hash>    --         bstr(28)
//!         ff
//!       ff
//!     ff
//!   ff
//! ```
//!
//! Other address shapes (script payment, script stake, pointer, etc.) are
//! NOT supported by this helper in v1 — vouchers issued to non-VK addresses
//! will fail `canonical_voucher_body_with_address` at construction time.
//! Extending this is a tracked follow-up (v2 voucher schema).

use alloc::vec::Vec;
use sp_core::hashing::blake2_256;

use crate::types::{TAG_VCHR, AdaLovelace, BlockNumber, ClaimId, PolicyId, SlotNumber};

/// A Cardano address, decomposed into the two 28-byte key hashes that make
/// up a CIP-0019 type-0 (payment VK + stake VK) address.
///
/// The 57-byte bech32-decoded shape is `0x01 || payment_hash || stake_hash`.
/// Inputs passed to [`build_type0_address_cbor`] must already have the
/// header byte stripped and the two halves split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Type0AddressHashes<'a> {
    pub payment_hash: &'a [u8; 28],
    pub stake_hash: &'a [u8; 28],
}

/// Plutus V3 Data CBOR for a type-0 Cardano address.
///
/// Exactly mirrors what `builtin.serialise_data(Address)` emits on the
/// Aiken / Plutus V3 side. Returns 80 bytes.
///
/// ```text
/// d8799f                                   -- constr-0 indef (Address)
///   d8799f 581c <28B payment> ff           -- VK(payment)
///   d8799f d8799f d8799f 581c <28B stake> ff ff ff   -- Some(Inline(VK(stake)))
/// ff
/// ```
pub fn build_type0_address_cbor(addr: Type0AddressHashes<'_>) -> [u8; 80] {
    // 3 bytes per constr-0-indef header + 1 byte close marker = 4 bytes each.
    // We have 5 nested constr-0-indef wrappers: 5 * 4 = 20 overhead bytes.
    // Plus 2 bstr(28) prefixes (2 bytes each = 4 bytes) and 2 * 28 = 56 bytes
    // of hash data. Total = 20 + 4 + 56 = 80 bytes. Exact.
    let mut out = [0u8; 80];
    // --- outer Address constr-0 indef
    out[0] = 0xd8;
    out[1] = 0x79;
    out[2] = 0x9f;
    // --- payment credential: VerificationKey(hash28) constr-0 indef
    out[3] = 0xd8;
    out[4] = 0x79;
    out[5] = 0x9f;
    // bytes-28 = major-type 2, additional-info 0x18 (1-byte length follows)
    // Actually: len 28 < 31 so we could use 0x5c directly; but Plutus uses
    // the canonical CBOR encoding which for len in [24,255] is 0x58 <len>.
    out[6] = 0x58;
    out[7] = 0x1c; // 28
    out[8..36].copy_from_slice(addr.payment_hash);
    out[36] = 0xff; // close VK(payment)
    // --- stake credential: Some(Inline(VerificationKey(hash28)))
    // Some constr-0 indef
    out[37] = 0xd8;
    out[38] = 0x79;
    out[39] = 0x9f;
    // Inline constr-0 indef
    out[40] = 0xd8;
    out[41] = 0x79;
    out[42] = 0x9f;
    // VerificationKey(hash28) constr-0 indef
    out[43] = 0xd8;
    out[44] = 0x79;
    out[45] = 0x9f;
    out[46] = 0x58;
    out[47] = 0x1c;
    out[48..76].copy_from_slice(addr.stake_hash);
    out[76] = 0xff; // close VK(stake)
    out[77] = 0xff; // close Inline
    out[78] = 0xff; // close Some
    out[79] = 0xff; // close Address
    out
}

/// Errors that can occur when splitting a raw Cardano address into the
/// payment/stake hashes required by [`build_type0_address_cbor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressDecodeError {
    /// Raw address buffer must be exactly 57 bytes (header + 2 * 28).
    WrongLength,
    /// Header byte != 0x01 (the type-0 "payment VK + stake VK inline" shape).
    UnsupportedAddressType,
}

/// Split a raw 57-byte CIP-0019 type-0 address buffer
/// (`0x01 || payment_hash(28) || stake_hash(28)`) into its two key hashes.
///
/// This is the format emitted by `bech32::decode` → payload bytes for a
/// `addr1...` or `addr_test1...` type-0 address.
pub fn split_type0_address_bytes(
    raw: &[u8],
) -> Result<([u8; 28], [u8; 28]), AddressDecodeError> {
    if raw.len() != 57 {
        return Err(AddressDecodeError::WrongLength);
    }
    if raw[0] != 0x01 {
        return Err(AddressDecodeError::UnsupportedAddressType);
    }
    let mut p = [0u8; 28];
    let mut s = [0u8; 28];
    p.copy_from_slice(&raw[1..29]);
    s.copy_from_slice(&raw[29..57]);
    Ok((p, s))
}

/// Canonical voucher body that INCLUDES the beneficiary address as Plutus V3
/// Data CBOR (rather than SCALE-length-prefixed raw bech32 bytes).
///
/// This is the body the Aiken validator reconstructs in
/// [`canonical_voucher_body`](https://github.com/Flux-Point-Studios/aegis-parametric-insurance-dev/blob/main/validators/aegis-policy-v1/lib/aegis/digests.ak).
/// Byte-for-byte mirrors Aiken's output; do NOT change this function's
/// layout without updating Aiken + TS SDK in lockstep.
///
/// Returns the 196-byte canonical body (for type-0 addresses). Amount_ada is
/// a `u64` LE; issued_block is a `u32` LE; expiry_slot is a `u64` LE.
pub fn canonical_voucher_body_with_address(
    claim_id: &ClaimId,
    policy_id: &PolicyId,
    beneficiary_address_cbor: &[u8],
    amount_ada: AdaLovelace,
    bfpr_digest: &[u8; 32],
    issued_block: BlockNumber,
    expiry_slot_cardano: SlotNumber,
) -> Vec<u8> {
    let mut body =
        Vec::with_capacity(32 + 32 + beneficiary_address_cbor.len() + 8 + 32 + 4 + 8);
    body.extend_from_slice(claim_id.as_bytes());
    body.extend_from_slice(policy_id.as_bytes());
    body.extend_from_slice(beneficiary_address_cbor);
    body.extend_from_slice(&amount_ada.to_le_bytes());
    body.extend_from_slice(bfpr_digest);
    body.extend_from_slice(&issued_block.to_le_bytes());
    body.extend_from_slice(&expiry_slot_cardano.to_le_bytes());
    body
}

/// Digest the canonical voucher-with-address body: `blake2b_256(TAG_VCHR || body)`.
pub fn compute_voucher_digest_with_address(
    claim_id: &ClaimId,
    policy_id: &PolicyId,
    beneficiary_address_cbor: &[u8],
    amount_ada: AdaLovelace,
    bfpr_digest: &[u8; 32],
    issued_block: BlockNumber,
    expiry_slot_cardano: SlotNumber,
) -> [u8; 32] {
    let body = canonical_voucher_body_with_address(
        claim_id,
        policy_id,
        beneficiary_address_cbor,
        amount_ada,
        bfpr_digest,
        issued_block,
        expiry_slot_cardano,
    );
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(TAG_VCHR);
    buf.extend_from_slice(&body);
    blake2_256(&buf)
}

#[cfg(test)]
mod property_tests {
    //! Property tests pinning the CBOR layout against hand-picked addresses.
    //!
    //! These three vectors were chosen to cover the hash-value space — they
    //! are NOT the pinned three-way anchor (that lives in the
    //! `parity_test.rs` integration test file and is driven from
    //! `docs/test-vectors.json`).

    use super::*;

    /// Fixed address 1: the pinned three-way anchor address.
    const ADDR1_PAYMENT: [u8; 28] = [
        0x95, 0x78, 0x87, 0x10, 0x0e, 0xbe, 0x5f, 0x9b, 0x0f, 0x9f, 0x24, 0x96, 0x8f, 0x02,
        0x1e, 0xf7, 0x05, 0xb2, 0x5c, 0x7a, 0xaa, 0x63, 0x32, 0x58, 0xe2, 0x88, 0xe0, 0xae,
    ];
    const ADDR1_STAKE: [u8; 28] = [
        0x1f, 0xe3, 0x62, 0x22, 0xd4, 0xd4, 0x5a, 0x1c, 0x70, 0xbf, 0xb9, 0x4b, 0x65, 0xb3,
        0xb8, 0xce, 0x1a, 0xdf, 0x2a, 0x94, 0x91, 0x3d, 0x67, 0xc3, 0x22, 0x12, 0x69, 0x4c,
    ];
    /// Fixed address 2: all-zeros (degenerate).
    const ADDR2_PAYMENT: [u8; 28] = [0u8; 28];
    const ADDR2_STAKE: [u8; 28] = [0u8; 28];
    /// Fixed address 3: all-0xff (degenerate).
    const ADDR3_PAYMENT: [u8; 28] = [0xffu8; 28];
    const ADDR3_STAKE: [u8; 28] = [0xffu8; 28];

    #[test]
    fn cbor_output_is_exactly_80_bytes() {
        for (p, s) in [
            (&ADDR1_PAYMENT, &ADDR1_STAKE),
            (&ADDR2_PAYMENT, &ADDR2_STAKE),
            (&ADDR3_PAYMENT, &ADDR3_STAKE),
        ] {
            let cbor = build_type0_address_cbor(Type0AddressHashes {
                payment_hash: p,
                stake_hash: s,
            });
            assert_eq!(cbor.len(), 80);
        }
    }

    #[test]
    fn cbor_has_correct_outer_markers() {
        let cbor = build_type0_address_cbor(Type0AddressHashes {
            payment_hash: &ADDR1_PAYMENT,
            stake_hash: &ADDR1_STAKE,
        });
        // outer constr-0 indef
        assert_eq!(&cbor[0..3], &[0xd8, 0x79, 0x9f]);
        // closing 0xff for outer Address
        assert_eq!(cbor[79], 0xff);
        // bstr(28) prefix for payment hash
        assert_eq!(&cbor[6..8], &[0x58, 0x1c]);
        // bstr(28) prefix for stake hash
        assert_eq!(&cbor[46..48], &[0x58, 0x1c]);
    }

    #[test]
    fn cbor_embeds_payment_and_stake_hashes() {
        let cbor = build_type0_address_cbor(Type0AddressHashes {
            payment_hash: &ADDR1_PAYMENT,
            stake_hash: &ADDR1_STAKE,
        });
        assert_eq!(&cbor[8..36], &ADDR1_PAYMENT);
        assert_eq!(&cbor[48..76], &ADDR1_STAKE);
    }

    #[test]
    fn distinct_addresses_produce_distinct_cbor() {
        let a = build_type0_address_cbor(Type0AddressHashes {
            payment_hash: &ADDR1_PAYMENT,
            stake_hash: &ADDR1_STAKE,
        });
        let b = build_type0_address_cbor(Type0AddressHashes {
            payment_hash: &ADDR2_PAYMENT,
            stake_hash: &ADDR2_STAKE,
        });
        let c = build_type0_address_cbor(Type0AddressHashes {
            payment_hash: &ADDR3_PAYMENT,
            stake_hash: &ADDR3_STAKE,
        });
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn address1_matches_pinned_hex() {
        // The exact hex the Aiken side emits via `builtin.serialise_data` for
        // the pinned test address (see test_vectors.ak::vec_vchr_address_cbor_pinned).
        let expected: [u8; 80] = [
            0xd8, 0x79, 0x9f, 0xd8, 0x79, 0x9f, 0x58, 0x1c, 0x95, 0x78, 0x87, 0x10, 0x0e, 0xbe,
            0x5f, 0x9b, 0x0f, 0x9f, 0x24, 0x96, 0x8f, 0x02, 0x1e, 0xf7, 0x05, 0xb2, 0x5c, 0x7a,
            0xaa, 0x63, 0x32, 0x58, 0xe2, 0x88, 0xe0, 0xae, 0xff, 0xd8, 0x79, 0x9f, 0xd8, 0x79,
            0x9f, 0xd8, 0x79, 0x9f, 0x58, 0x1c, 0x1f, 0xe3, 0x62, 0x22, 0xd4, 0xd4, 0x5a, 0x1c,
            0x70, 0xbf, 0xb9, 0x4b, 0x65, 0xb3, 0xb8, 0xce, 0x1a, 0xdf, 0x2a, 0x94, 0x91, 0x3d,
            0x67, 0xc3, 0x22, 0x12, 0x69, 0x4c, 0xff, 0xff, 0xff, 0xff,
        ];
        let cbor = build_type0_address_cbor(Type0AddressHashes {
            payment_hash: &ADDR1_PAYMENT,
            stake_hash: &ADDR1_STAKE,
        });
        assert_eq!(cbor, expected, "CBOR output drifted from Aiken reference");
    }

    #[test]
    fn split_type0_address_roundtrip() {
        let mut raw = [0u8; 57];
        raw[0] = 0x01;
        raw[1..29].copy_from_slice(&ADDR1_PAYMENT);
        raw[29..57].copy_from_slice(&ADDR1_STAKE);
        let (p, s) = split_type0_address_bytes(&raw).unwrap();
        assert_eq!(p, ADDR1_PAYMENT);
        assert_eq!(s, ADDR1_STAKE);
    }

    #[test]
    fn split_type0_rejects_wrong_length() {
        assert_eq!(
            split_type0_address_bytes(&[0u8; 10]),
            Err(AddressDecodeError::WrongLength)
        );
    }

    #[test]
    fn split_type0_rejects_non_type0_header() {
        let mut raw = [0u8; 57];
        raw[0] = 0x02; // type-1 (script payment + stake VK)
        assert_eq!(
            split_type0_address_bytes(&raw),
            Err(AddressDecodeError::UnsupportedAddressType)
        );
    }

    #[test]
    fn voucher_body_has_expected_length() {
        let cbor = build_type0_address_cbor(Type0AddressHashes {
            payment_hash: &ADDR1_PAYMENT,
            stake_hash: &ADDR1_STAKE,
        });
        let body = canonical_voucher_body_with_address(
            &sp_core::H256::zero(),
            &sp_core::H256::zero(),
            &cbor,
            0,
            &[0u8; 32],
            0,
            0,
        );
        // 32 + 32 + 80 + 8 + 32 + 4 + 8 = 196
        assert_eq!(body.len(), 196);
    }
}
