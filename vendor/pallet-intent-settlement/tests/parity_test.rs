//! Three-way cross-chain parity integration test.
//!
//! This test is the Rust-side half of the three-way voucher-with-address
//! parity anchor (Aiken ↔ Rust ↔ TypeScript). It reads the pinned vector
//! `voucher_digest_with_address` from `docs/test-vectors.json`, reconstructs
//! the canonical voucher pre-image using the [`voucher_canonicalize`] helpers,
//! and asserts byte-equality with the pinned `expected_hex` produced by
//! Aiken's `builtin.serialise_data(Address)` + `domain_hash(tag_voucher, body)`.
//!
//! If this test fails, do NOT patch the Rust side to match — investigate
//! both Aiken (Team B) and TS (Team C) before concluding which side drifted.
//! Likely culprits per the task brief:
//!   - definite-vs-indefinite CBOR length markers
//!   - wrong u64 endianness in amount / expiry_slot
//!   - wrong constr tag / nested wrapper count
//!   - wrong bstr length marker (28-byte hash should use `0x58 0x1c`)
//!
//! Run with:
//! ```sh
//! cargo test --package pallet-intent-settlement --test parity_test
//! ```

use pallet_intent_settlement::voucher_canonicalize::{
    build_type0_address_cbor, compute_voucher_digest_with_address, Type0AddressHashes,
};
use pallet_intent_settlement::types::TAG_VCHR;
use sp_core::{hashing::blake2_256, H256};

// -------- tiny self-contained hex decoder (the pallet itself avoids adding a
// `hex` dep — see tests.rs::mod hex). We duplicate the same helper here. -----
fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    assert!(s.len() % 2 == 0, "odd-length hex: {}", s);
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = nib(chunk[0]);
        let lo = nib(chunk[1]);
        out.push((hi << 4) | lo);
    }
    out
}

fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        other => panic!("invalid hex byte {other:#x}"),
    }
}

#[test]
fn voucher_digest_with_address_three_way_parity() {
    let raw = include_str!("../../../docs/test-vectors.json");
    let v: serde_json::Value = serde_json::from_str(raw).expect("valid JSON");
    let vector = &v["voucher_digest_with_address"];
    assert!(
        vector.is_object(),
        "voucher_digest_with_address missing from docs/test-vectors.json"
    );

    // Inputs from the pinned vector.
    let claim_id: [u8; 32] = hex_decode(vector["claim_id_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let policy_id: [u8; 32] = hex_decode(vector["policy_id_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let payment_hash: [u8; 28] =
        hex_decode(vector["payment_vk_hash_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
    let stake_hash: [u8; 28] = hex_decode(vector["stake_vk_hash_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let amount_ada: u64 = vector["amount_ada"].as_u64().unwrap();
    let bfpr_digest: [u8; 32] = hex_decode(vector["bfpr_digest_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let issued_block: u32 = vector["issued_block"].as_u64().unwrap() as u32;
    let expiry_slot: u64 = vector["expiry_slot_cardano"].as_u64().unwrap();
    let expected_cbor = hex_decode(
        vector["beneficiary_address_cbor_hex"].as_str().unwrap(),
    );
    let expected_digest: [u8; 32] = hex_decode(vector["expected_hex"].as_str().unwrap())
        .try_into()
        .unwrap();

    // Step 1: reproduce the 80-byte Plutus V3 Data CBOR for the Address.
    let cbor = build_type0_address_cbor(Type0AddressHashes {
        payment_hash: &payment_hash,
        stake_hash: &stake_hash,
    });
    assert_eq!(
        cbor.len(),
        80,
        "type-0 address CBOR must be exactly 80 bytes (got {})",
        cbor.len()
    );
    assert_eq!(
        &cbor[..],
        expected_cbor.as_slice(),
        "Rust CBOR output diverged from Aiken builtin.serialise_data output. \
         This is the SINGLE most likely bug locus — investigate indefinite vs \
         definite-length markers, bstr prefix, or constr-tag shape before \
         touching any other side.",
    );

    // Step 2: reproduce the full 196-byte canonical voucher body + digest.
    let digest = compute_voucher_digest_with_address(
        &H256::from(claim_id),
        &H256::from(policy_id),
        &cbor,
        amount_ada,
        &bfpr_digest,
        issued_block,
        expiry_slot,
    );
    assert_eq!(
        digest, expected_digest,
        "Rust voucher digest diverged from Aiken pinned anchor. \
         Cross-check with `vec_pinned_vchr_with_address` in \
         aegis-parametric-insurance-dev/validators/aegis-policy-v1/\
         lib/aegis/test_vectors.ak before patching.",
    );
}

#[test]
fn domain_tag_is_vchr_bytes() {
    // Sanity: the pallet tag constant matches the ASCII bytes expected by the
    // pinned vector pre-image (b"VCHR").
    assert_eq!(TAG_VCHR, b"VCHR");
}

#[test]
fn empty_body_digest_matches_vchr_empty_vector() {
    let raw = include_str!("../../../docs/test-vectors.json");
    let v: serde_json::Value = serde_json::from_str(raw).unwrap();
    let vector = &v["vchr_empty_body"];
    let mut buf = Vec::new();
    buf.extend_from_slice(TAG_VCHR);
    let got = blake2_256(&buf);
    let expected: [u8; 32] = hex_decode(vector["expected_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    assert_eq!(got, expected, "vchr_empty_body digest mismatch");
}
