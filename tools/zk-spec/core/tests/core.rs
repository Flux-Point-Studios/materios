use materios_zk_core::{activation, bridge, sapling};

fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!("../../fixtures/bundles.json")).expect("public corpus JSON")
}

#[test]
fn public_mainnet_proofs_and_complete_bundles() {
    let verifier = sapling::Verifier::new(
        include_bytes!("../../fixtures/sapling-spend.vk"),
        include_bytes!("../../fixtures/sapling-output.vk"),
    )
    .expect("public keys");
    let mut proof_count = 0;
    let mut full = 0;
    for b in corpus().as_array().expect("corpus array") {
        let spends: Vec<_> = b["spends"]
            .as_array()
            .expect("spends")
            .iter()
            .map(|s| hex::decode(s.as_str().expect("hex")).expect("hex"))
            .collect();
        let outputs: Vec<_> = b["outputs"]
            .as_array()
            .expect("outputs")
            .iter()
            .map(|s| hex::decode(s.as_str().expect("hex")).expect("hex"))
            .collect();
        for (kind, actions) in [(true, &spends), (false, &outputs)] {
            for action in actions {
                assert!(verifier.proof(kind, action), "{}", b["transaction_id"]);
                let mut bad = action.clone();
                bad[if kind { 128 } else { 756 }] ^= 1;
                assert!(!verifier.proof(kind, &bad));
                proof_count += 1;
            }
        }
        if spends.len() == 1 && outputs.len() == 2 {
            let sighash = hex::decode(b["sighash"].as_str().expect("digest")).expect("hex");
            let sig = hex::decode(b["binding_sig"].as_str().expect("signature")).expect("hex");
            let s: Vec<_> = spends.iter().map(Vec::as_slice).collect();
            let o: Vec<_> = outputs.iter().map(Vec::as_slice).collect();
            assert!(verifier.bundle(
                &s,
                &o,
                b["value_balance"].as_i64().expect("balance"),
                &sighash,
                &sig
            ));
            let mut bad = sig.clone();
            bad[0] ^= 1;
            assert!(!verifier.bundle(
                &s,
                &o,
                b["value_balance"].as_i64().expect("balance"),
                &sighash,
                &bad
            ));
            full += 1;
        }
    }
    assert!(proof_count >= 20);
    assert!(full > 0);
}

#[test]
fn canonical_bridge_roundtrips_and_reserved_tags_refuse() {
    for recipient in [
        bridge::Recipient::Account([0x11; 32]),
        bridge::Recipient::Utxo([0x22; 32]),
    ] {
        let encoded = bridge::encode(recipient);
        assert_eq!(bridge::decode(&encoded), Ok(recipient));
        for end in 0..encoded.len() {
            assert!(bridge::decode(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(bridge::decode(&trailing).is_err());
    }
    for tag in [2, 3, 23, 255] {
        let mut b = bridge::encode(bridge::Recipient::Account([0; 32]));
        b[3] = tag;
        assert!(bridge::decode(&b).is_err());
    }
}

#[test]
fn mainnet_and_unknown_targets_refuse_enablement() {
    assert!(activation::enable("Live", "materios_mainnet").is_err());
    assert!(activation::enable("Live", "unknown").is_err());
    assert!(activation::enable("dev", "materios_dev").is_ok());
    assert!(activation::enable("preprod", "materios_preprod_v6").is_ok());
    assert!(activation::enable("file", "materios_preprod_v6").is_err());
}
