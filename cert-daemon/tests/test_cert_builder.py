import hashlib
import cbor2
from daemon.cert_builder import build_cert
from daemon.models import AttestationLevel


def test_build_cert_structure():
    chain_id = "preprod-genesis-hash"
    receipt_id = "0xabcd1234"
    content_hash = b'\x01' * 32
    base_root = b'\x02' * 32
    locator_hash = b'\x03' * 32

    dcbor, cert_hash = build_cert(
        chain_id=chain_id,
        receipt_id=receipt_id,
        content_hash=content_hash,
        base_root_sha256=base_root,
        storage_locator_hash=locator_hash,
        attested_at_epoch=100,
        retention_days=365,
        attestation_level=AttestationLevel.ROOT_VERIFIED,
    )

    # Decode and verify structure
    decoded = cbor2.loads(dcbor)
    assert len(decoded) == 9
    assert decoded[0] == "materios-availability-cert-v1"
    assert decoded[1] == chain_id
    assert decoded[2] == receipt_id
    assert decoded[3] == content_hash
    assert decoded[4] == base_root
    assert decoded[5] == locator_hash
    assert decoded[6] == 100
    assert decoded[7] == 365
    assert decoded[8] == 3

    # Verify hash
    assert cert_hash == hashlib.sha256(dcbor).digest()


def test_build_cert_deterministic():
    kwargs = dict(
        chain_id="test",
        receipt_id="0x1234",
        content_hash=b'\xaa' * 32,
        base_root_sha256=b'\xbb' * 32,
        storage_locator_hash=b'\xcc' * 32,
        attested_at_epoch=50,
        retention_days=180,
        attestation_level=AttestationLevel.HASH_VERIFIED,
    )
    d1, h1 = build_cert(**kwargs)
    d2, h2 = build_cert(**kwargs)
    assert d1 == d2
    assert h1 == h2
