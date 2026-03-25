import hashlib
from daemon.merkle import sha256, merkle_root


def test_sha256():
    assert sha256(b"hello") == hashlib.sha256(b"hello").digest()


def test_merkle_root_empty():
    assert merkle_root([]) == b'\x00' * 32


def test_merkle_root_single():
    h = sha256(b"leaf")
    assert merkle_root([h]) == h


def test_merkle_root_two():
    h1 = sha256(b"a")
    h2 = sha256(b"b")
    expected = sha256(h1 + h2)
    assert merkle_root([h1, h2]) == expected


def test_merkle_root_three():
    h1 = sha256(b"a")
    h2 = sha256(b"b")
    h3 = sha256(b"c")
    # odd: h3 duplicated
    left = sha256(h1 + h2)
    right = sha256(h3 + h3)
    expected = sha256(left + right)
    assert merkle_root([h1, h2, h3]) == expected


def test_merkle_root_four():
    leaves = [sha256(bytes([i])) for i in range(4)]
    left = sha256(leaves[0] + leaves[1])
    right = sha256(leaves[2] + leaves[3])
    expected = sha256(left + right)
    assert merkle_root(leaves) == expected
