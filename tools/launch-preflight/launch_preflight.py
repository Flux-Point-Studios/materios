#!/usr/bin/env python3
"""Mainnet launch preflight: refuses a Materios genesis or launch that is not
safe to run with real value.

It reads the artifacts that actually launch: the raw chain spec every node
loads, the runtime metadata extracted from that spec's own `:code` (with
subwasm, the extractor the runtime-upgrade ceremony gate uses), the authority
nodes' launch commands and the RPC proxy configs in front of them, and what
Cardano holds, through a Kupo index: the cMATRA lock that backs genesis and the
permissioned candidates that become the committee after the first rotation. A
launch manifest, signed with the pinned launch key, supplies what genesis cannot
show: who holds each role, the explicit economics, where the lock is.

Rules, each of which refuses on its own:
  1 dev-keys     a well-known key anywhere: genesis storage, the runtime code, a
                 role or a member of a role's multisig, a Cardano permissioned
                 candidate, a node launch command, or the manifest signing key;
                 Sudo.Key or a genesis account that no declared role accounts
                 for; an off-chain role left undeclared; a chain spec the anchor
                 worker would read as a test network
  2 rewards      attestor reward and subsidy values or validator reward
                 parameters not declared, or genesis and the runtime do not
                 hold exactly the declared values
  3 rpc          an authority serves unsafe RPC methods on an external or
                 proxied listener, or an authority has no launch entry to check
  4 supply       an attestor endowment below bond + existential deposit + fee
                 buffer, or genesis issuance plus the runtime's emission
                 reserves above the cMATRA the lock holds on Cardano (the
                 reserve counted both on Cardano and on Materios)
  5 pallets      PerpEngine in the runtime metadata, under any name
  6 checkpoint   genesis hash, runtime code hash, chain-spec hash or launch
                 manifest differ from the signed launch manifest, the spec
                 carries code substitutes, an authority loads a local runtime
                 override, or genesis turns on a Cardano deposit observation
                 that has no checkpoint

    launch_preflight.py check --spec raw.json --launch launch.json \\
        --signed-manifest signed.json --manifest-key 0x<ed25519 pubkey> \\
        --kupo http://<mainnet kupo> [--extra-well-known exposed.json ...] [--subwasm PATH]
    launch_preflight.py sign --spec raw.json --launch launch.json --key <ed25519 seed file> --out signed.json

Exit 0 only when every rule passes; 1 with every reason when any refuses;
2 when an input cannot be read.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import http.client
import ipaddress
import json
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import base58
import cbor2
import xxhash
import yaml
import zstandard
from nacl import signing
from nacl.exceptions import BadSignatureError

HERE = Path(__file__).resolve().parent
KEYS, REWARDS, RPC, SUPPLY, PALLETS, CHECKPOINT = (
    "1 dev-keys", "2 rewards", "3 rpc", "4 supply", "5 pallets", "6 checkpoint")
CODE_KEY = b":code"
ZSTD_PREFIX = bytes.fromhex("52bc537646db8e05")
CODE_BOMB_LIMIT = 50 * 1024 * 1024
DOMAIN = b"materios-launch-manifest-v1"
DOMAIN_32 = DOMAIN.ljust(32, b"\0")
HASH_FIELDS = ("genesis_hash", "code_hash", "chain_spec_hash", "launch_manifest_hash")
# Pallet name in construct_runtime, and the crate its types keep under any name.
FORBIDDEN_PALLETS = {"PerpEngine": "pallet_perp_engine"}
EMISSION_RESERVES = ("ValidatorEmissionReserve", "AttestationRewardReserve")
# The storage a mainnet genesis may set, besides each pallet's storage version.
# Anything else (a pending withdrawal, a credit ledger entry) can hold a claim
# on MATRA that the supply check does not count.
GENESIS_STORAGE = frozenset({
    "System.Account", "System.BlockHash", "System.ParentHash", "System.LastRuntimeUpgrade",
    "System.UpgradedToU32RefCount", "System.UpgradedToTripleRefCount",
    "Aura.Authorities", "Grandpa.Authorities", "Grandpa.CurrentSetId", "Grandpa.SetIdSession",
    "Balances.TotalIssuance", "Sudo.Key",
    "OrinqReceipts.AttestationRewardPerSigner", "OrinqReceipts.EraCapBase", "OrinqReceipts.EraCapBaselineAttestorCount",
    "OrinqReceipts.BondRequirement", "OrinqReceipts.ReceiptExpiryBlocks", "OrinqReceipts.ReceiptSubmissionFee",
    "OrinqReceipts.ReceiptSubmissionFeeFloor",
    "Motra.Params", "Sidechain.GenesisUtxo", "Sidechain.SlotsPerEpoch",
    "SessionCommitteeManagement.CurrentCommittee", "SessionCommitteeManagement.MainChainScriptsConfiguration",
    "PalletSession.QueuedKeys", "PalletSession.Validators", "Session.ValidatorsAndKeys",
    "NativeTokenManagement.MainChainScriptsConfiguration", "Vesting.StorageVersion",
    "IntentSettlement.IntentTTL", "IntentSettlement.ClaimTTL", "IntentSettlement.MinSignerThreshold",
    "IntentSettlement.PoolUtilization",
})
GENESIS_WELL_KNOWN_KEYS = {CODE_KEY, b":extrinsic_index"}
STORAGE_VERSION_KEY = b":__STORAGE_VERSION__:"
POLICY_ID_LEN = 28
# Validator reward parameters are runtime constants: (economics field, OrinqReceipts constant).
VALIDATOR_REWARD_CONSTANTS = (
    ("validator_reward_per_era", "ValidatorRewardPerEra"),
    ("treasury_emission_share_perbill", "TreasuryEmissionShare"),
)
REWARD_ITEMS = (
    ("attestation_reward_per_signer", "AttestationRewardPerSigner", 16),
    ("era_cap_base", "EraCapBase", 16),
    ("era_cap_baseline_attestor_count", "EraCapBaselineAttestorCount", 4),
)
# Every launch names who holds these; the ones that always run must name a key.
REQUIRED_ROLES = ("sudo", "anchor_signer", "attestors", "oracle")
RUNNING_ROLES = ("anchor_signer", "attestors")
MULTISIG_ENTROPY = b"modlpy/utilisuba"
DEV_KEYRING_FLAGS = {"--alice", "--bob", "--charlie", "--dave", "--eve", "--ferdie",
                     "--one", "--two", "--dev"}
# A path with no phrase, which Substrate derives from the dev phrase, and an
# optional ///password that is never echoed. Not after a word, a scheme's colon
# or a path, and not a protocol-relative host.
DEV_URI = re.compile(r"(?<![\w:/.])(//[\w-]+(?:/{1,2}[\w-]+)*)(?:///\S*)?(?![\w./-])")
# What the anchor worker reads as a test network, shared with it in test_networks.json.
TEST_NETWORKS = json.loads((HERE / "test_networks.json").read_text())
TEST_NETWORK_NAME = re.compile(TEST_NETWORKS["name_pattern"], re.IGNORECASE | re.ASCII)
NODE_BINARIES = ("materios-node", "materios-node-spo")
SHELLS = {"sh", "bash", "dash", "ash", "zsh"}
SHELL_OPERATORS = ";&|()<>\n"
SHELL_LOGIN_OPTIONS = {"--login", "--noprofile", "--norc"}
SHELL_ASSIGNMENT = re.compile(r"[A-Za-z_]\w*=.*", re.DOTALL)
SHELL_NESTING = 4
RPC_ENDPOINT_FLAG = "--experimental-rpc-endpoint"
DEFAULT_RPC_PORT = 9944
WASM_OVERRIDES_FLAG = "--wasm-runtime-overrides"
LAUNCH_FIELDS = {"roles", "economics", "supply", "nodes", "rpc_proxies"}
PROXY_KINDS = ("nginx", "cloudflared")
PROXY_FIELDS = {"name", "node", "kind", "config", "other_targets"}
# Forwarding schemes nginx and cloudflared accept, with the port each implies; tcp names its own.
DEFAULT_PORTS = {"http": 80, "ws": 80, "grpc": 80, "https": 443, "wss": 443, "grpcs": 443,
                 "ssh": 22, "rdp": 3389, "smb": 445, "tcp": None}
NGINX_DUMP_FILE = re.compile(r"^# configuration file (.+):$", re.MULTILINE)
NGINX_INCLUDE = re.compile(r"\binclude\s+([^;\s]+)\s*;")
NGINX_FORWARD = re.compile(r"\b(?:proxy|grpc|uwsgi|scgi|fastcgi|memcached)_pass\s+([^;\s]+)\s*;")
NGINX_UPSTREAM = re.compile(r"\bupstream\s+([\w.-]+)\s*\{([^}]*)\}")
NGINX_SERVER = re.compile(r"\bserver\s+([^\s;]+)")
NGINX_INCLUDE_DEPTH = 8
HOST_PORT = re.compile(r"\[([0-9A-Fa-f:.]+)\](?::(\d+))?|([^\s:\[\]/]+)(?::(\d+))?")
# cMATRA (v2) on Cardano mainnet: policy id and asset name, as Kupo keys assets.
CMATRA_UNIT = "7ff33a5565393dc47b48ac47becc12d92c9952e724e8446dfb6adc66.634d41545241"
MAINNET_ADDRESS_PREFIX = "addr1"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
UTXO = re.compile(r"[0-9a-f]{64}#\d+")
KUPO_TIMEOUT = 30
KUPO_LIMIT = 16 * 1024 * 1024
# Five minutes of slots: a synced Kupo trails its node by a block or two.
KUPO_MAX_LAG_SLOTS = 300


class InputError(Exception):
    """An input the preflight cannot read. Refuses like a failed rule."""


@dataclass(frozen=True)
class Finding:
    rule: str
    message: str

    def __str__(self) -> str:
        return f"[{self.rule}] {self.message}"


def blake2_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def twox_128(data: bytes) -> bytes:
    return (xxhash.xxh64(data, seed=0).intdigest().to_bytes(8, "little")
            + xxhash.xxh64(data, seed=1).intdigest().to_bytes(8, "little"))


def storage_key(pallet: str, item: str) -> bytes:
    return twox_128(pallet.encode()) + twox_128(item.encode())


def compact(n: int) -> bytes:
    if n < 1 << 6:
        return bytes([n << 2])
    if n < 1 << 14:
        return ((n << 2) | 1).to_bytes(2, "little")
    if n < 1 << 30:
        return ((n << 2) | 2).to_bytes(4, "little")
    raw = n.to_bytes((n.bit_length() + 7) // 8, "little")
    return bytes([((len(raw) - 4) << 2) | 3]) + raw


def read_compact(data: bytes, pos: int) -> tuple[int, int]:
    mode = data[pos] & 3
    if mode == 0:
        return data[pos] >> 2, pos + 1
    if mode == 1:
        return int.from_bytes(data[pos:pos + 2], "little") >> 2, pos + 2
    if mode == 2:
        return int.from_bytes(data[pos:pos + 4], "little") >> 2, pos + 4
    size = (data[pos] >> 2) + 4
    return int.from_bytes(data[pos + 1:pos + 1 + size], "little"), pos + 1 + size


def canonical_json_hash(doc) -> bytes:
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return blake2_256(canonical.encode())


def ss58(account: bytes, prefix: int) -> str:
    head = bytes([prefix]) if prefix < 64 else bytes(
        [((prefix & 0xFC) >> 2) | 0x40, (prefix >> 8) | ((prefix & 0x3) << 6)])
    body = head + account
    return base58.b58encode(body + hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2]).decode()


# ---------------------------------------------------------------------------
# Genesis hash: sp-trie's LayoutV0/V1 root of the raw storage, then the header
# ---------------------------------------------------------------------------

def _node_header(size: int, prefix: int, prefix_bits: int) -> bytes:
    max_value = 255 >> prefix_bits
    first = min(max_value - 1, size)
    if size == first:
        return bytes([prefix + first])
    out, rem = bytearray([prefix + max_value]), size - first
    while rem > 0:
        if rem < 256:
            out.append(rem - 1)
            rem = 0
        else:
            out.append(255)
            rem -= 255
    return bytes(out)


def _partial(nibbles: list[int], prefix: int, prefix_bits: int) -> bytes:
    out = bytearray(_node_header(len(nibbles), prefix, prefix_bits))
    if len(nibbles) % 2:
        out.append(nibbles[0])
    rest = nibbles[len(nibbles) % 2:]
    out.extend(rest[i] << 4 | rest[i + 1] for i in range(0, len(rest), 2))
    return bytes(out)


def _encode_trie(items: list, cursor: int, threshold: int | None) -> bytes:
    if not items:
        return b"\x00"
    if len(items) == 1:
        key, value = items[0]
        if threshold is not None and len(value) >= threshold:
            return _partial(key[cursor:], 0x20, 3) + blake2_256(value)
        return _partial(key[cursor:], 0x40, 2) + compact(len(value)) + value
    first = items[0][0]
    shared = len(first)
    for key, _ in items[1:]:
        n = 0
        while n < min(shared, len(key)) and first[n] == key[n]:
            n += 1
        shared = n
    partial = first[cursor:shared] if shared > cursor else []
    cursor = max(cursor, shared)
    value = items[0][1] if cursor == len(first) else None
    begin = 0 if value is None else 1
    children = []
    for nibble in range(16):
        group = []
        while begin < len(items) and items[begin][0][cursor] == nibble:
            group.append(items[begin])
            begin += 1
        children.append(group)
    bitmap = sum(1 << i for i, group in enumerate(children) if group).to_bytes(2, "little")
    if value is None:
        out = _partial(partial, 0x80, 2) + bitmap
    elif threshold is not None and len(value) >= threshold:
        out = _partial(partial, 0x10, 4) + bitmap + blake2_256(value)
    else:
        out = _partial(partial, 0xC0, 2) + bitmap + compact(len(value)) + value
    for group in children:
        if group:
            child = _encode_trie(group, cursor + 1, threshold)
            out += compact(len(child)) + child if len(child) < 32 else compact(32) + blake2_256(child)
    return out


def trie_root(storage: dict[bytes, bytes], state_version: int) -> bytes:
    threshold = 33 if state_version == 1 else None
    items = [([n for b in key for n in (b >> 4, b & 15)], value)
             for key, value in sorted(storage.items())]
    return blake2_256(_encode_trie(items, 0, threshold))


def genesis_hash(storage: dict[bytes, bytes], state_version: int) -> bytes:
    header = (b"\0" * 32 + compact(0) + trie_root(storage, state_version)
              + trie_root({}, state_version) + compact(0))
    return blake2_256(header)


# ---------------------------------------------------------------------------
# Chain spec and runtime code
# ---------------------------------------------------------------------------

@dataclass
class Spec:
    doc: dict
    storage: dict[bytes, bytes]

    @property
    def code(self) -> bytes:
        if CODE_KEY not in self.storage:
            raise InputError("chain spec genesis has no :code")
        return self.storage[CODE_KEY]

    @property
    def ss58_prefix(self) -> int:
        prefix = (self.doc.get("properties") or {}).get("ss58Format")
        return prefix if isinstance(prefix, int) else 42

    def value(self, pallet: str, item: str) -> bytes | None:
        return self.storage.get(storage_key(pallet, item))

    def accounts(self) -> list[bytes]:
        """Every account System.Account holds at genesis."""
        prefix = storage_key("System", "Account")
        accounts = [key[len(prefix) + 16:] for key in sorted(self.storage) if key.startswith(prefix)]
        if any(len(account) != 32 for account in accounts):
            raise InputError("a System.Account key does not end in a 32-byte account")
        return accounts


def load_spec(path: str) -> Spec:
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        raise InputError(f"cannot read chain spec {path}: {e}") from e
    raw = doc.get("genesis", {}).get("raw")
    if not raw:
        raise InputError("the preflight needs the raw chain spec (build-spec --raw): "
                         "raw storage is what every node loads")
    if raw.get("childrenDefault"):
        raise InputError("chain spec has child tries; the genesis hash here covers top storage only")
    try:
        return Spec(doc, {bytes.fromhex(k[2:]): bytes.fromhex(v[2:]) for k, v in raw["top"].items()})
    except (ValueError, AttributeError) as e:
        raise InputError(f"chain spec raw storage is not 0x-hex: {e}") from e


def decompressed_code(code: bytes) -> bytes:
    if not code.startswith(ZSTD_PREFIX):
        return code
    reader = zstandard.ZstdDecompressor().stream_reader(code[len(ZSTD_PREFIX):])
    out = reader.read(CODE_BOMB_LIMIT + 1)
    if len(out) > CODE_BOMB_LIMIT:
        raise InputError("runtime code decompresses past the 50 MiB bomb limit")
    return out


def _leb128(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return result, pos


def runtime_state_version(wasm: bytes) -> int:
    """state_version from the `runtime_version` custom section, which is what
    the node reads when it builds genesis from this code."""
    if wasm[:4] != b"\0asm":
        raise InputError("runtime code is not a WASM module")
    pos = 8
    while pos < len(wasm):
        section_id = wasm[pos]
        size, body = _leb128(wasm, pos + 1)
        pos = body + size
        if section_id != 0:
            continue
        name_len, name_start = _leb128(wasm, body)
        if wasm[name_start:name_start + name_len] != b"runtime_version":
            continue
        payload = wasm[name_start + name_len:pos]
        cursor = 0
        for _ in range(2):
            length, cursor = read_compact(payload, cursor)
            cursor += length
        cursor += 12
        apis, cursor = read_compact(payload, cursor)
        cursor += apis * 12 + 4
        return payload[cursor] if cursor < len(payload) else 0
    raise InputError("runtime code has no runtime_version section")


def subwasm_metadata(code: bytes, subwasm: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".wasm") as wasm:
        wasm.write(code)
        wasm.flush()
        try:
            out = subprocess.run([subwasm, "metadata", wasm.name, "--format", "json"],
                                 capture_output=True, text=True, timeout=300)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise InputError(f"subwasm could not run: {e}") from e
    if out.returncode != 0:
        raise InputError(f"subwasm metadata failed: {out.stderr.strip()[:400]}")
    try:
        doc = json.loads(out.stdout)
    except ValueError as e:
        raise InputError(f"subwasm printed no JSON: {e}") from e
    if "V14" not in doc:
        raise InputError(f"expected V14 metadata, got {list(doc)[:3]}")
    return doc["V14"]


@dataclass
class Metadata:
    pallets: list[str]
    storage_names: dict[bytes, str]
    constants: dict[tuple[str, str], bytes]
    crates: set[str]

    @classmethod
    def from_v14(cls, v14: dict) -> "Metadata":
        types = v14.get("types")
        if not isinstance(types, dict) or not isinstance(types.get("types"), list):
            raise InputError("runtime metadata has no types: a pallet under another name cannot be found")
        crates = {entry["type"]["path"][0] for entry in types["types"] if entry.get("type", {}).get("path")}
        pallets, names, constants = [], {}, {}
        for pallet in v14["pallets"]:
            pallets.append(pallet["name"])
            storage = pallet.get("storage") or {}
            for entry in storage.get("entries", []):
                names[storage_key(storage["prefix"], entry["name"])] = f"{storage['prefix']}.{entry['name']}"
            for const in pallet.get("constants") or []:
                constants[(pallet["name"], const["name"])] = bytes(const["value"])
        return cls(pallets, names, constants, crates)

    def label(self, key: bytes) -> str:
        if key == CODE_KEY:
            return ":code (runtime WASM)"
        return self.storage_names.get(key[:32], f"storage 0x{key[:32].hex()}")


# ---------------------------------------------------------------------------
# Well-known keys, key strings and role entries
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KnownKey:
    label: str
    scheme: str
    needle: bytes

    def __str__(self) -> str:
        return f"{self.label} ({self.scheme})"


def load_well_known(extra: list[Path] = ()) -> tuple[list[KnownKey], str]:
    """The public table plus operator tables of keys whose exposure must not be
    named in a public repo. A 33-byte ECDSA key also matches the blake2-256
    account it maps to."""
    base = HERE / "well_known_keys.json"
    keys = []
    for path in (base, *extra):
        try:
            entries = json.loads(Path(path).read_text())["keys"]
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise InputError(f"cannot read key table {path}: {e}") from e
        for i, entry in enumerate(entries):
            if not all(isinstance(entry.get(f), str) for f in ("label", "scheme", "public")):
                raise InputError(f"key table {path}: keys[{i}] needs a label, a scheme and a public key")
            try:
                public = bytes.fromhex(entry["public"].removeprefix("0x"))
            except ValueError as e:
                raise InputError(f"key table {path}: keys[{i}] public is not hex") from e
            if len(public) not in (32, 33):
                raise InputError(f"key table {path}: keys[{i}] public is {len(public)} bytes; expected 32 or 33")
            for needle in (public, blake2_256(public)) if len(public) == 33 else (public,):
                if not any(k.needle == needle for k in keys):
                    keys.append(KnownKey(entry["label"], entry["scheme"], needle))
    return keys, json.loads(base.read_text())["dev_phrase_blake2_256"]


def decode_public_key(text: str) -> bytes:
    """A role key as SS58 or 0x-hex (32-byte account or 33-byte ECDSA key)."""
    if text.startswith("0x"):
        try:
            raw = bytes.fromhex(text[2:])
        except ValueError as e:
            raise ValueError("not hex") from e
        if len(raw) not in (32, 33):
            raise ValueError(f"{len(raw)} bytes; expected 32 or 33")
        return raw
    # base58 decoding is quadratic in length; an SS58 account is under 60 chars.
    if len(text) > 60 or not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", text):
        raise ValueError("not an SS58 address or 0x-hex public key")
    raw = base58.b58decode(text)
    if len(raw) < 3:
        raise ValueError("not an SS58 address or 0x-hex public key")
    prefix_len = 1 if raw[0] < 64 else 2
    body, checksum = raw[:-2], raw[-2:]
    if len(body) != prefix_len + 32:
        raise ValueError("SS58 payload is not a 32-byte account")
    if hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2] != checksum:
        raise ValueError("SS58 checksum mismatch")
    return body[prefix_len:]


def dev_uri(text: str) -> str | None:
    """The derivation path of a secret URI with no phrase, which Substrate
    derives from the dev phrase: `//Alice`, but also any other path such as
    `//Oracle//hot`. The result stops before any `///password`."""
    match = DEV_URI.search(text)
    return match.group(1) if match else None


def contains_phrase(text: str, phrase_hash: str) -> bool:
    words = re.findall(r"[a-z]+", text)
    return any(blake2_256(" ".join(words[i:i + 12]).encode()).hex() == phrase_hash
               for i in range(len(words) - 11))


def match_known(data: bytes, known: list[KnownKey]) -> list[KnownKey]:
    return [k for k in known if k.needle in data]


def multisig_account(members: list[bytes], threshold: int) -> bytes:
    """pallet_multisig's account for these signatories and threshold."""
    return blake2_256(MULTISIG_ENTROPY + compact(len(members)) + b"".join(sorted(members))
                      + threshold.to_bytes(2, "little"))


def role_leaves(entry, where: str):
    """(where, key string) for a role entry: the key itself, or every member of its multisig."""
    if isinstance(entry, dict):
        for i, member in enumerate(entry["members"]):
            yield from role_leaves(member, f"{where}.members[{i}]")
    else:
        yield where, entry


def role_account(entry) -> bytes:
    """The on-chain account a role entry names: a public key's account, or its
    multisig's. Raises ValueError when a key does not decode."""
    if isinstance(entry, dict):
        members = [role_account(member) for member in entry["members"]]
        if len(set(members)) != len(members):
            raise ValueError("a multisig lists a member twice")
        return multisig_account(members, entry["threshold"])
    raw = decode_public_key(entry)
    return blake2_256(raw) if len(raw) == 33 else raw


# ---------------------------------------------------------------------------
# Cardano, through Kupo
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    partner_chains_key: bytes
    keys: dict[str, bytes]


@dataclass
class CardanoView:
    lock: dict | None
    candidates: list[Candidate]


def kupo_get(base: str, path: str):
    if not base.startswith(("http://", "https://")):
        raise InputError("--kupo must be an http(s) URL")
    request = urllib.request.Request(base.rstrip("/") + path, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=KUPO_TIMEOUT) as response:
            body = response.read(KUPO_LIMIT + 1)
    except (OSError, ValueError, http.client.HTTPException) as e:
        raise InputError(f"Kupo request {path} failed: {e}") from e
    if len(body) > KUPO_LIMIT:
        raise InputError(f"Kupo response to {path} is over {KUPO_LIMIT} bytes")
    try:
        return json.loads(body)
    except ValueError as e:
        raise InputError(f"Kupo response to {path} is not JSON: {e}") from e


def unspent(matches, what: str) -> list[dict]:
    """The outputs of a Kupo /matches answer that are still unspent."""
    if not isinstance(matches, list) or not all(isinstance(m, dict) for m in matches):
        raise InputError(f"Kupo did not return a list of outputs for {what}")
    return [m for m in matches if m.get("spent_at") is None]


def permissioned_candidates_policy(spec: Spec) -> bytes:
    """The Cardano policy whose token marks the permissioned candidates datum,
    from genesis: committee candidate address, D-parameter policy, then this."""
    raw = spec.value("SessionCommitteeManagement", "MainChainScriptsConfiguration")
    if raw is None:
        raise InputError("genesis sets no SessionCommitteeManagement.MainChainScriptsConfiguration: "
                         "where the committee comes from on Cardano is unknown")
    try:
        address_len, pos = read_compact(raw, 0)
    except IndexError as e:
        raise InputError("SessionCommitteeManagement.MainChainScriptsConfiguration does not decode") from e
    start = pos + address_len + POLICY_ID_LEN
    policy = raw[start:start + POLICY_ID_LEN]
    if len(policy) != POLICY_ID_LEN:
        raise InputError("SessionCommitteeManagement.MainChainScriptsConfiguration does not decode")
    return policy


def _candidate_v0(row) -> Candidate:
    if not (isinstance(row, (list, tuple)) and len(row) == 3 and all(isinstance(k, bytes) for k in row)):
        raise ValueError("a V0 candidate is [partner chains key, aura key, grandpa key]")
    return Candidate(row[0], {"aura": row[1], "gran": row[2]})


def _candidate_v1(row) -> Candidate:
    if not (isinstance(row, (list, tuple)) and len(row) == 2 and isinstance(row[0], bytes)
            and isinstance(row[1], (list, tuple))):
        raise ValueError("a V1 candidate is [partner chains key, [[key id, key], ...]]")
    keys = {}
    for pair in row[1]:
        if not (isinstance(pair, (list, tuple)) and len(pair) == 2 and isinstance(pair[0], bytes)
                and len(pair[0]) == 4 and isinstance(pair[1], bytes)):
            raise ValueError("a V1 candidate key is [4-byte key id, key]")
        keys[pair[0].decode("ascii", errors="replace")] = pair[1]
    if "aura" not in keys:
        raise ValueError("a candidate has no aura key")
    return Candidate(row[0], keys)


def decode_candidates(raw: bytes) -> list[Candidate]:
    """partner-chains' permissioned candidates datum: the legacy bare list, or
    VersionedGenericDatum [datum, appendix, version] with a V0 or V1 appendix."""
    try:
        data = cbor2.loads(raw)
    except ValueError as e:
        raise InputError(f"the permissioned candidates datum is not CBOR: {e}") from e
    versioned = isinstance(data, (list, tuple)) and len(data) == 3 and isinstance(data[2], int)
    version, rows = (data[2], data[1]) if versioned else (0, data)
    if version not in (0, 1) or not isinstance(rows, (list, tuple)):
        raise InputError(f"the permissioned candidates datum has an unknown shape (version {version})")
    try:
        return [(_candidate_v0 if version == 0 else _candidate_v1)(row) for row in rows]
    except ValueError as e:
        raise InputError(f"the permissioned candidates datum does not decode: {e}") from e


def cardano_view(kupo: str, spec: Spec, launch: dict) -> CardanoView:
    """The genesis lock output and the permissioned candidates, as the Kupo index holds them now."""
    health = kupo_get(kupo, "/health")
    if not isinstance(health, dict):
        health = {}
    tip, checkpoint = health.get("most_recent_node_tip"), health.get("most_recent_checkpoint")
    if health.get("connection_status") != "connected" or not isinstance(tip, int) or not isinstance(checkpoint, int):
        raise InputError("Kupo does not report itself connected to a node")
    if tip - checkpoint > KUPO_MAX_LAG_SLOTS:
        raise InputError(f"Kupo is {tip - checkpoint} slots behind its node: an output it lists "
                         "as unspent may already be spent")
    tx, _, index = launch["supply"]["genesis_lock"]["utxo"].partition("#")
    matches = unspent(kupo_get(kupo, f"/matches/{int(index)}@{tx}?unspent"), "the genesis lock")
    lock = matches[0] if matches else None
    assets = (lock.get("value") or {}).get("assets") if lock is not None else {}
    if lock is not None and not (isinstance(lock.get("address"), str) and isinstance(assets, dict)
                                 and all(isinstance(v, int) for v in assets.values())):
        raise InputError("Kupo returned the genesis lock without an address and integer assets")
    policy = permissioned_candidates_policy(spec).hex()
    outputs = unspent(kupo_get(kupo, f"/matches/{policy}.*?unspent"), "the permissioned candidates token")
    if not outputs:
        raise InputError(f"Kupo has no unspent output holding the permissioned candidates token {policy}: "
                         "the committee after the first rotation cannot be checked")
    candidates = []
    for output in outputs:
        where = f"{output.get('transaction_id')}#{output.get('output_index')}"
        datum_hash = output.get("datum_hash")
        datum = kupo_get(kupo, f"/datums/{datum_hash}") if isinstance(datum_hash, str) else None
        if not isinstance(datum, dict) or not isinstance(datum.get("datum"), str):
            raise InputError(f"the permissioned candidates output {where} has no datum Kupo can serve")
        try:
            raw = bytes.fromhex(datum["datum"])
        except ValueError as e:
            raise InputError(f"the permissioned candidates datum at {where} is not hex") from e
        candidates += decode_candidates(raw)
    return CardanoView(lock, candidates)


def is_script_address(address: str) -> bool:
    """Whether a Shelley address's payment credential is a script. The first
    bech32 character after the separator carries the header's top five bits, so
    the address type is that character's value shifted right once; types 1, 3,
    5 and 7 pay to a script."""
    _, separator, data = address.rpartition("1")
    if not separator or not data or data[0] not in BECH32_CHARSET:
        return False
    return (BECH32_CHARSET.index(data[0]) >> 1) in (1, 3, 5, 7)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def check_chain_identity(spec: Spec) -> list[Finding]:
    """The anchor worker refuses a dev signer only on a chain it reads as
    mainnet, so the spec must read as mainnet to it."""
    findings = []
    chain_type = spec.doc.get("chainType")
    if chain_type != "Live":
        findings.append(Finding(KEYS, f"chain spec chainType is {chain_type!r}, not 'Live': the anchor worker "
                                      "treats the chain as a test network and accepts a dev signer"))
    name = spec.doc.get("name")
    if not isinstance(name, str) or TEST_NETWORK_NAME.search(name):
        findings.append(Finding(KEYS, f"chain spec name {name!r} reads as a test network: the anchor worker "
                                      "treats the chain as one and accepts a dev signer"))
    return findings


def check_dev_keys(spec: Spec, meta: Metadata, launch: dict, cardano: CardanoView, manifest_key: bytes,
                   known: list[KnownKey], phrase_hash: str) -> list[Finding]:
    findings = []
    code = decompressed_code(spec.code)
    for key, value in sorted(spec.storage.items()):
        data = code if key == CODE_KEY else key + value
        for hit in match_known(data, known):
            findings.append(Finding(KEYS, f"{meta.label(key)}: {hit} is in genesis"))
    roles = launch.get("roles", {})
    for role in REQUIRED_ROLES:
        if role not in roles:
            findings.append(Finding(KEYS, f"roles.{role} is not declared"))
    for role in RUNNING_ROLES:
        if role in roles and not roles[role]:
            findings.append(Finding(KEYS, f"roles.{role} is empty: name the key that runs it"))
    accounts: dict[str, list[bytes | None]] = {}
    for role, entries in sorted(roles.items()):
        for i, entry in enumerate(entries):
            where = f"roles.{role}[{i}]"
            decoded = True
            for leaf, text in role_leaves(entry, where):
                uri = dev_uri(text)
                if uri:
                    findings.append(Finding(KEYS, f"{leaf}: well-known secret URI {uri}"))
                    decoded = False
                    continue
                try:
                    raw = decode_public_key(text)
                except ValueError as e:
                    findings.append(Finding(KEYS, f"{leaf}: {e}; a role takes a public key only"))
                    decoded = False
                    continue
                findings += [Finding(KEYS, f"{leaf}: {hit}") for hit in match_known(raw, known)]
            account = None
            if decoded:
                try:
                    account = role_account(entry)
                except ValueError as e:
                    findings.append(Finding(KEYS, f"{where}: {e}"))
            accounts.setdefault(role, []).append(account)
    for i, entry in enumerate(roles.get("sudo", [])):
        if not isinstance(entry, dict):
            findings.append(Finding(KEYS, f"roles.sudo[{i}] is a single key: Root must be a multisig with a "
                                          "threshold of at least 2, declared by its members so each one is checked"))
        elif entry["threshold"] < 2:
            findings.append(Finding(KEYS, f"roles.sudo[{i}] has threshold 1: any one member alone holds Root"))
    sudo_key, sudo = spec.value("Sudo", "Key"), accounts.get("sudo", [])
    if sudo_key is None:
        if sudo:
            findings.append(Finding(KEYS, "roles.sudo declares a key, but genesis sets no Sudo.Key"))
    elif sudo != [sudo_key]:
        findings.append(Finding(KEYS, f"Sudo.Key {ss58(sudo_key, spec.ss58_prefix)} is not the account roles.sudo "
                                      "declares: who holds Root is unchecked"))
    declared = {account for role_accounts in accounts.values() for account in role_accounts}
    for account in spec.accounts():
        if account not in declared:
            findings.append(Finding(KEYS, f"genesis account {ss58(account, spec.ss58_prefix)} is not declared in "
                                          "any role: who holds it is unchecked"))
    for i, cand in enumerate(cardano.candidates):
        for name, raw in [("partner chains key", cand.partner_chains_key), *sorted(cand.keys.items())]:
            for hit in match_known(raw, known):
                findings.append(Finding(KEYS, f"Cardano permissioned candidate {i} {name}: {hit}"))
    for node in launch.get("nodes", []):
        node_findings = []
        for piece in launch_pieces(node):
            flag = piece.strip("\"'").split("=", 1)[0]
            if flag in DEV_KEYRING_FLAGS:
                node_findings.append(Finding(KEYS, f"node {node['name']}: {flag} loads the dev keyring"))
        for text in node_argv(node) + [f"{k}={v}" for k, v in sorted(node.get("env", {}).items())]:
            uri = dev_uri(text)
            if uri:
                node_findings.append(Finding(KEYS, f"node {node['name']}: launch config names {uri}"))
            if contains_phrase(text, phrase_hash):
                node_findings.append(Finding(KEYS, f"node {node['name']}: launch config holds the dev mnemonic"))
        findings += dict.fromkeys(node_findings)
    for hit in match_known(manifest_key, known):
        findings.append(Finding(KEYS, f"manifest signing key: {hit}"))
    return findings


def check_rewards(spec: Spec, meta: Metadata, launch: dict) -> list[Finding]:
    declared = launch.get("economics", {})
    findings = []
    for field, constant in VALIDATOR_REWARD_CONSTANTS:
        want = declared.get(field)
        actual = meta.constants.get(("OrinqReceipts", constant))
        if not isinstance(want, int) or isinstance(want, bool):
            findings.append(Finding(REWARDS, f"economics.{field} is not declared as an integer; "
                                             "validator rewards must be explicit"))
        elif actual is None:
            findings.append(Finding(REWARDS, f"the runtime metadata does not declare OrinqReceipts.{constant}, "
                                             "so the validator reward cannot be checked"))
        elif int.from_bytes(actual, "little") != want:
            findings.append(Finding(REWARDS, f"OrinqReceipts.{constant} is {int.from_bytes(actual, 'little')} "
                                             f"in the runtime, declared {want}"))
    for field, item, width in REWARD_ITEMS:
        want = declared.get(field)
        if not isinstance(want, int) or isinstance(want, bool):
            findings.append(Finding(REWARDS, f"economics.{field} is not declared as an integer; "
                                             "attestor rewards must be explicit"))
            continue
        stored = spec.value("OrinqReceipts", item)
        if stored is None:
            findings.append(Finding(REWARDS, f"OrinqReceipts.{item} is not set in genesis "
                                             f"(declared {want})"))
        elif int.from_bytes(stored[:width], "little") != want:
            findings.append(Finding(REWARDS, f"OrinqReceipts.{item} stores "
                                             f"{int.from_bytes(stored[:width], 'little')}, declared {want}"))
    if declared.get("era_cap_baseline_attestor_count") == 0:
        findings.append(Finding(REWARDS, "economics.era_cap_baseline_attestor_count is zero"))
    return findings


def node_argv(node: dict) -> list[str]:
    argv = node.get("argv", [])
    try:
        return shlex.split(argv) if isinstance(argv, str) else list(argv)
    except ValueError as e:
        raise InputError(f"node {node['name']}: its launch command does not parse: {e}") from e


def _program(words: list[str]) -> list[str]:
    """A shell command's words from its program on, past `exec` and NAME=value prefixes."""
    i = 0
    while i < len(words) and (words[i] == "exec" or SHELL_ASSIGNMENT.fullmatch(words[i])):
        i += 1
    return words[i:]


def _shell_script(argv: list[str], where: str) -> str:
    """The SCRIPT of `sh [-l|-e|--login ...] -c SCRIPT`."""
    for i, word in enumerate(argv[1:], 1):
        if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", word):
            if len(argv) != i + 2:
                raise InputError(f"{where}: a shell launch must end with its -c script")
            return argv[i + 1]
        if not (re.fullmatch(r"-[a-zA-Z]+", word) or word in SHELL_LOGIN_OPTIONS):
            break
    raise InputError(f"{where}: runs a shell without -c; the preflight cannot read a script file")


def _script_commands(script: str, where: str) -> list[list[str]]:
    """The commands of a shell script joined by `;`, `&&` or newlines. Any other
    operator (a pipe, a redirection, a subshell, `||`, `&`) is refused: the
    command that runs, or its words, would depend on evaluation."""
    lexer = shlex.shlex(script, posix=True, punctuation_chars=SHELL_OPERATORS)
    lexer.whitespace, lexer.whitespace_split, lexer.commenters = " \t\r", True, ""
    try:
        tokens = list(lexer)
    except ValueError as e:
        raise InputError(f"{where}: its shell command does not parse: {e}") from e
    commands, words = [], []
    for token in [*tokens, ";"]:
        if token and set(token.replace("&&", "")) <= {";", "\n"}:
            if words:
                commands.append(words)
            words = []
        elif token and set(token) <= set(SHELL_OPERATORS):
            raise InputError(f"{where}: its shell command uses {token!r}; the preflight reads only "
                             "commands joined by ; or &&")
        else:
            words.append(token)
    return commands


def _commands(words: list[str], where: str, depth: int) -> list[list[str]]:
    program = _program(words)
    if not program or Path(program[0]).name not in SHELLS:
        return [words]
    if depth == SHELL_NESTING:
        raise InputError(f"{where}: shells nest more than {SHELL_NESTING} deep")
    return [command for inner in _script_commands(_shell_script(program, where), where)
            for command in _commands(inner, where, depth + 1)]


def launch_commands(node: dict) -> list[list[str]]:
    """Every command a node's launch runs, as the words it is given, with each
    `sh -c` wrapper (a systemd unit's, a container entrypoint's) opened. A
    command that expands a variable, as systemd does `$VAR` in ExecStart, is
    refused: its words are not in the manifest."""
    where = f"node {node['name']}"
    argv = node_argv(node)
    if any(re.search(r"[$`]", word) for word in argv):
        raise InputError(f"{where}: its launch command expands a variable or a command; "
                         "give the argv the process receives")
    return _commands(argv, where, 0) if argv else []


def launch_pieces(node: dict) -> list[str]:
    """Every whitespace-separated piece of a node's launch words, wrapped or
    not, and of its environment: where a flag can hide."""
    words = node_argv(node) + [word for command in launch_commands(node) for word in command]
    return [piece for word in words + list(node.get("env", {}).values()) for piece in word.split()]


def node_process(node: dict) -> list[str]:
    """The argv an authority's node process receives: the last command its
    launch runs, which must start a node binary with one argument per word."""
    where = f"authority {node['name']}"
    commands = launch_commands(node)
    argv = _program(commands[-1]) if commands else []
    program = Path(argv[0]).name if argv else "nothing"
    if program not in NODE_BINARIES:
        raise InputError(f"{where}: its launch runs {program}, not a node binary ({', '.join(NODE_BINARIES)}); "
                         "give the argv the node process receives")
    for i, word in enumerate(argv):
        if re.search(r"\s-", word):
            raise InputError(f"{where}: argument {i} holds several arguments; give one per word")
    return argv


def _flag(argv: list[str], name: str) -> str | None:
    for i, token in enumerate(argv):
        if token == name and i + 1 < len(argv):
            return argv[i + 1]
        if token.startswith(name + "="):
            return token.split("=", 1)[1]
    return None


def canonical_host(host: str) -> str:
    """One spelling per address: lower case, no brackets or trailing dot, IPv4
    in dotted form (so 127.1 and 2130706433 read as 127.0.0.1) and IPv4-mapped
    IPv6 as its IPv4 address."""
    host = host.strip("[]").rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            return socket.inet_ntoa(socket.inet_aton(host))
        except OSError:
            return host
    return str(getattr(ip, "ipv4_mapped", None) or ip)


def is_loopback(host: str) -> bool:
    host = canonical_host(host)
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def reaches_proxy_host(host: str) -> bool:
    """A proxy target on the proxy's own host: loopback, or the unspecified
    address, which a connect() sends to the local host."""
    if is_loopback(host):
        return True
    try:
        return ipaddress.ip_address(canonical_host(host)).is_unspecified
    except ValueError:
        return False


def host_port(target: str, default_port: int | None) -> tuple[str, int]:
    match = HOST_PORT.fullmatch(target)
    if not match:
        raise InputError(f"proxy target {target} is not a host and port")
    host, port = match.group(1) or match.group(3), match.group(2) or match.group(4)
    if port is None:
        if default_port is None:
            raise InputError(f"proxy target {target} names no port")
        return host, default_port
    return host, int(port)


def read_text(path: Path, what: str) -> str:
    try:
        return path.read_text()
    except (OSError, UnicodeDecodeError) as e:
        raise InputError(f"cannot read {what} {path}: {e}") from e


def _strip_comments(text: str) -> str:
    return re.sub(r"#[^\n]*", "", text)


def _include_path(base: Path, pattern: str) -> str:
    pattern = pattern.strip("\"'")
    return pattern if pattern.startswith("/") else str(base / pattern)


def _has_glob(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")


def _nginx_expand(text: str, base: Path, depth: int) -> str:
    if depth > NGINX_INCLUDE_DEPTH:
        raise InputError(f"nginx includes nest deeper than {NGINX_INCLUDE_DEPTH} levels")

    def inline(match: re.Match) -> str:
        paths = sorted(glob.glob(_include_path(base, match.group(1))))
        if not paths:
            raise InputError(f"nginx include {match.group(1)} matches no file; give the output of "
                             "`nginx -T`, which carries every included file")
        return "\n".join(_nginx_expand(_strip_comments(read_text(Path(p), "nginx include")), base, depth + 1)
                         for p in paths)

    return NGINX_INCLUDE.sub(inline, text)


def nginx_text(path: Path, text: str) -> str:
    """The config with every include in it. `nginx -T` output already carries
    each file it read, under a `# configuration file <path>:` line."""
    files = NGINX_DUMP_FILE.findall(text)
    body = _strip_comments(text)
    if not files:
        return _nginx_expand(body, path.parent, 0)
    base = Path(files[0]).parent
    for pattern in NGINX_INCLUDE.findall(body):
        target = _include_path(base, pattern)
        if not _has_glob(target) and target not in files:
            raise InputError(f"nginx include {pattern} matches no file in the dump")
    return body


def forward_targets(target: str, upstreams: dict[str, list[str]]) -> list[tuple[str, int]]:
    target = target.strip("\"'")
    if "$" in target:
        raise InputError(f"proxy target {target} is a variable; the preflight cannot tell which node it reaches")
    scheme, separator, rest = target.partition("://")
    if not separator:
        scheme, rest = "", target
    authority = rest.split("/", 1)[0]
    servers = upstreams.get(authority, [authority])
    if any(server.startswith("unix:") for server in servers):
        raise InputError(f"proxy target {target} is a unix socket; the preflight cannot tell which node it reaches")
    return [host_port(server, DEFAULT_PORTS.get(scheme)) for server in servers]


def nginx_routes(path: Path, text: str) -> list[tuple[str, int]]:
    body = nginx_text(path, text)
    upstreams = {name: NGINX_SERVER.findall(block) for name, block in NGINX_UPSTREAM.findall(body)}
    return [route for target in NGINX_FORWARD.findall(body) for route in forward_targets(target, upstreams)]


def cloudflared_routes(text: str) -> list[tuple[str, int]]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise InputError(f"cloudflared config is not YAML: {e}") from e
    if not isinstance(doc, dict):
        raise InputError("cloudflared config is not a mapping")
    rules = doc.get("ingress") or []
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise InputError("cloudflared ingress must be a list of rules")
    warp = doc.get("warp-routing")
    if isinstance(warp, dict) and warp.get("enabled"):
        raise InputError("cloudflared warp-routing is enabled: it forwards clients to any private address, "
                         "so no listener on the network is bounded")
    origins = [origin for origin in (doc.get("originRequest"), *(rule.get("originRequest") for rule in rules))
               if isinstance(origin, dict)]
    if any(origin.get("bastionMode") for origin in origins):
        raise InputError("cloudflared bastion mode forwards clients to any address they name")
    if any(origin.get("proxyType") == "socks" for origin in origins):
        raise InputError("a cloudflared SOCKS origin forwards clients to any address they name")
    services = ([doc["url"]] if "url" in doc else []) + [rule.get("service") for rule in rules]
    routes = []
    for service in services:
        if not isinstance(service, str):
            raise InputError("a cloudflared ingress rule has no service")
        if service == "hello_world" or service.startswith("http_status:"):
            continue
        scheme, separator, rest = service.partition("://")
        if not separator or scheme not in DEFAULT_PORTS:
            raise InputError(f"cloudflared service {service}: the preflight cannot tell which node it reaches")
        routes.append(host_port(rest.split("/", 1)[0], DEFAULT_PORTS[scheme]))
    return routes


def proxy_routes(proxy: dict) -> list[tuple[str, int]]:
    """(host, port) of every place a proxy forwards to. A config that yields none
    refuses: a route the parser missed would pass unchecked."""
    path = Path(proxy["config"])
    text = read_text(path, "proxy config")
    routes = nginx_routes(path, text) if proxy["kind"] == "nginx" else cloudflared_routes(text)
    if not routes:
        raise InputError(f"proxy {proxy['name']}: {path} has no forwarding route the preflight can read")
    return routes


def authorities(spec: Spec, cardano: CardanoView) -> list[tuple[str, bytes]]:
    """(label, aura key) of every block author: the genesis Aura authorities, then
    the Cardano permissioned candidates, who author after the first rotation."""
    raw = spec.value("Aura", "Authorities")
    if raw is None:
        raise InputError("genesis sets no Aura.Authorities")
    try:
        count, pos = read_compact(raw, 0)
    except IndexError as e:
        raise InputError("Aura.Authorities does not decode") from e
    if len(raw) != pos + 32 * count:
        raise InputError("Aura.Authorities does not decode as a list of 32-byte keys")
    listed = [(f"genesis Aura.Authorities[{i}]", raw[pos + 32 * i:pos + 32 * i + 32]) for i in range(count)]
    return listed + [(f"Cardano permissioned candidate {i}", cand.keys["aura"])
                     for i, cand in enumerate(cardano.candidates)]


def node_addresses(node: dict) -> set[str]:
    return {canonical_host(a) for a in (node["host"], *node.get("addresses", []))}


def proxied_nodes(launch: dict) -> set[tuple[str, int, str]]:
    """(node name, port, proxy name) for every route a proxy forwards. A
    loopback target reaches every node on the proxy's machine (the nodes that
    share an address with the proxy's node); any other target must be a
    declared node's host or address, or one of the proxy's other_targets."""
    nodes = launch.get("nodes", [])
    by_name = {node["name"]: node for node in nodes}
    routes = set()
    for proxy in launch.get("rpc_proxies", []):
        machine = node_addresses(by_name[proxy["node"]])
        others = {(canonical_host(host), port)
                  for host, port in (host_port(t, None) for t in proxy.get("other_targets", []))}
        for host, port in proxy_routes(proxy):
            if reaches_proxy_host(host):
                reached = [node["name"] for node in nodes if node_addresses(node) & machine]
            else:
                reached = [node["name"] for node in nodes if canonical_host(host) in node_addresses(node)]
            if not reached and (canonical_host(host), port) not in others:
                raise InputError(f"proxy {proxy['name']} forwards to {host}:{port}, which is no declared node's host "
                                 "or address and not in its other_targets: the preflight cannot tell whether it "
                                 "reaches an authority")
            routes.update((name, port, proxy["name"]) for name in reached)
    return routes


def check_rpc(launch: dict, authority_keys: list[tuple[str, bytes]]) -> list[Finding]:
    proxied = proxied_nodes(launch)
    findings = []
    nodes = launch.get("nodes", [])
    covered = {decode_public_key(node["aura"]) for node in nodes if node["authority"]}
    for label, aura in authority_keys:
        if aura not in covered:
            findings.append(Finding(RPC, f"{label} (aura 0x{aura.hex()}) has no authority node in the launch "
                                         "manifest: its RPC listeners are unchecked"))
    for node in nodes:
        if not node["authority"]:
            if "--validator" in launch_pieces(node):
                findings.append(Finding(RPC, f"node {node['name']} runs --validator but is not "
                                             "declared an authority"))
            continue
        argv = node_process(node)
        port_flag = _flag(argv, "--rpc-port") or str(DEFAULT_RPC_PORT)
        if not port_flag.isdigit():
            raise InputError(f"node {node['name']}: --rpc-port {port_flag} is not a port")
        # (port, external, methods) for the default listener and every experimental endpoint.
        listeners = [(int(port_flag), "--rpc-external" in argv or "--unsafe-rpc-external" in argv,
                      (_flag(argv, "--rpc-methods") or "auto").lower())]
        for i, token in enumerate(argv):
            if token == RPC_ENDPOINT_FLAG and i + 1 < len(argv):
                endpoint = argv[i + 1]
            elif token.startswith(RPC_ENDPOINT_FLAG + "="):
                endpoint = token.split("=", 1)[1]
            else:
                continue
            options = dict(opt.split("=", 1) if "=" in opt else (opt, "") for opt in endpoint.split(","))
            address = options.get("listen-addr", "")
            if not re.search(r":\d+$", address):
                raise InputError(f"node {node['name']}: {RPC_ENDPOINT_FLAG} {endpoint} has no "
                                 "listen-addr ip:port")
            host, _, port = address.rpartition(":")
            listeners.append((int(port), not is_loopback(host), options.get("methods", "auto").lower()))
        reasons = []
        for port, external, methods in listeners:
            if methods not in ("auto", "safe", "unsafe"):
                reasons.append(f"node {node['name']}: unknown --rpc-methods {methods}")
                continue
            if methods == "safe" or (methods == "auto" and external):
                continue
            if external:
                reasons.append(f"authority {node['name']} serves unsafe RPC methods on an external listener")
            via = sorted(proxy for name, p, proxy in proxied if name == node["name"] and p == port)
            if via:
                reasons.append(f"authority {node['name']} serves unsafe RPC methods behind proxy {', '.join(via)}")
        findings += [Finding(RPC, reason) for reason in dict.fromkeys(reasons)]
    return findings


def free_balance(spec: Spec, account: bytes) -> int:
    key = storage_key("System", "Account") + hashlib.blake2b(account, digest_size=16).digest() + account
    info = spec.storage.get(key)
    return int.from_bytes(info[16:32], "little") if info else 0


def check_supply(spec: Spec, meta: Metadata, launch: dict, cardano: CardanoView) -> list[Finding]:
    findings = []
    economics = launch.get("economics", {})
    attestors = launch.get("roles", {}).get("attestors", [])
    bond_raw = spec.value("OrinqReceipts", "BondRequirement")
    ed_raw = meta.constants.get(("Balances", "ExistentialDeposit"))
    fee_buffer = economics.get("fee_buffer")
    if not attestors:
        findings.append(Finding(SUPPLY, "roles.attestors names no account: the endowment floor "
                                        "has nothing to check"))
    if bond_raw is None or ed_raw is None or not isinstance(fee_buffer, int):
        findings.append(Finding(SUPPLY, "cannot size attestor endowments: needs OrinqReceipts."
                                        "BondRequirement in genesis, Balances.ExistentialDeposit "
                                        "in metadata and economics.fee_buffer declared"))
    else:
        floor = int.from_bytes(bond_raw, "little") + int.from_bytes(ed_raw, "little") + fee_buffer
        for i, entry in enumerate(attestors):
            try:
                account = role_account(entry)
            except ValueError:
                continue  # rule 1 already refuses a role key that does not decode
            balance = free_balance(spec, account)
            if balance < floor:
                findings.append(Finding(SUPPLY, f"roles.attestors[{i}] is endowed {balance}, below "
                                                f"bond + existential deposit + fee buffer = {floor}"))
    issuance_raw = spec.value("Balances", "TotalIssuance")
    stored = int.from_bytes(issuance_raw, "little") if issuance_raw else 0
    prefix = storage_key("System", "Account")
    held = sum(int.from_bytes(info[16:32], "little") + int.from_bytes(info[32:48], "little")
               for key, info in spec.storage.items() if key.startswith(prefix))
    if stored != held:
        findings.append(Finding(SUPPLY, f"Balances.TotalIssuance stores {stored}, but genesis accounts "
                                        f"hold {held}"))
    issuance = max(stored, held)
    missing = [name for name in EMISSION_RESERVES if ("OrinqReceipts", name) not in meta.constants]
    if missing:
        findings.append(Finding(SUPPLY, "the runtime metadata does not declare "
                                        + ", ".join(f"OrinqReceipts.{name}" for name in missing)
                                        + ": what the runtime mints after genesis is unbounded here, "
                                          "so the supply cannot be checked against the Cardano lock"))
    lock, output = launch["supply"]["genesis_lock"], cardano.lock
    if not lock["address"].startswith(MAINNET_ADDRESS_PREFIX):
        findings.append(Finding(SUPPLY, f"the genesis lock address {lock['address']} is not a Cardano "
                                        "mainnet address"))
    if output is None:
        findings.append(Finding(SUPPLY, f"the genesis lock {lock['utxo']} is not an unspent output the Kupo "
                                        "index holds: nothing backs genesis issuance"))
    elif output["address"] != lock["address"]:
        findings.append(Finding(SUPPLY, f"the genesis lock {lock['utxo']} sits at {output['address']}, "
                                        f"not the declared {lock['address']}"))
    elif not is_script_address(output["address"]):
        findings.append(Finding(SUPPLY, f"the genesis lock {lock['utxo']} sits at {output['address']}, whose "
                                        "payment credential is a key: its holder can spend the backing"))
    elif not missing:
        amount = output["value"]["assets"].get(CMATRA_UNIT, 0)
        emission = sum(int.from_bytes(meta.constants[("OrinqReceipts", name)], "little")
                       for name in EMISSION_RESERVES)
        if issuance + emission > amount:
            findings.append(Finding(SUPPLY, f"Materios can issue {issuance + emission} (genesis {issuance} "
                                            f"+ runtime emission reserves {emission}) against {amount} cMATRA "
                                            f"locked on Cardano at {lock['utxo']}: the difference is reserve "
                                            "counted both as cMATRA and as MATRA"))
    return findings


def check_genesis_storage(spec: Spec, meta: Metadata) -> list[Finding]:
    """Genesis may set only GENESIS_STORAGE, each pallet's storage version and
    the runtime's own well-known keys."""
    versions = {twox_128(name.encode()) + twox_128(STORAGE_VERSION_KEY) for name in meta.pallets}
    outside: dict[str, int] = {}
    for key in sorted(spec.storage):
        if key in GENESIS_WELL_KNOWN_KEYS or key in versions:
            continue
        if key.startswith(b":"):
            label = key.decode(errors="replace")
        else:
            label = meta.storage_names.get(key[:32], f"storage 0x{key[:32].hex()}")
        if label not in GENESIS_STORAGE:
            outside[label] = outside.get(label, 0) + 1
    return [Finding(SUPPLY, f"genesis sets {label} ({count} {'entry' if count == 1 else 'entries'}), which a "
                            "mainnet genesis may not set: storage outside the genesis allowlist can hold a claim on "
                            "MATRA that the supply check does not count")
            for label, count in outside.items()]


def check_pallets(meta: Metadata) -> list[Finding]:
    findings = []
    for name, crate in FORBIDDEN_PALLETS.items():
        if name in meta.pallets:
            findings.append(Finding(PALLETS, f"{name} is in the runtime metadata"))
        elif crate in meta.crates:
            findings.append(Finding(PALLETS, f"the runtime metadata carries {crate} types: {name} under "
                                             "another name"))
    return findings


def canonical_payload(hashes: dict[str, bytes]) -> bytes:
    return DOMAIN_32 + b"".join(hashes[name] for name in HASH_FIELDS)


def launch_manifest_hash(launch: dict) -> bytes:
    return canonical_json_hash(launch)


def launch_hashes(spec: Spec, launch: dict) -> dict[str, bytes]:
    wasm = decompressed_code(spec.code)
    return {
        "genesis_hash": genesis_hash(spec.storage, runtime_state_version(wasm)),
        "code_hash": blake2_256(spec.code),
        "chain_spec_hash": canonical_json_hash(spec.doc),
        "launch_manifest_hash": launch_manifest_hash(launch),
    }


def check_observation(spec: Spec) -> list[Finding]:
    """The partner-chain native-token observation marks itself initialized only
    at its first non-zero transfer; until then every block asks for all
    transfers since Cardano genesis. So a genesis that sets its scripts counts
    every pre-launch lock, the genesis lock included, as a deposit."""
    raw = spec.value("NativeTokenManagement", "MainChainScriptsConfiguration")
    if raw is None:
        return []
    try:
        asset_len, pos = read_compact(raw, POLICY_ID_LEN)
        address_len, pos = read_compact(raw, pos + asset_len)
    except IndexError as e:
        raise InputError("NativeTokenManagement.MainChainScriptsConfiguration does not decode") from e
    address = raw[pos:pos + address_len]
    if len(address) != address_len:
        raise InputError("NativeTokenManagement.MainChainScriptsConfiguration is truncated")
    if not address:
        return []
    return [Finding(CHECKPOINT, f"genesis turns on the Cardano deposit observation for "
                                f"{address.decode(errors='replace')}, and this runtime has no observation "
                                "checkpoint: its first observation counts every transfer to that address "
                                "since Cardano genesis, the genesis lock included")]


def check_code_overrides(launch: dict) -> list[Finding]:
    return [Finding(CHECKPOINT, f"authority {node['name']} runs {WASM_OVERRIDES_FLAG}: a local runtime would "
                                "replace the signed runtime code")
            for node in launch.get("nodes", []) if node["authority"] and any(
                token == WASM_OVERRIDES_FLAG or token.startswith(WASM_OVERRIDES_FLAG + "=")
                for token in node_process(node))]


def check_checkpoint(spec: Spec, launch: dict, signed: dict, manifest_key: bytes) -> list[Finding]:
    findings = []
    if spec.doc.get("codeSubstitutes"):
        findings.append(Finding(CHECKPOINT, "chain spec carries codeSubstitutes"))
    try:
        claimed = {k: bytes.fromhex(signed[k].removeprefix("0x")) for k in (*HASH_FIELDS, "signature")}
    except (KeyError, ValueError, AttributeError) as e:
        return findings + [Finding(CHECKPOINT, f"signed manifest is malformed: {e}")]
    if signed.get("domain") != DOMAIN.decode():
        findings.append(Finding(CHECKPOINT, "signed manifest has the wrong domain"))
    for name, actual in launch_hashes(spec, launch).items():
        if claimed[name] != actual:
            findings.append(Finding(CHECKPOINT, f"{name} is 0x{actual.hex()}, signed manifest "
                                                f"says 0x{claimed[name].hex()}"))
    try:
        signing.VerifyKey(manifest_key).verify(canonical_payload(claimed), claimed["signature"])
    except (BadSignatureError, ValueError, TypeError):
        findings.append(Finding(CHECKPOINT, "signed manifest signature does not verify "
                                            "under the pinned launch key"))
    return findings


def pinned_key(text: str) -> bytes:
    try:
        key = bytes.fromhex(text.removeprefix("0x"))
    except ValueError as e:
        raise InputError(f"--manifest-key is not hex: {e}") from e
    if len(key) != 32:
        raise InputError("--manifest-key must be a 32-byte ed25519 public key")
    return key


def validate_role_entry(entry, where: str) -> None:
    if isinstance(entry, str):
        return
    if not isinstance(entry, dict):
        raise InputError(f"{where} must be a public key string or a multisig")
    if set(entry) != {"threshold", "members"}:
        raise InputError(f"{where} must hold exactly threshold and members")
    members, threshold = entry["members"], entry["threshold"]
    if not isinstance(members, list) or len(members) < 2:
        raise InputError(f"{where} members must list at least two signatories")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or not 1 <= threshold <= len(members):
        raise InputError(f"{where} threshold must be an integer from 1 to {len(members)}")
    for i, member in enumerate(members):
        validate_role_entry(member, f"{where}.members[{i}]")


def validate_node(node, where: str) -> None:
    if not isinstance(node, dict) or not isinstance(node.get("name"), str) or not isinstance(node.get("host"), str):
        raise InputError(f"{where} needs a name and a host")
    if not isinstance(node.get("authority"), bool):
        raise InputError(f"{where} must declare authority as true or false")
    addresses = node.get("addresses", [])
    if not isinstance(addresses, list) or not all(isinstance(a, str) for a in addresses):
        raise InputError(f"{where} addresses must be a list of strings")
    argv = node.get("argv", [])
    if not (isinstance(argv, str) or isinstance(argv, list) and all(isinstance(t, str) for t in argv)):
        raise InputError(f"{where} argv must be a string or a list of strings")
    env = node.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(v, str) for v in env.values()):
        raise InputError(f"{where} env must map names to strings")
    launch_commands(node)
    if node["authority"]:
        try:
            aura = decode_public_key(node["aura"]) if isinstance(node.get("aura"), str) else b""
        except ValueError:
            aura = b""
        if len(aura) != 32:
            raise InputError(f"{where} is an authority and must declare its aura public key (SS58 or 0x-hex)")
        node_process(node)


def validate_launch(launch) -> None:
    if not isinstance(launch, dict):
        raise InputError("launch manifest must be a JSON object")
    for field in sorted(set(launch) - LAUNCH_FIELDS):
        raise InputError(f"unknown launch manifest field {field}")
    roles = launch.get("roles")
    if not isinstance(roles, dict):
        raise InputError("launch manifest roles must map each role to a list of public keys")
    for role, entries in roles.items():
        if not isinstance(entries, list):
            raise InputError(f"roles.{role} must be a list of public keys")
        for i, entry in enumerate(entries):
            validate_role_entry(entry, f"roles.{role}[{i}]")
    if not isinstance(launch.get("economics", {}), dict):
        raise InputError("economics must be an object")
    supply = launch.get("supply", {})
    if not isinstance(supply, dict):
        raise InputError("supply must be an object")
    for field in sorted(set(supply) - {"genesis_lock"}):
        raise InputError(f"unknown supply field {field}: the backing is read from Cardano")
    lock = supply.get("genesis_lock")
    if not isinstance(lock, dict) or not all(isinstance(lock.get(k), str) for k in ("utxo", "address")):
        raise InputError("supply.genesis_lock is required: the utxo and address of the cMATRA lock "
                         "that backs genesis")
    if not UTXO.fullmatch(lock["utxo"]):
        raise InputError("supply.genesis_lock.utxo must be <64 hex>#<index>")
    nodes = launch.get("nodes", [])
    if not isinstance(nodes, list):
        raise InputError("nodes must be a list")
    for i, node in enumerate(nodes):
        validate_node(node, f"nodes[{i}]")
    proxies = launch.get("rpc_proxies", [])
    if not isinstance(proxies, list):
        raise InputError("rpc_proxies must be a list")
    node_names = {node["name"] for node in nodes}
    for i, proxy in enumerate(proxies):
        if not isinstance(proxy, dict):
            raise InputError(f"rpc_proxies[{i}] must be an object")
        for field in sorted(set(proxy) - PROXY_FIELDS):
            raise InputError(f"rpc_proxies[{i}] has unknown field {field}")
        if not all(isinstance(proxy.get(k), str) for k in ("name", "node", "config")):
            raise InputError(f"rpc_proxies[{i}] needs a name, the node it runs on and a config path")
        if proxy.get("kind") not in PROXY_KINDS:
            raise InputError(f"rpc_proxies[{i}] kind must be nginx or cloudflared")
        if proxy["node"] not in node_names:
            raise InputError(f"rpc_proxies[{i}] runs on {proxy['node']}, which is not a declared node: "
                             "declare the machine it runs on in nodes")
        others = proxy.get("other_targets", [])
        if not (isinstance(others, list) and all(isinstance(t, str) and HOST_PORT.fullmatch(t) and ":" in t
                                                 for t in others)):
            raise InputError(f"rpc_proxies[{i}] other_targets must be host:port strings")


def run_checks(spec: Spec, meta: Metadata, launch: dict, signed: dict, manifest_key: str,
               cardano: CardanoView, extra_well_known: list[Path] = ()) -> list[Finding]:
    validate_launch(launch)
    key = pinned_key(manifest_key)
    known, phrase_hash = load_well_known(extra_well_known)
    return (check_chain_identity(spec)
            + check_dev_keys(spec, meta, launch, cardano, key, known, phrase_hash)
            + check_rewards(spec, meta, launch)
            + check_rpc(launch, authorities(spec, cardano))
            + check_supply(spec, meta, launch, cardano)
            + check_genesis_storage(spec, meta)
            + check_pallets(meta)
            + check_checkpoint(spec, launch, signed, key)
            + check_code_overrides(launch)
            + check_observation(spec))


def read_json(path: str, what: str):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError, RecursionError) as e:
        raise InputError(f"cannot read {what} {path}: {e}") from e


def cmd_check(args) -> int:
    spec = load_spec(args.spec)
    launch = read_json(args.launch, "launch manifest")
    validate_launch(launch)
    meta = Metadata.from_v14(subwasm_metadata(spec.code, args.subwasm))
    cardano = cardano_view(args.kupo, spec, launch)
    findings = run_checks(spec, meta, launch, read_json(args.signed_manifest, "signed manifest"),
                          args.manifest_key, cardano, [Path(p) for p in args.extra_well_known])
    if findings:
        print(f"MAINNET LAUNCH PREFLIGHT: REFUSE ({len(findings)} reasons)")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print("MAINNET LAUNCH PREFLIGHT: PASS")
    return 0


def signed_manifest(spec: Spec, launch: dict, key: signing.SigningKey) -> dict:
    hashes = launch_hashes(spec, launch)
    return {"domain": DOMAIN.decode(), "signature": "0x" + key.sign(canonical_payload(hashes)).signature.hex(),
            **{name: "0x" + value.hex() for name, value in hashes.items()}}


def cmd_sign(args) -> int:
    try:
        key = signing.SigningKey(bytes.fromhex(Path(args.key).read_text().strip().removeprefix("0x")))
    except (OSError, ValueError, TypeError) as e:
        raise InputError(f"cannot load the launch signing key from {args.key}: {type(e).__name__}") from e
    launch = read_json(args.launch, "launch manifest")
    validate_launch(launch)
    manifest = signed_manifest(load_spec(args.spec), launch, key)
    Path(args.out).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"signed launch manifest -> {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("check", help="refuse an unsafe mainnet genesis or launch")
    check.add_argument("--spec", required=True, help="raw chain spec")
    check.add_argument("--launch", required=True, help="launch manifest JSON")
    check.add_argument("--signed-manifest", required=True)
    check.add_argument("--manifest-key", required=True, help="pinned ed25519 launch key, 0x-hex")
    check.add_argument("--kupo", required=True, help="Kupo on Cardano mainnet, indexing the genesis lock "
                                                     "and the permissioned candidates token")
    check.add_argument("--subwasm", default="subwasm")
    check.add_argument("--extra-well-known", action="append", default=[], metavar="TABLE",
                       help="JSON key table of exposed keys kept out of the public table; repeatable")
    check.set_defaults(func=cmd_check)
    sign = sub.add_parser("sign", help="sign the launch hashes of a raw chain spec and a launch manifest")
    sign.add_argument("--spec", required=True)
    sign.add_argument("--launch", required=True, help="launch manifest JSON")
    sign.add_argument("--key", required=True, help="file holding the ed25519 seed, hex")
    sign.add_argument("--out", required=True)
    sign.set_defaults(func=cmd_sign)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except InputError as e:
        print(f"MAINNET LAUNCH PREFLIGHT: REFUSE (input) {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
