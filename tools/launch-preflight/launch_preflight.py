#!/usr/bin/env python3
"""Mainnet launch preflight: refuses a Materios genesis or launch that is not
safe to run with real value.

It reads the artifacts that actually launch: the raw chain spec every node
loads, the runtime metadata extracted from that spec's own `:code` (with
subwasm, the extractor the runtime-upgrade ceremony gate uses), the authority
nodes' launch commands and the RPC proxy configs in front of them. A launch
manifest supplies what genesis cannot show: off-chain role keys, the explicit
economics, the Cardano-side supply backing.

Rules, each of which refuses on its own:
  1 dev-keys     a well-known key anywhere: genesis storage, the runtime code,
                 a role, a node launch command, or the manifest signing key
  2 rewards      attestor reward and subsidy values not declared, or genesis
                 does not store exactly the declared values
  3 rpc          an authority serves unsafe RPC methods on an external or
                 proxied listener
  4 supply       an attestor endowment below bond + existential deposit + fee
                 buffer, or genesis issuance plus the runtime's emission
                 reserves not backed by locked cMATRA (the reserve counted both
                 on Cardano and on Materios)
  5 pallets      PerpEngine in the runtime metadata
  6 checkpoint   genesis hash, runtime code hash or chain-spec hash differ from
                 the signed launch manifest, the spec carries code substitutes,
                 or genesis turns on a Cardano deposit observation that has no
                 checkpoint

    launch_preflight.py check --spec raw.json --launch launch.json \\
        --signed-manifest signed.json --manifest-key 0x<ed25519 pubkey> \\
        [--extra-well-known exposed.json ...] [--subwasm PATH]
    launch_preflight.py sign --spec raw.json --key <ed25519 seed file> --out signed.json

Exit 0 only when every rule passes; 1 with every reason when any refuses;
2 when an input cannot be read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import base58
import xxhash
import zstandard
from nacl import signing
from nacl.exceptions import BadSignatureError

HERE = Path(__file__).resolve().parent
CODE_KEY = b":code"
ZSTD_PREFIX = bytes.fromhex("52bc537646db8e05")
CODE_BOMB_LIMIT = 50 * 1024 * 1024
DOMAIN = b"materios-launch-manifest-v1"
DOMAIN_32 = DOMAIN.ljust(32, b"\0")
FORBIDDEN_PALLETS = ("PerpEngine",)
EMISSION_RESERVES = ("ValidatorEmissionReserve", "AttestationRewardReserve")
POLICY_ID_LEN = 28
REWARD_ITEMS = (
    ("attestation_reward_per_signer", "AttestationRewardPerSigner", 16),
    ("era_cap_base", "EraCapBase", 16),
    ("era_cap_baseline_attestor_count", "EraCapBaselineAttestorCount", 4),
)
DEV_KEYRING_FLAGS = {"--alice", "--bob", "--charlie", "--dave", "--eve", "--ferdie",
                     "--one", "--two", "--dev"}
LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
DEFAULT_RPC_PORT = 9944


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

    def value(self, pallet: str, item: str) -> bytes | None:
        return self.storage.get(storage_key(pallet, item))


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


def chain_spec_hash(doc: dict) -> bytes:
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return blake2_256(canonical.encode())


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

    @classmethod
    def from_v14(cls, v14: dict) -> "Metadata":
        pallets, names, constants = [], {}, {}
        for pallet in v14["pallets"]:
            pallets.append(pallet["name"])
            storage = pallet.get("storage") or {}
            for entry in storage.get("entries", []):
                names[storage_key(storage["prefix"], entry["name"])] = f"{storage['prefix']}.{entry['name']}"
            for const in pallet.get("constants") or []:
                constants[(pallet["name"], const["name"])] = bytes(const["value"])
        return cls(pallets, names, constants)

    def label(self, key: bytes) -> str:
        if key == CODE_KEY:
            return ":code (runtime WASM)"
        return self.storage_names.get(key[:32], f"storage 0x{key[:32].hex()}")


# ---------------------------------------------------------------------------
# Well-known keys and key strings
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
    match = re.search(r"//(Alice|Bob|Charlie|Dave|Eve|Ferdie|One|Two)(//stash)?\b", text)
    return match.group(0) if match else None


def contains_phrase(text: str, phrase_hash: str) -> bool:
    words = re.findall(r"[a-z]+", text)
    return any(blake2_256(" ".join(words[i:i + 12]).encode()).hex() == phrase_hash
               for i in range(len(words) - 11))


def match_known(data: bytes, known: list[KnownKey]) -> list[KnownKey]:
    return [k for k in known if k.needle in data]


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def check_dev_keys(spec: Spec, meta: Metadata, launch: dict, manifest_key: bytes,
                   known: list[KnownKey], phrase_hash: str) -> list[Finding]:
    findings = []
    code = decompressed_code(spec.code)
    for key, value in sorted(spec.storage.items()):
        data = code if key == CODE_KEY else key + value
        for hit in match_known(data, known):
            findings.append(Finding("1 dev-keys", f"{meta.label(key)}: {hit} is in genesis"))
    for role, values in sorted(launch.get("roles", {}).items()):
        for i, text in enumerate(values):
            where = f"roles.{role}[{i}]"
            if not isinstance(text, str):
                findings.append(Finding("1 dev-keys", f"{where}: not a public key string"))
                continue
            uri = dev_uri(text)
            if uri:
                findings.append(Finding("1 dev-keys", f"{where}: well-known secret URI {uri}"))
                continue
            try:
                raw = decode_public_key(text)
            except ValueError as e:
                findings.append(Finding("1 dev-keys", f"{where}: {e}; a role takes a public key only"))
                continue
            for hit in match_known(raw, known):
                findings.append(Finding("1 dev-keys", f"{where}: {hit}"))
    for node in launch.get("nodes", []):
        strings = node_argv(node) + [f"{k}={v}" for k, v in sorted(node.get("env", {}).items())]
        for text in strings:
            flag = text.split("=", 1)[0]
            if flag in DEV_KEYRING_FLAGS:
                findings.append(Finding("1 dev-keys", f"node {node['name']}: {flag} loads the dev keyring"))
            uri = dev_uri(text)
            if uri:
                findings.append(Finding("1 dev-keys", f"node {node['name']}: launch config names {uri}"))
            if contains_phrase(text, phrase_hash):
                findings.append(Finding("1 dev-keys", f"node {node['name']}: launch config holds the dev mnemonic"))
    for hit in match_known(manifest_key, known):
        findings.append(Finding("1 dev-keys", f"manifest signing key: {hit}"))
    return findings


def check_rewards(spec: Spec, launch: dict) -> list[Finding]:
    declared = launch.get("economics", {})
    findings = []
    for field, item, width in REWARD_ITEMS:
        want = declared.get(field)
        if not isinstance(want, int) or isinstance(want, bool):
            findings.append(Finding("2 rewards", f"economics.{field} is not declared as an integer; "
                                                 "attestor rewards must be explicit"))
            continue
        stored = spec.value("OrinqReceipts", item)
        if stored is None:
            findings.append(Finding("2 rewards", f"OrinqReceipts.{item} is not set in genesis "
                                                 f"(declared {want})"))
        elif int.from_bytes(stored[:width], "little") != want:
            findings.append(Finding("2 rewards", f"OrinqReceipts.{item} stores "
                                                 f"{int.from_bytes(stored[:width], 'little')}, declared {want}"))
    if declared.get("era_cap_baseline_attestor_count") == 0:
        findings.append(Finding("2 rewards", "economics.era_cap_baseline_attestor_count is zero"))
    return findings


def node_argv(node: dict) -> list[str]:
    argv = node.get("argv", [])
    return shlex.split(argv) if isinstance(argv, str) else list(argv)


def _flag(argv: list[str], name: str) -> str | None:
    for i, token in enumerate(argv):
        if token == name and i + 1 < len(argv):
            return argv[i + 1]
        if token.startswith(name + "="):
            return token.split("=", 1)[1]
    return None


def proxy_upstreams(config: str) -> list[tuple[str, int]]:
    """(host, port) of every proxy_pass target, resolving nginx upstream blocks."""
    upstreams = {}
    for name, body in re.findall(r"upstream\s+([\w.-]+)\s*\{([^}]*)\}", config):
        upstreams[name] = re.findall(r"server\s+([^\s;]+)", body)
    targets = []
    for target in re.findall(r"proxy_pass\s+\w+://([^/;\s]+)", config):
        if "$" in target:
            raise InputError(f"proxy_pass target {target} is a variable; the preflight "
                             "cannot tell which node it reaches")
        for server in upstreams.get(target, [target]):
            host, _, port = server.rpartition(":") if re.search(r":\d+$", server) else (server, "", "80")
            targets.append((host, int(port)))
    return targets


def check_rpc(launch: dict) -> list[Finding]:
    proxied = set()
    for proxy in launch.get("rpc_proxies", []):
        try:
            config = Path(proxy["config"]).read_text()
        except OSError as e:
            raise InputError(f"cannot read proxy config {proxy['config']}: {e}") from e
        for host, port in proxy_upstreams(config):
            proxied.add((proxy["host"] if host in LOOPBACK else host, port, proxy["name"]))
    findings = []
    for node in launch.get("nodes", []):
        if not node.get("authority"):
            continue
        argv = node_argv(node)
        methods = (_flag(argv, "--rpc-methods") or "auto").lower()
        if methods not in ("auto", "safe", "unsafe"):
            findings.append(Finding("3 rpc", f"node {node['name']}: unknown --rpc-methods {methods}"))
            continue
        external = "--rpc-external" in argv or "--unsafe-rpc-external" in argv
        unsafe = methods == "unsafe" or (methods == "auto" and not external)
        port_flag = _flag(argv, "--rpc-port") or str(DEFAULT_RPC_PORT)
        if not port_flag.isdigit():
            raise InputError(f"node {node['name']}: --rpc-port {port_flag} is not a port")
        port = int(port_flag)
        addresses = {node["host"], *node.get("addresses", [])}
        via = sorted(name for host, p, name in proxied if host in addresses and p == port)
        if unsafe and external:
            findings.append(Finding("3 rpc", f"authority {node['name']} serves unsafe RPC methods "
                                             "on an external listener"))
        if unsafe and via:
            findings.append(Finding("3 rpc", f"authority {node['name']} serves unsafe RPC methods "
                                             f"behind proxy {', '.join(via)}"))
    return findings


def free_balance(spec: Spec, account: bytes) -> int:
    key = storage_key("System", "Account") + hashlib.blake2b(account, digest_size=16).digest() + account
    info = spec.storage.get(key)
    return int.from_bytes(info[16:32], "little") if info else 0


def check_supply(spec: Spec, meta: Metadata, launch: dict) -> list[Finding]:
    findings = []
    economics, supply = launch.get("economics", {}), launch.get("supply", {})
    bond_raw = spec.value("OrinqReceipts", "BondRequirement")
    ed_raw = meta.constants.get(("Balances", "ExistentialDeposit"))
    fee_buffer = economics.get("fee_buffer")
    if bond_raw is None or ed_raw is None or not isinstance(fee_buffer, int):
        findings.append(Finding("4 supply", "cannot size attestor endowments: needs OrinqReceipts."
                                            "BondRequirement in genesis, Balances.ExistentialDeposit "
                                            "in metadata and economics.fee_buffer declared"))
    else:
        floor = int.from_bytes(bond_raw, "little") + int.from_bytes(ed_raw, "little") + fee_buffer
        for i, text in enumerate(launch.get("roles", {}).get("attestors", [])):
            try:
                account = decode_public_key(text)
            except (ValueError, TypeError):
                continue  # rule 1 already refuses a role key that does not decode
            if len(account) == 33:
                account = blake2_256(account)
            balance = free_balance(spec, account)
            if balance < floor:
                findings.append(Finding("4 supply", f"roles.attestors[{i}] is endowed {balance}, below "
                                                    f"bond + existential deposit + fee buffer = {floor}"))
    issuance_raw = spec.value("Balances", "TotalIssuance")
    issuance = int.from_bytes(issuance_raw, "little") if issuance_raw else 0
    backing = supply.get("cardano_backing")
    missing = [name for name in EMISSION_RESERVES if ("OrinqReceipts", name) not in meta.constants]
    if missing:
        findings.append(Finding("4 supply", "the runtime metadata does not declare "
                                            + ", ".join(f"OrinqReceipts.{name}" for name in missing)
                                            + ": what the runtime mints after genesis is unbounded here, "
                                              "so the supply cannot be checked against the Cardano lock"))
    if not isinstance(backing, int) or isinstance(backing, bool):
        findings.append(Finding("4 supply", "supply.cardano_backing must be declared as an integer"))
    elif not missing:
        emission = sum(int.from_bytes(meta.constants[("OrinqReceipts", name)], "little")
                       for name in EMISSION_RESERVES)
        if issuance + emission > backing:
            findings.append(Finding("4 supply", f"Materios can issue {issuance + emission} (genesis "
                                                f"{issuance} + runtime emission reserves {emission}) against "
                                                f"{backing} locked on Cardano: the difference is reserve "
                                                "counted both as cMATRA and as MATRA"))
    return findings


def check_pallets(meta: Metadata) -> list[Finding]:
    return [Finding("5 pallets", f"{name} is in the runtime metadata")
            for name in FORBIDDEN_PALLETS if name in meta.pallets]


def canonical_payload(genesis: bytes, code_hash: bytes, spec_hash: bytes) -> bytes:
    return DOMAIN_32 + genesis + code_hash + spec_hash


def launch_hashes(spec: Spec) -> dict[str, bytes]:
    wasm = decompressed_code(spec.code)
    return {
        "genesis_hash": genesis_hash(spec.storage, runtime_state_version(wasm)),
        "code_hash": blake2_256(spec.code),
        "chain_spec_hash": chain_spec_hash(spec.doc),
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
    return [Finding("6 checkpoint", f"genesis turns on the Cardano deposit observation for "
                                    f"{address.decode(errors='replace')}, and this runtime has no observation "
                                    "checkpoint: its first observation counts every transfer to that address "
                                    "since Cardano genesis, the genesis lock included")]


def check_checkpoint(spec: Spec, signed: dict, manifest_key: bytes) -> list[Finding]:
    findings = []
    if spec.doc.get("codeSubstitutes"):
        findings.append(Finding("6 checkpoint", "chain spec carries codeSubstitutes"))
    try:
        claimed = {k: bytes.fromhex(signed[k].removeprefix("0x"))
                   for k in ("genesis_hash", "code_hash", "chain_spec_hash", "signature")}
    except (KeyError, ValueError, AttributeError) as e:
        return findings + [Finding("6 checkpoint", f"signed manifest is malformed: {e}")]
    if signed.get("domain") != DOMAIN.decode():
        findings.append(Finding("6 checkpoint", "signed manifest has the wrong domain"))
    for name, actual in launch_hashes(spec).items():
        if claimed[name] != actual:
            findings.append(Finding("6 checkpoint", f"{name} is 0x{actual.hex()}, signed manifest "
                                                    f"says 0x{claimed[name].hex()}"))
    payload = canonical_payload(claimed["genesis_hash"], claimed["code_hash"], claimed["chain_spec_hash"])
    try:
        signing.VerifyKey(manifest_key).verify(payload, claimed["signature"])
    except (BadSignatureError, ValueError, TypeError):
        findings.append(Finding("6 checkpoint", "signed manifest signature does not verify "
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


def validate_launch(launch: dict) -> None:
    if not isinstance(launch.get("roles"), dict) or not all(
            isinstance(v, list) for v in launch["roles"].values()):
        raise InputError("launch manifest roles must map each role to a list of public keys")
    for i, node in enumerate(launch.get("nodes", [])):
        if not isinstance(node.get("name"), str) or not isinstance(node.get("host"), str):
            raise InputError(f"launch manifest nodes[{i}] needs a name and a host")
        if not isinstance(node.get("addresses", []), list):
            raise InputError(f"launch manifest nodes[{i}] addresses must be a list")
    for i, proxy in enumerate(launch.get("rpc_proxies", [])):
        if not all(isinstance(proxy.get(k), str) for k in ("name", "host", "config")):
            raise InputError(f"launch manifest rpc_proxies[{i}] needs a name, a host and a config path")


def run_checks(spec: Spec, meta: Metadata, launch: dict, signed: dict, manifest_key: str,
               extra_well_known: list[Path] = ()) -> list[Finding]:
    validate_launch(launch)
    key = pinned_key(manifest_key)
    known, phrase_hash = load_well_known(extra_well_known)
    return (check_dev_keys(spec, meta, launch, key, known, phrase_hash)
            + check_rewards(spec, launch)
            + check_rpc(launch)
            + check_supply(spec, meta, launch)
            + check_pallets(meta)
            + check_checkpoint(spec, signed, key)
            + check_observation(spec))


def read_json(path: str, what: str) -> dict:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        raise InputError(f"cannot read {what} {path}: {e}") from e


def cmd_check(args) -> int:
    spec = load_spec(args.spec)
    meta = Metadata.from_v14(subwasm_metadata(spec.code, args.subwasm))
    findings = run_checks(spec, meta, read_json(args.launch, "launch manifest"),
                          read_json(args.signed_manifest, "signed manifest"), args.manifest_key,
                          [Path(p) for p in args.extra_well_known])
    if findings:
        print(f"MAINNET LAUNCH PREFLIGHT: REFUSE ({len(findings)} reasons)")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print("MAINNET LAUNCH PREFLIGHT: PASS")
    return 0


def signed_manifest(spec: Spec, key: signing.SigningKey) -> dict:
    hashes = launch_hashes(spec)
    payload = canonical_payload(hashes["genesis_hash"], hashes["code_hash"], hashes["chain_spec_hash"])
    return {"domain": DOMAIN.decode(), "signature": "0x" + key.sign(payload).signature.hex(),
            **{name: "0x" + value.hex() for name, value in hashes.items()}}


def cmd_sign(args) -> int:
    try:
        key = signing.SigningKey(bytes.fromhex(Path(args.key).read_text().strip().removeprefix("0x")))
    except (OSError, ValueError, TypeError) as e:
        raise InputError(f"cannot load the launch signing key from {args.key}: {type(e).__name__}") from e
    manifest = signed_manifest(load_spec(args.spec), key)
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
    check.add_argument("--subwasm", default="subwasm")
    check.add_argument("--extra-well-known", action="append", default=[], metavar="TABLE",
                       help="JSON key table of exposed keys kept out of the public table; repeatable")
    check.set_defaults(func=cmd_check)
    sign = sub.add_parser("sign", help="sign the launch hashes of a raw chain spec")
    sign.add_argument("--spec", required=True)
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
