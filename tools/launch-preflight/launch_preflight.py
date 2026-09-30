#!/usr/bin/env python3
"""Mainnet launch preflight: refuses a Materios genesis or launch that is not
safe to run with real value.

It reads the artifacts that actually launch: the raw chain spec every node
loads, the runtime metadata extracted from that spec's own `:code` (with
subwasm, the extractor the runtime-upgrade ceremony gate uses), the authority
nodes' launch commands and the RPC proxy configs in front of them, what each
public RPC URL serves, probed live, and what Cardano holds, through a Kupo index:
the cMATRA lock that backs genesis and the permissioned candidates that become
the committee after the first rotation. A launch manifest, signed with a launch
key launch_keys.json pins, supplies what genesis cannot show: who holds each
role, the explicit economics, where the lock is.

Rules, each of which refuses on its own:
  1 dev-keys     a well-known key anywhere: genesis storage, the runtime code, a
                 role or a member of a role's multisig, a Cardano permissioned
                 candidate, a node launch command, or the manifest signing key;
                 Sudo.Key or a genesis account that no declared role accounts
                 for, or Root not a multisig of threshold 2 or more; an
                 off-chain role left undeclared; a chain spec the anchor worker
                 would read as a test network
  2 rewards      attestor reward and subsidy values or validator reward
                 parameters not declared, or genesis and the runtime do not
                 hold exactly the declared values
  3 rpc          an authority's running node process serves unsafe RPC methods
                 on an external or proxied listener, a public RPC URL lists or
                 answers an unsafe method, or an authority has no launch entry
  4 supply       an attestor endowment below bond + existential deposit + fee
                 buffer; genesis issuance plus the runtime's emission reserves
                 above the cMATRA the lock holds on Cardano (the reserve counted
                 both on Cardano and on Materios); a lock fewer than two key
                 holders can spend, or not bound to this genesis by its datum;
                 genesis storage outside the allowlist
  5 pallets      PerpEngine in the runtime metadata, under any name
  6 checkpoint   genesis hash, runtime code hash, chain-spec hash or launch
                 manifest differ from the signed launch manifest, or no pinned
                 launch key signed it; the spec carries code substitutes, an
                 authority loads a local runtime override, or genesis turns on
                 a Cardano deposit observation that has no checkpoint
  7 timelock     the Root timelock's guardian missing from genesis, not the
                 multisig of threshold 2 or more roles.guardian declares, the
                 sudo key, or sharing any account or member with it; its delays
                 missing, below the runtime's mainnet delays, above its
                 MaxDelay or out of the runtime's order
  8 node         an authority's own node binary, run offline on the options
                 its node process runs with, builds another genesis than the
                 one the preflight computes, the manifest signs and the lock's
                 datum binds; its --chain names a chain built into the node or
                 a file that is not the checked spec; it runs another binary
                 than the one the manifest pins

    launch_preflight.py check --spec raw.json --launch launch.json \\
        --signed-manifest signed.json --kupo http://<mainnet kupo> \\
        [--manifest-key 0x<ed25519 pubkey>] [--extra-well-known exposed.json ...] [--subwasm PATH]
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
import itertools
import json
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
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
from websockets.exceptions import WebSocketException
from websockets.sync.client import connect as ws_connect

HERE = Path(__file__).resolve().parent
# The launch key holders' ed25519 public keys: a signed manifest counts only under one of these.
LAUNCH_KEYS = HERE / "launch_keys.json"
KEYS, REWARDS, RPC, SUPPLY, PALLETS, CHECKPOINT, TIMELOCK, NODE = (
    "1 dev-keys", "2 rewards", "3 rpc", "4 supply", "5 pallets", "6 checkpoint", "7 timelock", "8 node")
CODE_KEY = b":code"
# sp_api's id of the Core API, blake2_64 of its name; an API entry is the 8-byte id and a u32 version.
CORE_API = hashlib.blake2b(b"Core", digest_size=8).digest()
API_ENTRY = 12
ZSTD_PREFIX = bytes.fromhex("52bc537646db8e05")
CODE_BOMB_LIMIT = 50 * 1024 * 1024
# Compressed bytes decoded at a time. A zstd block of up to 128 KiB takes as few as 4 bytes, so a step decodes at
# most 8 MiB and a bomb stops within that of the limit.
ZSTD_STEP = 256
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
    # The Root timelock's delay per call class and its guardian hold no MATRA;
    # rule 7 checks what they hold. Its queue (Tasks, CounterForTasks,
    # NextTaskId, PendingGuardianChange, Approval) stays out: a new chain has
    # queued nothing, and a call queued or approved at genesis could run as Root
    # without waiting out its delay in public.
    "RootTimelock.Delays", "RootTimelock.Guardian",
})
GENESIS_WELL_KNOWN_KEYS = {CODE_KEY, b":extrinsic_index"}
STORAGE_VERSION_KEY = b":__STORAGE_VERSION__:"
POLICY_ID_LEN = 28
# Validator reward parameters are runtime constants: (economics field, OrinqReceipts constant).
VALIDATOR_REWARD_CONSTANTS = (
    ("validator_reward_per_era", "ValidatorRewardPerEra"),
    ("treasury_emission_share_perbill", "TreasuryEmissionShare"),
)
# The runtime's Balance is a u128.
BALANCE = 16
REWARD_ITEMS = (
    ("attestation_reward_per_signer", "AttestationRewardPerSigner", BALANCE),
    ("era_cap_base", "EraCapBase", BALANCE),
    ("era_cap_baseline_attestor_count", "EraCapBaselineAttestorCount", 4),
)
# System.Account's AccountInfo<Nonce = u32, AccountData<Balance>>: nonce, consumers, providers and sufficients, then
# free, reserved, frozen and flags.
ACCOUNT_INFO = (4, 4, 4, 4, BALANCE, BALANCE, BALANCE, BALANCE)
ECONOMICS_FIELDS = {"fee_buffer", *(field for field, _ in VALIDATOR_REWARD_CONSTANTS),
                    *(field for field, _, _ in REWARD_ITEMS)}
# Every launch names who holds these; the ones that always run must name a key.
REQUIRED_ROLES = ("sudo", "anchor_signer", "attestors", "oracle")
RUNNING_ROLES = ("anchor_signer", "attestors")
MULTISIG_ENTROPY = b"modlpy/utilisuba"
# The Root timelock's call classes, in the order its DelayTable stores their delays.
DELAY_CLASSES = ("recovery", "standard", "long")
DEV_KEYRING_FLAGS = {"--alice", "--bob", "--charlie", "--dave", "--eve", "--ferdie",
                     "--one", "--two", "--dev"}
# A path with no phrase, which Substrate derives from the dev phrase, and an
# optional ///password that is never echoed. Not after a word, a scheme's colon
# or a path, and not a protocol-relative host.
DEV_URI = re.compile(r"(?<![\w:/.])(//[\w-]+(?:/{1,2}[\w-]+)*)(?:///\S*)?(?![\w./-])")
# A setting that holds a secret URI, unless its name says it holds where one is.
SECRET_SETTING = re.compile(r"uri|seed|mnemonic|phrase|secret", re.IGNORECASE)
SECRET_LOCATION = re.compile(r"(file|path|dir)$", re.IGNORECASE)
HEX_SEED = re.compile(r"0x([0-9a-fA-F]{64})")
# What the anchor worker reads as a test network, shared with it in test_networks.json.
TEST_NETWORKS = json.loads((HERE / "test_networks.json").read_text())
TEST_NETWORK_NAME = re.compile(TEST_NETWORKS["name_pattern"], re.IGNORECASE | re.ASCII)
NODE_BINARIES = ("materios-node", "materios-node-spo")
# Shells whose `-c` script is opened. zsh is not one: it runs its zshenv files before any script.
SHELLS = {"sh", "bash", "dash", "ash"}
SHELL_OPERATORS = ";&|()<>\n"
# A script word bash rewrites and shlex reads literally: brace, filename or tilde expansion, or a comment.
SHELL_REWRITTEN = re.compile(r"[{}*?\[~]|^#")
SHELL_QUIET_OPTIONS = {"--noprofile", "--norc"}
# The shell options the preflight reads through: allexport, errexit and nounset run no code and change no word.
SHELL_OPTIONS = re.compile(r"[-+][aeu]*")
# Settings the shell or the dynamic loader acts on, refused in any node's launch: a file or code it runs
# ($BASH_ENV, BASH_FUNC_* imports, $PS4 under xtrace, $ENV, LD_PRELOAD and LD_AUDIT), the options it
# starts with (SHELLOPTS, BASHOPTS), or where a program or library is found (PATH, LD_LIBRARY_PATH).
LOADER_SETTINGS = re.compile(r"BASH_ENV|BASH_FUNC_.*|PS4|ENV|SHELLOPTS|BASHOPTS|PATH|LD_.*", re.DOTALL)
# The settings an authority may set: logging, the time zone and the node's own Cardano follower settings.
# Anything else (a gconv or OpenSSL module path, the mock follower, the mithril client binary) could run
# code or change the node beyond its argv.
AUTHORITY_SETTINGS = frozenset({
    "RUST_LOG", "RUST_BACKTRACE", "RUST_LIB_BACKTRACE", "TZ",
    "MAIN_CHAIN_FOLLOWER", "DB_SYNC_POSTGRES_CONNECTION_STRING", "CARDANO_SECURITY_PARAMETER",
    "CARDANO_ACTIVE_SLOTS_COEFF", "BLOCK_STABILITY_MARGIN", "SIDECHAIN_BLOCK_BENEFICIARY",
    "MC__FIRST_EPOCH_TIMESTAMP_MILLIS", "MC__EPOCH_DURATION_MILLIS", "MC__FIRST_EPOCH_NUMBER", "MC__FIRST_SLOT_NUMBER",
    "MITHRIL_AGGREGATOR_ENDPOINT", "MITHRIL_GENESIS_VERIFICATION_KEY",
})
# What an authority's launch may run before its node, as bare words: builtins and mkdir, which start nothing.
SETUP_COMMANDS = ("set", "export", "cd", "umask", "ulimit", "mkdir")
SHELL_ASSIGNMENT = re.compile(r"[A-Za-z_]\w*\+?=.*", re.DOTALL)
WORD_SETTING = re.compile(r"([^\s=\"']+?)\+?=([^\s\"']*)")
# GNU env's long options that take the next word as their argument.
ENV_LONG_OPTIONS_WITH_ARGUMENT = ("--argv0", "--chdir", "--unset")
SHELL_NESTING = 4
RPC_ENDPOINT_FLAG = "--experimental-rpc-endpoint"
DEFAULT_RPC_PORT = 9944
WASM_OVERRIDES_FLAG = "--wasm-runtime-overrides"
MANY = -1
# Every option materios-node's run command takes (sc-cli at polkadot-stable2409-4: what `materios-node --help` lists,
# and the aliases clap also takes), with how many values it takes (MANY: one or more, up to the next option), and
# whether export-blocks is given it. export-blocks builds genesis the way the node does at startup and takes the
# chain, logging, pruning and database options with the same definitions, so it gets them as the authority gives
# them. The base path gives way to a fresh directory. Every other option sets up what the running node does (its
# network, RPC, telemetry, Prometheus, keystore, role, transaction pool, offchain workers or executor), none the
# genesis it builds, and export-blocks takes none of them.
NODE_OPTIONS = {
    **dict.fromkeys(("--chain", "--tracing-targets", "--tracing-receiver", "--state-pruning", "--pruning",
                     "--blocks-pruning", "--keep-blocks", "--database", "--db", "--db-cache"), (1, True)),
    **dict.fromkeys(("--dev", "--detailed-log-output", "--disable-log-color", "--enable-log-reloading"), (0, True)),
    **dict.fromkeys(("--log", "-l"), (MANY, True)),
    **dict.fromkeys(("--base-path", "-d"), (1, False)),
    **dict.fromkeys((
        "--rpc-methods", "--rpc-rate-limit", "--rpc-max-request-size", "--rpc-max-response-size",
        "--rpc-max-subscriptions-per-connection", "--rpc-port", "--rpc-max-connections",
        "--rpc-message-buffer-capacity-per-connection", "--rpc-max-batch-request-len", "--rpc-cors", "--name",
        "--telemetry-url", "--prometheus-port", "--max-runtime-instances", "--runtime-cache-size",
        "--offchain-worker", "--enable-offchain-indexing", "--wasm-execution", "--wasmtime-instantiation-strategy",
        WASM_OVERRIDES_FLAG, "--execution-syncing", "--execution-import-block", "--execution-block-construction",
        "--execution-offchain-worker", "--execution-other", "--execution", "--trie-cache-size", "--state-cache-size",
        "--port", "--out-peers", "--in-peers", "--in-peers-light", "--max-parallel-downloads", "--node-key",
        "--node-key-type", "--node-key-file", "--kademlia-replication-factor", "--sync", "--max-blocks-per-request",
        "--network-backend", "--pool-limit", "--pool-kbytes", "--tx-ban-seconds", "--keystore-path", "--password",
        "--password-filename"), (1, False)),
    **dict.fromkeys((
        "--tmp", "--validator", "--no-grandpa", "--rpc-external", "--unsafe-rpc-external",
        "--rpc-rate-limit-trust-proxy-headers", "--rpc-disable-batch-requests", "--rpc_no_batch_requests",
        "--no-telemetry", "--prometheus-external", "--no-prometheus", "--reserved-only", "--no-private-ip",
        "--no-private-ipv4", "--allow-private-ip", "--allow-private-ipv4", "--no-mdns",
        "--unsafe-force-node-key-generation", "--discover-local", "--kademlia-disjoint-query-paths", "--ipfs-server",
        "--password-interactive", "--force-authoring", *sorted(DEV_KEYRING_FLAGS - {"--dev"})), (0, False)),
    **dict.fromkeys(("--rpc-rate-limit-whitelisted-ips", RPC_ENDPOINT_FLAG, "--bootnodes", "--reserved-nodes",
                     "--public-addr", "--listen-addr"), (MANY, False)),
}
# What the node reads before it builds genesis, and does not build it from: its Cardano follower settings, here the
# mock follower, which connects to nothing, and Cardano mainnet's Shelley epoch layout.
NODE_ENV = {"USE_MAIN_CHAIN_FOLLOWER_MOCK": "true", "MC__FIRST_EPOCH_TIMESTAMP_MILLIS": "1596059091000",
            "MC__EPOCH_DURATION_MILLIS": "432000000", "MC__FIRST_EPOCH_NUMBER": "208",
            "MC__FIRST_SLOT_NUMBER": "4492800"}
NODE_TIMEOUT = 900
# What the node prints when its --chain names a file that does not exist: sc-chain-spec's ChainSpec::from_json_file,
# the branch the node's load_spec takes for any name it does not build in.
MISSING_SPEC_FILE = "Error opening spec file `{}`: No such file or directory"
# What export-blocks --binary writes for --from 0 --to 0: a u64 block count, then genesis as SCALE, its header (zero
# parent hash, number 0, state root, extrinsics root, empty digest), no extrinsics and no justifications.
GENESIS_HEADER = 32 + 1 + 32 + 32 + 1
GENESIS_EXPORT = 8 + GENESIS_HEADER + 2
LAUNCH_FIELDS = {"roles", "economics", "supply", "nodes", "rpc_proxies", "public_rpc"}
PROXY_KINDS = ("nginx", "nginx-dump", "cloudflared")
PROXY_FIELDS = {"name", "node", "kind", "config", "other_targets"}
# What a node built from polkadot-stable2409-4 serves under --rpc-methods safe: its rpc_methods less each method whose
# handler calls check_if_safe (author, system, offchain and state in sc-rpc, and substrate-frame-rpc-system's dry
# run). A node lists every method it registers under --rpc-methods safe too, the unsafe ones included.
SAFE_RPC_METHODS = frozenset({
    "account_nextIndex",
    "author_pendingExtrinsics", "author_submitAndWatchExtrinsic", "author_submitExtrinsic",
    "author_unwatchExtrinsic",
    "chainHead_v1_body", "chainHead_v1_call", "chainHead_v1_continue", "chainHead_v1_follow", "chainHead_v1_header",
    "chainHead_v1_stopOperation", "chainHead_v1_storage", "chainHead_v1_unfollow", "chainHead_v1_unpin",
    "chainSpec_v1_chainName", "chainSpec_v1_genesisHash", "chainSpec_v1_properties",
    "chain_getBlock", "chain_getBlockHash", "chain_getFinalisedHead", "chain_getFinalizedHead", "chain_getHead",
    "chain_getHeader", "chain_getRuntimeVersion", "chain_subscribeAllHeads", "chain_subscribeFinalisedHeads",
    "chain_subscribeFinalizedHeads", "chain_subscribeNewHead", "chain_subscribeNewHeads",
    "chain_subscribeRuntimeVersion", "chain_unsubscribeAllHeads", "chain_unsubscribeFinalisedHeads",
    "chain_unsubscribeFinalizedHeads", "chain_unsubscribeNewHead", "chain_unsubscribeNewHeads",
    "chain_unsubscribeRuntimeVersion",
    "childstate_getKeys", "childstate_getKeysPaged", "childstate_getKeysPagedAt", "childstate_getStorage",
    "childstate_getStorageEntries", "childstate_getStorageHash", "childstate_getStorageSize",
    "motra_estimateFee", "motra_getBalance", "motra_getParams", "motra_insufficientFailures", "motra_totalBurned",
    "motra_totalIssued",
    "orinq_getReceipt", "orinq_getReceiptCount", "orinq_getReceiptStatus", "orinq_getReceiptsByContent",
    "orinq_receiptExists",
    "rpc_methods",
    "state_call", "state_callAt", "state_getChildReadProof", "state_getKeys", "state_getKeysPaged",
    "state_getKeysPagedAt", "state_getMetadata", "state_getReadProof", "state_getRuntimeVersion",
    "state_getStorage", "state_getStorageAt", "state_getStorageHash", "state_getStorageHashAt",
    "state_getStorageSize", "state_getStorageSizeAt", "state_queryStorageAt", "state_subscribeRuntimeVersion",
    "state_subscribeStorage", "state_unsubscribeRuntimeVersion", "state_unsubscribeStorage",
    "subscribe_newHead",
    "system_accountNextIndex", "system_chain", "system_chainType", "system_health", "system_localListenAddresses",
    "system_localPeerId", "system_name", "system_nodeRoles", "system_properties", "system_reservedPeers",
    "system_syncState", "system_version",
    "transactionWatch_v1_submitAndWatch", "transactionWatch_v1_unwatch",
    "transaction_v1_broadcast", "transaction_v1_stop",
    "unsubscribe_newHead",
})
# An unsafe method that changes nothing: its handler calls check_if_safe, then reads the peer list.
UNSAFE_PROBE = "system_peers"
# What sc-rpc answers an unsafe call with where unsafe methods are denied, and a proxy an unknown method with.
METHOD_NOT_FOUND = -32601
# A node serves JSON-RPC over HTTP and over a WebSocket at one address, and a client picks either.
RPC_TRANSPORTS = {"http": "ws", "https": "wss", "ws": "http", "wss": "https"}
PUBLIC_RPC_TIMEOUT = 30
PUBLIC_RPC_LIMIT = 1024 * 1024
# The messages read over a WebSocket for one answer: the probe subscribes to nothing, so any other is a stray.
PUBLIC_RPC_MESSAGES = 16
USER_AGENT = "materios-launch-preflight"
# Forwarding schemes nginx and cloudflared accept, with the port each implies; tcp names its own.
DEFAULT_PORTS = {"http": 80, "ws": 80, "grpc": 80, "https": 443, "wss": 443, "grpcs": 443,
                 "ssh": 22, "rdp": 3389, "smb": 445, "tcp": None}
NGINX_SPACE = " \t\r\n"
NGINX_ESCAPE = re.compile(r"\\([\"'\\trn])")
NGINX_DUMP_FILE = re.compile(r"^# configuration file (.+):$", re.MULTILINE)
NGINX_FORWARDS = frozenset({"proxy_pass", "grpc_pass", "uwsgi_pass", "scgi_pass", "fastcgi_pass", "memcached_pass"})
# A dynamic module, or the directives of a scripting module a build may carry statically (njs, perl, lua): code
# inside nginx that can open its own connections, which no forwarding directive shows.
NGINX_CODE = re.compile(r"load_module|js_\w+|perl\w*|\w*_by_lua\w*|lua_\w+")
NGINX_INCLUDE_DEPTH = 8
# Include pattern syntax glob(3), which nginx reads a pattern with, reads apart from Python's glob: glibc negates
# with [^x], takes [[:class:]], escapes with a backslash, and in nginx's C locale matches one byte with '?'.
NGINX_GLOB_APART = re.compile(r"[?\[\\]")
# The upstream server parameters that leave a server's address as written. nginx takes the port and host of a
# `service=` server from a DNS SRV record, and resolves a `resolve` server's name again, while it runs.
NGINX_SERVER_PARAMETERS = re.compile(r"(?:weight|max_conns|max_fails|fail_timeout)=\S*|backup|down")
HOST_PORT = re.compile(r"\[([0-9A-Fa-f:.]+)\](?::(\d+))?|([^\s:\[\]/]+)(?::(\d+))?")
# cMATRA (v2) on Cardano mainnet: policy id and asset name, as Kupo keys assets.
CMATRA_UNIT = "7ff33a5565393dc47b48ac47becc12d92c9952e724e8446dfb6adc66.634d41545241"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
# Shelley address header types whose payment credential is a script, and the mainnet network id.
SCRIPT_PAYMENT_TYPES = (1, 3, 5, 7)
CARDANO_MAINNET = 1
# A native script's hash is blake2b-224 over this tag and its CBOR.
NATIVE_SCRIPT_TAG = b"\x00"
NATIVE_SCRIPT_DEPTH = 16
NATIVE_SCRIPT_KEYS = 16
GENESIS_LOCK_FIELDS = {"utxo", "address", "native_script"}
UTXO = re.compile(r"[0-9a-f]{64}#\d+")
KUPO_TIMEOUT = 30
KUPO_LIMIT = 16 * 1024 * 1024
# Five minutes of slots: a synced Kupo trails its node by a block or two.
KUPO_MAX_LAG_SLOTS = 300
# Hex is read in the one spelling its writer writes: lowercase digits, two a byte, after 0x in the raw spec (as
# build-spec writes it), the manifests and the launch keys, and with no 0x in the key tables (as
# gen_well_known_keys.py writes them and the anchor worker reads them) and from Kupo. The node reads a raw spec with
# impl-serde's from_hex, which also takes upper case and no 0x, and skips a space, tab, CR or LF while still counting
# it toward nibble alignment; FRAME then ignores the bytes a value has left over. So `0x 11..` loads as 0x0111.., and
# a key with two trailing spaces as that key and a zero byte: any other spelling could launch other bytes than the
# preflight checked.
LOWER_HEX = re.compile(r"[0-9a-f]*")


class InputError(Exception):
    """An input the preflight cannot read. Refuses like a failed rule."""


def hex_bytes(value, where: str, prefix: str = "0x") -> bytes:
    """The bytes `value` spells as `prefix` and lowercase hex of whole bytes,
    and nothing else. The error names `where`, never the value: a seed is one."""
    digits = value[len(prefix):] if isinstance(value, str) and value.startswith(prefix) else None
    if digits is None or len(digits) % 2 or not LOWER_HEX.fullmatch(digits):
        spelling = f"{prefix}-prefixed lowercase hex of whole bytes" if prefix else \
            "lowercase hex of whole bytes with no 0x"
        raise InputError(f"{where} is not {spelling}, the one spelling the preflight reads: another reader can take "
                         "any other (whitespace, upper case, a missing or extra prefix, an odd digit) as other bytes")
    return bytes.fromhex(digits)


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


def account_key(account: bytes) -> bytes:
    """Where System.Account files an account: blake2_128 of it, then the account."""
    return storage_key("System", "Account") + hashlib.blake2b(account, digest_size=16).digest() + account


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


def scale_uints(raw: bytes, widths: tuple[int, ...]) -> tuple[int, ...] | None:
    """The little-endian unsigned fields of a value of these widths, or None unless it is exactly that long."""
    if len(raw) != sum(widths):
        return None
    return tuple(int.from_bytes(raw[end - width:end], "little")
                 for end, width in zip(itertools.accumulate(widths), widths))


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
    # The file as read, the bytes a node given it loads.
    source: bytes

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

    def uints(self, key: bytes, widths: tuple[int, ...], where: str) -> tuple[int, ...] | None:
        """The unsigned fields genesis stores at `key`, or None if it stores
        nothing there. FRAME reads a value too short for its type as the item's
        default and ignores bytes past its type, so a value of any other length
        launches other numbers than the ones read here."""
        raw = self.storage.get(key)
        if raw is None:
            return None
        fields = scale_uints(raw, widths)
        if fields is None:
            raise InputError(f"chain spec raw storage: {where} is {len(raw)} byte{'s' * (len(raw) != 1)}, not the "
                             f"{sum(widths)} its type encodes to: the node reads a shorter value as its default, "
                             "zero, and only the first bytes of a longer one")
        return fields

    def uint(self, pallet: str, item: str, width: int) -> int | None:
        fields = self.uints(storage_key(pallet, item), (width,), f"{pallet}.{item}")
        return None if fields is None else fields[0]

    def accounts(self) -> list[bytes]:
        """Every account System.Account holds at genesis."""
        prefix = storage_key("System", "Account")
        keys = [key for key in sorted(self.storage) if key.startswith(prefix)]
        for key in keys:
            if key != account_key(key[-32:]):
                raise InputError(f"chain spec raw storage: the System.Account key 0x{key.hex()} is not blake2_128 of "
                                 "a 32-byte account followed by that account, the one key the runtime reads it at")
        return [key[-32:] for key in keys]

    def balance(self, account: bytes) -> tuple[int, int]:
        """An account's free and reserved balance at genesis, none if genesis does not endow it."""
        key = account_key(account)
        info = self.uints(key, ACCOUNT_INFO, f"System.Account value at 0x{key.hex()}")
        return (0, 0) if info is None else info[4:6]


def load_spec(path: str) -> Spec:
    source = read_file(path, "chain spec")
    doc = parse_json(source, path, "chain spec")
    genesis = doc.get("genesis") if isinstance(doc, dict) else None
    raw = genesis.get("raw") if isinstance(genesis, dict) else None
    if not isinstance(raw, dict) or not isinstance(raw.get("top"), dict):
        raise InputError("the preflight needs the raw chain spec (build-spec --raw): "
                         "raw storage is what every node loads")
    if raw.get("childrenDefault"):
        raise InputError("chain spec has child tries; the genesis hash here covers top storage only")
    return Spec(doc, {hex_bytes(key, f"chain spec raw storage key {key[:80]!r}"):
                      hex_bytes(value, f"chain spec raw storage value at {key}")
                      for key, value in raw["top"].items()}, source)


def decompressed_code(code: bytes) -> bytes:
    """The runtime WASM. Compressed code must be one whole zstd frame, as the
    runtime's build writes it: the node's decoder also reads any frame after
    the first and refuses one cut short, where zstandard's readers stop at the
    end of the first frame or of the input."""
    if not code.startswith(ZSTD_PREFIX):
        return code
    compressed, frame, out = code[len(ZSTD_PREFIX):], zstandard.ZstdDecompressor().decompressobj(), bytearray()
    pos = 0
    try:
        while pos < len(compressed) and not frame.eof:
            out += frame.decompress(compressed[pos:pos + ZSTD_STEP])
            pos += ZSTD_STEP
            if len(out) > CODE_BOMB_LIMIT:
                raise InputError("runtime code decompresses past the 50 MiB bomb limit")
    except zstandard.ZstdError as e:
        raise InputError(f"runtime code is not one whole zstd frame: {e}") from e
    if not frame.eof or frame.unused_data or pos < len(compressed):
        raise InputError("runtime code is not one whole zstd frame: it ends inside the frame or goes on after it")
    return bytes(out)


def _leb128(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return result, pos


def custom_sections(wasm: bytes) -> dict[bytes, bytes]:
    """Each custom section's payload by name, the first of a name as the node's RuntimeBlob finds it."""
    if wasm[:4] != b"\0asm":
        raise InputError("runtime code is not a WASM module")
    sections, pos = {}, 8
    try:
        while pos < len(wasm):
            section_id = wasm[pos]
            size, body = _leb128(wasm, pos + 1)
            pos = body + size
            if section_id == 0:
                name_len, name_start = _leb128(wasm, body)
                sections.setdefault(wasm[name_start:name_start + name_len], wasm[name_start + name_len:pos])
    except IndexError as e:
        raise InputError("runtime code is not a WASM module the preflight can read") from e
    return sections


def core_api_version(apis: bytes) -> int | None:
    """The version of the first Core API in a list of API entries."""
    for entry in range(0, len(apis), API_ENTRY):
        if apis[entry:entry + 8] == CORE_API:
            return int.from_bytes(apis[entry + 8:entry + API_ENTRY], "little")
    return None


def runtime_state_version(wasm: bytes) -> int:
    """The trie layout the node builds genesis from this code with. sc-executor
    decodes the `runtime_version` section with the Core API version that the
    `runtime_apis` section declares, else the one the version lists itself; it
    reads a transaction version from Core 3 on and a state version from Core 4
    on, and sp-version takes any state version but 0 as V1."""
    sections = custom_sections(wasm)
    version, apis = sections.get(b"runtime_version"), sections.get(b"runtime_apis")
    if version is None:
        raise InputError("runtime code has no runtime_version section")
    if apis is not None and len(apis) % API_ENTRY:
        raise InputError("runtime code's runtime_apis section does not decode as whole API entries, so the node "
                         "builds no genesis from it")
    undecodable = InputError("runtime code's runtime_version section does not decode, so the node builds no genesis "
                             "from it")
    try:
        cursor = 0
        for _ in range(2):  # spec and impl name
            length, cursor = read_compact(version, cursor)
            cursor += length
        count, cursor = read_compact(version, cursor + 12)  # past the authoring, spec and impl versions
    except IndexError as e:
        raise undecodable from e
    listed, cursor = version[cursor:cursor + API_ENTRY * count], cursor + API_ENTRY * count
    core = core_api_version(listed if apis is None else apis) or 0
    state = cursor + 4  # past the transaction version
    if cursor + 4 * (core >= 3) + (core >= 4) > len(version):
        raise undecodable
    return 1 if core >= 4 and version[state] else 0


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


@dataclass(frozen=True)
class WellKnown:
    keys: list[KnownKey]
    phrase_hash: bytes
    seed_hash: bytes


def load_well_known(extra: list[Path] = ()) -> WellKnown:
    """The public table plus operator tables of keys whose exposure must not be
    named in a public repo. A 33-byte ECDSA key also matches the blake2-256
    account it maps to. The dev phrase and its seed are held by their hashes."""
    base = HERE / "well_known_keys.json"
    keys = []
    for path in (base, *extra):
        try:
            entries = json.loads(Path(path).read_text(), object_pairs_hook=unique_keys)["keys"]
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise InputError(f"cannot read key table {path}: {e}") from e
        for i, entry in enumerate(entries):
            if not all(isinstance(entry.get(f), str) for f in ("label", "scheme", "public")):
                raise InputError(f"key table {path}: keys[{i}] needs a label, a scheme and a public key")
            public = hex_bytes(entry["public"], f"key table {path}: keys[{i}] public", prefix="")
            if len(public) not in (32, 33):
                raise InputError(f"key table {path}: keys[{i}] public is {len(public)} bytes; expected 32 or 33")
            for needle in (public, blake2_256(public)) if len(public) == 33 else (public,):
                if not any(k.needle == needle for k in keys):
                    keys.append(KnownKey(entry["label"], entry["scheme"], needle))
    table = json.loads(base.read_text())
    phrase_hash, seed_hash = (hex_bytes(table.get(field), f"key table {base}: {field}", prefix="")
                              for field in ("dev_phrase_blake2_256", "dev_seed_blake2_256"))
    return WellKnown(keys, phrase_hash, seed_hash)


def decode_public_key(text: str) -> bytes:
    """A role key as SS58 or 0x-hex (32-byte account or 33-byte ECDSA key)."""
    if text.startswith("0x"):
        raw = hex_bytes(text, "a public key")
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


def phraseless_uri(value: str) -> str | None:
    """The path of a secret URI with no phrase (`/Name`, `//Name//x`, `///pw`):
    Substrate and @polkadot/keyring derive it from the dev phrase. The result
    stops before any `///password`; the root reads as `(root)`."""
    match = re.fullmatch(r"((?:/{1,2}[^/]+)*)(?:///.*)?", value.strip(), re.DOTALL)
    return (match.group(1) or "(root)") if match and value.strip().startswith("/") else None


def secret_settings(node: dict):
    """(setting, value) for each environment variable, flag or setting a word
    of a node's launch hands a program, whose name marks it as a secret URI
    and not a file or path holding one."""
    names = [(name, value) for name, value in sorted(node.get("env", {}).items())]
    for words in launch_commands(node):
        for i, word in enumerate(words):
            if word.startswith("--") and "=" not in word and i + 1 < len(words):
                names.append((word, words[i + 1]))
            names += word_settings(word)
    return [(name, value) for name, value in names
            if SECRET_SETTING.search(name) and not SECRET_LOCATION.search(name)]


def dev_uri(text: str) -> str | None:
    """The derivation path of a secret URI with no phrase, which Substrate
    derives from the dev phrase: `//Alice`, but also any other path such as
    `//Oracle//hot`. The result stops before any `///password`."""
    match = DEV_URI.search(text)
    return match.group(1) if match else None


def contains_phrase(text: str, phrase_hash: bytes) -> bool:
    words = re.findall(r"[a-z]+", text)
    return any(blake2_256(" ".join(words[i:i + 12]).encode()) == phrase_hash for i in range(len(words) - 11))


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


def role_accounts(entry, where: str):
    """(where, account) for a role entry and each member of its multisig, at any
    depth. Raises ValueError when a key does not decode."""
    yield where, role_account(entry)
    if isinstance(entry, dict):
        for i, member in enumerate(entry["members"]):
            yield from role_accounts(member, f"{where}.members[{i}]")


def role_multisigs(entry, where: str):
    """(where, multisig) for a role entry's multisig and each one nested in it."""
    if isinstance(entry, dict):
        yield where, entry
        for i, member in enumerate(entry["members"]):
            yield from role_multisigs(member, f"{where}.members[{i}]")


def lone_holders(entry) -> list[bytes]:
    """The keys of a role entry whose holder alone can act as its account. A key
    signs as itself and, through pallet_multisig, as every nested multisig whose
    threshold the accounts it signs as meet, wherever that multisig's account is
    a member, a flat address included. Raises ValueError when a key does not
    decode."""
    multisigs = [(role_account(multisig), {role_account(member) for member in multisig["members"]},
                  multisig["threshold"]) for _, multisig in role_multisigs(entry, "")]
    target = role_account(entry)

    def acts_alone(key: bytes) -> bool:
        signs_as, grown = {key}, True
        while grown:
            grown = False
            for account, members, threshold in multisigs:
                if account not in signs_as and len(members & signs_as) >= threshold:
                    signs_as.add(account)
                    grown = True
        return target in signs_as

    return sorted(key for key in {role_account(text) for _, text in role_leaves(entry, "")} if acts_alone(key))


def max_signatories(meta: Metadata) -> int | None:
    raw = meta.constants.get(("Multisig", "MaxSignatories"), b"")
    return int.from_bytes(raw, "little") if len(raw) == 4 else None


def multisig_faults(entry, where: str, name: str, power: str, meta: Metadata, prefix: int) -> list[str]:
    """Why a role entry that must need two keyholders to act does not: it is a
    single key, one key meets its threshold alone, or pallet_multisig refuses
    to sign through it or through a multisig nested in it, since it has more
    members than the runtime's MaxSignatories."""
    if not isinstance(entry, dict):
        return [f"{where} is a single key: {name} must be a multisig with a threshold of at least 2, declared by its "
                "members so each one is checked"]
    limit = max_signatories(meta)
    if limit is None:
        faults = [f"{where}: the runtime metadata declares no Multisig.MaxSignatories the preflight can read: "
                  "whether pallet_multisig lets this multisig sign is unknown here"]
    else:
        faults = [f"{path} has {len(multisig['members'])} members, more than the runtime's Multisig.MaxSignatories "
                  f"{limit}: pallet_multisig refuses every call signed through it"
                  for path, multisig in role_multisigs(entry, where) if len(multisig["members"]) > limit]
    if entry["threshold"] < 2:
        return faults + [f"{where} has threshold 1: any one member alone {power}"]
    try:
        holders = lone_holders(entry)
    except ValueError:
        return faults  # rule 1 refuses a key that does not decode and a multisig that lists a member twice
    paths: dict[bytes, list[str]] = {}
    for path, text in role_leaves(entry, where):
        paths.setdefault(role_account(text), []).append(path)
    return faults + [f"{where}: {ss58(key, prefix)}, the member at {' and '.join(paths[key])}, meets its threshold "
                     f"alone by also signing as a nested multisig, so one keyholder alone {power}"
                     for key in holders]


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
    lock_datum: bytes | None = None


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
    lock_datum = None
    if lock is not None and lock.get("datum_type") == "inline":
        lock_datum = kupo_datum(kupo, lock.get("datum_hash"), "the genesis lock")
    policy = permissioned_candidates_policy(spec).hex()
    outputs = unspent(kupo_get(kupo, f"/matches/{policy}.*?unspent"), "the permissioned candidates token")
    if not outputs:
        raise InputError(f"Kupo has no unspent output holding the permissioned candidates token {policy}: "
                         "the committee after the first rotation cannot be checked")
    candidates = []
    for output in outputs:
        where = f"the permissioned candidates output {output.get('transaction_id')}#{output.get('output_index')}"
        candidates += decode_candidates(kupo_datum(kupo, output.get("datum_hash"), where))
    return CardanoView(lock, candidates, lock_datum)


def kupo_datum(kupo: str, datum_hash, what: str) -> bytes:
    """The datum Kupo holds for a datum hash, checked against that hash."""
    if not (isinstance(datum_hash, str) and re.fullmatch(r"[0-9a-f]{64}", datum_hash)):
        raise InputError(f"{what} has no datum hash Kupo can serve a datum for")
    datum = kupo_get(kupo, f"/datums/{datum_hash}")
    if not isinstance(datum, dict) or not isinstance(datum.get("datum"), str):
        raise InputError(f"{what} has no datum Kupo can serve")
    raw = hex_bytes(datum["datum"], f"the datum Kupo serves for {what}", prefix="")
    if hashlib.blake2b(raw, digest_size=32).hexdigest() != datum_hash:
        raise InputError(f"Kupo served a datum for {what} that does not hash to {datum_hash}")
    return raw


def bech32_polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for i, generator in enumerate(BECH32_GENERATOR):
            checksum ^= generator if (top >> i) & 1 else 0
    return checksum


def bech32_decode(text: str) -> tuple[str, bytes]:
    """The human-readable part and data of a bech32 string. Cardano addresses
    run past BIP-173's 90 characters, so there is no length limit."""
    hrp, separator, data = text.rpartition("1")
    if text != text.lower() or not hrp or not separator or len(data) < 6 or any(c not in BECH32_CHARSET for c in data):
        raise ValueError("is not a valid bech32 address")
    values = [BECH32_CHARSET.index(c) for c in data]
    if bech32_polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + values) != 1:
        raise ValueError("is not a valid bech32 address")
    acc = bits = 0
    out = bytearray()
    for value in values[:-6]:
        acc, bits = (acc << 5) | value, bits + 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or acc & ((1 << bits) - 1):
        raise ValueError("is not a valid bech32 address")
    return hrp, bytes(out)


def lock_script_hash(address: str) -> bytes:
    """The script hash a mainnet Shelley address pays to. Raises ValueError
    with the reason when the address is not one."""
    hrp, data = bech32_decode(address)
    if hrp != "addr" or not data or data[0] & 0x0F != CARDANO_MAINNET:
        raise ValueError("is not a Cardano mainnet address")
    if data[0] >> 4 not in SCRIPT_PAYMENT_TYPES:
        raise ValueError("pays to a key: its holder can spend the backing")
    if len(data) < 29:
        raise ValueError("is not a valid bech32 address")
    return data[1:29]


def native_script(raw: bytes):
    """A Cardano native script decoded from its CBOR, its shape checked."""
    try:
        script = cbor2.loads(raw)
    except (ValueError, RecursionError) as e:
        raise InputError("the genesis lock native script does not decode") from e
    _check_native_script(script, 0)
    return script


def _check_native_script(script, depth: int) -> None:
    kind = script[0] if isinstance(script, list) and script and type(script[0]) is int else None
    if kind == 0:
        ok = len(script) == 2 and isinstance(script[1], bytes) and len(script[1]) == 28
    elif kind in (1, 2):
        ok = len(script) == 2 and isinstance(script[1], list)
    elif kind == 3:
        ok = len(script) == 3 and type(script[1]) is int and isinstance(script[2], list)
    elif kind in (4, 5):
        ok = len(script) == 2 and type(script[1]) is int
    else:
        ok = False
    if not ok or depth == NATIVE_SCRIPT_DEPTH:
        raise InputError("the genesis lock native script does not decode")
    for sub in _native_children(script):
        _check_native_script(sub, depth + 1)


def _native_children(script) -> list:
    return script[1] if script[0] in (1, 2) else script[2] if script[0] == 3 else []


def _native_keys(script) -> set[bytes]:
    return {script[1]} if script[0] == 0 else {k for sub in _native_children(script) for k in _native_keys(sub)}


def _native_satisfied(script, signed: set[bytes]) -> bool:
    """Whether these key signatures satisfy a native script. A time bound counts
    as met: whoever holds the keys can wait for, or act before, the slot."""
    kind = script[0]
    if kind == 0:
        return script[1] in signed
    results = [_native_satisfied(sub, signed) for sub in _native_children(script)]
    if kind == 1:
        return all(results)
    if kind == 2:
        return any(results)
    if kind == 3:
        return sum(results) >= script[1]
    return True


def native_script_holders(script, anyone: set[bytes]) -> int | None:
    """The fewest key holders whose signatures, with those of the keys anyone
    holds, satisfy a native script; None when no set of signatures does."""
    held = sorted(_native_keys(script) - anyone)
    if len(held) > NATIVE_SCRIPT_KEYS:
        raise InputError(f"the genesis lock native script names more than {NATIVE_SCRIPT_KEYS} keys")
    for size in range(len(held) + 1):
        if any(_native_satisfied(script, set(chosen) | anyone) for chosen in itertools.combinations(held, size)):
            return size
    return None


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


def check_dev_keys(spec: Spec, meta: Metadata, launch: dict, cardano: CardanoView, launch_keys: list[bytes],
                   well_known: WellKnown) -> list[Finding]:
    known = well_known.keys
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
                uri = phraseless_uri(text) or dev_uri(text)
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
        findings += [Finding(KEYS, fault) for fault in multisig_faults(entry, f"roles.sudo[{i}]", "Root", "holds Root",
                                                                        meta, spec.ss58_prefix)]
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
        texts = node.get("argv", []) + [f"{k}={v}" for k, v in sorted(node.get("env", {}).items())]
        uris = [dev_uri(text) for text in texts] + [phraseless_uri(value) for _, value in secret_settings(node)]
        node_findings += [Finding(KEYS, f"node {node['name']}: launch config names {uri}") for uri in uris if uri]
        for text in texts:
            if contains_phrase(text, well_known.phrase_hash):
                node_findings.append(Finding(KEYS, f"node {node['name']}: launch config holds the dev mnemonic"))
            if any(blake2_256(bytes.fromhex(seed)) == well_known.seed_hash for seed in HEX_SEED.findall(text)):
                node_findings.append(Finding(KEYS, f"node {node['name']}: launch config holds the dev seed"))
        findings += dict.fromkeys(node_findings)
    for launch_key in launch_keys:
        findings += [Finding(KEYS, f"manifest signing key: {hit}") for hit in match_known(launch_key, known)]
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
        stored = spec.uint("OrinqReceipts", item, width)
        if stored is None:
            findings.append(Finding(REWARDS, f"OrinqReceipts.{item} is not set in genesis "
                                             f"(declared {want})"))
        elif stored != want:
            findings.append(Finding(REWARDS, f"OrinqReceipts.{item} stores {stored}, declared {want}"))
    if declared.get("era_cap_baseline_attestor_count") == 0:
        findings.append(Finding(REWARDS, "economics.era_cap_baseline_attestor_count is zero"))
    return findings


def _program(words: list[str]) -> list[str]:
    """A shell command's words from its program on, past `exec` and NAME=value prefixes."""
    i = 0
    while i < len(words) and (words[i] == "exec" or SHELL_ASSIGNMENT.fullmatch(words[i])):
        i += 1
    return words[i:]


def _shell_script(argv: list[str], where: str) -> str:
    """The SCRIPT of `sh [--norc ...] [-e|-u ...] -c SCRIPT`. A shell that
    first runs startup files, which can start or replace the node, is refused:
    a login or interactive shell, and bash without --norc, which runs its rc
    files under -c when started by sshd or with a socket on its stdin."""
    quiet = set()
    for i, word in enumerate(argv[1:], 1):
        if word == "--login" or re.fullmatch(r"-[a-zA-Z]*[il][a-zA-Z]*", word):
            raise InputError(f"{where}: runs a login or interactive shell, whose startup files the preflight "
                             "cannot read; put the node's settings in the unit's environment and declare them in env")
        if word in SHELL_QUIET_OPTIONS:
            if len(quiet) != i - 1:
                raise InputError(f"{where}: gives {word} after a short option, where bash refuses it")
            quiet.add(word)
            continue
        if not re.fullmatch(r"-[a-zA-Z]+", word):
            break
        _refuse_shell_option(word, word.replace("c", ""), where)
        if "c" in word:
            if len(argv) != i + 2:
                raise InputError(f"{where}: a shell launch must end with its -c script")
            if Path(argv[0]).name == "bash" and "--norc" not in quiet:
                raise InputError(f"{where}: runs bash -c without --norc, so bash runs ~/.bashrc and "
                                 "/etc/bash.bashrc first when SSH_CLIENT is set or its stdin is a socket; the "
                                 "preflight cannot read them. Start it as bash --norc -c")
            return argv[i + 1]
    raise InputError(f"{where}: runs a shell without -c; the preflight cannot read a script file")


def _refuse_shell_option(word: str, options: str, where: str) -> None:
    if not SHELL_OPTIONS.fullmatch(options):
        raise InputError(f"{where}: sets shell option {word}; the preflight reads a shell only with -a, -e and -u: "
                         "-x runs $PS4 as code, and other options change what a command gets")


def _script_commands(script: str, where: str) -> list[list[str]]:
    """The commands of a shell script joined by `;`, `&&` or newlines. Any other
    operator (a pipe, a redirection, a subshell, `||`, `&`) is refused: the
    command that runs, or its words, would depend on evaluation. So is a word
    the shell rewrites before a command gets it, or a line it joins to the next."""
    if "\\\n" in script:
        raise InputError(f"{where}: its shell command continues a line with a backslash, which the shell joins "
                         "into the next; give each command on one line")
    lexer = shlex.shlex(script, posix=True, punctuation_chars=SHELL_OPERATORS)
    lexer.whitespace, lexer.whitespace_split, lexer.commenters = " \t", True, ""
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
        elif rewritten := SHELL_REWRITTEN.search(token):
            raise InputError(f"{where}: its shell command has a word holding {rewritten.group()!r} that the shell "
                             "rewrites (brace, filename or tilde expansion, or a comment); "
                             "give each word literally")
        else:
            words.append(token)
    return commands


def _setting(word: str) -> str:
    """The name a NAME=value or NAME+=value word sets."""
    return word.split("=", 1)[0].removesuffix("+")


def word_settings(word: str) -> list[tuple[str, str]]:
    """(name, value) of each NAME=value or NAME+=value setting a word can hand
    a program: the word itself, one after whitespace, a quote or '=' in it (a
    settings string, systemd-run --setenv=NAME=value, --flag=value), or one
    after any letter of a leading short-option cluster (docker -eNAME=value)."""
    cluster = re.match(r"-[A-Za-z]+", word)
    starts = {0, *range(1, cluster.end() if cluster else 0), *(m.end() for m in re.finditer(r"[\s=\"']", word))}
    return [(m.group(1), m.group(2)) for m in (WORD_SETTING.match(word, i) for i in sorted(starts)) if m]


def _shell_runs(program: list[str]) -> list[str]:
    """A command's words from what the shell runs, past `builtin` and
    `command` (and command's options), which run the next word themselves."""
    while program[:1] in (["builtin"], ["command"]):
        program = list(itertools.dropwhile(lambda word: word.startswith("-"), program[1:]))
    return program


def _env_splits_a_string(args: list[str]) -> bool:
    """Whether GNU env's options include -S (--split-string). They end at the
    first word that is neither an option nor the argument of -a, -C or -u."""
    takes_next = False
    for word in args:
        if takes_next:
            takes_next = False
            continue
        if not word.startswith("-") or word == "--":
            return False
        if word.startswith("--"):
            name = word.split("=", 1)[0]
            if "--split-string".startswith(name):
                return True
            takes_next = "=" not in word and any(o.startswith(name) for o in ENV_LONG_OPTIONS_WITH_ARGUMENT)
        else:
            cut = next((i for i, letter in enumerate(word[1:]) if letter in "aCSu"), None)
            if cut is not None and word[1 + cut] == "S":
                return True
            takes_next = cut == len(word) - 2
    return False


def _refuse_settings(names, authority: bool, where: str) -> None:
    for name in names:
        if LOADER_SETTINGS.fullmatch(name):
            raise InputError(f"{where}: sets {name}, which changes what the shell or the dynamic loader runs; "
                             "the preflight cannot read it")
        if authority and name not in AUTHORITY_SETTINGS:
            raise InputError(f"{where}: sets {name}, which is not a setting an authority may set (logging, TZ "
                             "and the node's Cardano follower settings); the preflight cannot read what it changes")


def _commands(words: list[str], where: str, depth: int, authority: bool) -> list[list[str]]:
    # A setting any word hands a program counts, since a program such as env or systemd-run passes it on.
    _refuse_settings((name for word in words for name, _ in word_settings(word)), False, where)
    if any(Path(word).name == "env" and _env_splits_a_string(words[i + 1:]) for i, word in enumerate(words)):
        raise InputError(f"{where}: runs env -S, which splits a string into settings and arguments by env's own "
                         "quoting and escapes; the preflight cannot read it")
    program = _program(words)
    assigned = [word for word in words[:len(words) - len(program)] if word != "exec"]
    if program[:1] == ["export"]:
        assigned += program[1:]
    _refuse_settings(map(_setting, assigned), authority, where)
    if program[:1] == ["set"]:
        for word in program[1:]:
            _refuse_shell_option(word, word, where)
    runs = next(iter(_shell_runs(program)), None)
    if runs in (".", "source"):
        raise InputError(f"{where}: its launch sources a file with {runs}, which the preflight cannot read; "
                         "put the node's settings in the unit's environment and declare them in env")
    if runs in ("eval", "trap"):
        raise InputError(f"{where}: its launch runs {runs}, whose string the shell runs as code the preflight "
                         "does not open")
    if not program or Path(program[0]).name not in SHELLS:
        return [words]
    if depth == SHELL_NESTING:
        raise InputError(f"{where}: shells nest more than {SHELL_NESTING} deep")
    return [command for inner in _script_commands(_shell_script(program, where), where)
            for command in _commands(inner, where, depth + 1, authority)]


def launch_commands(node: dict) -> list[list[str]]:
    """Every command a node's launch runs, as the words it is given, with each
    `sh -c` wrapper (a systemd unit's, a container entrypoint's) opened. A
    word that expands a variable or a command (`$`, a backtick) is refused:
    what the shell makes of it is not in the manifest. So is a setting the
    shell or the dynamic loader acts on, and, for an authority, any setting
    outside AUTHORITY_SETTINGS, in the node's env or assigned in a command."""
    where = f"node {node['name']}"
    authority = node.get("authority") is True
    argv = node.get("argv", [])
    env = node.get("env", {})
    if any("\0" in text for text in (*argv, *env, *env.values())):
        raise InputError(f"{where}: its launch holds a NUL byte, where execve ends an argument or setting; "
                         "give the argv and env the process receives")
    if any(re.search(r"[$`]", word) for word in argv):
        raise InputError(f"{where}: its launch command expands a variable or a command; "
                         "give the argv the process receives")
    _refuse_settings(env, authority, where)
    return _commands(argv, where, 0, authority) if argv else []


def launch_pieces(node: dict) -> list[str]:
    """Every whitespace-separated piece of a node's launch words, wrapped or
    not, and of its environment: where a flag can hide."""
    words = node.get("argv", []) + [word for command in launch_commands(node) for word in command]
    return [piece for word in words + list(node.get("env", {}).values()) for piece in word.split()]


def node_process(node: dict) -> list[str]:
    """The argv an authority's node process receives: the last command its
    launch runs, which must start a node binary with one argument per word.
    An earlier command may only set up the shell or run a node subcommand:
    any other program can start a node whose listeners go unchecked."""
    where = f"authority {node['name']}"
    commands = launch_commands(node)
    argv = _program(commands[-1]) if commands else []
    program = Path(argv[0]).name if argv else "nothing"
    if program not in NODE_BINARIES:
        raise InputError(f"{where}: its launch runs {program}, not a node binary ({', '.join(NODE_BINARIES)}); "
                         "give the argv the node process receives")
    for earlier in map(_program, commands[:-1]):
        if not earlier or earlier[0] in SETUP_COMMANDS:
            continue
        if Path(earlier[0]).name not in NODE_BINARIES:
            raise InputError(f"{where}: its launch runs {earlier[0]} before its last command; the preflight reads "
                             f"only {', '.join(SETUP_COMMANDS)} or a node subcommand there, since any other "
                             "program can start a node it never checks")
        # A node binary with a subcommand (`build-spec`, `purge-chain`) is a tool run, not a node.
        if len(earlier) == 1 or earlier[1].startswith("-"):
            raise InputError(f"{where}: its launch starts a node before its last command; the preflight "
                             "checks the last command as the one node process")
    for i, word in enumerate(argv):
        if re.search(r"\s-", word):
            raise InputError(f"{where}: argument {i} holds several arguments; give one per word")
    return argv


def running_argv(node: dict) -> list[str]:
    """The argv an authority's node process runs with, from its captured /proc/<pid>/cmdline, where the kernel
    ends each word with a NUL. Its launch's reading must give the same words: a node started some other way, or a
    launch the preflight misread, leaves which argv runs unresolved."""
    where, path = f"authority {node['name']}", node.get("cmdline")
    if path is None:
        raise InputError(f"{where}: give its running node process's /proc/<pid>/cmdline as cmdline; the preflight "
                         "checks the argv the node runs with")
    try:
        raw = Path(path).read_bytes()
    except OSError as e:
        raise InputError(f"{where}: cannot read cmdline {path}: {e}") from e
    if not raw.endswith(b"\0"):
        raise InputError(f"{where}: cmdline {path} is not a /proc/<pid>/cmdline capture, which ends each word with "
                         "a NUL byte")
    try:
        running = raw[:-1].decode().split("\0")
    except UnicodeDecodeError as e:
        raise InputError(f"{where}: cmdline {path} is not UTF-8") from e
    launched = node_process(node)
    differs = next((i for i, (a, b) in enumerate(zip(running, launched)) if a != b), None)
    if differs is not None:
        raise InputError(f"{where}: word {differs} of its running node process differs from its launch; the "
                         "preflight cannot resolve which argv runs")
    if len(running) != len(launched):
        raise InputError(f"{where}: its running node process has {len(running)} words, its launch gives "
                         f"{len(launched)}; the preflight cannot resolve which argv runs")
    return running


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


@dataclass
class NginxStatement:
    file: str
    words: list[str]
    block: list[NginxStatement] | None


def _nginx_word(raw: str) -> str:
    """A token as nginx stores it: \\", \\' and \\\\ lose the backslash, and \\t, \\r and \\n become the character."""
    return NGINX_ESCAPE.sub(lambda m: {"t": "\t", "r": "\r", "n": "\n"}.get(m.group(1), m.group(1)), raw)


def _nginx_tokens(text: str, where: str):
    """(words, ';' or '{') for each directive and ([], '}') for each block end, read as ngx_conf_read_token
    reads them. A token ends at whitespace, ';' or '{', not at '}' nor at a '{' after '$'; a quoted token ends
    at its closing quote, which whitespace, ';', '{' or ')' must follow; a '#' starts a comment only where a
    token would start; a backslash keeps the next character in the token."""
    words: list[str] = []
    start, quote = 0, None
    last_space, need_space, comment, escaped, variable = True, False, False, False, False
    for pos, ch in enumerate(text):
        if ch == "\n":
            comment = False
        if comment:
            continue
        if escaped:
            escaped = False
            continue
        if need_space:
            need_space = False
            if ch in NGINX_SPACE:
                last_space = True
                continue
            if ch in ";{":
                yield words, ch
                words, last_space = [], True
                continue
            if ch != ")":
                raise InputError(f"{where}: unexpected {ch!r} after a quoted token")
            last_space = True
        if last_space:
            start = pos
            if ch in NGINX_SPACE:
                continue
            if ch in ";{" and not words or ch == "}" and words:
                raise InputError(f"{where}: unexpected {ch!r}")
            if ch in ";{}":
                yield words, ch
                words = []
            elif ch == "#":
                comment = True
            else:
                last_space, escaped, variable = False, ch == "\\", ch == "$"
                if ch in "\"'":
                    start, quote = pos + 1, ch
            continue
        if ch == "{" and variable:
            continue
        variable = False
        if ch == "\\":
            escaped = True
            continue
        if ch == "$":
            variable = True
            continue
        if quote:
            if ch != quote:
                continue
            quote, need_space = None, True
        elif ch in NGINX_SPACE or ch in ";{":
            last_space = True
        else:
            continue
        words.append(_nginx_word(text[start:pos]))
        if ch in ";{":
            yield words, ch
            words = []
    if words or not last_space:
        raise InputError(f"{where}: unexpected end of file")


def _nginx_statements(text: str, where: str) -> list[NginxStatement]:
    """A file's directives, each block directive holding its own, as ngx_conf_parse nests them."""
    top: list[NginxStatement] = []
    blocks = [top]
    for words, end in _nginx_tokens(text, where):
        if end == "}":
            if len(blocks) == 1:
                raise InputError(f"{where}: unexpected '}}'")
            blocks.pop()
            continue
        statement = NginxStatement(where, words, [] if end == "{" else None)
        blocks[-1].append(statement)
        if statement.block is not None:
            blocks.append(statement.block)
    if len(blocks) > 1:
        raise InputError(f"{where}: unexpected end of file, expecting '}}'")
    return top


def _nginx_walk(statements: list[NginxStatement], include):
    """(directive, the block directive it sits directly in, or None) for every directive, depth first, with
    each include replaced in its place by the statements include(statement, depth) gives for it."""
    stack = [(iter(statements), None, 0)]
    while stack:
        items, parent, depth = stack[-1]
        statement = next(items, None)
        if statement is None:
            stack.pop()
        elif statement.words[0] == "include" and statement.block is None:
            if len(statement.words) != 2:
                raise InputError(f"{statement.file}: include takes one file name")
            stack.append((iter(include(statement, depth)), parent, depth + 1))
        else:
            yield statement, parent
            if statement.block is not None:
                stack.append((iter(statement.block), statement, depth))


def _include_path(base: Path, pattern: str) -> str:
    return pattern if pattern.startswith("/") else str(base / pattern)


def _has_glob(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")


def _nginx_config(path: Path, text: str):
    """The walk of a config file, with each include read from disk in its place, a relative name from the
    config's directory, as nginx reads them from its prefix."""
    def include(statement: NginxStatement, depth: int) -> list[NginxStatement]:
        if depth == NGINX_INCLUDE_DEPTH:
            raise InputError(f"nginx includes nest deeper than {NGINX_INCLUDE_DEPTH} levels")
        pattern = statement.words[1]
        if _has_glob(pattern) and (apart := NGINX_GLOB_APART.search(pattern)):
            raise InputError(f"nginx include {pattern} uses {apart.group()!r}, which nginx's glob(3) reads apart "
                             "from the preflight's, so it cannot resolve the files the include names; use * alone, "
                             "name each file, or give the output of `nginx -T` as kind nginx-dump")
        paths = sorted(glob.glob(_include_path(path.parent, pattern)))
        if not paths:
            raise InputError(f"nginx include {pattern} matches no file; give the config files it names, or the "
                             "output of `nginx -T` as kind nginx-dump")
        return [s for p in paths for s in _nginx_statements(read_text(Path(p), "nginx include"), p)]

    return _nginx_walk(_nginx_statements(text, str(path)), include)


def _nginx_dump(path: Path, text: str):
    """The walks of each file `nginx -T` printed, under its `# configuration file <name>:` line. An include is
    not read in place: its file has its own walk, and a named file must be in the dump."""
    heads = list(NGINX_DUMP_FILE.finditer(text))
    if not heads or text[:heads[0].start()].strip():
        raise InputError(f"{path} is not `nginx -T` output: it does not start with a `# configuration file` line")
    files = [(head.group(1), text[head.end():end])
             for head, end in zip(heads, [head.start() for head in heads[1:]] + [len(text)])]
    names = {name for name, _ in files}
    base = Path(files[0][0]).parent

    def include(statement: NginxStatement, depth: int) -> list[NginxStatement]:
        target = _include_path(base, statement.words[1])
        if not _has_glob(target) and target not in names:
            raise InputError(f"nginx include {statement.words[1]} matches no file in the dump")
        return []

    return itertools.chain.from_iterable(_nginx_walk(_nginx_statements(body, name), include) for name, body in files)


def forward_targets(target: str, upstreams: dict[str, list[str]]) -> list[tuple[str, int]]:
    if "$" in target:
        raise InputError(f"proxy target {target} is a variable; the preflight cannot tell which node it reaches")
    scheme, separator, rest = target.partition("://")
    if not separator:
        scheme, rest = "", target
    # nginx ends the host and port at '/' or '?' (ngx_parse_inet_url), and matches an upstream's name
    # case-insensitively.
    authority = re.split(r"[/?]", rest, maxsplit=1)[0]
    servers = upstreams.get(authority.lower(), [authority])
    if not servers:
        raise InputError(f"proxy target {target}: upstream {authority} has no server the preflight can read")
    if any(server.startswith("unix:") for server in servers):
        raise InputError(f"proxy target {target} is a unix socket; the preflight cannot tell which node it reaches")
    return [host_port(server, DEFAULT_PORTS.get(scheme)) for server in servers]


def nginx_routes(path: Path, text: str, dump: bool) -> list[tuple[str, int]]:
    """(host, port) of every place an nginx config forwards to, read directive by directive as nginx parses
    it: each forwarding directive, and each upstream's servers by the block they sit in. An upstream's name
    counts for every upstream block that takes it, http and stream alike."""
    forwards, upstreams = [], {}
    for statement, parent in (_nginx_dump if dump else _nginx_config)(path, text):
        name, args = statement.words[0], statement.words[1:]
        if NGINX_CODE.fullmatch(name):
            raise InputError(f"{statement.file}: {name} runs code inside nginx that can open its own connections; "
                             "the preflight reads only forwarding directives")
        if name.endswith("_pass") and name not in NGINX_FORWARDS:
            raise InputError(f"{statement.file}: {name} forwards through a module that nginx does not ship, so the "
                             "preflight cannot resolve where it connects")
        if name in NGINX_FORWARDS:
            forwards += args
        elif name == "upstream" and statement.block is not None:
            upstreams.setdefault(_upstream_name(statement), [])
        elif name == "server" and statement.block is None:
            if not args:
                raise InputError(f"{statement.file}: a server directive names no address")
            if parent is None or parent.words[0] != "upstream":
                raise InputError(f"{statement.file}: server {args[0]} sits outside any upstream block, so the "
                                 "preflight cannot tell which upstream it serves; keep each upstream's servers in "
                                 "its own block, since `nginx -T` output shows an included file apart from it")
            for parameter in args[1:]:
                if not NGINX_SERVER_PARAMETERS.fullmatch(parameter):
                    raise InputError(f"{statement.file}: server {args[0]} takes {parameter}; the preflight reads "
                                     "weight=, max_conns=, max_fails=, fail_timeout=, backup and down, and cannot "
                                     "resolve where nginx connects otherwise (service= takes the port and host from "
                                     "DNS SRV, resolve looks the name up again while nginx runs)")
            upstreams[_upstream_name(parent)].append(args[0])
    return [route for target in forwards for route in forward_targets(target, upstreams)]


def _upstream_name(statement: NginxStatement) -> str:
    if len(statement.words) != 2:
        raise InputError(f"{statement.file}: upstream takes one name")
    return statement.words[1].lower()


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
    if proxy["kind"] == "cloudflared":
        routes = cloudflared_routes(text)
    else:
        routes = nginx_routes(path, text, dump=proxy["kind"] == "nginx-dump")
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
        argv = running_argv(node)
        port_flag = _flag(argv, "--rpc-port") or str(DEFAULT_RPC_PORT)
        if not port_flag.isdigit():
            raise InputError(f"node {node['name']}: --rpc-port {port_flag} is not a port")
        # (port, external, methods) for the default listener and every experimental endpoint.
        listeners = [(int(port_flag), "--rpc-external" in argv or "--unsafe-rpc-external" in argv,
                      (_flag(argv, "--rpc-methods") or "auto").lower())]
        # sc-cli takes `--flag=value` as one endpoint, and `--flag` as every word up to the next
        # option (a word starting with '-', other than '-' itself).
        endpoints = [token.split("=", 1)[1] for token in argv if token.startswith(RPC_ENDPOINT_FLAG + "=")]
        for i, token in enumerate(argv):
            if token == RPC_ENDPOINT_FLAG:
                endpoints += itertools.takewhile(option_value, argv[i + 1:])
        for endpoint in endpoints:
            # Trimmed as the node trims each option, its key and its value.
            options = {key.strip(): value.strip()
                       for key, _, value in (opt.partition("=") for opt in endpoint.split(","))}
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


def rpc_transports(url: str) -> list[str]:
    """A public RPC URL as given, then the same address over the other transport."""
    parts = urllib.parse.urlsplit(url)
    return [parts.geturl(), parts._replace(scheme=RPC_TRANSPORTS[parts.scheme]).geturl()]


def _http_answer(url: str, call: str, method: str):
    parts = urllib.parse.urlsplit(url)
    connection = (http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection)(
        parts.hostname, parts.port, timeout=PUBLIC_RPC_TIMEOUT)
    try:
        connection.request("POST", urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, "")), call,
                           {"Content-Type": "application/json", "User-Agent": USER_AGENT})
        response = connection.getresponse()
        body = response.read(PUBLIC_RPC_LIMIT + 1)
    finally:
        connection.close()
    if response.status != 200:
        raise InputError(f"public RPC {url} answered {method} with HTTP {response.status}; the preflight cannot "
                         "resolve what it serves")
    if len(body) > PUBLIC_RPC_LIMIT:
        raise InputError(f"public RPC {url} answered {method} with over {PUBLIC_RPC_LIMIT} bytes")
    return json.loads(body)


def _ws_answer(url: str, call: str, method: str):
    """The first message over the WebSocket that answers a call."""
    with ws_connect(url, proxy=None, open_timeout=PUBLIC_RPC_TIMEOUT, close_timeout=PUBLIC_RPC_TIMEOUT,
                    max_size=PUBLIC_RPC_LIMIT, user_agent_header=USER_AGENT) as ws:
        ws.send(call)
        deadline = time.monotonic() + PUBLIC_RPC_TIMEOUT
        for _ in range(PUBLIC_RPC_MESSAGES):
            message = json.loads(ws.recv(timeout=max(deadline - time.monotonic(), 0)))
            if isinstance(message, dict) and "id" in message:
                return message
    raise InputError(f"public RPC {url} sent no answer to {method} in {PUBLIC_RPC_MESSAGES} messages")


def rpc_answer(url: str, method: str) -> dict:
    """A public endpoint's JSON-RPC 2.0 answer to `method` with no params: over HTTP POST at an http(s) URL, over
    a WebSocket at a ws(s) URL. Anything but a result or an error object answering this call is unreadable."""
    call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []})
    try:
        answer = (_ws_answer if url.startswith("ws") else _http_answer)(url, call, method)
    except (OSError, ValueError, http.client.HTTPException, WebSocketException) as e:
        raise InputError(f"public RPC {url}: {method} failed: {e}") from e
    error = answer.get("error") if isinstance(answer, dict) else None
    if not (isinstance(answer, dict) and answer.get("jsonrpc") == "2.0" and type(answer.get("id")) is int
            and answer["id"] == 1 and ("result" in answer) != ("error" in answer)
            and ("result" in answer or isinstance(error, dict) and type(error.get("code")) is int)):
        raise InputError(f"public RPC {url} did not answer {method} as JSON-RPC 2.0")
    return answer


def check_public_rpc(launch: dict) -> list[Finding]:
    """Rule 3 on what each public RPC URL serves, over HTTP and over a WebSocket: every method rpc_methods lists
    must be in the safe set, and an unsafe method that changes nothing must be refused."""
    if "public_rpc" not in launch:
        return [Finding(RPC, "public_rpc is not declared: the public RPC endpoints go unprobed; list every public "
                             "RPC URL, or [] when the launch serves none")]
    findings = []
    for url in dict.fromkeys(transport for given in launch["public_rpc"] for transport in rpc_transports(given)):
        listed = rpc_answer(url, "rpc_methods").get("result")
        methods = listed.get("methods") if isinstance(listed, dict) else None
        if not (isinstance(methods, list) and all(isinstance(method, str) for method in methods)):
            raise InputError(f"public RPC {url} did not answer rpc_methods with a list of methods; the preflight "
                             "cannot resolve which methods it serves")
        if outside := sorted(set(methods) - SAFE_RPC_METHODS):
            findings.append(Finding(RPC, f"public RPC {url} lists methods outside the safe set: {', '.join(outside)}"))
        probe = rpc_answer(url, UNSAFE_PROBE)
        if "result" in probe:
            findings.append(Finding(RPC, f"public RPC {url} answers {UNSAFE_PROBE}, which a node serves only with "
                                         "unsafe methods on"))
        elif probe["error"]["code"] != METHOD_NOT_FOUND:
            raise InputError(f"public RPC {url} answered {UNSAFE_PROBE} with error {probe['error']['code']}: the "
                             "preflight cannot resolve whether it serves unsafe methods")
    return findings


def check_supply(spec: Spec, meta: Metadata, launch: dict, cardano: CardanoView) -> list[Finding]:
    findings = []
    economics = launch.get("economics", {})
    attestors = launch.get("roles", {}).get("attestors", [])
    bond = spec.uint("OrinqReceipts", "BondRequirement", BALANCE)
    ed_raw = meta.constants.get(("Balances", "ExistentialDeposit"))
    fee_buffer = economics.get("fee_buffer")
    if not attestors:
        findings.append(Finding(SUPPLY, "roles.attestors names no account: the endowment floor "
                                        "has nothing to check"))
    if bond is None or ed_raw is None or not isinstance(fee_buffer, int):
        findings.append(Finding(SUPPLY, "cannot size attestor endowments: needs OrinqReceipts."
                                        "BondRequirement in genesis, Balances.ExistentialDeposit "
                                        "in metadata and economics.fee_buffer declared"))
    else:
        floor = bond + int.from_bytes(ed_raw, "little") + fee_buffer
        for i, entry in enumerate(attestors):
            try:
                account = role_account(entry)
            except ValueError:
                continue  # rule 1 already refuses a role key that does not decode
            balance, _ = spec.balance(account)
            if balance < floor:
                findings.append(Finding(SUPPLY, f"roles.attestors[{i}] is endowed {balance}, below "
                                                f"bond + existential deposit + fee buffer = {floor}"))
    stored = spec.uint("Balances", "TotalIssuance", BALANCE) or 0
    held = sum(sum(spec.balance(account)) for account in spec.accounts())
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
    if output is not None and output["address"] == lock["address"] and not missing:
        amount = output["value"]["assets"].get(CMATRA_UNIT, 0)
        emission = sum(int.from_bytes(meta.constants[("OrinqReceipts", name)], "little")
                       for name in EMISSION_RESERVES)
        if issuance + emission > amount:
            findings.append(Finding(SUPPLY, f"Materios can issue {issuance + emission} (genesis {issuance} "
                                            f"+ runtime emission reserves {emission}) against {amount} cMATRA "
                                            f"locked on Cardano at {lock['utxo']}: the difference is reserve "
                                            "counted both as cMATRA and as MATRA"))
    return findings


def check_genesis_lock(spec: Spec, launch: dict, cardano: CardanoView, well_known: WellKnown) -> list[Finding]:
    """The cMATRA lock backing genesis: an unspent output at the declared
    mainnet address, which pays to the declared native script, which no fewer
    than two key holders can spend, and whose inline datum is this genesis
    hash, so the lock backs this chain and no other."""
    lock, output = launch["supply"]["genesis_lock"], cardano.lock
    findings = []
    try:
        paid_to = lock_script_hash(lock["address"])
    except ValueError as e:
        findings.append(Finding(SUPPLY, f"the genesis lock address {lock['address']} {e}"))
        paid_to = None
    if paid_to is not None:
        raw = hex_bytes(lock["native_script"], "supply.genesis_lock.native_script")
        declared = hashlib.blake2b(NATIVE_SCRIPT_TAG + raw, digest_size=28).digest()
        if declared != paid_to:
            findings.append(Finding(SUPPLY, f"the genesis lock address {lock['address']} pays to script "
                                            f"{paid_to.hex()}, not the declared native script {declared.hex()}; "
                                            "a lock the preflight cannot read as a native script is refused"))
        else:
            anyone = {hashlib.blake2b(k.needle, digest_size=28).digest()
                      for k in well_known.keys if k.scheme == "ed25519"}
            holders = native_script_holders(native_script(raw), anyone)
            if holders is not None and holders < 2:
                findings.append(Finding(SUPPLY, f"the genesis lock's native script can be spent by {holders} key "
                                                f"holder{'' if holders == 1 else 's'} (a well-known key counts as "
                                                "anyone's): fewer than two can move the backing"))
    if output is None:
        return findings + [Finding(SUPPLY, f"the genesis lock {lock['utxo']} is not an unspent output the Kupo "
                                           "index holds: nothing backs genesis issuance")]
    if output["address"] != lock["address"]:
        findings.append(Finding(SUPPLY, f"the genesis lock {lock['utxo']} sits at {output['address']}, "
                                        f"not the declared {lock['address']}"))
    genesis = spec_genesis_hash(spec)
    if cardano.lock_datum is None:
        findings.append(Finding(SUPPLY, f"the genesis lock {lock['utxo']} carries no inline datum: nothing binds "
                                        "it to this genesis, so one lock could back two chains"))
    elif _plutus_bytes(cardano.lock_datum) != genesis:
        findings.append(Finding(SUPPLY, f"the genesis lock {lock['utxo']} carries a datum that is not this genesis "
                                        f"hash 0x{genesis.hex()}: it was not made for this chain"))
    return findings


def _plutus_bytes(datum: bytes) -> bytes | None:
    try:
        value = cbor2.loads(datum)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, bytes) else None


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


def spec_genesis_hash(spec: Spec) -> bytes:
    return genesis_hash(spec.storage, runtime_state_version(decompressed_code(spec.code)))


def launch_hashes(spec: Spec, launch: dict) -> dict[str, bytes]:
    return {
        "genesis_hash": spec_genesis_hash(spec),
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


def check_checkpoint(spec: Spec, launch: dict, signed: dict, launch_keys: list[bytes]) -> list[Finding]:
    findings = []
    if spec.doc.get("codeSubstitutes"):
        findings.append(Finding(CHECKPOINT, "chain spec carries codeSubstitutes"))
    if not isinstance(signed, dict):
        raise InputError("signed manifest must be a JSON object")
    claimed = {k: hex_bytes(signed.get(k), f"signed manifest {k}") for k in (*HASH_FIELDS, "signature")}
    if signed.get("domain") != DOMAIN.decode():
        findings.append(Finding(CHECKPOINT, "signed manifest has the wrong domain"))
    for name, actual in launch_hashes(spec, launch).items():
        if claimed[name] != actual:
            findings.append(Finding(CHECKPOINT, f"{name} is 0x{actual.hex()}, signed manifest "
                                                f"says 0x{claimed[name].hex()}"))
    if not any(signature_verifies(key, canonical_payload(claimed), claimed["signature"]) for key in launch_keys):
        findings.append(Finding(CHECKPOINT, "signed manifest signature does not verify "
                                            "under any launch key checked"))
    return findings


def check_guardian(spec: Spec, meta: Metadata, launch: dict) -> list[Finding]:
    """The Root timelock's guardian, who can veto the Root calls the sudo key
    queues and co-sign them early. The runtime refuses a genesis whose guardian
    is the sudo key, or that has none unless the sudo key is a dev key; on
    mainnet genesis must name the multisig roles.guardian declares: one of keys,
    whose veto the runtime takes first, that needs two keyholders and that
    pallet_multisig signs through. No account in it, down to each member, may
    be one the sudo key's holders hold."""
    findings = []
    stored, sudo_key = spec.value("RootTimelock", "Guardian"), spec.value("Sudo", "Key")
    if stored is None:
        findings.append(Finding(TIMELOCK, "genesis sets no RootTimelock.Guardian: nothing apart from the sudo key "
                                          "can veto the Root calls it queues"))
    elif stored == sudo_key:
        findings.append(Finding(TIMELOCK, "RootTimelock.Guardian is Sudo.Key: the sudo key would veto and co-sign "
                                          "its own Root calls"))
    roles = launch.get("roles", {})
    entries = roles.get("guardian", [])
    if len(entries) != 1:
        return findings + [Finding(TIMELOCK, "roles.guardian must declare the one guardian genesis names: who can "
                                             "veto Root is unchecked")]
    findings += [Finding(TIMELOCK, fault) for fault in multisig_faults(
        entries[0], "roles.guardian[0]", "the guardian", "can veto Root's queued calls or co-sign them early", meta,
        spec.ss58_prefix)]
    if isinstance(entries[0], dict):
        findings += [Finding(TIMELOCK, f"roles.guardian[0].members[{i}] is a multisig: the runtime takes the "
                                       "guardian's veto ahead of fee-paying calls only when a member key signs it "
                                       "through one as_multi, so a veto through a nested multisig can be crowded out "
                                       "of blocks")
                     for i, member in enumerate(entries[0]["members"]) if isinstance(member, dict)]
    try:
        guardian = list(role_accounts(entries[0], "roles.guardian[0]"))
    except ValueError:
        return findings  # rule 1 already refuses a role key that does not decode
    sudo = {} if sudo_key is None else {sudo_key: "Sudo.Key"}
    for i, entry in enumerate(roles.get("sudo", [])):
        try:
            sudo.update((account, where) for where, account in role_accounts(entry, f"roles.sudo[{i}]"))
        except ValueError:
            continue  # rule 1 already refuses a role key that does not decode
    if stored is not None and stored != guardian[0][1]:
        findings.append(Finding(TIMELOCK, f"RootTimelock.Guardian {ss58(stored, spec.ss58_prefix)} is not the "
                                          "account roles.guardian declares: who can veto Root is unchecked"))
    for where, account in guardian:
        if account in sudo:
            findings.append(Finding(TIMELOCK, f"{where} {ss58(account, spec.ss58_prefix)} is also {sudo[account]}: "
                                              "the guardian must be held by keyholders apart from the sudo key's, or "
                                              "whoever takes Root also holds its veto"))
    return findings


def block_counts(raw: bytes, width: int) -> tuple[int, ...] | None:
    """A DelayTable's three delays, or None unless it is three block counts of this width."""
    return scale_uints(raw, (width,) * 3) if width else None


def check_delays(spec: Spec, meta: Metadata) -> list[Finding]:
    """How long the Root timelock holds each class of Root call, in blocks: no
    shorter than the runtime's mainnet delays, DefaultDelays, and within the
    runtime's own bounds, non-zero, recovery <= standard <= long, and long at
    most MaxDelay. Both constants are read from the runtime metadata."""
    ceiling = meta.constants.get(("RootTimelock", "MaxDelay"), b"")
    floor = block_counts(meta.constants.get(("RootTimelock", "DefaultDelays"), b""), len(ceiling))
    if floor is None:
        return [Finding(TIMELOCK, "the runtime metadata declares no RootTimelock.DefaultDelays and "
                                  "RootTimelock.MaxDelay the preflight can read: how long mainnet must hold Root's "
                                  "calls is unknown here")]
    raw = spec.value("RootTimelock", "Delays")
    if raw is None:
        return [Finding(TIMELOCK, "genesis sets no RootTimelock.Delays, which every genesis the runtime builds sets: "
                                  "how long Root's calls wait is unchecked")]
    held = block_counts(raw, len(ceiling))
    if held is None:
        return [Finding(TIMELOCK, f"RootTimelock.Delays is {len(raw)} bytes, not three {len(ceiling)}-byte block "
                                  "counts")]
    findings = [Finding(TIMELOCK, f"RootTimelock.Delays holds {name} calls {blocks} blocks, below the {least} the "
                                  "runtime sets for mainnet")
                for name, blocks, least in zip(DELAY_CLASSES, held, floor) if blocks < least]
    recovery, standard, long = held
    maximum = int.from_bytes(ceiling, "little")
    if long > maximum:
        findings.append(Finding(TIMELOCK, f"RootTimelock.Delays holds long calls {long} blocks, above the runtime's "
                                          f"MaxDelay {maximum}: a guardian change, or a cut to the long delay itself, "
                                          "would wait longer than the runtime lets any delay be"))
    if not 0 < recovery <= standard <= long:
        findings.append(Finding(TIMELOCK, f"RootTimelock.Delays (recovery {recovery}, standard {standard}, long {long} "
                                          "blocks) breaks the order 0 < recovery <= standard <= long that the "
                                          "runtime's genesis builder asserts"))
    return findings


def option_value(word: str) -> bool:
    """Whether clap takes a word after an option as its value, not as the next option: `-` alone, or no leading
    `-` (no option of the node's allows a hyphen value)."""
    return word == "-" or not word.startswith("-")


def attested_options(argv: list[str], where: str) -> list[str]:
    """The words of a node argv that export-blocks is given, as given: its chain, logging, pruning and database
    options, each with its values, read as the node reads them by NODE_OPTIONS. An option the table does not list
    refuses, since it could change the genesis the node builds, as does a word no option takes, which the node
    refuses or runs as a subcommand instead of a node. No value is echoed: an argv can hold a keystore password."""
    words, chains, i = [], 0, 1
    while i < len(argv):
        word = argv[i]
        if word.startswith("--"):
            option, given, _ = word.partition("=")
        elif word.startswith("-") and len(word) > 1:
            option, given = word[:2], word[2:]
        else:
            raise InputError(f"{where}: word {i} of its node argv is not an option; the node takes only options, and "
                             "would run a subcommand instead of a node")
        if option not in NODE_OPTIONS:
            raise InputError(f"{where}: gives {option}, an option the preflight does not know, so it cannot tell "
                             "whether it changes the genesis the node builds")
        values, passed = NODE_OPTIONS[option]
        if given and not values:
            raise InputError(f"{where}: {option} takes no value")
        taken = 0
        if values and not given:
            following = len(list(itertools.takewhile(option_value, argv[i + 1:])))
            if not following:
                raise InputError(f"{where}: {option} takes a value its node argv does not give")
            taken = following if values == MANY else 1
        if passed:
            words += argv[i:i + 1 + taken]
        chains += option == "--chain"
        i += 1 + taken
    if chains > 1:
        raise InputError(f"{where}: gives --chain {chains} times, which the node refuses")
    if chains and "--dev" in words:
        raise InputError(f"{where}: gives --dev with --chain, which the node refuses")
    return words


def exported_genesis(raw: bytes, where: str) -> bytes:
    """The hash of the genesis block export-blocks --binary writes for --from 0 --to 0: blake2-256 of its header,
    as the node encodes it. The count before it is not read: sc-service counts the block after --to 0 too."""
    header = raw[8:8 + GENESIS_HEADER]
    if (len(raw) != GENESIS_EXPORT or header[:32] != bytes(32) or header[32] or header[-1]
            or raw[8 + GENESIS_HEADER:] != b"\0\0"):
        raise InputError(f"{where}: its node's export of block 0 is not one genesis block")
    return blake2_256(header)


def node_genesis(exe: Path, options: list[str], cwd: Path, scratch: Path, where: str) -> tuple[bytes | None, str]:
    """The genesis hash the node builds from these options, as export-blocks writes block 0, or None when it builds
    none, and what it printed. It runs in an empty working directory, on a fresh base path, with NODE_ENV alone for
    its environment: no network option, and no follower that connects anywhere."""
    run = Path(tempfile.mkdtemp(dir=scratch))
    out = run / "block-0"
    env = dict(NODE_ENV, MAIN_CHAIN_FOLLOWER_MOCK_REGISTRATIONS_FILE=str(scratch / "registrations.json"))
    command = [str(exe), "export-blocks", *options, "--base-path", str(run / "base"), "--from", "0", "--to", "0",
               "--binary", str(out)]
    try:
        done = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=NODE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, f"it ran past {NODE_TIMEOUT} seconds"
    except OSError as e:
        raise InputError(f"{where}: cannot run its node binary on this host: {e.strerror}") from e
    said = (done.stdout + done.stderr).decode(errors="replace")
    if done.returncode or not out.exists():
        return None, said or f"exit status {done.returncode}"
    return exported_genesis(out.read_bytes(), where), said


def stop_reason(output: str) -> str:
    """The line of a node's output that says why it stopped: its last error or panic line, else its last line."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    telling = [line for line in lines if "Error" in line or "panicked" in line]
    return (telling or lines or [output])[-1][:300]


def pinned_binary(node: dict, scratch: Path, where: str) -> tuple[str, Path]:
    """The sha256 of an authority's captured node binary, and a private copy of it to run, hashed as it is copied
    so the binary that runs is the one hashed."""
    path = node.get("exe")
    if path is None:
        raise InputError(f"{where}: give a copy of its running node process's /proc/<pid>/exe as exe; the preflight "
                         "runs that binary to attest the genesis it builds")
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as source, tempfile.NamedTemporaryFile(dir=scratch, delete=False) as private:
            for chunk in iter(lambda: source.read(1 << 20), b""):
                digest.update(chunk)
                private.write(chunk)
    except OSError as e:
        raise InputError(f"{where}: cannot read exe {path}: {e.strerror}") from e
    pinned = scratch / f"exe-{digest.hexdigest()}"
    Path(private.name).replace(pinned)
    pinned.chmod(0o700)
    return "0x" + digest.hexdigest(), pinned


def check_node_genesis(spec: Spec, launch: dict) -> list[Finding]:
    """Each authority's own node binary, pinned by sha256, must build the genesis the preflight computes, which the
    signed manifest and the lock's datum bind. It runs offline on export-blocks, which builds genesis as the node
    does at startup, with the options its node process runs with: as launched, in an empty working directory, where
    a --chain that names no file here can only be a chain built into the node, and on the checked spec, with its
    --chain value swapped for that file. The file each authority's --chain names, as captured, must be the checked
    spec, byte for byte. Wherever the node and the preflight read a spec apart, the hashes differ."""
    authorities = [node for node in launch.get("nodes", []) if node["authority"]]
    if not authorities:
        return []
    if spec.doc.get("telemetryEndpoints"):
        raise InputError("the chain spec names telemetryEndpoints, which the node connects to while it builds "
                         "genesis; the attestation runs offline, so give none (a node can take --telemetry-url)")
    genesis, spec_sha = spec_genesis_hash(spec), hashlib.sha256(spec.source).hexdigest()
    findings, runs = [], {}
    with tempfile.TemporaryDirectory(prefix="launch-preflight-node-") as tmp:
        scratch = Path(tmp)
        checked = scratch / "chain-spec.json"
        checked.write_bytes(spec.source)
        (scratch / "registrations.json").write_text("[]")

        def built(exe: Path, pin: str, options: list[str], cwd: Path, where: str) -> tuple[bytes | None, str]:
            """What the node builds from these options, run once for every authority whose binary and options are
            the same: every run's working directory is new and empty."""
            if (pin, *options) not in runs:
                runs[(pin, *options)] = node_genesis(exe, options, cwd, scratch, where)
            return runs[(pin, *options)]

        for node in authorities:
            where = f"authority {node['name']}"
            options = attested_options(running_argv(node), where)
            sha, exe = pinned_binary(node, scratch, where)
            if node.get("chain_spec") is None:
                raise InputError(f"{where}: give a copy of the file its node's --chain names, taken on its machine, "
                                 "as chain_spec")
            try:
                chain_sha = hashlib.sha256(Path(node["chain_spec"]).read_bytes()).hexdigest()
            except OSError as e:
                raise InputError(f"{where}: cannot read chain_spec {node['chain_spec']}: {e.strerror}") from e
            if sha != node["exe_sha256"]:
                findings.append(Finding(NODE, f"{where} runs a node binary whose sha256 is {sha}, not its pinned "
                                              f"exe_sha256 {node['exe_sha256']}: only the pinned binary is run to "
                                              "attest its genesis"))
                continue
            if chain_sha != spec_sha:
                findings.append(Finding(NODE, f"{where}: its --chain file, as captured, is not the checked chain "
                                              f"spec (sha256 0x{chain_sha}, the spec's 0x{spec_sha}): its node loads "
                                              "another chain spec"))
                continue
            chain = next((i for i, word in enumerate(options) if word.partition("=")[0] == "--chain"), None)
            if chain is None:
                findings.append(Finding(NODE, f"{where} gives no --chain: its node loads the chain built into it as "
                                              f"{'dev' if '--dev' in options else 'local'}, not the checked chain "
                                              "spec"))
                continue
            split = options[chain] == "--chain"
            value = options[chain + 1] if split else options[chain].partition("=")[2]
            cwd = Path(tempfile.mkdtemp(dir=scratch))
            here = (cwd / value).is_file()
            if here and (cwd / value).read_bytes() != spec.source:
                raise InputError(f"{where}: --chain {value!r} names a file on this host that is not the checked chain "
                                 "spec, and the node would load it here; run check where that path holds the checked "
                                 "spec, or nothing")
            launched, said = built(exe, sha, options, cwd, where)
            if not here and launched is not None:
                findings.append(Finding(NODE, f"{where}: --chain {value!r} builds genesis 0x{launched.hex()} with no "
                                              "file of that name here: the node takes it as a chain built into it, "
                                              "not the checked chain spec"))
                continue
            if not here and MISSING_SPEC_FILE.format(value) not in said:
                raise InputError(f"{where}: its node builds no genesis from --chain {value!r} here, and does not "
                                 "report it as a missing file: the preflight cannot tell whether the node reads it as "
                                 f"a file or as a chain built into it ({stop_reason(said)})")
            if here and launched is None:
                raise InputError(f"{where}: its node builds no genesis from --chain {value!r} on this host, where it "
                                 f"is the checked chain spec: {stop_reason(said)}")
            swapped = ["--chain", str(checked)] if split else [f"--chain={checked}"]
            attested, said = built(exe, sha, options[:chain] + swapped + options[chain + 1 + split:],
                                   Path(tempfile.mkdtemp(dir=scratch)), where)
            if attested is None:
                raise InputError(f"{where}: its node builds no genesis from the checked chain spec: "
                                 f"{stop_reason(said)}")
            wrong = next((h for h in (attested, launched) if h not in (None, genesis)), None)
            if wrong is not None:
                findings.append(Finding(NODE, f"{where}: its node builds genesis 0x{wrong.hex()} from the checked "
                                              f"chain spec, and the preflight computes 0x{genesis.hex()}: the signed "
                                              "genesis hash and the lock's datum bind the preflight's, not the chain "
                                              "this authority starts"))
    return findings


def signature_verifies(key: bytes, payload: bytes, signature: bytes) -> bool:
    try:
        signing.VerifyKey(key).verify(payload, signature)
    except (BadSignatureError, ValueError, TypeError):
        return False
    return True


def pinned_launch_keys() -> list[bytes]:
    try:
        entries = json.loads(LAUNCH_KEYS.read_text(), object_pairs_hook=unique_keys)["keys"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise InputError(f"cannot read the pinned keys in launch_keys.json: {e}") from e
    shape = "launch_keys.json must list 32-byte ed25519 public keys in 0x-hex"
    if not isinstance(entries, list):
        raise InputError(shape)
    keys = [hex_bytes(entry, f"launch_keys.json keys[{i}]") for i, entry in enumerate(entries)]
    if any(len(key) != 32 for key in keys):
        raise InputError(shape)
    return keys


def launch_keys(given: str | None) -> tuple[list[bytes], list[Finding]]:
    """The keys a signed manifest is checked against: the pinned ones, or the
    one given on the command line, which refuses unless it is pinned."""
    pinned = pinned_launch_keys()
    if given is None:
        return pinned, [] if pinned else [Finding(CHECKPOINT, "no launch key is pinned in launch_keys.json: "
                                                              "nothing authorizes this launch")]
    key = parse_launch_key(given)
    if key in pinned:
        return [key], []
    return [key], [Finding(CHECKPOINT, f"launch key 0x{key.hex()} is not pinned in launch_keys.json: a signature "
                                       "under it proves only that the artifacts match the key this run was handed")]


def parse_launch_key(text: str) -> bytes:
    key = hex_bytes(text, "--manifest-key")
    if len(key) != 32:
        raise InputError("--manifest-key must be a 32-byte ed25519 public key")
    return key


def validate_key_text(text: str, where: str) -> None:
    """A key given in hex is spelled as hex_bytes reads it; any other string is
    read as SS58, and rule 1 refuses one that does not decode."""
    if text.startswith(("0x", "0X")):
        hex_bytes(text, where)


def validate_role_entry(entry, where: str) -> None:
    if isinstance(entry, str):
        validate_key_text(entry, where)
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
    if not (isinstance(argv, list) and all(isinstance(t, str) for t in argv)):
        raise InputError(f"{where} argv must be a list of strings: the words the process receives, as "
                         "/proc/<pid>/cmdline lists them. One command line string is not read: systemd rewrites "
                         "an ExecStart line (\\xNN escapes, % specifiers, an '@' prefix, a ';' between commands) "
                         "and a shell or a container runtime splits one by its own rules")
    env = node.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(v, str) for v in env.values()):
        raise InputError(f"{where} env must map names to strings")
    for field in ("cmdline", "exe", "chain_spec", "exe_sha256"):
        if field in node and not node["authority"]:
            raise InputError(f"{where} {field} is read for an authority only")
    if not isinstance(node.get("cmdline", ""), str):
        raise InputError(f"{where} cmdline must be the path of a /proc/<pid>/cmdline capture")
    for field in ("exe", "chain_spec"):
        if not isinstance(node.get(field, ""), str):
            raise InputError(f"{where} {field} must be the path of a capture")
    launch_commands(node)
    if node["authority"]:
        text = node["aura"] if isinstance(node.get("aura"), str) else ""
        validate_key_text(text, f"{where} aura")
        try:
            aura = decode_public_key(text)
        except ValueError:
            aura = b""
        if len(aura) != 32:
            raise InputError(f"{where} is an authority and must declare its aura public key (SS58 or 0x-hex)")
        pin = node.get("exe_sha256")
        if not isinstance(pin, str) or len(hex_bytes(pin, f"{where} exe_sha256")) != 32:
            raise InputError(f"{where} is an authority and must pin the sha256 of its node binary as exe_sha256")
        attested_options(node_process(node), f"authority {node['name']}")


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
    economics = launch.get("economics", {})
    if not isinstance(economics, dict):
        raise InputError("economics must be an object")
    for field in sorted(set(economics) - ECONOMICS_FIELDS):
        raise InputError(f"unknown economics field {field}")
    for field, value in sorted(economics.items()):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise InputError(f"economics.{field} must be a non-negative integer")
    supply = launch.get("supply", {})
    if not isinstance(supply, dict):
        raise InputError("supply must be an object")
    for field in sorted(set(supply) - {"genesis_lock"}):
        raise InputError(f"unknown supply field {field}: the backing is read from Cardano")
    lock = supply.get("genesis_lock")
    if isinstance(lock, dict):
        for field in sorted(set(lock) - GENESIS_LOCK_FIELDS):
            raise InputError(f"unknown supply.genesis_lock field {field}")
    if not isinstance(lock, dict) or not all(isinstance(lock.get(k), str) for k in GENESIS_LOCK_FIELDS):
        raise InputError("supply.genesis_lock is required: the utxo, address and native_script of the cMATRA "
                         "lock that backs genesis")
    if not UTXO.fullmatch(lock["utxo"]):
        raise InputError("supply.genesis_lock.utxo must be <64 hex>#<index>")
    hex_bytes(lock["native_script"], "supply.genesis_lock.native_script")
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
            raise InputError(f"rpc_proxies[{i}] kind must be nginx, nginx-dump or cloudflared")
        if proxy["node"] not in node_names:
            raise InputError(f"rpc_proxies[{i}] runs on {proxy['node']}, which is not a declared node: "
                             "declare the machine it runs on in nodes")
        others = proxy.get("other_targets", [])
        if not (isinstance(others, list) and all(isinstance(t, str) and HOST_PORT.fullmatch(t) and ":" in t
                                                 for t in others)):
            raise InputError(f"rpc_proxies[{i}] other_targets must be host:port strings")
    public = launch.get("public_rpc", [])
    if not isinstance(public, list):
        raise InputError("public_rpc must be a list of URLs")
    for i, url in enumerate(public):
        parts = urllib.parse.urlsplit(url) if isinstance(url, str) else None
        try:
            readable = parts is not None and parts.scheme in RPC_TRANSPORTS and bool(parts.hostname) \
                and parts.port != 0
        except ValueError:
            readable = False
        if not readable:
            raise InputError(f"public_rpc[{i}] must be an http, https, ws or wss URL")
        if parts.username is not None or parts.password is not None or parts.fragment:
            raise InputError(f"public_rpc[{i}] must name no user, password or fragment")


def run_checks(spec: Spec, meta: Metadata, launch: dict, signed: dict, manifest_key: str | None,
               cardano: CardanoView, extra_well_known: list[Path] = ()) -> list[Finding]:
    validate_launch(launch)
    keys, key_findings = launch_keys(manifest_key)
    well_known = load_well_known(extra_well_known)
    return (check_chain_identity(spec)
            + check_dev_keys(spec, meta, launch, cardano, keys, well_known)
            + check_rewards(spec, meta, launch)
            + check_rpc(launch, authorities(spec, cardano))
            + check_public_rpc(launch)
            + check_supply(spec, meta, launch, cardano)
            + check_genesis_lock(spec, launch, cardano, well_known)
            + check_genesis_storage(spec, meta)
            + check_pallets(meta)
            + key_findings
            + check_checkpoint(spec, launch, signed, keys)
            + check_code_overrides(launch)
            + check_observation(spec)
            + check_guardian(spec, meta, launch)
            + check_delays(spec, meta)
            + check_node_genesis(spec, launch))


def unique_keys(pairs: list[tuple[str, object]]) -> dict:
    """A JSON object that names each key once. serde keeps the last of a key a
    map repeats and refuses a field given twice, and a JSON escape makes two
    keys that read apart in the file one key, so a repeated key is not read."""
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"an object holds the key {key[:80]!r} twice")
        seen.add(key)
    return dict(pairs)


def read_file(path: str, what: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as e:
        raise InputError(f"cannot read {what} {path}: {e}") from e


def parse_json(raw: bytes, path: str, what: str):
    """JSON in UTF-8, the one encoding serde_json reads, with each key once."""
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys)
    except (ValueError, RecursionError) as e:
        raise InputError(f"cannot read {what} {path}: {e}") from e


def read_json(path: str, what: str):
    return parse_json(read_file(path, what), path, what)


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
    where = f"cannot load the launch signing key from {args.key}"
    try:
        key = signing.SigningKey(hex_bytes(Path(args.key).read_text().removesuffix("\n"), f"{where}: its seed"))
    except (OSError, ValueError) as e:
        raise InputError(f"{where}: {type(e).__name__}") from e
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
    check.add_argument("--manifest-key", help="check against this ed25519 launch key (0x-hex) instead of "
                                              "the ones launch_keys.json pins; refuses unless it is pinned")
    check.add_argument("--kupo", required=True, help="Kupo on Cardano mainnet, indexing the genesis lock "
                                                     "and the permissioned candidates token")
    check.add_argument("--subwasm", default="subwasm")
    check.add_argument("--extra-well-known", action="append", default=[], metavar="TABLE",
                       help="JSON key table of exposed keys kept out of the public table; repeatable")
    check.set_defaults(func=cmd_check)
    sign = sub.add_parser("sign", help="sign the launch hashes of a raw chain spec and a launch manifest")
    sign.add_argument("--spec", required=True)
    sign.add_argument("--launch", required=True, help="launch manifest JSON")
    sign.add_argument("--key", required=True, help="file holding the 32-byte ed25519 seed as 0x-hex")
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
