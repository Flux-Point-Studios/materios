//! Chain specification for Materios mainnet, built from the launch manifest
//! that the launch preflight (`tools/launch-preflight`) checks the launch
//! against: `--chain mainnet:<launch manifest>`.
//!
//! Mainnet starts with a fixed MATRA issuance of under one MATRA. It is dust:
//! enough for each of the launch's role accounts to exist, pay the multisig
//! and recovery deposits its role takes, and generate the MOTRA its calls
//! cost. Nothing is minted after genesis and no signed call moves MATRA.

use crate::chain_spec::{
    get_from_seed, motra_genesis, properties, Authority, ChainSpec, MOTRA_KEPT_PER_BLOCK,
    MOTRA_LENGTH_FEE_PER_BYTE, MOTRA_MIN_FEE,
};
use frame_support::dispatch::DispatchClass;
use materios_runtime::{
    input_sanity::MAX_COMMITTEE_SIZE, opaque::SessionKeys, AccountId, Balance, CrossChainPublic,
    DepositBase, DepositFactor, ExistentialDeposit, Multisig, OracleMaxAttestors,
    OracleMinAttestorThreshold, RecoveryConfigDepositBase, RecoveryDeposit,
    RecoveryFriendDepositFactor, RootTimelockDefaultDelays, RuntimeBlockLength, CARDANO_MAINNET,
    DAYS, MATRA, MAX_RECOVERY_FRIENDS, MAX_SIGNATORIES, MAX_VALIDATORS, WASM_BINARY,
};
use sc_service::ChainType;
use serde_json::Value as Json;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{crypto::Ss58Codec, ecdsa, ed25519, sr25519};
use std::collections::{BTreeMap, BTreeSet};

mod committee_candidate;

/// What `--chain` starts with to build mainnet from the launch manifest whose
/// path follows.
pub const CHAIN_PREFIX: &str = "mainnet:";

/// Mainnet's session: 600 six-second slots, an hour, of which 120 make a
/// Cardano epoch. The era hook's weight needs at least 249, and under 600 the
/// sudo key's exempt `note_stalled` delay falls below the 30 blocks the
/// recovery tooling uses.
pub const MAINNET_SLOTS_PER_EPOCH: u32 = 600;

/// The MOTRA base units one MATRA generates each block. An account's MOTRA
/// settles at its generation over the share each block decays, so a hundredth
/// of a MATRA settles at 10^12 MOTRA base units, some 800 fees of a
/// 250-byte call, and generates 1.44 * 10^12 a day.
pub const MAINNET_GENERATION_PER_MATRA_PER_BLOCK: u128 = 10_000_000_000;

/// The fewest authorities a mainnet genesis seats: GRANDPA finalizes with one
/// of four down, and with none of three.
pub const MIN_AUTHORITIES: usize = 4;

/// The Cardano follower settings every mainnet authority runs with, as the
/// launch preflight holds them: Cardano mainnet's Shelley-era layout.
const CARDANO_MAINNET_FOLLOWER: [(&str, &str); 7] = [
    ("MC__FIRST_EPOCH_TIMESTAMP_MILLIS", "1596059091000"),
    ("MC__EPOCH_DURATION_MILLIS", "432000000"),
    ("MC__FIRST_EPOCH_NUMBER", "208"),
    ("MC__FIRST_SLOT_NUMBER", "4492800"),
    ("MC__SLOT_DURATION_MILLIS", "1000"),
    ("CARDANO_SECURITY_PARAMETER", "2160"),
    ("CARDANO_ACTIVE_SLOTS_COEFF", "0.05"),
];

/// The fields a launch manifest holds: the preflight's, and those genesis
/// needs that the preflight does not read.
const LAUNCH_FIELDS: &[&str] = &[
    "roles",
    "economics",
    "supply",
    "slots_per_epoch",
    "cardano_follower",
    "settlement",
    "nodes",
    "rpc_proxies",
    "public_rpc",
    "dust",
    "attestation_threshold",
    "partner_chain",
];

/// The fields of each object of a fixed shape the manifest holds, as the
/// launch preflight and this builder read them.
const OBJECT_FIELDS: [(&str, &[&str]); 4] = [
    (
        "economics",
        &[
            "attestation_reward_per_signer",
            "era_cap_base",
            "era_cap_baseline_attestor_count",
            "validator_reward_per_era",
            "treasury_emission_share_perbill",
            "fee_buffer",
        ],
    ),
    (
        "partner_chain",
        &[
            "genesis_utxo",
            "committee_candidate_address",
            "d_parameter_policy_id",
            "permissioned_candidates_policy_id",
        ],
    ),
    ("settlement", &["aegis_policy_v1_script_hash"]),
    ("supply", &["genesis_lock"]),
];

const GENESIS_LOCK_FIELDS: &[&str] = &["utxo", "address", "native_script"];

/// The fields of each entry of a list of objects the manifest holds.
const ITEM_FIELDS: [(&str, &[&str]); 2] = [
    (
        "nodes",
        &[
            "name",
            "host",
            "authority",
            "addresses",
            "argv",
            "env",
            "exe_sha256",
            "aura",
            "grandpa",
            "cross_chain",
            "cmdline",
            "exe",
            "chain_spec",
            "served_genesis",
            "served_chain",
            "served_chain_type",
            "served_properties",
            "process_stat",
            "system_stat",
            "chain_spec_stat",
        ],
    ),
    (
        "rpc_proxies",
        &["name", "node", "kind", "config", "other_targets"],
    ),
];

/// The roles a mainnet genesis gives a meaning.
const ROLES: [&str; 11] = [
    "sudo",
    "guardian",
    "endowed",
    "anchor_signer",
    "attestors",
    "oracle",
    "enactor",
    "gateway_sponsor",
    "recovery_friends",
    "recovery_rescuers",
    DUST_POOL,
];

/// The highest output index partner-chains' `UtxoIndex` reads: it parses a
/// genesis UTXO's index as a `u16` that must also be an `i16`.
const MAX_GENESIS_UTXO_INDEX: u16 = i16::MAX as u16;

/// Cardano mainnet's enterprise script address header: address type 7, a
/// script hash and no stake part, on network 1.
const MAINNET_SCRIPT_ADDRESS: u8 = 0x71;

/// The role whose accounts hold dust for signers admitted after genesis. No
/// signed call moves MATRA and none may be minted, so Root's force transfer
/// out of this dust is the one way a later signer gets the provider it needs.
pub const DUST_POOL: &str = "dust_pool";

/// What an account signs, which its dust has to generate the MOTRA for: the
/// calls a day it sustains, the bytes of one, and whether it also carries a
/// call that holds a whole runtime, as scheduling or enacting an upgrade does.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Load {
    pub calls_per_day: u128,
    pub call_bytes: u128,
    pub carries_runtime: bool,
}

/// A sudo keyholder: a multisig call an hour, and the upgrade it schedules.
pub const SUDO_MEMBER: Load = Load {
    calls_per_day: 24,
    call_bytes: 512,
    carries_runtime: true,
};

/// A guardian keyholder: a veto of every task the timelock can hold, which is
/// `RootTimelock::MaxPendingTasks`, each day.
pub const GUARDIAN_MEMBER: Load = Load {
    calls_per_day: 64,
    call_bytes: 384,
    carries_runtime: false,
};

/// The load of each entry of a role, by the role's name in the manifest.
/// `enactor` enacts every task the timelock can hold each day, an upgrade
/// among them. `anchor_signer` writes 1,000 anchor records a day and
/// `gateway_sponsor` submits 2,000 receipts. `oracle` feeds a price every
/// third block, twenty times as often as the oracle's staleness bound asks.
/// `attestors` attest without fee and sign 100 other calls. A
/// `recovery_friends` entry vouches and a `recovery_rescuers` entry runs a
/// recovery.
pub const ROLE_LOADS: [(&str, Load); 7] = [
    ("anchor_signer", load(1_000, 512)),
    ("attestors", load(100, 256)),
    (
        "enactor",
        Load {
            calls_per_day: 64,
            call_bytes: 512,
            carries_runtime: true,
        },
    ),
    ("gateway_sponsor", load(2_000, 512)),
    ("oracle", load(4_800, 512)),
    ("recovery_friends", load(8, 256)),
    ("recovery_rescuers", load(24, 512)),
];

const fn load(calls_per_day: u128, call_bytes: u128) -> Load {
    Load {
        calls_per_day,
        call_bytes,
        carries_runtime: false,
    }
}

/// The MOTRA fee of a call of `bytes` bytes while blocks stay under their
/// target fullness, where the congestion price is zero.
pub fn fee(bytes: u128) -> u128 {
    MOTRA_MIN_FEE + MOTRA_LENGTH_FEE_PER_BYTE * bytes
}

/// The MOTRA `free` MATRA base units generate each block.
pub fn generated_per_block(free: Balance) -> u128 {
    free * MAINNET_GENERATION_PER_MATRA_PER_BLOCK / MATRA
}

/// The MOTRA balance `free` MATRA base units settle at: each block's
/// generation over the share a block decays.
pub fn settled_motra(free: Balance) -> u128 {
    generated_per_block(free) * 1_000_000_000 / u128::from(1_000_000_000 - MOTRA_KEPT_PER_BLOCK)
}

/// The bytes of the longest call that carries a runtime: the most a block
/// takes, so whatever runtime a later upgrade brings, its call is no longer.
pub fn upgrade_bytes() -> u128 {
    (*RuntimeBlockLength::get()
        .max
        .get(DispatchClass::Operational))
    .into()
}

/// The free MATRA base units that carry `loads` together: enough to generate
/// each day what their calls cost, and, when one carries a runtime, to settle
/// at twice the fee of a call of `upgrade_bytes` on top, so that call is paid
/// for again half a day after it was made.
pub fn working_dust(loads: &[Load]) -> Balance {
    let daily: u128 = loads
        .iter()
        .map(|load| load.calls_per_day * fee(load.call_bytes))
        .sum();
    let upgrade = if loads.iter().any(|load| load.carries_runtime) {
        2 * fee(upgrade_bytes())
    } else {
        0
    };
    (daily * MATRA).div_ceil(generated_per_block(MATRA) * u128::from(DAYS))
        + (upgrade * MATRA).div_ceil(settled_motra(MATRA))
}

/// The deposit `pallet_multisig` reserves from the keyholder who opens a call
/// that `threshold` of them approve.
pub fn multisig_deposit(threshold: u16) -> Balance {
    DepositBase::get() + DepositFactor::get() * Balance::from(threshold)
}

/// The mainnet chain spec the launch manifest at `manifest` declares.
pub fn mainnet_config(manifest: &std::path::Path) -> Result<ChainSpec, String> {
    let text = std::fs::read_to_string(manifest).map_err(|error| {
        format!(
            "cannot read the launch manifest {}: {error}",
            manifest.display()
        )
    })?;
    mainnet_config_from(&text)
}

/// The mainnet chain spec a launch manifest, given as JSON, declares.
pub fn mainnet_config_from(manifest: &str) -> Result<ChainSpec, String> {
    let code = WASM_BINARY.ok_or("WASM binary not available")?;
    let launch = parse_once_each(manifest).map_err(|error| {
        format!("the launch manifest is not JSON that names each key once: {error}")
    })?;
    let patch = genesis_patch(&launch)
        .map_err(|refusal| format!("refusing the launch manifest: {refusal}"))?;
    Ok(ChainSpec::builder(code, None)
        .with_name("Materios")
        .with_id("materios_mainnet")
        .with_chain_type(ChainType::Live)
        .with_protocol_id("materios")
        .with_properties(properties())
        .with_genesis_config_patch(patch)
        .build())
}

/// JSON whose objects name each key once. serde_json keeps the last of a key
/// an object repeats, so the value written first would be read by no one.
fn parse_once_each(text: &str) -> Result<Json, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let json = serde::Deserializer::deserialize_any(&mut deserializer, OnceEach)?;
    deserializer.end()?;
    Ok(json)
}

struct OnceEach;

impl<'de> serde::de::DeserializeSeed<'de> for OnceEach {
    type Value = Json;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Json, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for OnceEach {
    type Value = Json;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Json, E> {
        Ok(value.into())
    }

    fn visit_i64<E>(self, value: i64) -> Result<Json, E> {
        Ok(value.into())
    }

    fn visit_u64<E>(self, value: u64) -> Result<Json, E> {
        Ok(value.into())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Json, E> {
        Ok(value.into())
    }

    fn visit_str<E>(self, value: &str) -> Result<Json, E> {
        Ok(value.into())
    }

    fn visit_string<E>(self, value: String) -> Result<Json, E> {
        Ok(value.into())
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(OnceEach)? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "an object names the key {key:?} twice"
                )));
            }
            let value = map.next_value_seed(OnceEach)?;
            object.insert(key, value);
        }
        Ok(Json::Object(object))
    }
}

/// A value of the launch manifest and the path that names it in a refusal.
#[derive(Clone)]
struct At<'a> {
    path: String,
    value: &'a Json,
}

impl<'a> At<'a> {
    fn field(&self, name: &str) -> Result<At<'a>, String> {
        self.optional(name)?
            .ok_or_else(|| format!("{} is missing", self.child(name)))
    }

    fn optional(&self, name: &str) -> Result<Option<At<'a>>, String> {
        let object = self
            .value
            .as_object()
            .ok_or_else(|| format!("{} must be an object", self.path))?;
        Ok(object.get(name).map(|value| At {
            path: self.child(name),
            value,
        }))
    }

    fn child(&self, name: &str) -> String {
        if self.path == ROOT {
            name.to_string()
        } else {
            format!("{}.{name}", self.path)
        }
    }

    fn items(&self) -> Result<Vec<At<'a>>, String> {
        let list = self
            .value
            .as_array()
            .ok_or_else(|| format!("{} must be a list", self.path))?;
        Ok(list
            .iter()
            .enumerate()
            .map(|(index, value)| At {
                path: format!("{}[{index}]", self.path),
                value,
            })
            .collect())
    }

    fn entries(&self) -> Result<Vec<(&'a str, At<'a>)>, String> {
        let object = self
            .value
            .as_object()
            .ok_or_else(|| format!("{} must be an object", self.path))?;
        Ok(object
            .iter()
            .map(|(name, value)| {
                let at = At {
                    path: self.child(name),
                    value,
                };
                (name.as_str(), at)
            })
            .collect())
    }

    /// Refuses a field outside `fields`.
    fn only(&self, fields: &[&str]) -> Result<(), String> {
        match self
            .entries()?
            .into_iter()
            .find(|(name, _)| !fields.contains(name))
        {
            Some((_, at)) => Err(format!("{} is not a field {} may hold", at.path, self.path)),
            None => Ok(()),
        }
    }

    fn text(&self) -> Result<&'a str, String> {
        self.value
            .as_str()
            .ok_or_else(|| format!("{} must be a string", self.path))
    }

    fn uint(&self) -> Result<u64, String> {
        self.value
            .as_u64()
            .ok_or_else(|| format!("{} must be a non-negative integer", self.path))
    }

    /// Lowercase hex after `0x`, two digits a byte: the one spelling the
    /// launch preflight reads.
    fn hex(&self) -> Result<Vec<u8>, String> {
        let text = self.text()?;
        text.strip_prefix("0x")
            .filter(|digits| {
                digits.len() % 2 == 0
                    && digits
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
            .and_then(|_| sp_core::bytes::from_hex(text).ok())
            .ok_or_else(|| {
                format!(
                    "{} must be 0x and lowercase hex, two digits a byte",
                    self.path
                )
            })
    }

    fn hex_of<const N: usize>(&self, what: &str) -> Result<[u8; N], String> {
        self.hex()?
            .try_into()
            .map_err(|_| format!("{} must be {what}: {N} bytes of 0x-hex", self.path))
    }
}

const ROOT: &str = "the launch manifest";

/// Values no mainnet launch may name, each with what it is: every key a
/// development seed derives, with the account of each ECDSA one, and every
/// account, key, script and Cardano output preprod's genesis names.
struct Burned(BTreeMap<Vec<u8>, &'static str>);

impl Burned {
    fn known() -> Self {
        let mut burned = BTreeMap::new();
        let mut strings = Vec::new();
        collect_strings(&crate::chain_spec_preprod::genesis_patch(), &mut strings);
        for text in strings {
            let readings = [
                AccountId::from_ss58check(&text)
                    .ok()
                    .map(|account| AsRef::<[u8]>::as_ref(&account).to_vec()),
                ecdsa::Public::from_ss58check(&text)
                    .ok()
                    .map(|key| key.0.to_vec()),
                sp_core::bytes::from_hex(&text).ok(),
                Some(text.into_bytes()),
            ];
            for value in readings.into_iter().flatten() {
                burned.insert(value, "a value preprod's genesis names");
            }
        }
        let holders = ["Alice", "Bob", "Charlie", "Dave", "Eve", "Ferdie"];
        let seeds = holders
            .iter()
            .map(|holder| holder.to_string())
            .chain(holders.iter().map(|holder| format!("{holder}//stash")))
            .chain(["One".to_string(), "Two".to_string()]);
        for seed in seeds {
            let cross_chain = get_from_seed::<ecdsa::Public>(&seed);
            for key in [
                get_from_seed::<sr25519::Public>(&seed).0.to_vec(),
                get_from_seed::<ed25519::Public>(&seed).0.to_vec(),
                cross_chain.0.to_vec(),
                sp_core::blake2_256(&cross_chain.0).to_vec(),
            ] {
                burned.insert(key, "a well-known development key");
            }
        }
        Burned(burned)
    }

    fn refuse(&self, at: &At, value: &[u8]) -> Result<(), String> {
        match self.0.get(value) {
            Some(what) => Err(format!("{} is {what}", at.path)),
            None if value.iter().all(|byte| *byte == 0) => Err(format!("{} is all zero", at.path)),
            None => Ok(()),
        }
    }
}

fn collect_strings(json: &Json, strings: &mut Vec<String>) {
    match json {
        Json::String(text) => strings.push(text.clone()),
        Json::Array(items) => items.iter().for_each(|item| collect_strings(item, strings)),
        Json::Object(fields) => fields
            .values()
            .for_each(|field| collect_strings(field, strings)),
        _ => {}
    }
}

/// A public key as the manifest gives it: an SS58 address, or 0x-hex of a
/// 32-byte key or a 33-byte ECDSA key.
fn public_key(at: &At, burned: &Burned) -> Result<Vec<u8>, String> {
    let text = at.text()?;
    let key = if text.starts_with("0x") {
        at.hex()?
    } else {
        AccountId::from_ss58check_with_version(text)
            .map(|(account, _)| AsRef::<[u8]>::as_ref(&account).to_vec())
            .map_err(|_| format!("{} is not an SS58 address or a 0x-hex public key", at.path))?
    };
    if !matches!(key.len(), 32 | 33) {
        return Err(format!(
            "{} is {} bytes: a public key is 32, or 33 for ECDSA",
            at.path,
            key.len()
        ));
    }
    burned.refuse(at, &key)?;
    Ok(key)
}

fn key_of<const N: usize>(at: &At, burned: &Burned, what: &str) -> Result<[u8; N], String> {
    public_key(at, burned)?
        .try_into()
        .map_err(|_| format!("{} must be {what}: a {N}-byte public key", at.path))
}

/// The account of a public key: the key itself, or blake2-256 of an ECDSA key.
fn account_of(key: &[u8]) -> AccountId {
    match <[u8; 32]>::try_from(key) {
        Ok(account) => account.into(),
        Err(_) => sp_core::blake2_256(key).into(),
    }
}

/// A role entry: the account it names and, for a multisig, who holds it.
struct Entry {
    path: String,
    account: AccountId,
    multisig: Option<Keyholders>,
}

/// A multisig's threshold, its members' accounts, ascending, each with the
/// path that names it, and whether a member is a multisig in turn.
struct Keyholders {
    threshold: u16,
    members: Vec<(AccountId, String)>,
    nested: bool,
}

/// A role entry as the launch preflight reads one: a public key, a multisig
/// member's `{"key": ..}`, or `{"threshold": k, "members": [..]}`, whose
/// account is `pallet_multisig`'s for those members and threshold.
fn entry(at: &At, burned: &Burned) -> Result<Entry, String> {
    let account = |account| Entry {
        path: at.path.clone(),
        account,
        multisig: None,
    };
    if at.value.is_string() {
        return Ok(account(account_of(&public_key(at, burned)?)));
    }
    if !at.value.is_object() {
        return Err(format!("{} must be a public key or a multisig", at.path));
    }
    if let Some(key) = at.optional("key")? {
        at.only(&["key", "pop"])?;
        return Ok(account(account_of(&public_key(&key, burned)?)));
    }
    at.only(&["threshold", "members"])?;
    let listed = at
        .field("members")?
        .items()?
        .iter()
        .map(|member| entry(member, burned))
        .collect::<Result<Vec<_>, _>>()?;
    let nested = listed.iter().any(|member| member.multisig.is_some());
    let mut members: Vec<(AccountId, String)> = listed
        .into_iter()
        .map(|member| (member.account, member.path))
        .collect();
    members.sort();
    if members.len() < 2 || members.len() > MAX_SIGNATORIES as usize {
        return Err(format!(
            "{}.members must list from 2 to {MAX_SIGNATORIES} signatories",
            at.path
        ));
    }
    if members.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(format!("{}.members lists a member twice", at.path));
    }
    let threshold = at.field("threshold")?;
    let threshold = u16::try_from(threshold.uint()?)
        .ok()
        .filter(|threshold| (1..=members.len()).contains(&usize::from(*threshold)))
        .ok_or_else(|| format!("{} must be from 1 to {}", threshold.path, members.len()))?;
    Ok(Entry {
        path: at.path.clone(),
        account: Multisig::multi_account_id(
            &members
                .iter()
                .map(|(account, _)| account.clone())
                .collect::<Vec<_>>(),
            threshold,
        ),
        multisig: Some(Keyholders {
            threshold,
            members,
            nested,
        }),
    })
}

/// The one entry of `role` and its keyholders: a multisig of keys that needs
/// two of them.
fn keyholders<'a>(
    roles: &'a BTreeMap<String, Vec<Entry>>,
    role: &str,
) -> Result<(&'a Entry, &'a Keyholders), String> {
    let entries = roles
        .get(role)
        .ok_or_else(|| format!("roles.{role} is missing"))?;
    match entries.as_slice() {
        [entry] => match &entry.multisig {
            Some(holders) if holders.threshold >= 2 && !holders.nested => Ok((entry, holders)),
            _ => Err(format!(
                "{} must be a multisig of keys with a threshold of at least 2",
                entry.path
            )),
        },
        _ => Err(format!("roles.{role} must name exactly one multisig")),
    }
}

/// The genesis committee: each authority's cross-chain, aura and grandpa
/// keys, ascending by cross-chain key as the runtime seats them.
fn authorities(launch: &At, burned: &Burned) -> Result<Vec<Authority>, String> {
    let mut committee = Vec::new();
    let mut seen = BTreeSet::new();
    for node in launch.field("nodes")?.items()? {
        let authority = node.field("authority")?;
        let seated = authority
            .value
            .as_bool()
            .ok_or_else(|| format!("{} must be true or false", authority.path))?;
        if !seated {
            continue;
        }
        let cross_chain = node.field("cross_chain")?;
        let (aura, grandpa) = (node.field("aura")?, node.field("grandpa")?);
        let keys: (ecdsa::Public, sr25519::Public, ed25519::Public) = (
            cross_chain
                .hex_of::<33>("the authority's ECDSA partner-chain key")
                .map(ecdsa::Public::from_raw)?,
            key_of::<32>(&aura, burned, "the authority's sr25519 aura key")
                .map(sr25519::Public::from_raw)?,
            key_of::<32>(&grandpa, burned, "the authority's ed25519 grandpa key")
                .map(ed25519::Public::from_raw)?,
        );
        burned.refuse(&cross_chain, &keys.0 .0)?;
        if !matches!(keys.0 .0[0], 2 | 3) {
            return Err(format!(
                "{} is not a compressed ECDSA key",
                cross_chain.path
            ));
        }
        for (at, key) in [
            (&cross_chain, keys.0 .0.to_vec()),
            (&aura, keys.1 .0.to_vec()),
            (&grandpa, keys.2 .0.to_vec()),
        ] {
            if !seen.insert(key) {
                return Err(format!("{} is another authority's key too", at.path));
            }
        }
        committee.push((
            CrossChainPublic::from(keys.0),
            SessionKeys {
                aura: AuraId::from(keys.1),
                grandpa: GrandpaId::from(keys.2),
            },
        ));
    }
    if committee.len() < MIN_AUTHORITIES || committee.len() > MAX_VALIDATORS as usize {
        return Err(format!(
            "nodes seats {} authorities: a mainnet genesis seats from {MIN_AUTHORITIES} to \
             {MAX_VALIDATORS}",
            committee.len()
        ));
    }
    committee.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(committee)
}

/// The Cardano values the committee is drawn through: the genesis UTXO the
/// partner-chain setup spent, and the scripts that follow from it.
fn partner_chain(launch: &At, burned: &Burned) -> Result<(Json, Json), String> {
    let partner_chain = launch.field("partner_chain")?;
    let genesis_utxo = partner_chain.field("genesis_utxo")?;
    let utxo = genesis_utxo.text()?;
    let (tx, index) = utxo
        .split_once('#')
        .filter(|(tx, _)| {
            tx.len() == 64 && tx.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
        .and_then(|(tx, index)| {
            let tx: [u8; 32] = sp_core::bytes::from_hex(tx).ok()?.try_into().ok()?;
            let index = index
                .parse::<u16>()
                .ok()
                .filter(|n| n.to_string() == index)?;
            Some((tx, index))
        })
        .ok_or_else(|| {
            format!(
                "{} must be <64 lowercase hex>#<output index>",
                genesis_utxo.path
            )
        })?;
    if index > MAX_GENESIS_UTXO_INDEX {
        return Err(format!(
            "{} names output {index}: the runtime reads an output index of at most \
             {MAX_GENESIS_UTXO_INDEX}",
            genesis_utxo.path
        ));
    }
    burned.refuse(&genesis_utxo, utxo.as_bytes())?;
    if tx == [0; 32] {
        return Err(format!("{} is all zero", genesis_utxo.path));
    }
    let validator = committee_candidate::validator_hash(&tx, index)?;
    let bech32 = committee_candidate_address(
        &partner_chain.field("committee_candidate_address")?,
        &validator,
        &genesis_utxo.path,
    )?;
    let policy = |name: &str| -> Result<String, String> {
        let at = partner_chain.field(name)?;
        let id = at.hex_of::<28>("a Cardano policy id")?;
        burned.refuse(&at, &id)?;
        Ok(sp_core::bytes::to_hex(&id, false))
    };
    let sidechain = serde_json::json!({
        "genesisUtxo": utxo,
        "slotsPerEpoch": MAINNET_SLOTS_PER_EPOCH,
    });
    // The pallet-level keys are camelCase; `MainChainScripts` derives serde
    // plainly, so its fields are snake_case, and a camelCase one is dropped
    // without an error and leaves its default. The address is the hex of
    // its bech32 text, which the follower looks registrations up by.
    let scripts = serde_json::json!({
        "committee_candidate_address": sp_core::bytes::to_hex(bech32.as_bytes(), false),
        "d_parameter_policy_id": policy("d_parameter_policy_id")?,
        "permissioned_candidates_policy_id": policy("permissioned_candidates_policy_id")?,
    });
    Ok((sidechain, scripts))
}

/// The committee candidate address as the manifest gives it: lowercase
/// bech32 whose checksum holds, and Cardano mainnet's enterprise address of
/// `validator`, the committee candidate validator the genesis UTXO at
/// `utxo_path` parameterises.
fn committee_candidate_address<'a>(
    at: &At<'a>,
    validator: &[u8; 28],
    utxo_path: &str,
) -> Result<&'a str, String> {
    use bech32::{FromBase32, ToBase32};
    let text = at.text()?;
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(format!("{} must be lowercase bech32", at.path));
    }
    let (hrp, data) = bech32::decode(text)
        .map_err(|error| format!("{} is not a bech32 address: {error}", at.path))?;
    if hrp != "addr" {
        return Err(format!(
            "{} is not a Cardano mainnet address: its prefix is {hrp}, not addr",
            at.path
        ));
    }
    let payload = Vec::<u8>::from_base32(&data)
        .map_err(|error| format!("{} is not a bech32 address: {error}", at.path))?;
    let expected = [&[MAINNET_SCRIPT_ADDRESS], &validator[..]].concat();
    match payload.split_first() {
        _ if payload == expected => Ok(text),
        Some((header, _)) if header & 0x0f != MAINNET_SCRIPT_ADDRESS & 0x0f => Err(format!(
            "{} is not on Cardano mainnet: its header names network {}",
            at.path,
            header & 0x0f
        )),
        Some((&MAINNET_SCRIPT_ADDRESS, hash)) if hash.len() == validator.len() => {
            let derived = bech32::encode("addr", expected.to_base32())
                .map_err(|error| format!("cannot write the derived address: {error}"))?;
            Err(format!(
                "{} is the address of script {}, but the committee candidate validator {utxo_path} \
                 parameterises is at {derived}",
                at.path,
                sp_core::bytes::to_hex(hash, false)
            ))
        }
        Some((&MAINNET_SCRIPT_ADDRESS, _)) => Err(format!(
            "{} holds {} bytes: a header and a 28-byte script hash are 29",
            at.path,
            payload.len()
        )),
        _ => Err(format!(
            "{} is not an enterprise script address: its header must be 0x{MAINNET_SCRIPT_ADDRESS:02x}",
            at.path
        )),
    }
}

/// Refuses a field no reader of the manifest knows in any object of a fixed
/// shape, and a role a mainnet genesis gives no meaning.
fn ensure_known_fields(launch: &At) -> Result<(), String> {
    launch.only(LAUNCH_FIELDS)?;
    for (name, fields) in OBJECT_FIELDS {
        if let Some(object) = launch.optional(name)? {
            object.only(fields)?;
        }
    }
    if let Some(follower) = launch.optional("cardano_follower")? {
        follower.only(&CARDANO_MAINNET_FOLLOWER.map(|(name, _)| name))?;
    }
    if let Some(lock) = launch
        .optional("supply")?
        .map(|supply| supply.optional("genesis_lock"))
        .transpose()?
        .flatten()
    {
        lock.only(GENESIS_LOCK_FIELDS)?;
    }
    for (name, fields) in ITEM_FIELDS {
        for item in launch
            .optional(name)?
            .map(|list| list.items())
            .transpose()?
            .into_iter()
            .flatten()
        {
            item.only(fields)?;
        }
    }
    for (role, at) in launch.field("roles")?.entries()? {
        if !ROLES.contains(&role) {
            return Err(format!(
                "{} is not a role a mainnet genesis knows: the roles are {}",
                at.path,
                ROLES.join(", ")
            ));
        }
    }
    Ok(())
}

/// Refuses a launch whose sessions or Cardano follower settings are not
/// mainnet's.
fn ensure_mainnet_settings(launch: &At) -> Result<(), String> {
    let slots = launch.field("slots_per_epoch")?;
    if slots.uint()? != u64::from(MAINNET_SLOTS_PER_EPOCH) {
        return Err(format!(
            "{} is {}: mainnet's sessions are {MAINNET_SLOTS_PER_EPOCH} slots",
            slots.path, slots.value
        ));
    }
    let follower = launch.field("cardano_follower")?;
    for (name, mainnet) in CARDANO_MAINNET_FOLLOWER {
        let setting = follower.field(name)?;
        if setting.text()? != mainnet {
            return Err(format!(
                "{} is {}, not Cardano mainnet's {mainnet}",
                setting.path, setting.value
            ));
        }
    }
    Ok(())
}

/// The Cardano network settlement binds: mainnet, with the Aegis policy the
/// launch declares deployed, or none where it declares null for Root to bind
/// after genesis.
fn cardano_ids(launch: &At) -> Result<Json, String> {
    let policy = launch
        .field("settlement")?
        .field("aegis_policy_v1_script_hash")?;
    let mut ids = CARDANO_MAINNET;
    if !policy.value.is_null() {
        ids.aegis_policy_v1_script_hash =
            policy.hex_of::<28>("the deployed policy's script hash, or null")?;
        if ids.aegis_policy_v1_script_hash == [0; 28] {
            return Err(format!("{} is all zero", policy.path));
        }
    }
    Ok(serde_json::json!(ids))
}

/// The dust each account is endowed, from `dust`, which maps a role to the
/// accounts of its entries, each named by its key or, for a multisig, by its
/// account, and to the base units each holds.
fn endowments(
    launch: &At,
    roles: &BTreeMap<String, Vec<Entry>>,
    burned: &Burned,
) -> Result<BTreeMap<AccountId, (Balance, String)>, String> {
    let mut endowed = BTreeMap::new();
    for (role, accounts) in launch.field("dust")?.entries()? {
        let entries = roles.get(role).ok_or_else(|| {
            format!(
                "{} endows a role that roles does not declare",
                accounts.path
            )
        })?;
        for (key, amount) in accounts.entries()? {
            let named = Json::from(key);
            let at = At {
                path: amount.path.clone(),
                value: &named,
            };
            let account = account_of(&public_key(&at, burned)?);
            if !entries.iter().any(|entry| entry.account == account) {
                return Err(format!(
                    "{} names {account}, which is no entry of roles.{role}",
                    amount.path
                ));
            }
            let dust = Balance::from(amount.uint()?);
            if let Some((_, other)) = endowed.insert(account, (dust, amount.path.clone())) {
                return Err(format!(
                    "{} endows the account {other} endows already",
                    amount.path
                ));
            }
        }
    }
    Ok(endowed)
}

/// The dust floor of each account that has to sign or pay a deposit, with
/// what the account is: the existential deposit, the deposits its roles
/// reserve, and the working dust that generates the MOTRA its roles' calls
/// cost.
fn dust_floors(
    roles: &BTreeMap<String, Vec<Entry>>,
    sudo: (&Entry, &Keyholders),
    guardian: (&Entry, &Keyholders),
) -> BTreeMap<AccountId, (Balance, String)> {
    let mut needs: BTreeMap<AccountId, (Balance, Vec<Load>, String)> = BTreeMap::new();
    let mut need = |account: &AccountId, deposit: Balance, load: Option<Load>, who: String| {
        let (deposits, loads, _) = needs.entry(account.clone()).or_insert((0, Vec::new(), who));
        *deposits += deposit;
        loads.extend(load);
    };
    let friends = roles.get("recovery_friends").map_or(0, Vec::len);
    if friends > 0 {
        need(
            &sudo.0.account,
            RecoveryConfigDepositBase::get()
                + RecoveryFriendDepositFactor::get() * friends as Balance,
            None,
            format!(
                "{} ({}), which reserves the recovery deposit,",
                sudo.0.path, sudo.0.account
            ),
        );
    }
    for ((entry, holders), load) in [(sudo, SUDO_MEMBER), (guardian, GUARDIAN_MEMBER)] {
        for (member, path) in &holders.members {
            need(
                member,
                multisig_deposit(holders.threshold),
                Some(load),
                format!("{path} ({member}), a keyholder of {},", entry.path),
            );
        }
    }
    for (role, load) in ROLE_LOADS {
        let deposit = match role {
            "recovery_rescuers" => RecoveryDeposit::get(),
            _ => 0,
        };
        for entry in roles.get(role).into_iter().flatten() {
            let who = format!("{} ({})", entry.path, entry.account);
            need(&entry.account, deposit, Some(load), who);
        }
    }
    needs
        .into_iter()
        .map(|(account, (deposits, loads, who))| {
            let floor = ExistentialDeposit::get() + deposits + working_dust(&loads);
            (account, (floor, who))
        })
        .collect()
}

fn genesis_patch(launch: &Json) -> Result<Json, String> {
    let launch = At {
        path: ROOT.to_string(),
        value: launch,
    };
    ensure_known_fields(&launch)?;
    let burned = Burned::known();
    let mut roles = BTreeMap::new();
    for (role, entries) in launch.field("roles")?.entries()? {
        let entries = entries
            .items()?
            .iter()
            .map(|at| entry(at, &burned))
            .collect::<Result<Vec<_>, _>>()?;
        roles.insert(role.to_string(), entries);
    }
    let mut named = BTreeMap::new();
    for entry in roles.values().flatten() {
        if let Some(other) = named.insert(&entry.account, &entry.path) {
            return Err(format!(
                "{} names the account {other} names: each entry has an account of its own",
                entry.path
            ));
        }
    }
    for role in ["anchor_signer", "attestors", "oracle"] {
        if !roles.contains_key(role) {
            return Err(format!("roles.{role} is missing"));
        }
    }
    let oracles = roles["oracle"].len();
    let (needed, roster) = (
        OracleMinAttestorThreshold::get() as usize,
        OracleMaxAttestors::get() as usize,
    );
    if !(needed..=roster).contains(&oracles) {
        return Err(format!(
            "roles.oracle names {oracles} oracles: a price needs {needed} \
             (OracleMinAttestorThreshold), and a pair's roster holds at most {roster} \
             (OracleMaxAttestors)"
        ));
    }
    if roles["anchor_signer"].is_empty() {
        return Err("roles.anchor_signer is empty: name the key that writes anchors".to_string());
    }
    let friends = roles.get("recovery_friends").map_or(0, Vec::len);
    if friends > MAX_RECOVERY_FRIENDS as usize {
        return Err(format!(
            "roles.recovery_friends names {friends} friends: a recovery takes at most \
             {MAX_RECOVERY_FRIENDS}"
        ));
    }
    let (sudo, sudo_holders) = keyholders(&roles, "sudo")?;
    let (guardian, guardian_holders) = keyholders(&roles, "guardian")?;
    if let Some((shared, path)) = guardian_holders.members.iter().find(|(member, _)| {
        sudo_holders
            .members
            .iter()
            .any(|(keyholder, _)| keyholder == member)
    }) {
        return Err(format!(
            "{path} is {shared}, which holds the sudo key too: the guardian vetoes the sudo \
             key's calls, so no keyholder may be in both"
        ));
    }

    let attestors: Vec<&AccountId> = roles["attestors"]
        .iter()
        .map(|attestor| &attestor.account)
        .collect();
    if attestors.is_empty() || attestors.len() > usize::from(MAX_COMMITTEE_SIZE) {
        return Err(format!(
            "roles.attestors must name from 1 to {MAX_COMMITTEE_SIZE} attestors"
        ));
    }
    let threshold = launch.field("attestation_threshold")?;
    let attestation_threshold = threshold.uint()?;
    if !(1..=attestors.len() as u64).contains(&attestation_threshold) {
        return Err(format!(
            "{} must be from 1 to the {} attestors of roles.attestors",
            threshold.path,
            attestors.len()
        ));
    }

    let economics = launch.field("economics")?;
    let reward = economics.field("attestation_reward_per_signer")?;
    if reward.uint()? != 0 {
        return Err(format!(
            "{} must be 0: mainnet's issuance is fixed, so nothing is minted to pay attestors",
            reward.path
        ));
    }
    let era_cap_base = economics.field("era_cap_base")?.uint()?;
    let baseline = economics.field("era_cap_baseline_attestor_count")?;
    let era_cap_baseline = u32::try_from(baseline.uint()?)
        .ok()
        .filter(|count| *count > 0)
        .ok_or_else(|| format!("{} must be a u32 above zero", baseline.path))?;

    ensure_mainnet_settings(&launch)?;
    let (sidechain, main_chain_scripts) = partner_chain(&launch, &burned)?;
    let cardano_ids = cardano_ids(&launch)?;
    let committee = authorities(&launch, &burned)?;

    let endowed = endowments(&launch, &roles, &burned)?;
    let floors = dust_floors(&roles, (sudo, sudo_holders), (guardian, guardian_holders));
    for (account, (floor, who)) in &floors {
        match endowed.get(account) {
            None => {
                return Err(format!(
                    "{who} holds no dust: endow it at least {floor} under dust, or it cannot sign"
                ))
            }
            Some((dust, at)) if dust < floor => {
                return Err(format!(
                    "{at} endows {who} {dust}, below its floor of {floor}: the existential \
                     deposit, its deposits and the dust that generates its MOTRA"
                ))
            }
            Some(_) => {}
        }
    }
    let pool = roles.get(DUST_POOL).into_iter().flatten();
    let pooled: BTreeSet<&AccountId> = pool.map(|entry| &entry.account).collect();
    for (account, (dust, at)) in &endowed {
        if !floors.contains_key(account) && *account != sudo.account && !pooled.contains(account) {
            return Err(format!(
                "{at} endows an account the builder sizes no dust for: endow the sudo account, \
                 a sudo or guardian keyholder, an entry of {}, or of {DUST_POOL}",
                ROLE_LOADS.map(|(role, _)| role).join(", ")
            ));
        }
        if *dust < ExistentialDeposit::get() {
            return Err(format!(
                "{at} endows {dust}, below the existential deposit of {}",
                ExistentialDeposit::get()
            ));
        }
    }
    // The Treasury's genesis endows its own account the existential deposit.
    let issuance =
        endowed.values().map(|(dust, _)| dust).sum::<Balance>() + ExistentialDeposit::get();
    if issuance >= MATRA {
        return Err(format!(
            "dust endows {issuance} base units with the Treasury's existential deposit: mainnet \
             issues less than one MATRA ({MATRA})"
        ));
    }

    Ok(serde_json::json!({
        "balances": {
            "balances": endowed
                .iter()
                .map(|(account, (dust, _))| (account, dust))
                .collect::<Vec<_>>(),
        },
        "sudo": { "key": sudo.account },
        "rootTimelock": {
            "delays": RootTimelockDefaultDelays::get(),
            "guardian": guardian.account,
        },
        "motra": motra_genesis(MAINNET_GENERATION_PER_MATRA_PER_BLOCK),
        // The fee, its floor and the bond requirement are left at zero,
        // which a genesis that fixes its issuance stores as zero.
        "orinqReceipts": {
            "attestationRewardPerSigner": 0,
            "eraCapBase": era_cap_base,
            "eraCapBaselineAttestorCount": era_cap_baseline,
            "fixedIssuance": issuance,
            "committeeMembers": attestors,
            "attestationThreshold": attestation_threshold,
        },
        "sidechain": sidechain,
        "sessionCommitteeManagement": {
            "initialAuthorities": committee,
            "mainChainScripts": main_chain_scripts,
        },
        "intentSettlement": { "cardanoIds": cardano_ids },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_spec::{
        check_genesis_committee,
        tests::{
            cardano, genesis_header, load_file, opening, play, propose, run,
            seated_after_first_rotation, seated_at_genesis, start,
        },
        Seated, MOTRA_MAX_BALANCE,
    };
    use authority_selection_inherents::authority_selection_inputs::AuthoritySelectionInputs;
    use frame_support::{dispatch::GetDispatchInfo, traits::ReservableCurrency};
    use materios_runtime::{
        frame_system, pallet_motra, pallet_oracle, Balances, Header, Motra, OrinqReceipts, Runtime,
        RuntimeCall, RuntimeEvent, RuntimeOrigin, SessionCommitteeManagement, Sidechain,
        SignedExtra, System, UncheckedExtrinsic,
    };
    use pallet_root_timelock::{Guardian, Tasks};
    use sc_service::ChainSpec as _;
    use sp_core::{Encode, Pair, H256};
    use sp_runtime::{
        generic::{Era, SignedPayload},
        traits::Block as _,
        BuildStorage,
    };

    const FIXTURE: &str =
        include_str!("../../../tools/launch-preflight/fixtures/mainnet-launch.json");

    fn fixture() -> Json {
        serde_json::from_str(FIXTURE).expect("the fixture is JSON")
    }

    fn build(launch: &Json) -> Result<ChainSpec, String> {
        mainnet_config_from(&launch.to_string())
    }

    fn edited(edit: impl FnOnce(&mut Json)) -> Json {
        let mut launch = fixture();
        edit(&mut launch);
        launch
    }

    /// Why the builder refuses the fixture once `edit` has changed it.
    fn refusal(edit: impl FnOnce(&mut Json)) -> String {
        match build(&edited(edit)) {
            Ok(_) => "the builder took it".to_string(),
            Err(refusal) => refusal,
        }
    }

    /// The sudo key genesis stores; `pallet_sudo` keeps the item private.
    fn sudo_key() -> Option<AccountId> {
        frame_support::storage::unhashed::get(&frame_support::storage::storage_prefix(
            b"Sudo", b"Key",
        ))
    }

    fn account(key: &Json) -> AccountId {
        AccountId::from_ss58check(key.as_str().expect("a key")).expect("an SS58 address")
    }

    /// The accounts of `role`'s entries, each a key.
    fn holders(launch: &Json, role: &str) -> Vec<AccountId> {
        launch["roles"][role]
            .as_array()
            .expect("a role")
            .iter()
            .map(account)
            .collect()
    }

    /// The members of `role`'s multisig, in the manifest's order.
    fn members(launch: &Json, role: &str) -> Vec<AccountId> {
        launch["roles"][role][0]["members"]
            .as_array()
            .expect("a multisig")
            .iter()
            .map(|member| account(&member["key"]))
            .collect()
    }

    /// The account the launch preflight derives for a multisig: blake2-256 of
    /// `pallet_multisig`'s prefix, the sorted members and the threshold.
    fn preflight_multisig(mut members: Vec<AccountId>, threshold: u16) -> AccountId {
        members.sort();
        sp_core::blake2_256(&(b"modlpy/utilisuba", members, threshold).encode()).into()
    }

    fn authorities_of(launch: &Json) -> Vec<Authority> {
        let bytes = |key: &Json| sp_core::bytes::from_hex(key.as_str().unwrap()).unwrap();
        let mut seated: Vec<Authority> = launch["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| {
                (
                    CrossChainPublic::try_from(&bytes(&node["cross_chain"])[..]).unwrap(),
                    SessionKeys {
                        aura: TryFrom::try_from(&bytes(&node["aura"])[..]).unwrap(),
                        grandpa: TryFrom::try_from(&bytes(&node["grandpa"])[..]).unwrap(),
                    },
                )
            })
            .collect();
        seated.sort_by(|a, b| a.0.cmp(&b.0));
        seated
    }

    /// Each account the fixture's `dust` endows, with its dust.
    fn fixture_endowments(launch: &Json) -> BTreeMap<AccountId, Balance> {
        launch["dust"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|accounts| accounts.as_object().unwrap())
            .map(|(key, amount)| {
                let account = AccountId::from_ss58check(key).expect("an SS58 address");
                (account, Balance::from(amount.as_u64().unwrap()))
            })
            .collect()
    }

    fn fixture_dust() -> Balance {
        fixture_endowments(&fixture()).values().sum()
    }

    /// The JSON pointer of the dust `role` endows `who`.
    fn dust_of(role: &str, who: &AccountId) -> String {
        format!("/dust/{role}/{}", who.to_ss58check())
    }

    #[test]
    fn the_fixture_launch_builds_a_live_mainnet_spec_the_node_loads() {
        let spec = build(&fixture()).unwrap();
        assert_eq!(
            (spec.name(), spec.id(), spec.chain_type()),
            ("Materios", "materios_mainnet", ChainType::Live)
        );
        assert_eq!(spec.properties()["ss58Format"], 42);
        assert_eq!(spec.properties()["tokenSymbol"], "MATRA");
        assert_eq!(spec.properties()["tokenDecimals"], 6);
        check_genesis_committee(&spec).unwrap();
    }

    /// `--chain mainnet:<manifest>` builds the spec from the file, and its
    /// `build-spec --raw` form holds the same genesis and loads as well.
    #[test]
    fn the_node_builds_mainnet_from_a_manifest_file_and_loads_its_raw_spec() {
        use sc_cli::SubstrateCli;
        let manifest = std::env::temp_dir().join(format!(
            "materios-node-test-{}-launch.json",
            std::process::id()
        ));
        std::fs::write(&manifest, FIXTURE).unwrap();
        let cli = <crate::cli::Cli as clap::Parser>::parse_from(["materios-node"]);
        let chain = format!("{CHAIN_PREFIX}{}", manifest.display());
        let built = cli.load_spec(&chain);
        std::fs::remove_file(&manifest).unwrap();
        let built = built.unwrap();
        let raw: Json = serde_json::from_str(&built.as_json(true).unwrap()).unwrap();
        assert!(raw["genesis"]["raw"]["top"].is_object());
        let loaded = load_file("mainnet-raw", &raw).unwrap();
        assert_eq!(
            loaded.build_storage().unwrap().top,
            built.build_storage().unwrap().top
        );
        let missing = cli.load_spec(&chain).err().expect("no manifest, no spec");
        assert!(
            missing.contains("cannot read the launch manifest"),
            "{missing}"
        );
    }

    /// The launch preflight's tests check `fixtures/mainnet-launch-raw.json`:
    /// it is the raw spec this source builds from the fixture launch, less
    /// its code.
    #[test]
    fn the_preflights_raw_fixture_is_the_spec_the_fixture_launch_builds() {
        let built = build(&fixture()).unwrap().as_json(true).unwrap();
        let mut built: Json = serde_json::from_str(&built).unwrap();
        let code = built["genesis"]["raw"]["top"]
            .as_object_mut()
            .unwrap()
            .remove("0x3a636f6465");
        assert!(code.is_some(), "the raw spec holds the code");
        let fixture: Json = serde_json::from_str(include_str!(
            "../../../tools/launch-preflight/fixtures/mainnet-launch-raw.json"
        ))
        .unwrap();
        assert_eq!(built, fixture);
    }

    #[test]
    fn the_same_manifest_builds_the_same_genesis_whatever_order_it_lists_things_in() {
        let spec = build(&fixture()).unwrap();
        assert_eq!(
            spec.as_json(false).unwrap(),
            build(&fixture()).unwrap().as_json(false).unwrap()
        );
        let reordered = edited(|launch| {
            launch["nodes"].as_array_mut().unwrap().reverse();
            for role in ["sudo", "guardian"] {
                launch["roles"][role][0]["members"]
                    .as_array_mut()
                    .unwrap()
                    .reverse();
            }
            launch["roles"]["attestors"]
                .as_array_mut()
                .unwrap()
                .rotate_left(1);
        });
        assert_eq!(
            build(&reordered).unwrap().build_storage().unwrap().top,
            spec.build_storage().unwrap().top
        );
    }

    #[test]
    fn sessions_are_600_slots() {
        start(&build(&fixture()).unwrap()).execute_with(|| {
            assert_eq!(Sidechain::slots_per_epoch().0, 600);
        });
        for slots in [60, 599, 601] {
            let refused = refusal(|launch| launch["slots_per_epoch"] = slots.into());
            assert!(
                refused.contains(&format!(
                    "slots_per_epoch is {slots}: mainnet's sessions are 600 slots"
                )),
                "{refused}"
            );
        }
    }

    /// Genesis issues the dust the manifest declares and the Treasury's
    /// existential deposit, under one MATRA in all, declares exactly that as
    /// the fixed issuance, and holds no other account. Nothing is charged
    /// for a receipt, bonded or paid to attestors.
    #[test]
    fn the_issuance_is_the_declared_dust_and_the_treasurys_deposit() {
        let launch = fixture();
        let issued = fixture_dust() + ExistentialDeposit::get();
        assert!(issued < MATRA);
        start(&build(&launch).unwrap()).execute_with(|| {
            assert_eq!(Balances::total_issuance(), issued);
            assert_eq!(
                pallet_orinq_receipts::FixedIssuance::<Runtime>::get(),
                Some(issued)
            );
            assert_eq!(OrinqReceipts::ensure_fixed_issuance(), Ok(()));
            let mut expected = fixture_endowments(&launch);
            expected.insert(
                materios_runtime::treasury_account(),
                ExistentialDeposit::get(),
            );
            assert!(expected.contains_key(&sudo_key().expect("genesis sets the sudo key")));
            let held: BTreeMap<AccountId, Balance> = frame_system::Account::<Runtime>::iter()
                .map(|(who, info)| (who, info.data.free + info.data.reserved))
                .collect();
            assert_eq!(held, expected);
            assert_eq!(OrinqReceipts::receipt_submission_fee(), 0);
            assert_eq!(OrinqReceipts::receipt_submission_fee_floor(), 0);
            assert_eq!(OrinqReceipts::bond_requirement(), 0);
            assert_eq!(OrinqReceipts::attestation_reward_per_signer(), 0);
        });
    }

    /// The sudo key and the guardian are the accounts the launch preflight
    /// derives from the same members and thresholds, apart from each other,
    /// and the delays are the runtime's mainnet delays.
    #[test]
    fn the_sudo_key_and_the_guardian_are_the_multisigs_the_preflight_derives() {
        let launch = fixture();
        let sudo = preflight_multisig(members(&launch, "sudo"), 2);
        let guardian = preflight_multisig(members(&launch, "guardian"), 2);
        assert_ne!(sudo, guardian);
        start(&build(&launch).unwrap()).execute_with(|| {
            assert_eq!(sudo_key(), Some(sudo));
            assert_eq!(Guardian::<Runtime>::get(), Some(guardian));
            let delays = pallet_root_timelock::Delays::<Runtime>::get();
            assert_eq!(delays, RootTimelockDefaultDelays::get());
            assert_eq!(
                (delays.recovery, delays.standard, delays.long),
                (DAYS, 7 * DAYS, 30 * DAYS)
            );
        });
    }

    #[test]
    fn genesis_seats_the_declared_authorities_and_keeps_them_through_the_first_rotation() {
        let launch = fixture();
        let seated = authorities_of(&launch);
        assert_eq!(seated.len(), 4);
        let spec = build(&launch).unwrap();
        assert_eq!(seated_at_genesis(&spec), Seated::by(&seated));
        assert_eq!(
            seated_after_first_rotation(&spec, &seated),
            Seated::by(&seated)
        );
    }

    /// The scripts are read back as the runtime decodes them, so a field
    /// name it drops, which leaves the all-zero default, fails here.
    #[test]
    fn genesis_stores_the_manifests_cardano_values_and_binds_cardano_mainnet() {
        let launch = fixture();
        let declared = &launch["partner_chain"];
        let policy =
            |name: &str| sp_core::bytes::from_hex(declared[name].as_str().unwrap()).unwrap();
        start(&build(&launch).unwrap()).execute_with(|| {
            assert_eq!(
                Sidechain::genesis_utxo().to_string(),
                declared["genesis_utxo"].as_str().unwrap()
            );
            let scripts = SessionCommitteeManagement::get_main_chain_scripts();
            assert_eq!(
                scripts.committee_candidate_address.to_string(),
                declared["committee_candidate_address"].as_str().unwrap()
            );
            assert_eq!(
                scripts.d_parameter_policy_id.0.to_vec(),
                policy("d_parameter_policy_id")
            );
            assert_eq!(
                scripts.permissioned_candidates_policy_id.0.to_vec(),
                policy("permissioned_candidates_policy_id")
            );
            assert_eq!(
                pallet_intent_settlement::CardanoIds::<Runtime>::get(),
                Some(CARDANO_MAINNET)
            );
        });
        let deployed = edited(|launch| {
            launch["settlement"]["aegis_policy_v1_script_hash"] =
                format!("0x{}", "5a".repeat(28)).into();
        });
        start(&build(&deployed).unwrap()).execute_with(|| {
            let mut bound = CARDANO_MAINNET;
            bound.aegis_policy_v1_script_hash = [0x5a; 28];
            assert_eq!(
                pallet_intent_settlement::CardanoIds::<Runtime>::get(),
                Some(bound)
            );
        });
    }

    #[test]
    fn genesis_seats_the_declared_attestors_behind_the_declared_threshold() {
        let launch = fixture();
        start(&build(&launch).unwrap()).execute_with(|| {
            assert_eq!(
                OrinqReceipts::committee_members()
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                holders(&launch, "attestors").into_iter().collect()
            );
            assert_eq!(OrinqReceipts::attestation_threshold(), 2);
        });
    }

    #[test]
    fn mainnet_generates_motra_at_the_pinned_rate_and_caps_no_dust() {
        start(&build(&fixture()).unwrap()).execute_with(|| {
            let params = Motra::params();
            assert_eq!(params.generation_per_matra_per_block, 10_000_000_000);
            assert_eq!(params.min_fee, MOTRA_MIN_FEE);
            assert_eq!(params.length_fee_per_byte, MOTRA_LENGTH_FEE_PER_BYTE);
            assert_eq!(
                params.decay_rate_per_block.deconstruct(),
                MOTRA_KEPT_PER_BLOCK
            );
            assert_eq!(params.max_balance, MOTRA_MAX_BALANCE);
            assert_eq!(params.congestion_rate, 0);
        });
        assert_eq!(settled_motra(MATRA / 100), 1_000_000_000_000);
        assert_eq!(
            generated_per_block(MATRA / 100) * u128::from(DAYS),
            1_440_000_000_000
        );
        assert!(settled_motra(MATRA) < MOTRA_MAX_BALANCE / 1_000);
    }

    /// One role's account, the role its dust is listed under, what it
    /// reserves, what it signs, and a call of each kind it signs as the
    /// runtime takes it.
    struct Signer {
        dust: &'static str,
        who: AccountId,
        deposits: Balance,
        load: Load,
        call: RuntimeCall,
    }

    fn set_committee() -> RuntimeCall {
        RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::set_committee {
            members: (1..=3u8).map(|seed| AccountId::from([seed; 32])).collect(),
            threshold: 2,
        })
    }

    fn sudo_schedules(call: RuntimeCall) -> RuntimeCall {
        RuntimeCall::Sudo(pallet_sudo::Call::sudo {
            call: Box::new(RuntimeCall::RootTimelock(
                pallet_root_timelock::Call::schedule {
                    call: Box::new(call),
                },
            )),
        })
    }

    /// The extrinsic `index` of block `height`, which names a multisig
    /// call's first approval; `pallet_multisig` keeps its fields private.
    fn timepoint(height: u32, index: u32) -> pallet_multisig::Timepoint<u32> {
        sp_core::Decode::decode(&mut &(height, index).encode()[..])
            .expect("a timepoint is its height and index")
    }

    /// `call` as `signer` approves it for a multisig of `members` that two
    /// approve, with `when` the approval that opened it.
    fn as_multi(
        members: &[AccountId],
        signer: &AccountId,
        when: Option<pallet_multisig::Timepoint<u32>>,
        call: RuntimeCall,
    ) -> RuntimeCall {
        let mut other_signatories: Vec<AccountId> = members
            .iter()
            .filter(|member| *member != signer)
            .cloned()
            .collect();
        other_signatories.sort();
        RuntimeCall::Multisig(pallet_multisig::Call::as_multi {
            threshold: 2,
            other_signatories,
            maybe_timepoint: when,
            max_weight: call.get_dispatch_info().weight,
            call: Box::new(call),
        })
    }

    fn submit_receipt(receipt_id: H256) -> RuntimeCall {
        RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::submit_receipt {
            receipt_id,
            content_hash: H256::repeat_byte(0xC1),
            base_root_sha256: [1; 32],
            zk_root_poseidon: Some([8; 32]),
            poseidon_params_hash: Some([9; 32]),
            base_manifest_hash: [2; 32],
            safety_manifest_hash: [3; 32],
            monitor_config_hash: [4; 32],
            attestation_evidence_hash: [5; 32],
            storage_locator_hash: [6; 32],
            schema_hash: [7; 32],
        })
    }

    fn role_load(name: &str) -> Load {
        ROLE_LOADS
            .iter()
            .find(|(role, _)| *role == name)
            .expect("a sized role")
            .1
    }

    fn signers(launch: &Json) -> Vec<Signer> {
        let sudo = members(launch, "sudo");
        let guardian = members(launch, "guardian");
        let sudo_account = preflight_multisig(sudo.clone(), 2);
        let of = |name: &'static str, deposits: Balance, call: RuntimeCall| Signer {
            dust: name,
            who: holders(launch, name)[0].clone(),
            deposits,
            load: role_load(name),
            call,
        };
        vec![
            Signer {
                dust: "endowed",
                who: sudo[0].clone(),
                deposits: DepositBase::get() + 2 * DepositFactor::get(),
                load: SUDO_MEMBER,
                call: as_multi(
                    &sudo,
                    &sudo[0],
                    Some(timepoint(u32::MAX, u32::MAX)),
                    sudo_schedules(set_committee()),
                ),
            },
            Signer {
                dust: "endowed",
                who: guardian[0].clone(),
                deposits: DepositBase::get() + 2 * DepositFactor::get(),
                load: GUARDIAN_MEMBER,
                call: as_multi(
                    &guardian,
                    &guardian[0],
                    Some(timepoint(u32::MAX, u32::MAX)),
                    RuntimeCall::RootTimelock(pallet_root_timelock::Call::cancel { id: u32::MAX }),
                ),
            },
            of(
                "enactor",
                0,
                RuntimeCall::RootTimelock(pallet_root_timelock::Call::enact {
                    id: u32::MAX,
                    call: Box::new(set_committee()),
                }),
            ),
            of(
                "anchor_signer",
                0,
                RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::submit_anchor {
                    anchor_id: H256::repeat_byte(1),
                    content_hash: H256::repeat_byte(2),
                    root_hash: H256::repeat_byte(3),
                    manifest_hash: H256::repeat_byte(4),
                }),
            ),
            of(
                "gateway_sponsor",
                0,
                submit_receipt(H256::repeat_byte(0xA1)),
            ),
            of(
                "oracle",
                0,
                RuntimeCall::Oracle(pallet_oracle::Call::submit_price {
                    pair_id: [1; 32],
                    price: u64::MAX,
                    decimals: 8,
                    slot_observed: u64::MAX,
                    pubkey: [2; 32],
                    sig: [3; 64],
                }),
            ),
            of(
                "attestors",
                0,
                RuntimeCall::Motra(pallet_motra::Call::claim_motra {}),
            ),
            of(
                "recovery_friends",
                0,
                RuntimeCall::Recovery(pallet_recovery::Call::vouch_recovery {
                    lost: sudo_account.clone().into(),
                    rescuer: holders(launch, "recovery_rescuers")[0].clone().into(),
                }),
            ),
            of(
                "recovery_rescuers",
                RecoveryDeposit::get(),
                RuntimeCall::Recovery(pallet_recovery::Call::as_recovered {
                    account: sudo_account.into(),
                    call: Box::new(sudo_schedules(set_committee())),
                }),
            ),
        ]
    }

    /// `call` as a signed transaction of the widest signature and nonce,
    /// which is how long it is on the wire.
    fn on_the_wire(call: RuntimeCall) -> usize {
        let extra: SignedExtra = (
            frame_system::CheckNonZeroSender::new(),
            frame_system::CheckSpecVersion::new(),
            frame_system::CheckTxVersion::new(),
            frame_system::CheckGenesis::new(),
            frame_system::CheckEra::from(Era::mortal(64, 63)),
            frame_system::CheckNonce::from(u32::MAX),
            frame_system::CheckWeight::new(),
            pallet_motra::fee::ChargeMotra::new(),
        );
        UncheckedExtrinsic::new_signed(
            call,
            AccountId::from([7; 32]).into(),
            sp_core::sr25519::Signature::from_raw([7; 64]).into(),
            extra,
        )
        .encoded_size()
    }

    /// Each role's floor is the existential deposit, its deposits and its
    /// working dust. The builder takes dust at the floor and refuses one base
    /// unit less.
    #[test]
    fn each_role_is_refused_below_its_dust_floor_and_built_at_it() {
        let launch = fixture();
        let sudo = preflight_multisig(members(&launch, "sudo"), 2);
        let mut checked: Vec<(&str, AccountId, Balance)> = signers(&launch)
            .into_iter()
            .map(|signer| {
                let floor =
                    ExistentialDeposit::get() + signer.deposits + working_dust(&[signer.load]);
                (signer.dust, signer.who, floor)
            })
            .collect();
        checked.push((
            "sudo",
            sudo,
            ExistentialDeposit::get()
                + RecoveryConfigDepositBase::get()
                + 3 * RecoveryFriendDepositFactor::get(),
        ));
        let pinned: Vec<Balance> = checked.iter().map(|(_, _, floor)| *floor).collect();
        assert_eq!(
            pinned,
            [107_630, 3_116, 106_050, 11_000, 21_500, 50_900, 1_373, 570, 1_752, 3_000]
        );
        for (role, who, floor) in checked {
            let pointer = dust_of(role, &who);
            let at = |dust: Balance| {
                edited(|launch| *launch.pointer_mut(&pointer).unwrap() = (dust as u64).into())
            };
            assert!(build(&at(floor)).is_ok(), "{pointer} at {floor}");
            let refused = build(&at(floor - 1)).err().unwrap_or_default();
            let path = format!("dust.{role}.{}", who.to_ss58check());
            assert!(
                refused.contains(&format!("{path} endows"))
                    && refused.contains(&format!("below its floor of {floor}")),
                "{pointer} at {}: {refused}",
                floor - 1
            );
        }
    }

    /// A role's call is no longer on the wire than the builder sizes its
    /// dust for, and the runtime charges for it what the builder reckons.
    #[test]
    fn each_roles_call_fits_the_bytes_its_dust_is_sized_for_at_the_fee_the_runtime_charges() {
        let launch = fixture();
        let code = WASM_BINARY.unwrap().to_vec();
        let sudo = members(&launch, "sudo");
        let set_code = || RuntimeCall::System(frame_system::Call::set_code { code: code.clone() });
        let upgrades = [
            (
                "a sudo member schedules an upgrade",
                SUDO_MEMBER,
                as_multi(&sudo, &sudo[0], None, sudo_schedules(set_code())),
            ),
            (
                "the enactor enacts an upgrade",
                role_load("enactor"),
                RuntimeCall::RootTimelock(pallet_root_timelock::Call::enact {
                    id: u32::MAX,
                    call: Box::new(set_code()),
                }),
            ),
        ];
        start(&build(&launch).unwrap()).execute_with(|| {
            for signer in signers(&launch) {
                let bytes = on_the_wire(signer.call.clone());
                assert!(
                    bytes as u128 <= signer.load.call_bytes,
                    "{}: {bytes} bytes",
                    signer.who
                );
                assert_eq!(
                    Motra::compute_fee(signer.call.get_dispatch_info().weight, bytes),
                    fee(bytes as u128)
                );
            }
            assert_eq!(upgrade_bytes(), 5 * 1024 * 1024);
            for (case, load, call) in upgrades {
                assert!(load.carries_runtime, "{case}");
                let bytes = on_the_wire(call) as u128;
                assert!(bytes <= upgrade_bytes(), "{case}: {bytes} bytes");
            }
        });
    }

    /// Each role, endowed exactly its floor and with its deposits reserved,
    /// pays for a day of its calls as they come due, and a role that carries
    /// a runtime pays for that call too after half a day of them.
    #[test]
    fn each_role_at_its_dust_floor_generates_the_motra_its_calls_cost() {
        let launch = fixture();
        start(&build(&launch).unwrap()).execute_with(|| {
            for signer in signers(&launch) {
                let Signer {
                    who,
                    deposits,
                    load,
                    ..
                } = signer;
                let floor = ExistentialDeposit::get() + deposits + working_dust(&[load]);
                System::set_block_number(0);
                Balances::force_set_balance(RuntimeOrigin::root(), who.clone().into(), floor)
                    .unwrap();
                <Balances as ReservableCurrency<AccountId>>::reserve(&who, deposits).unwrap();
                let due =
                    |call: u128| (call * u128::from(DAYS)).div_ceil(load.calls_per_day) as u32;
                for call in 1..=load.calls_per_day {
                    if load.carries_runtime && call == load.calls_per_day / 2 + 1 {
                        System::set_block_number(DAYS / 2);
                        Motra::burn_fee(&who, fee(upgrade_bytes()))
                            .unwrap_or_else(|_| panic!("{who}: the upgrade"));
                    }
                    System::set_block_number(due(call));
                    Motra::burn_fee(&who, fee(load.call_bytes))
                        .unwrap_or_else(|_| panic!("{who}: call {call}"));
                }
            }
        });
    }

    /// The fixture's keys with a freshly generated key in place of each that
    /// signs in a test, and the sudo account's dust under the account those
    /// keys make.
    struct Held {
        launch: Json,
        sudo: Vec<sr25519::Pair>,
        gateway: sr25519::Pair,
        attestors: Vec<sr25519::Pair>,
    }

    fn held() -> Held {
        let launch = fixture();
        let mut text = FIXTURE.to_string();
        let mut hold = |who: &AccountId| {
            let (pair, _) = sr25519::Pair::generate();
            text = text.replace(&who.to_ss58check(), &pair.public().to_ss58check());
            pair
        };
        let sudo = members(&launch, "sudo").iter().map(&mut hold).collect();
        let gateway = hold(&holders(&launch, "gateway_sponsor")[0]);
        let attestors = holders(&launch, "attestors")
            .iter()
            .map(&mut hold)
            .collect();
        let mut launch: Json = serde_json::from_str(&text).unwrap();
        let account = preflight_multisig(members(&launch, "sudo"), 2).to_ss58check();
        let dust = launch["dust"]["sudo"].as_object_mut().unwrap();
        let amount = dust.values().next().unwrap().clone();
        *dust = serde_json::Map::from_iter([(account, amount)]);
        Held {
            launch,
            sudo,
            gateway,
            attestors,
        }
    }

    fn signed_by(pair: &sr25519::Pair, nonce: u32, call: RuntimeCall) -> UncheckedExtrinsic {
        let extra: SignedExtra = (
            frame_system::CheckNonZeroSender::new(),
            frame_system::CheckSpecVersion::new(),
            frame_system::CheckTxVersion::new(),
            frame_system::CheckGenesis::new(),
            frame_system::CheckEra::from(Era::Immortal),
            frame_system::CheckNonce::from(nonce),
            frame_system::CheckWeight::new(),
            pallet_motra::fee::ChargeMotra::new(),
        );
        let payload = SignedPayload::new(call, extra).expect("the payload is signable");
        let signature = payload.using_encoded(|bytes| pair.sign(bytes));
        let (call, extra, _) = payload.deconstruct();
        UncheckedExtrinsic::new_signed(
            call,
            AccountId::from(pair.public()).into(),
            signature.into(),
            extra,
        )
    }

    /// A chain's blocks, played one slot after another from its first.
    struct Chain {
        head: Header,
        slot: u64,
        cardano: AuthoritySelectionInputs,
    }

    impl Chain {
        fn launched(launch: &Json) -> Self {
            Chain {
                head: genesis_header(),
                slot: 1_000 * u64::from(MAINNET_SLOTS_PER_EPOCH),
                cardano: cardano(&authorities_of(launch)),
            }
        }

        /// Plays the next block as the network does, carrying `signed` after
        /// its inherents. Every transaction must be valid and dispatch.
        fn play(&mut self, signed: Vec<UncheckedExtrinsic>) {
            self.slot += 1;
            self.head = if signed.is_empty() {
                play(&self.head, self.slot, &self.cardano)
                    .unwrap_or_else(|rejection| panic!("{rejection}"))
            } else {
                let (block, data) = propose(&self.head, self.slot, &self.cardano);
                let (_, mut extrinsics) = block.deconstruct();
                extrinsics.extend(signed);
                run(&opening(&self.head, self.slot), Some(extrinsics), &data).0
            };
        }
    }

    /// Two sudo keyholders who hold nothing but their dust schedule a Root
    /// call with signed transactions: the first pays the multisig deposit
    /// from its dust and is not reaped, the second's approval returns it,
    /// the task waits the mainnet delay, and the issuance has not moved.
    #[test]
    fn the_sudo_multisig_schedules_through_the_timelock_on_its_dust_alone() {
        let Held { launch, sudo, .. } = held();
        let keyholders = members(&launch, "sudo");
        let opener = AccountId::from(sudo[0].public());
        let dust = Balance::from(
            launch
                .pointer(&dust_of("endowed", &opener))
                .unwrap()
                .as_u64()
                .unwrap(),
        );
        let issued = fixture_dust() + ExistentialDeposit::get();
        let scheduled = sudo_schedules(set_committee());
        start(&build(&launch).unwrap()).execute_with(|| {
            let mut chain = Chain::launched(&launch);
            for _ in 0..4 {
                chain.play(vec![]);
            }
            chain.play(vec![signed_by(
                &sudo[0],
                0,
                as_multi(&keyholders, &opener, None, scheduled.clone()),
            )]);
            let deposit = DepositBase::get() + 2 * DepositFactor::get();
            assert_eq!(Balances::reserved_balance(&opener), deposit);
            assert_eq!(Balances::free_balance(&opener), dust - deposit);
            assert!(System::account_exists(&opener));
            assert_eq!(Tasks::<Runtime>::iter().count(), 0);

            assert_eq!(pallet_multisig::Multisigs::<Runtime>::iter().count(), 1);
            let opened = System::events()
                .into_iter()
                .find_map(|record| match (record.phase, record.event) {
                    (
                        frame_system::Phase::ApplyExtrinsic(index),
                        RuntimeEvent::Multisig(pallet_multisig::Event::NewMultisig { .. }),
                    ) => Some(timepoint(System::block_number(), index)),
                    _ => None,
                })
                .expect("the first approval opens the call");
            chain.play(vec![signed_by(
                &sudo[1],
                0,
                as_multi(
                    &keyholders,
                    &AccountId::from(sudo[1].public()),
                    Some(opened),
                    scheduled,
                ),
            )]);
            let (_, task) = Tasks::<Runtime>::iter()
                .next()
                .expect("the second approval schedules the task");
            assert_eq!(task.ready_at, System::block_number() + 7 * DAYS);
            assert_eq!(Balances::reserved_balance(&opener), 0);
            assert_eq!(Balances::free_balance(&opener), dust);
            assert_eq!(Balances::total_issuance(), issued);
            assert_eq!(OrinqReceipts::ensure_fixed_issuance(), Ok(()));
        });
    }

    /// The attestors genesis seats certify a receipt its submitter paid no
    /// MATRA for, in the chain's first blocks: each attest is a signed
    /// transaction that costs its attestor no MOTRA.
    #[test]
    fn the_genesis_attestors_certify_a_zero_fee_receipt_in_the_first_blocks() {
        let Held {
            launch,
            gateway,
            attestors,
            ..
        } = held();
        let issued = fixture_dust() + ExistentialDeposit::get();
        let receipt = H256::repeat_byte(0xA1);
        start(&build(&launch).unwrap()).execute_with(|| {
            let mut chain = Chain::launched(&launch);
            for _ in 0..4 {
                chain.play(vec![]);
            }
            let submission = signed_by(&gateway, 0, submit_receipt(receipt));
            let burned = fee(submission.encoded_size() as u128);
            chain.play(vec![submission]);
            assert_eq!(pallet_motra::TotalBurned::<Runtime>::get(), burned);
            assert_eq!(
                Balances::reserved_balance(AccountId::from(gateway.public())),
                0
            );
            let canonical = OrinqReceipts::canonical_cert_hash(receipt)
                .expect("the receipt is stored")
                .0;
            let attest =
                RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::attest_availability_cert {
                    receipt_id: receipt,
                    claimed_hash: canonical,
                });
            chain.play(
                attestors[..2]
                    .iter()
                    .map(|attestor| signed_by(attestor, 0, attest.clone()))
                    .collect(),
            );
            assert!(System::block_number() <= 6);
            assert_eq!(
                pallet_orinq_receipts::Receipts::<Runtime>::get(receipt)
                    .expect("the receipt is stored")
                    .availability_cert_hash,
                canonical
            );
            assert_eq!(pallet_motra::TotalBurned::<Runtime>::get(), burned);
            for attestor in &attestors[..2] {
                assert_eq!(System::account_nonce(AccountId::from(attestor.public())), 1);
            }
            assert_eq!(Balances::total_issuance(), issued);
            assert_eq!(OrinqReceipts::ensure_fixed_issuance(), Ok(()));
        });
    }

    /// An edit that removes the field at `path`.
    fn remove(path: &'static [&'static str]) -> Box<dyn Fn(&mut Json)> {
        Box::new(move |launch: &mut Json| {
            let (last, parents) = path.split_last().unwrap();
            let mut at = launch;
            for name in parents {
                at = match name.parse::<usize>() {
                    Ok(index) => &mut at[index],
                    Err(_) => &mut at[*name],
                };
            }
            at.as_object_mut().unwrap().remove(*last);
        })
    }

    /// An edit that sets the fixture's field at `pointer` to `value`.
    fn set(pointer: impl Into<String>, value: Json) -> Box<dyn Fn(&mut Json)> {
        let pointer = pointer.into();
        Box::new(move |launch: &mut Json| {
            *launch
                .pointer_mut(&pointer)
                .expect("the fixture has the field") = value.clone();
        })
    }

    /// An edit that adds `name` to the object at `pointer`.
    fn insert(pointer: &'static str, name: &'static str, value: Json) -> Box<dyn Fn(&mut Json)> {
        Box::new(move |launch: &mut Json| {
            launch
                .pointer_mut(pointer)
                .and_then(Json::as_object_mut)
                .expect("the fixture has the object")
                .insert(name.to_string(), value.clone());
        })
    }

    /// Each edit of the fixture the builder does not refuse with its reason,
    /// with what it did instead.
    fn unrefused(cases: Vec<(Box<dyn Fn(&mut Json)>, String)>) -> Vec<String> {
        cases
            .into_iter()
            .filter_map(|(edit, reason)| {
                let refused = refusal(|launch| edit(launch));
                (!refused.contains(&reason))
                    .then(|| format!("expected `{reason}`, got `{refused}`"))
            })
            .collect()
    }

    #[test]
    fn a_malformed_or_incomplete_manifest_is_refused_naming_the_field() {
        let oracle = dust_of("oracle", &holders(&fixture(), "oracle")[0]);
        let not_an_amount = format!(
            "{} must be a non-negative integer",
            oracle[1..].replace('/', ".")
        );
        let friends: Vec<Json> = (1..=10u8)
            .map(|seed| AccountId::from([seed; 32]).to_ss58check().into())
            .collect();
        let cases: Vec<(Box<dyn Fn(&mut Json)>, &str)> = vec![
            (remove(&["roles"]), "roles is missing"),
            (remove(&["roles", "sudo"]), "roles.sudo is missing"),
            (remove(&["roles", "guardian"]), "roles.guardian is missing"),
            (remove(&["roles", "oracle"]), "roles.oracle is missing"),
            (remove(&["roles", "anchor_signer"]), "roles.anchor_signer is missing"),
            (remove(&["dust"]), "dust is missing"),
            (remove(&["attestation_threshold"]), "attestation_threshold is missing"),
            (remove(&["economics"]), "economics is missing"),
            (
                remove(&["economics", "attestation_reward_per_signer"]),
                "economics.attestation_reward_per_signer is missing",
            ),
            (remove(&["economics", "era_cap_base"]), "economics.era_cap_base is missing"),
            (remove(&["slots_per_epoch"]), "slots_per_epoch is missing"),
            (remove(&["cardano_follower"]), "cardano_follower is missing"),
            (
                remove(&["cardano_follower", "CARDANO_SECURITY_PARAMETER"]),
                "cardano_follower.CARDANO_SECURITY_PARAMETER is missing",
            ),
            (remove(&["settlement"]), "settlement is missing"),
            (
                remove(&["settlement", "aegis_policy_v1_script_hash"]),
                "settlement.aegis_policy_v1_script_hash is missing",
            ),
            (remove(&["partner_chain"]), "partner_chain is missing"),
            (
                remove(&["partner_chain", "genesis_utxo"]),
                "partner_chain.genesis_utxo is missing",
            ),
            (
                remove(&["partner_chain", "committee_candidate_address"]),
                "partner_chain.committee_candidate_address is missing",
            ),
            (
                remove(&["partner_chain", "d_parameter_policy_id"]),
                "partner_chain.d_parameter_policy_id is missing",
            ),
            (
                remove(&["partner_chain", "permissioned_candidates_policy_id"]),
                "partner_chain.permissioned_candidates_policy_id is missing",
            ),
            (remove(&["nodes"]), "nodes is missing"),
            (remove(&["nodes", "0", "authority"]), "nodes[0].authority is missing"),
            (remove(&["nodes", "1", "cross_chain"]), "nodes[1].cross_chain is missing"),
            (remove(&["nodes", "2", "aura"]), "nodes[2].aura is missing"),
            (remove(&["nodes", "3", "grandpa"]), "nodes[3].grandpa is missing"),
            (
                remove(&["roles", "sudo", "0", "threshold"]),
                "roles.sudo[0].threshold is missing",
            ),
            (set("/roles", 7.into()), "roles must be an object"),
            (set("/roles/attestors", "5F".into()), "roles.attestors must be a list"),
            (set("/roles/attestors/0", 7.into()), "roles.attestors[0] must be a public key or a multisig"),
            (
                set("/roles/attestors/0", "not-an-address".into()),
                "roles.attestors[0] is not an SS58 address or a 0x-hex public key",
            ),
            (
                set("/roles/oracle/0", format!("0x{}", "AB".repeat(32)).into()),
                "roles.oracle[0] must be 0x and lowercase hex",
            ),
            (
                set("/roles/oracle/0", format!("0x{}", "ab".repeat(31)).into()),
                "roles.oracle[0] is 31 bytes: a public key is 32, or 33 for ECDSA",
            ),
            (set("/dust", json_list()), "dust must be an object"),
            (set("/dust/oracle", 7.into()), "dust.oracle must be an object"),
            (set(&oracle, "100000".into()), &not_an_amount),
            (set(&oracle, (-1).into()), &not_an_amount),
            (set("/roles/anchor_signer", json_list()), "roles.anchor_signer is empty"),
            (
                set("/roles/recovery_friends", Json::Array(friends)),
                "roles.recovery_friends names 10 friends: a recovery takes at most 9",
            ),
            (set("/attestation_threshold", "2".into()), "attestation_threshold must be a non-negative integer"),
            (set("/slots_per_epoch", "600".into()), "slots_per_epoch must be a non-negative integer"),
            (set("/nodes/0/authority", "yes".into()), "nodes[0].authority must be true or false"),
            (
                set("/nodes/0/aura", format!("0x{}", "ab".repeat(33)).into()),
                "nodes[0].aura must be the authority's sr25519 aura key: a 32-byte public key",
            ),
            (
                set("/nodes/0/cross_chain", format!("0x{}", "ab".repeat(32)).into()),
                "nodes[0].cross_chain must be the authority's ECDSA partner-chain key: 33 bytes of 0x-hex",
            ),
            (
                set("/nodes/0/cross_chain", format!("0x04{}", "ab".repeat(32)).into()),
                "nodes[0].cross_chain is not a compressed ECDSA key",
            ),
            (
                set("/partner_chain/genesis_utxo", format!("{}#0", "AB".repeat(32)).into()),
                "partner_chain.genesis_utxo must be <64 lowercase hex>#<output index>",
            ),
            (
                set("/partner_chain/genesis_utxo", "ab".repeat(32).into()),
                "partner_chain.genesis_utxo must be <64 lowercase hex>#<output index>",
            ),
            (
                set("/partner_chain/genesis_utxo", format!("{}#0", "00".repeat(32)).into()),
                "partner_chain.genesis_utxo is all zero",
            ),
            (
                set("/partner_chain/d_parameter_policy_id", format!("0x{}", "ab".repeat(32)).into()),
                "partner_chain.d_parameter_policy_id must be a Cardano policy id: 28 bytes of 0x-hex",
            ),
            (
                set("/partner_chain/permissioned_candidates_policy_id", format!("0x{}", "00".repeat(28)).into()),
                "partner_chain.permissioned_candidates_policy_id is all zero",
            ),
            (
                set("/settlement/aegis_policy_v1_script_hash", format!("0x{}", "00".repeat(28)).into()),
                "settlement.aegis_policy_v1_script_hash is all zero",
            ),
            (
                set("/settlement/aegis_policy_v1_script_hash", format!("0x{}", "5a".repeat(32)).into()),
                "settlement.aegis_policy_v1_script_hash must be the deployed policy's script hash, or null",
            ),
            (
                set("/economics/attestation_reward_per_signer", 1.into()),
                "economics.attestation_reward_per_signer must be 0",
            ),
            (
                set("/economics/era_cap_baseline_attestor_count", 0.into()),
                "economics.era_cap_baseline_attestor_count must be a u32 above zero",
            ),
            (set("/attestation_threshold", 0.into()), "attestation_threshold must be from 1 to the 3 attestors"),
            (set("/attestation_threshold", 4.into()), "attestation_threshold must be from 1 to the 3 attestors"),
            (
                Box::new(|launch: &mut Json| {
                    launch["roles"]["attestors"] = json_list();
                    launch["dust"]["attestors"] = serde_json::json!({});
                }),
                "roles.attestors must name from 1 to 96 attestors",
            ),
            (set("/roles/sudo/0/threshold", 1.into()), "roles.sudo[0] must be a multisig of keys with a threshold of at least 2"),
            (set("/roles/sudo/0/threshold", 4.into()), "roles.sudo[0].threshold must be from 1 to 3"),
            (set("/roles/guardian", json_list()), "roles.guardian must name exactly one multisig"),
            (set("/nodes/0/authority", false.into()), "nodes seats 3 authorities: a mainnet genesis seats from 4 to 32"),
        ];
        let cases = cases
            .into_iter()
            .map(|(edit, reason)| (edit, format!("refusing the launch manifest: {reason}")))
            .collect();
        let wrong = unrefused(cases);
        assert!(wrong.is_empty(), "{wrong:#?}");
        let not_json = mainnet_config_from("{").err().unwrap();
        assert!(
            not_json.contains("the launch manifest is not JSON"),
            "{not_json}"
        );
    }

    /// Hex is `0x`, then lowercase digits, two a byte, as many bytes as its
    /// field holds. `from_hex` reads an odd count of digits with a zero
    /// nibble in front, which would make 55 digits a policy id and 65 a
    /// compressed key.
    #[test]
    fn hex_is_0x_and_two_lowercase_digits_a_byte_of_exactly_the_fields_bytes() {
        let digits = |n: usize| -> String { "a7c3".chars().cycle().take(n).collect() };
        let not_hex = "must be 0x and lowercase hex, two digits a byte";
        let not_a_key = "is not an SS58 address or a 0x-hex public key";
        let policy = "/partner_chain/d_parameter_policy_id";
        let utxo = "partner_chain.genesis_utxo must be <64 lowercase hex>#<output index>";
        let cases: Vec<(&str, String, String)> = vec![
            (policy, format!("0x{}", digits(55)), format!("partner_chain.d_parameter_policy_id {not_hex}")),
            (
                "/partner_chain/permissioned_candidates_policy_id",
                format!("0x{}", digits(57)),
                format!("partner_chain.permissioned_candidates_policy_id {not_hex}"),
            ),
            (
                "/settlement/aegis_policy_v1_script_hash",
                format!("0x{}", digits(55)),
                format!("settlement.aegis_policy_v1_script_hash {not_hex}"),
            ),
            ("/nodes/0/aura", format!("0x{}", digits(63)), format!("nodes[0].aura {not_hex}")),
            ("/nodes/1/grandpa", format!("0x{}", digits(63)), format!("nodes[1].grandpa {not_hex}")),
            ("/nodes/2/cross_chain", format!("0x2{}", digits(64)), format!("nodes[2].cross_chain {not_hex}")),
            ("/nodes/2/cross_chain", format!("0x3{}", digits(64)), format!("nodes[2].cross_chain {not_hex}")),
            ("/roles/oracle/0", format!("0x{}", digits(63)), format!("roles.oracle[0] {not_hex}")),
            ("/roles/sudo/0/members/1/key", format!("0x{}", digits(65)), format!("roles.sudo[0].members[1].key {not_hex}")),
            (policy, format!("0x{}", digits(56).to_uppercase()), format!("partner_chain.d_parameter_policy_id {not_hex}")),
            ("/nodes/0/cross_chain", format!("0x02{}", digits(64).to_uppercase()), format!("nodes[0].cross_chain {not_hex}")),
            (policy, digits(56), format!("partner_chain.d_parameter_policy_id {not_hex}")),
            ("/nodes/0/cross_chain", format!("02{}", digits(64)), format!("nodes[0].cross_chain {not_hex}")),
            ("/nodes/0/aura", digits(64), format!("nodes[0].aura {not_a_key}")),
            ("/nodes/1/grandpa", format!("0X{}", digits(64)), format!("nodes[1].grandpa {not_a_key}")),
            (policy, format!(" 0x{}", digits(56)), format!("partner_chain.d_parameter_policy_id {not_hex}")),
            (policy, format!("0x{}\n", digits(56)), format!("partner_chain.d_parameter_policy_id {not_hex}")),
            ("/nodes/1/grandpa", format!("0x{} {}", digits(32), digits(32)), format!("nodes[1].grandpa {not_hex}")),
            ("/nodes/3/aura", format!("0x{}", digits(62)), "nodes[3].aura is 31 bytes".to_string()),
            (
                policy,
                format!("0x{}", digits(54)),
                "partner_chain.d_parameter_policy_id must be a Cardano policy id: 28 bytes of 0x-hex"
                    .to_string(),
            ),
            ("/partner_chain/genesis_utxo", format!("{}#0", digits(63)), utxo.to_string()),
            ("/partner_chain/genesis_utxo", format!("{}#0", digits(65)), utxo.to_string()),
            ("/partner_chain/genesis_utxo", format!("0x{}#0", digits(64)), utxo.to_string()),
        ];
        let wrong = unrefused(
            cases
                .into_iter()
                .map(|(pointer, value, reason)| (set(pointer, value.into()), reason))
                .collect(),
        );
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    fn bech32_text(hrp: &str, payload: &[u8]) -> String {
        use bech32::ToBase32;
        bech32::encode(hrp, payload.to_base32()).unwrap()
    }

    fn genesis_utxo(launch: &Json) -> ([u8; 32], u16) {
        let (tx, index) = launch["partner_chain"]["genesis_utxo"]
            .as_str()
            .and_then(|utxo| utxo.split_once('#'))
            .unwrap();
        let tx = sp_core::bytes::from_hex(tx).unwrap().try_into().unwrap();
        (tx, index.parse().unwrap())
    }

    /// The follower reads registrations at the committee candidate address,
    /// so it must be, checksum and all, Cardano mainnet's enterprise address
    /// of the validator `genesis_utxo` parameterises.
    #[test]
    fn the_committee_candidate_address_is_mainnets_address_of_the_validator_of_the_genesis_utxo() {
        let launch = fixture();
        let declared = launch["partner_chain"]["committee_candidate_address"]
            .as_str()
            .unwrap()
            .to_string();
        let (tx, index) = genesis_utxo(&launch);
        let validator = committee_candidate::validator_hash(&tx, index).unwrap();
        assert_eq!(
            bech32_text("addr", &[&[0x71], &validator[..]].concat()),
            declared
        );
        build(&launch).unwrap();
        let address = |header: u8, hash: &[u8]| bech32_text("addr", &[&[header], hash].concat());
        let last = declared.len() - 1;
        let checksum = if declared.ends_with('q') { "p" } else { "q" };
        let field = "partner_chain.committee_candidate_address";
        let not_bech32 = format!("{field} is not a bech32 address");
        let not_enterprise = format!("{field} is not an enterprise script address");
        let cases = vec![
            (
                format!("{}b{}", &declared[..10], &declared[11..]),
                not_bech32.clone(),
            ),
            (
                format!("{}{checksum}", &declared[..last]),
                not_bech32.clone(),
            ),
            (declared[..last].to_string(), not_bech32.clone()),
            (String::new(), not_bech32.clone()),
            (format!("{declared} "), not_bech32),
            (
                declared.to_uppercase(),
                format!("{field} must be lowercase bech32"),
            ),
            (
                bech32_text("addr_test", &[&[0x70], &validator[..]].concat()),
                format!("{field} is not a Cardano mainnet address: its prefix is addr_test"),
            ),
            (
                bech32_text("stake", &[&[0xf1], &validator[..]].concat()),
                format!("{field} is not a Cardano mainnet address: its prefix is stake"),
            ),
            (
                address(0x70, &validator),
                format!("{field} is not on Cardano mainnet: its header names network 0"),
            ),
            (address(0x61, &validator), not_enterprise.clone()),
            (
                address(0x11, &[validator, validator].concat()),
                not_enterprise.clone(),
            ),
            (
                address(0x01, &[validator, validator].concat()),
                not_enterprise,
            ),
            (
                address(0x71, &validator[..27]),
                format!("{field} holds 28 bytes: a header and a 28-byte script hash are 29"),
            ),
            (
                address(0x71, &[&validator[..], &[0]].concat()),
                format!("{field} holds 30 bytes"),
            ),
            (
                address(0x71, &[0x5a; 28]),
                format!(
                    "{field} is the address of script 0x{}, but the committee candidate validator \
                     partner_chain.genesis_utxo parameterises is at {declared}",
                    "5a".repeat(28)
                ),
            ),
        ];
        let wrong = unrefused(
            cases
                .into_iter()
                .map(|(value, reason)| {
                    (
                        set("/partner_chain/committee_candidate_address", value.into()),
                        reason,
                    )
                })
                .collect(),
        );
        assert!(wrong.is_empty(), "{wrong:#?}");
        let other_utxo = refusal(|launch| {
            launch["partner_chain"]["genesis_utxo"] =
                format!("{}#1", &sp_core::bytes::to_hex(&tx, false)[2..]).into();
        });
        assert!(
            other_utxo.contains("but the committee candidate validator partner_chain.genesis_utxo parameterises is at addr1"),
            "{other_utxo}"
        );
    }

    /// The runtime reads a genesis UTXO's output index as partner-chains'
    /// `UtxoIndex`, which refuses one above `i16::MAX`.
    #[test]
    fn a_genesis_utxo_output_index_the_runtime_cannot_read_is_refused() {
        let launch = fixture();
        let (tx, _) = genesis_utxo(&launch);
        let tx_hex = sp_core::bytes::to_hex(&tx, false)[2..].to_string();
        for index in [32_768u32, 65_535] {
            let refused = refusal(|launch| {
                launch["partner_chain"]["genesis_utxo"] = format!("{tx_hex}#{index}").into();
            });
            assert!(
                refused.contains(&format!(
                    "partner_chain.genesis_utxo names output {index}: the runtime reads an output \
                     index of at most 32767"
                )),
                "{refused}"
            );
        }
        let validator = committee_candidate::validator_hash(&tx, 32_767).unwrap();
        let at_the_cap = edited(|launch| {
            launch["partner_chain"]["genesis_utxo"] = format!("{tx_hex}#32767").into();
            launch["partner_chain"]["committee_candidate_address"] =
                bech32_text("addr", &[&[0x71], &validator[..]].concat()).into();
        });
        start(&build(&at_the_cap).unwrap()).execute_with(|| {
            assert_eq!(
                Sidechain::genesis_utxo().to_string(),
                format!("{tx_hex}#32767")
            );
        });
    }

    /// Every object of the manifest holds only the fields some reader of it
    /// knows, and `roles` only the roles a mainnet genesis gives a meaning:
    /// a misspelt optional field would be read by no one.
    #[test]
    fn a_field_or_role_no_reader_of_the_manifest_knows_is_refused() {
        let key: Json = AccountId::from([7; 32]).to_ss58check().into();
        let proxy = serde_json::json!([{
            "name": "rpc", "node": "a", "kind": "nginx", "config": "rpc.conf", "nmae": "rpc"
        }]);
        let cases: Vec<(Box<dyn Fn(&mut Json)>, &str)> = vec![
            (insert("", "attestation_treshold", 2.into()), "attestation_treshold is not a field the launch manifest may hold"),
            (
                insert("/partner_chain", "committeeCandidateAddress", "addr1".into()),
                "partner_chain.committeeCandidateAddress is not a field partner_chain may hold",
            ),
            (insert("/economics", "era_cap_bse", 0.into()), "economics.era_cap_bse is not a field economics may hold"),
            (
                insert("/settlement", "aegis_policy_v2_script_hash", Json::Null),
                "settlement.aegis_policy_v2_script_hash is not a field settlement may hold",
            ),
            (
                insert("/cardano_follower", "MC__SECURITY_PARAMETER", "2160".into()),
                "cardano_follower.MC__SECURITY_PARAMETER is not a field cardano_follower may hold",
            ),
            (insert("/supply", "genesis_locks", serde_json::json!({})), "supply.genesis_locks is not a field supply may hold"),
            (
                insert("/supply/genesis_lock", "datum", "0x00".into()),
                "supply.genesis_lock.datum is not a field supply.genesis_lock may hold",
            ),
            (insert("/nodes/0", "cross_chian", "0x02".into()), "nodes[0].cross_chian is not a field nodes[0] may hold"),
            (insert("", "rpc_proxies", proxy), "rpc_proxies[0].nmae is not a field rpc_proxies[0] may hold"),
            (
                insert("/roles", "recovery_freinds", serde_json::json!([key])),
                "roles.recovery_freinds is not a role a mainnet genesis knows",
            ),
            (insert("/roles/sudo/0", "treshold", 2.into()), "roles.sudo[0].treshold is not a field roles.sudo[0] may hold"),
            (
                insert("/roles/guardian/0/members/1", "pop_", "0x00".into()),
                "roles.guardian[0].members[1].pop_ is not a field roles.guardian[0].members[1] may hold",
            ),
            (
                insert("/roles/sudo/0/members/0", "threshold", 1.into()),
                "roles.sudo[0].members[0].threshold is not a field roles.sudo[0].members[0] may hold",
            ),
        ];
        let wrong = unrefused(
            cases
                .into_iter()
                .map(|(edit, reason)| (edit, format!("refusing the launch manifest: {reason}")))
                .collect(),
        );
        assert!(wrong.is_empty(), "{wrong:#?}");
        let with_the_preflights_fields = edited(|launch| {
            let node = launch["nodes"][0].as_object_mut().unwrap();
            for capture in [
                "cmdline",
                "exe",
                "chain_spec",
                "served_genesis",
                "served_chain",
                "served_chain_type",
                "served_properties",
                "process_stat",
                "system_stat",
                "chain_spec_stat",
            ] {
                node.insert(capture.to_string(), format!("captures/{capture}").into());
            }
            node.insert(
                "addresses".to_string(),
                serde_json::json!(["/dns/a/tcp/30333"]),
            );
            launch["rpc_proxies"] = serde_json::json!([{
                "name": "rpc", "node": "a", "kind": "nginx", "config": "rpc.conf", "other_targets": []
            }]);
            launch["public_rpc"] = serde_json::json!(["wss://rpc.invalid"]);
            launch["roles"]["sudo"][0]["members"][0]["pop"] = "0x00".into();
        });
        build(&with_the_preflights_fields).unwrap();
    }

    /// serde_json keeps the last of a key an object repeats, so the value
    /// written first would be read by no one, and a JSON escape can spell
    /// the same key two ways.
    #[test]
    fn a_key_one_object_names_twice_is_refused() {
        let oracle = holders(&fixture(), "oracle")[0].to_ss58check();
        let threshold = "\"attestation_threshold\": 2,";
        let cases = [
            (
                "attestation_threshold",
                FIXTURE.replacen(
                    threshold,
                    &format!("{threshold} \"attestation_threshold\": 3,"),
                    1,
                ),
            ),
            (
                "attestation_threshold",
                FIXTURE.replacen(
                    threshold,
                    &format!("{threshold} \"\\u0061ttestation_threshold\": 3,"),
                    1,
                ),
            ),
            (
                oracle.as_str(),
                FIXTURE.replacen(
                    &format!("\"{oracle}\": "),
                    &format!("\"{oracle}\": 60000, \"{oracle}\": "),
                    1,
                ),
            ),
            (
                "threshold",
                FIXTURE.replacen(
                    "\"threshold\": 2,",
                    "\"threshold\": 2, \"threshold\": 3,",
                    1,
                ),
            ),
        ];
        for (key, text) in cases {
            assert_ne!(text, FIXTURE);
            let refused = mainnet_config_from(&text).err().unwrap_or_default();
            assert!(
                refused.contains(&format!("an object names the key {key:?} twice")),
                "{key}: {refused}"
            );
        }
        build(&fixture()).unwrap();
    }

    /// The oracle aggregates a price once `OracleMinAttestorThreshold`
    /// attestors have submitted it, and holds at most `OracleMaxAttestors` on
    /// a pair's roster, which Root fills after genesis.
    #[test]
    fn a_launch_names_from_as_many_oracles_as_a_price_needs_to_as_many_as_a_roster_holds() {
        let launch = fixture();
        let oracles = holders(&launch, "oracle");
        assert_eq!(oracles.len(), 3);
        build(&launch).unwrap();
        let reason = |named: usize| {
            format!(
                "roles.oracle names {named} oracles: a price needs 3 (OracleMinAttestorThreshold), \
                 and a pair's roster holds at most 16 (OracleMaxAttestors)"
            )
        };
        let mut cases: Vec<(Box<dyn Fn(&mut Json)>, String)> = Vec::new();
        for kept in [0, 2] {
            let dropped: Vec<String> = oracles[kept..].iter().map(|o| o.to_ss58check()).collect();
            cases.push((
                Box::new(move |launch: &mut Json| {
                    launch["roles"]["oracle"]
                        .as_array_mut()
                        .unwrap()
                        .truncate(kept);
                    for key in &dropped {
                        launch["dust"]["oracle"]
                            .as_object_mut()
                            .unwrap()
                            .remove(key);
                    }
                }),
                reason(kept),
            ));
        }
        let seventeen: Vec<Json> = (100..117u8)
            .map(|seed| AccountId::from([seed; 32]).to_ss58check().into())
            .collect();
        cases.push((set("/roles/oracle", Json::Array(seventeen)), reason(17)));
        let wrong = unrefused(cases);
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    fn json_list() -> Json {
        Json::Array(Vec::new())
    }

    /// Every key field refuses the key of each development seed, in each
    /// scheme, and the account of its ECDSA key.
    #[test]
    fn a_development_key_is_refused_in_every_key_field() {
        let seeds = [
            "Alice",
            "Bob",
            "Charlie",
            "Dave",
            "Eve",
            "Ferdie",
            "Alice//stash",
            "Ferdie//stash",
            "One",
            "Two",
        ];
        let hex = |bytes: &[u8]| Json::from(sp_core::bytes::to_hex(bytes, false));
        let mut taken = Vec::new();
        for seed in seeds {
            let account = get_from_seed::<sr25519::Public>(seed);
            let grandpa = get_from_seed::<ed25519::Public>(seed);
            let cross_chain = get_from_seed::<ecdsa::Public>(seed);
            let fields: Vec<(&str, Json)> = vec![
                ("/roles/sudo/0/members/0/key", account.to_ss58check().into()),
                ("/roles/guardian/0/members/2/key", hex(&account.0)),
                ("/roles/anchor_signer/0", account.to_ss58check().into()),
                ("/roles/attestors/1", hex(&account.0)),
                ("/roles/oracle/0", hex(&cross_chain.0)),
                ("/roles/oracle/0", hex(&sp_core::blake2_256(&cross_chain.0))),
                ("/roles/enactor/0", hex(&grandpa.0)),
                ("/roles/endowed/4", account.to_ss58check().into()),
                ("/nodes/0/aura", hex(&account.0)),
                ("/nodes/1/grandpa", hex(&grandpa.0)),
                ("/nodes/2/cross_chain", hex(&cross_chain.0)),
            ];
            for (pointer, key) in fields {
                let refused = refusal(|launch| *launch.pointer_mut(pointer).unwrap() = key);
                if !refused.contains("is a well-known development key") {
                    taken.push(format!("//{seed} at {pointer}: {refused}"));
                }
            }
        }
        assert!(taken.is_empty(), "{taken:#?}");
        let zero = refusal(|launch| {
            launch["roles"]["attestors"][0] = hex(&[0; 32]);
        });
        assert!(zero.contains("roles.attestors[0] is all zero"), "{zero}");
    }

    /// The manifest names nothing preprod's genesis names, and no Cardano
    /// setting of another network.
    #[test]
    fn a_manifest_that_carries_preprod_values_is_refused() {
        let preprod = crate::chain_spec_preprod::genesis_patch();
        let scripts = &preprod["sessionCommitteeManagement"]["mainChainScripts"];
        let authority = &preprod["sessionCommitteeManagement"]["initialAuthorities"][0];
        let cross_chain = ecdsa::Public::from_ss58check(authority[0].as_str().unwrap()).unwrap();
        let named = "is a value preprod's genesis names";
        let cases: Vec<(&str, Json, &str)> = vec![
            (
                "/partner_chain/genesis_utxo",
                preprod["sidechain"]["genesisUtxo"].clone(),
                named,
            ),
            (
                "/partner_chain/d_parameter_policy_id",
                scripts["d_parameter_policy_id"].clone(),
                named,
            ),
            (
                "/partner_chain/permissioned_candidates_policy_id",
                scripts["permissioned_candidates_policy_id"].clone(),
                named,
            ),
            (
                "/partner_chain/committee_candidate_address",
                "addr_test1wrld9uhaepas48twjy3qevncsyrhjdqnkz2wzu4yzjc2qhq24f4v4".into(),
                "partner_chain.committee_candidate_address is not a Cardano mainnet address",
            ),
            ("/roles/attestors/0", preprod["sudo"]["key"].clone(), named),
            (
                "/roles/sudo/0/members/1/key",
                preprod["balances"]["balances"][2][0].clone(),
                named,
            ),
            (
                "/roles/oracle/0",
                preprod["rootTimelock"]["guardian"].clone(),
                named,
            ),
            ("/nodes/0/aura", authority[1]["aura"].clone(), named),
            ("/nodes/0/grandpa", authority[1]["grandpa"].clone(), named),
            (
                "/nodes/0/cross_chain",
                sp_core::bytes::to_hex(&cross_chain.0, false).into(),
                named,
            ),
            (
                "/cardano_follower/MC__FIRST_EPOCH_NUMBER",
                "4".into(),
                "cardano_follower.MC__FIRST_EPOCH_NUMBER is \"4\", not Cardano mainnet's 208",
            ),
            (
                "/cardano_follower/MC__FIRST_SLOT_NUMBER",
                "86400".into(),
                "not Cardano mainnet's 4492800",
            ),
            (
                "/cardano_follower/MC__FIRST_EPOCH_TIMESTAMP_MILLIS",
                "1655769600000".into(),
                "not Cardano mainnet's 1596059091000",
            ),
        ];
        let mut taken = Vec::new();
        for (pointer, value, reason) in cases {
            let refused = refusal(|launch| *launch.pointer_mut(pointer).unwrap() = value);
            if !refused.contains(reason) {
                taken.push(format!("{pointer}: {refused}"));
            }
        }
        assert!(taken.is_empty(), "{taken:#?}");
    }

    #[test]
    fn a_key_two_holders_may_not_share_is_refused() {
        let launch = fixture();
        let copy = |from: &'static str, to: &'static str| {
            let value = launch
                .pointer(from)
                .expect("the fixture has the field")
                .clone();
            refusal(move |launch| *launch.pointer_mut(to).unwrap() = value)
        };
        for (from, to, reason) in [
            (
                "/roles/sudo/0/members/0/key",
                "/roles/guardian/0/members/1/key",
                "which holds the sudo key too",
            ),
            (
                "/roles/sudo/0/members/0",
                "/roles/sudo/0/members/2",
                "roles.sudo[0].members lists a member twice",
            ),
            (
                "/roles/attestors/0",
                "/roles/attestors/2",
                "roles.attestors[2] names the account roles.attestors[0] names",
            ),
            (
                "/nodes/0/aura",
                "/nodes/1/aura",
                "nodes[1].aura is another authority's key too",
            ),
            (
                "/nodes/0/grandpa",
                "/nodes/3/grandpa",
                "nodes[3].grandpa is another authority's key too",
            ),
            (
                "/nodes/1/cross_chain",
                "/nodes/2/cross_chain",
                "nodes[2].cross_chain is another authority's key too",
            ),
            (
                "/roles/oracle/0",
                "/roles/enactor/0",
                "roles.oracle[0] names the account roles.enactor[0] names",
            ),
            (
                "/roles/sudo/0/members/1/key",
                "/roles/attestors/1",
                "roles.endowed[1] names the account roles.attestors[1] names",
            ),
        ] {
            let refused = copy(from, to);
            assert!(refused.contains(reason), "{from} at {to}: {refused}");
        }
        let nested = refusal(|launch| {
            let inner = launch["roles"]["guardian"][0].clone();
            launch["roles"]["sudo"][0]["members"][0] = inner;
        });
        assert!(
            nested.contains("roles.sudo[0] must be a multisig of keys"),
            "{nested}"
        );
        let lone = refusal(|launch| {
            launch["roles"]["sudo"][0] = AccountId::from([9; 32]).to_ss58check().into();
        });
        assert!(
            lone.contains("roles.sudo[0] must be a multisig of keys"),
            "{lone}"
        );
    }

    #[test]
    fn dust_that_leaves_a_signer_out_or_endows_the_unsized_is_refused() {
        let launch = fixture();
        let sudo = preflight_multisig(members(&launch, "sudo"), 2);
        let (attestor, oracle) = (
            holders(&launch, "attestors")[1].clone(),
            holders(&launch, "oracle")[0].clone(),
        );
        let (keyholder, guardian) = (
            members(&launch, "sudo")[1].clone(),
            members(&launch, "guardian")[2].clone(),
        );
        let spare = AccountId::from([7; 32]);
        let unendowed = |role: &'static str, who: &AccountId| -> Box<dyn Fn(&mut Json)> {
            let key = who.to_ss58check();
            Box::new(move |launch: &mut Json| {
                launch["dust"][role].as_object_mut().unwrap().remove(&key);
            })
        };
        let cases: Vec<(Box<dyn Fn(&mut Json)>, String)> = vec![
            (
                unendowed("attestors", &attestor),
                format!("roles.attestors[1] ({attestor}) holds no dust: endow it at least 1373"),
            ),
            (
                unendowed("endowed", &keyholder),
                format!(
                    "roles.sudo[0].members[1] ({keyholder}), a keyholder of roles.sudo[0], holds \
                     no dust: endow it at least 107630"
                ),
            ),
            (
                unendowed("endowed", &guardian),
                format!(
                    "roles.guardian[0].members[2] ({guardian}), a keyholder of roles.guardian[0], \
                     holds no dust: endow it at least 3116"
                ),
            ),
            (
                unendowed("sudo", &sudo),
                format!(
                    "roles.sudo[0] ({sudo}), which reserves the recovery deposit, holds no dust: \
                     endow it at least 3000"
                ),
            ),
            (
                Box::new(|launch: &mut Json| {
                    launch["dust"].as_object_mut().unwrap().remove("oracle");
                }),
                format!("roles.oracle[0] ({oracle}) holds no dust"),
            ),
            (
                {
                    let key = oracle.to_ss58check();
                    Box::new(move |launch: &mut Json| {
                        launch["dust"]["attestors"][&key] = 5_000.into()
                    })
                },
                format!(
                    "dust.attestors.{oracle} names {oracle}, which is no entry of roles.attestors"
                ),
            ),
            (
                {
                    let hex = sp_core::bytes::to_hex(attestor.as_ref(), false);
                    Box::new(move |launch: &mut Json| {
                        launch["dust"]["attestors"][&hex] = 5_000.into()
                    })
                },
                "endows already".to_string(),
            ),
            (
                Box::new(|launch: &mut Json| launch["dust"]["treasury"] = serde_json::json!({})),
                "dust.treasury endows a role that roles does not declare".to_string(),
            ),
            (
                {
                    let key = spare.to_ss58check();
                    Box::new(move |launch: &mut Json| {
                        launch["roles"]["endowed"]
                            .as_array_mut()
                            .unwrap()
                            .push(key.clone().into());
                        launch["dust"]["endowed"][&key] = 5_000.into();
                    })
                },
                format!("dust.endowed.{spare} endows an account the builder sizes no dust for"),
            ),
            (
                {
                    let key = sudo.to_ss58check();
                    Box::new(move |launch: &mut Json| launch["dust"]["sudo"][&key] = 700_000.into())
                },
                "mainnet issues less than one MATRA (1000000)".to_string(),
            ),
        ];
        let wrong = unrefused(cases);
        assert!(wrong.is_empty(), "{wrong:#?}");
        let without_recovery = edited(|launch| {
            for list in ["roles", "dust"] {
                let lists = launch[list].as_object_mut().unwrap();
                lists.remove("recovery_friends");
                lists.remove("recovery_rescuers");
            }
            launch["dust"].as_object_mut().unwrap().remove("sudo");
        });
        let spec = build(&without_recovery).expect("a sudo account with no deposit needs no dust");
        start(&spec).execute_with(|| {
            assert!(!System::account_exists(&sudo_key().unwrap()));
        });
    }

    /// The dust pool holds dust Root can hand to a signer admitted after
    /// genesis: it is sized for no load, so it needs only the existential
    /// deposit.
    #[test]
    fn the_dust_pool_holds_its_dust_from_the_existential_deposit_up() {
        let launch = fixture();
        let pool = holders(&launch, DUST_POOL)[0].clone();
        let pointer = dust_of(DUST_POOL, &pool);
        let at = |dust: u64| edited(|launch| *launch.pointer_mut(&pointer).unwrap() = dust.into());
        start(&build(&at(ExistentialDeposit::get() as u64)).unwrap()).execute_with(|| {
            assert_eq!(Balances::free_balance(&pool), ExistentialDeposit::get());
        });
        let refused = build(&at(ExistentialDeposit::get() as u64 - 1))
            .err()
            .unwrap_or_default();
        assert!(
            refused.contains(&format!(
                "dust.{DUST_POOL}.{pool} endows 499, below the existential deposit of 500"
            )),
            "{refused}"
        );
    }

    #[test]
    fn the_cardano_follower_settings_are_the_fixtures() {
        let declared = &fixture()["cardano_follower"];
        assert_eq!(
            declared.as_object().unwrap().len(),
            CARDANO_MAINNET_FOLLOWER.len()
        );
        for (name, value) in CARDANO_MAINNET_FOLLOWER {
            assert_eq!(declared[name], value);
        }
    }
}
