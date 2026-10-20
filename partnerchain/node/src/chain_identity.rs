//! `materios-node chain-id`: the chain ids a chain spec's runtime binds into
//! signed payloads, read from its own code in the state block one's calls see.

use materios_runtime::{Block, System};
use sp_core::{
    traits::{CallContext, CodeExecutor, RuntimeCode, WrappedRuntimeCode},
    Decode, H256,
};
use sp_runtime::traits::{BlakeTwo256, Block as _};

pub type Executor = sc_executor::WasmExecutor<sp_io::SubstrateHostFunctions>;

/// A chain spec's genesis, as the node builds it at startup.
pub struct Genesis {
    pub code: Vec<u8>,
    pub state: sp_io::TestExternalities,
    pub hash: H256,
}

/// The genesis `spec` builds, its state versioned as `executor` reads the
/// spec's own code. It opens no database and connects to nothing.
pub fn genesis(spec: &dyn sc_service::ChainSpec, executor: &Executor) -> Result<Genesis, String> {
    let storage = spec.build_storage()?;
    let code = storage
        .top
        .get(sp_core::storage::well_known_keys::CODE)
        .ok_or("the genesis holds no runtime code")?
        .clone();
    let version = sc_service::resolve_state_version_from_wasm::<_, BlakeTwo256>(&storage, executor)
        .map_err(|e| e.to_string())?;
    let mut state = sp_io::TestExternalities::new_with_code_and_state(&code, storage, version);
    let root = state.execute_with(|| H256::from_slice(&sp_io::storage::root(version)));
    let hash = sc_service::construct_genesis_block::<Block>(root, version).hash();
    Ok(Genesis { code, state, hash })
}

/// The genesis hash `spec` builds, as the node builds it at startup, and each
/// runtime metadata constant whose name holds `ChainId` or `GenesisHash` in
/// any case, as the spec's own Wasm reports it once block one has initialised
/// on that genesis. It opens no database and connects to nothing.
pub fn inspect(spec: &dyn sc_service::ChainSpec) -> Result<serde_json::Value, String> {
    let executor = Executor::builder().build();
    let Genesis {
        code,
        mut state,
        hash: genesis,
    } = genesis(spec, &executor)?;
    state.execute_with(|| System::initialize(&1, &genesis, &Default::default()));

    let fetcher = WrappedRuntimeCode(code.as_slice().into());
    let runtime_code = RuntimeCode {
        code_fetcher: &fetcher,
        heap_pages: None,
        hash: sp_core::blake2_256(&code).to_vec(),
    };
    let (metadata, _) = executor.call(
        &mut state.ext(),
        &runtime_code,
        "Metadata_metadata",
        &[],
        CallContext::Offchain,
    );
    let metadata = metadata.map_err(|e| format!("the runtime's metadata call failed: {e}"))?;
    let metadata = sp_core::OpaqueMetadata::decode(&mut &metadata[..])
        .map_err(|e| format!("the runtime's metadata is not SCALE: {e}"))?;
    let frame_metadata::RuntimeMetadataPrefixed(_, frame_metadata::RuntimeMetadata::V14(metadata)) =
        Decode::decode(&mut &metadata[..])
            .map_err(|e| format!("the runtime's metadata does not decode: {e}"))?
    else {
        return Err("the runtime serves metadata other than V14".into());
    };
    let constants: Vec<_> = metadata
        .pallets
        .into_iter()
        .flat_map(|pallet| {
            let name = pallet.name;
            pallet
                .constants
                .into_iter()
                .map(move |constant| (name.clone(), constant.name, constant.value))
        })
        .filter(|(_, name, _)| {
            let name = name.to_ascii_lowercase();
            name.contains("chainid") || name.contains("genesishash")
        })
        .collect();
    Ok(serde_json::json!({ "genesis_hash": genesis, "constants": constants }))
}
