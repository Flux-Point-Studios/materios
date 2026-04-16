//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.
//!
//! Configured for IOG partner-chain permissioned-only mode (D=1.0):
//! - Block beneficiary inherent provider is included for `pallet_block_rewards`.
//! - Mainchain follower data sources (mc_hash, ariadne, native_token) are omitted;
//!   those will be added when the Cardano bridge is activated.

use materios_runtime::{self, opaque::Block, RuntimeApi};
use sc_client_api::{Backend, BlockBackend};
use sc_consensus_aura::{ImportQueueParams, SlotProportion, StartAuraParams};
use sc_consensus_grandpa::SharedVoterState;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sp_consensus_aura::sr25519::AuthorityPair as AuraPair;
use std::sync::Arc;

/// The full client type.
pub type FullClient = sc_service::TFullClient<Block, RuntimeApi, sc_executor::WasmExecutor<sp_io::SubstrateHostFunctions>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

/// Environment variable name for the block beneficiary address.
/// Set this to a hex-encoded 32-byte identifier to receive block rewards.
/// If not set, block authoring will fail with a fatal inherent error.
const BLOCK_BENEFICIARY_ENV: &str = "SIDECHAIN_BLOCK_BENEFICIARY";

/// The BeneficiaryId type must match the runtime's pallet_block_rewards::Config::BeneficiaryId.
/// Using a 32-byte sized byte string, same as the IOG reference implementation.
type BeneficiaryId = sidechain_domain::byte_string::SizedByteString<32>;

/// Build the full service components.
pub fn new_full<N: sc_network::NetworkBackend<Block, <Block as sp_runtime::traits::Block>::Hash>>(
    config: Configuration,
) -> Result<TaskManager, ServiceError> {
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (grandpa_block_import, grandpa_link, _telemetry),
    } = new_partial(&config)?;

    let mut net_config = sc_network::config::FullNetworkConfiguration::<
        Block,
        <Block as sp_runtime::traits::Block>::Hash,
        N,
    >::new(&config.network, config.prometheus_registry().cloned());

    let metrics = N::register_notification_metrics(config.prometheus_registry());
    let peer_store_handle = net_config.peer_store_handle();

    let grandpa_protocol_name = sc_consensus_grandpa::protocol_standard_name(
        &client
            .block_hash(0)
            .ok()
            .flatten()
            .expect("Genesis block exists; qed"),
        &config.chain_spec,
    );

    let (grandpa_protocol_config, grandpa_notification_service) =
        sc_consensus_grandpa::grandpa_peers_set_config::<_, N>(
            grandpa_protocol_name.clone(),
            metrics.clone(),
            peer_store_handle,
        );

    net_config.add_notification_protocol(grandpa_protocol_config);

    let (network, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            net_config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            block_announce_validator_builder: None,
            warp_sync_config: None,
            block_relay: None,
            metrics,
        })?;

    let role = config.role;
    let force_authoring = config.force_authoring;
    let backoff_authoring_blocks: Option<()> = None;
    let name = config.network.node_name.clone();
    let enable_grandpa = !config.disable_grandpa;
    let prometheus_registry = config.prometheus_registry().cloned();

    // RPC extensions
    let rpc_extensions_builder = {
        let client = client.clone();
        let pool = transaction_pool.clone();

        Box::new(move |_| {
            let deps = crate::rpc::FullDeps {
                client: client.clone(),
                pool: pool.clone(),
            };
            crate::rpc::create_full(deps).map_err(Into::into)
        })
    };

    let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network: Arc::new(network.clone()),
        client: client.clone(),
        keystore: keystore_container.keystore(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        rpc_builder: rpc_extensions_builder,
        backend,
        system_rpc_tx,
        tx_handler_controller,
        sync_service: sync_service.clone(),
        config,
        telemetry: None,
    })?;

    // Aura authoring
    if role.is_authority() {
        let proposer_factory = sc_basic_authorship::ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool.clone(),
            prometheus_registry.as_ref(),
            None,
        );

        let slot_duration = sc_consensus_aura::slot_duration(&*client)?;

        let aura = sc_consensus_aura::start_aura::<AuraPair, _, _, _, _, _, _, _, _, _, _>(
            StartAuraParams {
                slot_duration,
                client: client.clone(),
                select_chain,
                block_import: grandpa_block_import.clone(),
                proposer_factory,
                create_inherent_data_providers: move |_, ()| async move {
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
                    let slot = sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                        *timestamp,
                        slot_duration,
                    );

                    // Block beneficiary inherent for pallet_block_rewards.
                    // Required for every authored block; reads the beneficiary
                    // address from the SIDECHAIN_BLOCK_BENEFICIARY env var.
                    let block_beneficiary =
                        sp_block_rewards::BlockBeneficiaryInherentProvider::<BeneficiaryId>::from_env(
                            BLOCK_BENEFICIARY_ENV,
                        )?;

                    Ok((slot, timestamp, block_beneficiary))
                },
                force_authoring,
                backoff_authoring_blocks,
                keystore: keystore_container.keystore(),
                sync_oracle: sync_service.clone(),
                justification_sync_link: sync_service.clone(),
                block_proposal_slot_portion: SlotProportion::new(2f32 / 3f32),
                max_block_proposal_slot_portion: None,
                telemetry: None,
                compatibility_mode: Default::default(),
            },
        )?;

        task_manager
            .spawn_essential_handle()
            .spawn_blocking("aura", Some("block-authoring"), aura);
    }

    // Grandpa finality
    if enable_grandpa {
        let grandpa_config = sc_consensus_grandpa::Config {
            gossip_duration: std::time::Duration::from_millis(333),
            justification_generation_period: 512,
            name: Some(name),
            observer_enabled: false,
            keystore: Some(keystore_container.keystore()),
            local_role: role,
            telemetry: None,
            protocol_name: grandpa_protocol_name,
        };

        let grandpa_params = sc_consensus_grandpa::GrandpaParams {
            config: grandpa_config,
            link: grandpa_link,
            network,
            sync: Arc::new(sync_service),
            notification_service: grandpa_notification_service,
            voting_rule: sc_consensus_grandpa::VotingRulesBuilder::default().build(),
            prometheus_registry,
            shared_voter_state: SharedVoterState::empty(),
            telemetry: None,
            offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool),
        };

        task_manager.spawn_essential_handle().spawn_blocking(
            "grandpa-voter",
            None,
            sc_consensus_grandpa::run_grandpa_voter(grandpa_params)?,
        );
    }

    network_starter.start_network();
    Ok(task_manager)
}

/// Build the partial service components (shared between full and light).
pub fn new_partial(
    config: &Configuration,
) -> Result<
    sc_service::PartialComponents<
        FullClient,
        FullBackend,
        FullSelectChain,
        sc_consensus::DefaultImportQueue<Block>,
        sc_transaction_pool::FullPool<Block, FullClient>,
        (
            sc_consensus_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>,
            sc_consensus_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
            Option<()>, // telemetry placeholder
        ),
    >,
    ServiceError,
> {
    let executor = sc_service::new_wasm_executor::<sp_io::SubstrateHostFunctions>(&config.executor);
    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, _>(config, None, executor)?;
    let client = Arc::new(client);

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        config.prometheus_registry(),
        task_manager.spawn_essential_handle(),
        client.clone(),
    );

    let (grandpa_block_import, grandpa_link) = sc_consensus_grandpa::block_import(
        client.clone(),
        512,
        &client,
        select_chain.clone(),
        None,
    )?;

    let slot_duration = sc_consensus_aura::slot_duration(&*client)?;

    let import_queue = sc_consensus_aura::import_queue::<AuraPair, _, _, _, _, _>(
        ImportQueueParams {
            block_import: grandpa_block_import.clone(),
            justification_import: Some(Box::new(grandpa_block_import.clone())),
            client: client.clone(),
            create_inherent_data_providers: move |_, ()| async move {
                let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
                let slot = sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                    *timestamp,
                    slot_duration,
                );
                Ok((slot, timestamp))
            },
            spawner: &task_manager.spawn_essential_handle(),
            registry: config.prometheus_registry(),
            check_for_equivocation: Default::default(),
            telemetry: None,
            compatibility_mode: Default::default(),
        },
    )?;

    Ok(sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (grandpa_block_import, grandpa_link, None),
    })
}
