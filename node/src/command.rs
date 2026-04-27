//! CLI command dispatch.

use crate::chain_spec;
use crate::chain_spec_preprod;
use crate::cli::{Cli, MotraCmd, OrinqCmd, Subcommand};
use crate::service;
use sc_cli::SubstrateCli;
use sc_service::PartialComponents;

impl SubstrateCli for Cli {
    fn impl_name() -> String {
        "Materios Node".into()
    }

    fn impl_version() -> String {
        env!("SUBSTRATE_CLI_IMPL_VERSION").into()
    }

    fn description() -> String {
        "Materios Partner Chain Node".into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "https://github.com/materios/materios/issues".into()
    }

    fn copyright_start_year() -> i32 {
        2024
    }

    fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
        Ok(match id {
            "dev" => Box::new(chain_spec::development_config()?),
            "" | "local" => Box::new(chain_spec::local_testnet_config()?),
            "preprod" => Box::new(chain_spec_preprod::preprod_config()?),
            path => Box::new(chain_spec::ChainSpec::from_json_file(
                std::path::PathBuf::from(path),
            )?),
        })
    }
}

/// Parse and run command line.
pub fn run() -> sc_cli::Result<()> {
    let cli = Cli::from_args();

    match &cli.subcommand {
        Some(Subcommand::BuildSpec(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.chain_spec, config.network))
        }
        Some(Subcommand::CheckBlock(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    import_queue,
                    ..
                } = service::new_partial(&config)?;
                Ok((cmd.run(client, import_queue), task_manager))
            })
        }
        Some(Subcommand::ExportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    ..
                } = service::new_partial(&config)?;
                Ok((cmd.run(client, config.database), task_manager))
            })
        }
        Some(Subcommand::ExportState(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    ..
                } = service::new_partial(&config)?;
                Ok((cmd.run(client, config.chain_spec), task_manager))
            })
        }
        Some(Subcommand::ImportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    import_queue,
                    ..
                } = service::new_partial(&config)?;
                Ok((cmd.run(client, import_queue), task_manager))
            })
        }
        Some(Subcommand::PurgeChain(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.database))
        }
        Some(Subcommand::Revert(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    backend,
                    ..
                } = service::new_partial(&config)?;
                let aux_revert = Box::new(|client, _, blocks| {
                    sc_consensus_grandpa::revert(client, blocks)?;
                    Ok(())
                });
                Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
            })
        }
        Some(Subcommand::Orinq(orinq_cmd)) => match orinq_cmd {
            OrinqCmd::SubmitReceipt {
                receipt_id,
                content_hash,
            } => {
                eprintln!(
                    "Error: CLI receipt submission is not implemented.\n\
                     Use the receipt-builder CLI to construct receipts,\n\
                     then submit via polkadot.js or subxt.\n\
                     (receipt_id={}, content_hash={})",
                    receipt_id, content_hash
                );
                Err("CLI receipt submission not implemented".into())
            }
        },
        Some(Subcommand::Motra(motra_cmd)) => match motra_cmd {
            MotraCmd::Balance { account } => {
                eprintln!(
                    "Error: CLI balance query is not implemented.\n\
                     Use RPC method motra_getBalance instead.\n\
                     Example: curl -X POST http://localhost:9944 \\\n\
                       -H 'Content-Type: application/json' \\\n\
                       -d '{{\"jsonrpc\":\"2.0\",\"method\":\"motra_getBalance\",\"params\":[\"{}\"],\"id\":1}}'",
                    account
                );
                Err("CLI balance query not implemented; use RPC motra_getBalance".into())
            }
            MotraCmd::SetDelegatee { target } => {
                eprintln!(
                    "Error: CLI set-delegatee is not implemented.\n\
                     Submit a motra.setDelegatee extrinsic via polkadot.js or subxt.\n\
                     (target={})",
                    target
                );
                Err("CLI set-delegatee not implemented; submit via polkadot.js".into())
            }
        },
        None => {
            let runner = cli.create_runner(&cli.run)?;
            runner.run_node_until_exit(|config| async move {
                service::new_full::<sc_network::NetworkWorker<materios_runtime::opaque::Block, <materios_runtime::opaque::Block as sp_runtime::traits::Block>::Hash>>(config).map_err(sc_cli::Error::Service)
            })
        }
    }
}
