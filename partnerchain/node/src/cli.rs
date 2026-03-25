use clap::Parser;
use sc_cli::RunCmd;

/// Custom Orinq-specific sub-commands.
#[derive(Debug, clap::Subcommand)]
pub enum OrinqCmd {
    /// Submit a receipt via the node CLI (offline-signed extrinsic).
    SubmitReceipt {
        /// Hex-encoded receipt ID (32 bytes).
        #[arg(long)]
        receipt_id: String,

        /// Hex-encoded content hash (32 bytes).
        #[arg(long)]
        content_hash: String,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
    /// Build a chain specification.
    BuildSpec(sc_cli::BuildSpecCmd),

    /// Validate blocks.
    CheckBlock(sc_cli::CheckBlockCmd),

    /// Export blocks.
    ExportBlocks(sc_cli::ExportBlocksCmd),

    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Import blocks.
    ImportBlocks(sc_cli::ImportBlocksCmd),

    /// Remove the whole chain.
    PurgeChain(sc_cli::PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Orinq-specific commands.
    #[command(subcommand)]
    Orinq(OrinqCmd),

    /// MOTRA capacity token commands.
    #[command(subcommand)]
    Motra(MotraCmd),
}

/// MOTRA CLI sub-commands.
#[derive(Debug, clap::Subcommand)]
pub enum MotraCmd {
    /// Query MOTRA balance for an account.
    Balance {
        /// SS58-encoded account address.
        #[arg(long)]
        account: String,
    },
    /// Set MOTRA delegation target.
    SetDelegatee {
        /// SS58-encoded delegatee address, or "none" to clear.
        #[arg(long)]
        target: String,
    },
}

#[derive(Debug, Parser)]
#[command(
    name = "materios-node",
    about = "Materios Partner Chain node",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: Option<Subcommand>,

    #[command(flatten)]
    pub run: RunCmd,
}
