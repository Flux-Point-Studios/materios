//! Materios Partner Chain node binary.

mod chain_spec;
mod chain_spec_preprod;
mod cli;
mod command;
mod inherent_data;
mod main_chain_follower;
mod rpc;
mod service;

fn main() -> sc_cli::Result<()> {
    command::run()
}
