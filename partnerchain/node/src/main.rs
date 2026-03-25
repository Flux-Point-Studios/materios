//! Materios Partner Chain node binary.

mod chain_spec;
mod chain_spec_preprod;
mod cli;
mod command;
mod rpc;
mod service;

fn main() -> sc_cli::Result<()> {
    command::run()
}
