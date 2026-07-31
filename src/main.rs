use anyhow::Result;
use clap::Parser;

use fedramp_aion::cli::{Cli, Command};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let code = match &cli.command {
        Command::Plan(args) => fedramp_aion::run_plan(args),
        Command::Sync(args) => fedramp_aion::run_sync(args),
        Command::Verify(args) => fedramp_aion::run_verify(args),
        Command::Capture(args) => fedramp_aion::run_capture(args),
        Command::Keygen(args) => fedramp_aion::run_keygen(args),
        Command::Secret(args) => fedramp_aion::run_secret(args),
        Command::Obligations(args) => fedramp_aion::run_obligations(args),
        Command::Receipt(args) => fedramp_aion::run_receipt(args),
        Command::ReceiptVerify(args) => fedramp_aion::run_receipt_verify(args),
        Command::Mcp(args) => fedramp_aion::run_mcp(args),
        Command::Validate(args) => fedramp_aion::run_validate(args),
        Command::Control(args) => fedramp_aion::run_control(args),
        Command::Kev(args) => fedramp_aion::run_kev(args),
    }?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
