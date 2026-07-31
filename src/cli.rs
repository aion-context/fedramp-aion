//! Command surface.
//!
//! `plan` is read-only and is what the logic is iterated against; `sync` is
//! the same pipeline with the signing and writing steps enabled.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::severity::Severity;

#[derive(Parser, Debug)]
#[command(name = "fedramp-aion", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Fetch, diff against the chain, and report. Writes nothing.
    Plan(PlanArgs),
    /// Plan, then sign a new chain version and write the snapshots.
    Sync(SyncArgs),
    /// Verify the chain and that `data/` matches what was signed.
    Verify(VerifyArgs),
    /// Save the current upstream snapshots for offline replay.
    Capture(CaptureArgs),
    /// Create the signing key and the registry that pins it.
    Keygen(KeygenArgs),
    /// Print an existing key's seed on stdout, for piping into a CI secret.
    Secret(SecretArgs),
    /// List the obligations that apply to a given profile.
    Obligations(ObligationArgs),
    /// Sign a receipt binding an action to the obligations in force.
    Receipt(ReceiptArgs),
    /// Verify a receipt: signature, claim binding, and the cited rules.
    ReceiptVerify(ReceiptVerifyArgs),
    /// Serve the signed ruleset to agents over MCP (stdio).
    Mcp(McpArgs),
}

#[derive(Args, Debug)]
pub struct McpArgs {
    #[arg(long, default_value = "fedramp.aion")]
    pub chain: PathBuf,
    #[arg(long, default_value = "registry.json")]
    pub registry: PathBuf,
}

#[derive(Args, Debug)]
pub struct ReceiptArgs {
    /// What was done, in the operator's own words.
    #[arg(long)]
    pub action: String,
    /// satisfied, not-satisfied, compensating, unevaluated.
    #[arg(long, default_value = "satisfied")]
    pub decision: String,
    /// Operator author id — must differ from the feed author.
    #[arg(long)]
    pub operator: u64,
    /// Keystore key id the operator signs with.
    #[arg(long)]
    pub key: u64,
    /// Monotonic counter per operator, for replay defence.
    #[arg(long, default_value_t = 1)]
    pub receipt_version: u64,
    /// Rule ids this receipt covers. Repeatable; defaults to the whole profile.
    #[arg(long = "obligation", value_name = "ID")]
    pub obligations: Vec<String>,
    /// Files to commit by digest. Contents are never read into the receipt.
    #[arg(long = "evidence", value_name = "FILE")]
    pub evidence: Vec<PathBuf>,
    #[arg(long, default_value = "Providers")]
    pub role: String,
    #[arg(long)]
    pub class: Option<String>,
    #[arg(long = "type", value_name = "TYPE")]
    pub cert_type: Option<String>,
    #[arg(long)]
    pub path: Option<String>,
    /// Author id of the feed that signed the chain.
    #[arg(long, default_value_t = 1)]
    pub feed_author: u64,
    #[arg(long, default_value = "fedramp.aion")]
    pub chain: PathBuf,
    #[arg(long, default_value = "registry.json")]
    pub registry: PathBuf,
    #[arg(long, env = "AION_KEYSTORE_DIR", value_name = "DIR")]
    pub keystore: Option<PathBuf>,
    /// Hex Ed25519 seed, in place of a keystore.
    #[arg(
        long,
        env = "AION_OPERATOR_KEY",
        hide_env_values = true,
        value_name = "HEX"
    )]
    pub signing_key: Option<String>,
    #[arg(long, short, default_value = "receipt.json")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct ReceiptVerifyArgs {
    pub receipt: PathBuf,
    #[arg(long, default_value = "registry.json")]
    pub registry: PathBuf,
    /// Chain to cross-check the cited rules against.
    #[arg(long, default_value = "fedramp.aion")]
    pub chain: PathBuf,
    /// Verify the signature and claim binding only.
    #[arg(long)]
    pub no_chain: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ObligationArgs {
    /// Party the rules apply to: Providers, Agencies, Assessors, Advisors, FedRAMP.
    #[arg(long, default_value = "Providers")]
    pub role: String,
    /// Certification class A-D. Omitted means any, reporting the strictest variant.
    #[arg(long)]
    pub class: Option<String>,
    /// Certification type: 20x or Rev5.
    #[arg(long = "type", value_name = "TYPE")]
    pub cert_type: Option<String>,
    /// Authorization path: Program or Agency.
    #[arg(long)]
    pub path: Option<String>,
    /// Only obligations at this force, e.g. MUST.
    #[arg(long)]
    pub force: Option<String>,
    /// Only obligations that bind a machine-readable artifact.
    #[arg(long)]
    pub with_schema: bool,
    /// Read rules from this file instead of the chain.
    #[arg(long, value_name = "FILE")]
    pub rules: Option<PathBuf>,
    /// Chain to read the signed ruleset from.
    #[arg(long, default_value = "fedramp.aion")]
    pub chain: PathBuf,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SecretArgs {
    /// Keystore key id to reveal.
    #[arg(long, default_value_t = 1)]
    pub key: u64,
    /// Author the key must be pinned for in the registry.
    #[arg(long, default_value_t = 1)]
    pub author: u64,
    #[arg(long, env = "AION_KEYSTORE_DIR", value_name = "DIR")]
    pub keystore: Option<PathBuf>,
    /// Registry the key is checked against.
    #[arg(long, default_value = "registry.json")]
    pub registry: PathBuf,
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Keystore key id to create.
    #[arg(long)]
    pub key: u64,
    /// Author id to pin in the registry.
    #[arg(long)]
    pub author: u64,
    #[arg(long, env = "AION_KEYSTORE_DIR", value_name = "DIR")]
    pub keystore: Option<PathBuf>,
    /// Registry file to write.
    #[arg(long, default_value = "registry.json")]
    pub registry: PathBuf,
    /// Print the seed once so it can be stored as a CI secret.
    #[arg(long)]
    pub print_secret: bool,
    /// Add this author to an existing registry instead of refusing.
    #[arg(long)]
    pub append: bool,
}

#[derive(Args, Debug)]
pub struct SourceArgs {
    /// Replay snapshots from a directory instead of fetching.
    #[arg(long, value_name = "DIR")]
    pub from_dir: Option<PathBuf>,
    /// GitHub token, only needed to lift the anonymous rate limit.
    #[arg(long, env = "GITHUB_TOKEN", hide_env_values = true)]
    pub token: Option<String>,
}

#[derive(Args, Debug)]
pub struct PlanArgs {
    #[command(flatten)]
    pub sources: SourceArgs,
    /// Chain to compare against. Absent file means genesis.
    #[arg(long, default_value = "fedramp.aion")]
    pub chain: PathBuf,
    /// Emit the plan as JSON instead of Markdown.
    #[arg(long)]
    pub json: bool,
    /// Write `key=value` lines here (use `$GITHUB_OUTPUT` in CI).
    #[arg(long, value_name = "FILE")]
    pub outputs: Option<PathBuf>,
    /// Write the Markdown report here.
    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,
    /// Exit 2 when the detected severity is at least this loud.
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<Severity>,
}

#[derive(Args, Debug)]
pub struct SyncArgs {
    #[command(flatten)]
    pub plan: PlanArgs,
    /// Author id recorded in the chain.
    #[arg(long)]
    pub author: u64,
    /// Keystore key id used to sign.
    #[arg(long)]
    pub key: u64,
    /// Trusted key registry (RFC-0034).
    #[arg(long, default_value = "registry.json")]
    pub registry: PathBuf,
    /// Directory for canonical per-source snapshots.
    #[arg(long, default_value = "data")]
    pub data_dir: PathBuf,
    /// File-backed keystore directory. Required wherever no OS keyring exists.
    #[arg(long, env = "AION_KEYSTORE_DIR", value_name = "DIR")]
    pub keystore: Option<PathBuf>,
    /// Hex Ed25519 seed to sign with, in place of any keystore. Key files are
    /// encrypted to the machine that made them, so CI supplies the seed.
    #[arg(
        long,
        env = "AION_SIGNING_KEY",
        hide_env_values = true,
        value_name = "HEX"
    )]
    pub signing_key: Option<String>,
    /// Commit even when nothing moved.
    #[arg(long)]
    pub force: bool,
    /// Run the whole pipeline but do not sign or write.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(long, default_value = "fedramp.aion")]
    pub chain: PathBuf,
    #[arg(long, default_value = "registry.json")]
    pub registry: PathBuf,
    #[arg(long, default_value = "data")]
    pub data_dir: PathBuf,
    /// Skip the `data/` cross-check and verify only the signature chain.
    #[arg(long)]
    pub chain_only: bool,
}

#[derive(Args, Debug)]
pub struct CaptureArgs {
    #[command(flatten)]
    pub sources: SourceArgs,
    /// Destination directory.
    #[arg(long, short, default_value = "snapshots")]
    pub out: PathBuf,
}
