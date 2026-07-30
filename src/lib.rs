//! Detect change in FedRAMP's machine-readable sources and emit a signed
//! `.aion` chain. See DESIGN.md for the pipeline and its invariants.

pub mod bundle;
pub mod canon;
pub mod chain;
pub mod cli;
pub mod diff;
pub mod plan;
pub mod report;
pub mod severity;
pub mod sources;

use anyhow::{bail, Result};
use std::path::Path;

use crate::cli::{CaptureArgs, KeygenArgs, PlanArgs, SyncArgs, VerifyArgs};
use crate::plan::Plan;
use crate::sources::Fetcher;

/// Exit code used when `--fail-on` trips. Distinct from 1 (pipeline error).
pub const EXIT_THRESHOLD: i32 = 2;

pub fn fetcher(args: &cli::SourceArgs) -> Fetcher {
    match &args.from_dir {
        Some(root) => Fetcher::Dir { root: root.clone() },
        None => Fetcher::Http {
            token: args.token.clone(),
        },
    }
}

pub fn run_plan(args: &PlanArgs) -> Result<i32> {
    let previous = chain::previous_bundle(&args.chain)?;
    let plan = plan::build(&fetcher(&args.sources), previous.as_ref())?;
    emit_reports(&plan, args, None)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        print!("{}", report::changes_markdown(&plan));
    }
    Ok(threshold_code(&plan, args))
}

pub fn run_sync(args: &SyncArgs) -> Result<i32> {
    let previous = chain::previous_bundle(&args.plan.chain)?;
    let plan = plan::build(&fetcher(&args.plan.sources), previous.as_ref())?;

    if !plan.changed && !args.force {
        emit_reports(&plan, &args.plan, None)?;
        println!("{}", plan.headline());
        return Ok(threshold_code(&plan, &args.plan));
    }

    if args.dry_run {
        emit_reports(&plan, &args.plan, None)?;
        print!("{}", report::changes_markdown(&plan));
        println!("dry run — nothing signed or written");
        return Ok(threshold_code(&plan, &args.plan));
    }

    write_snapshots(&plan, &args.data_dir)?;
    let registry = chain::load_registry(&args.registry)?;
    let signer = chain::Signer {
        author: args.author,
        key: args.key,
        keystore_dir: args.keystore.clone(),
        secret_hex: args.signing_key.clone(),
    };
    let version = chain::commit(
        &args.plan.chain,
        &plan.bundle,
        &report::commit_message(&plan),
        &signer,
        &registry,
    )?;

    let mismatches = chain::digests_match(&plan.bundle, &args.data_dir)?;
    if !mismatches.is_empty() {
        bail!(
            "signed payload disagrees with data/: {}",
            mismatches.join("; ")
        );
    }

    emit_reports(&plan, &args.plan, Some(version))?;
    print!("{}", report::changes_markdown(&plan));
    println!(
        "signed chain version {version} at {}",
        args.plan.chain.display()
    );
    Ok(threshold_code(&plan, &args.plan))
}

pub fn run_verify(args: &VerifyArgs) -> Result<i32> {
    let registry = chain::load_registry(&args.registry)?;
    let report = chain::verify(&args.chain, &registry)?;
    if !report.is_valid {
        bail!("chain is invalid: {:?}", report.errors);
    }
    println!(
        "chain valid — {} version(s), file {:#x}",
        report.version_count, report.file_id.0
    );

    if !args.chain_only {
        let Some(bundle) = chain::previous_bundle(&args.chain)? else {
            bail!("chain has no payload to cross-check");
        };
        let mismatches = chain::digests_match(&bundle, &args.data_dir)?;
        if !mismatches.is_empty() {
            bail!(
                "data/ disagrees with the signed payload: {}",
                mismatches.join("; ")
            );
        }
        println!(
            "data/ matches the signed payload for {} source(s)",
            bundle.sources.len()
        );
    }
    Ok(0)
}

pub fn run_keygen(args: &KeygenArgs) -> Result<i32> {
    if args.registry.exists() {
        bail!(
            "{} already exists — refusing to overwrite a registry in use",
            args.registry.display()
        );
    }
    let secret = chain::keygen(
        args.key,
        args.author,
        args.keystore.as_deref(),
        &args.registry,
    )?;
    println!(
        "key {} created; author {} pinned in {}",
        args.key,
        args.author,
        args.registry.display()
    );
    println!(
        "\ncommit {} — it holds only public keys.",
        args.registry.display()
    );
    if args.print_secret {
        println!(
            "\nStore this as the AION_SIGNING_KEY repository secret. It is shown once,\n\
             is not recoverable from the keystore copy on another machine, and must\n\
             never be committed:\n\n{secret}"
        );
    } else {
        println!("Re-run with --print-secret to reveal the seed for a CI secret.");
    }
    Ok(0)
}

/// Only the seed goes to stdout, so the output can be piped straight into
/// `gh secret set` without a human reading it off the screen.
pub fn run_secret(args: &cli::SecretArgs) -> Result<i32> {
    let secret =
        chain::reveal_secret(args.key, args.author, args.keystore.clone(), &args.registry)?;
    eprintln!(
        "key {} verified against {} — the seed below is on stdout only",
        args.key,
        args.registry.display()
    );
    println!("{secret}");
    Ok(0)
}

pub fn run_capture(args: &CaptureArgs) -> Result<i32> {
    std::fs::create_dir_all(&args.out)?;
    let fetcher = fetcher(&args.sources);
    for spec in sources::SOURCES {
        let snapshot = fetcher.snapshot(spec)?;
        std::fs::write(
            args.out.join(format!("{}.json", spec.id)),
            canon::canonical_bytes(&snapshot.content)?,
        )?;
        std::fs::write(
            args.out.join(format!("{}.provenance.json", spec.id)),
            serde_json::to_vec_pretty(&snapshot.provenance)?,
        )?;
        println!(
            "captured {} @ {} ({} bytes)",
            spec.id, snapshot.provenance.commit, snapshot.provenance.bytes
        );
    }
    Ok(0)
}

/// Canonical per-source snapshots. These are what a reviewer diffs in the PR;
/// `verify` re-derives their digests from the signed payload.
fn write_snapshots(plan: &Plan, data_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(data_dir)?;
    for (id, content) in &plan.bundle.content {
        std::fs::write(
            data_dir.join(format!("{id}.json")),
            canon::canonical_bytes(content)?,
        )?;
    }
    std::fs::write(
        data_dir.join("provenance.json"),
        serde_json::to_vec_pretty(&plan.bundle.sources)?,
    )?;
    Ok(())
}

fn emit_reports(plan: &Plan, args: &PlanArgs, version: Option<u64>) -> Result<()> {
    if let Some(path) = &args.report {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, report::changes_markdown(plan))?;
    }
    if let Some(path) = &args.outputs {
        let mut existing = std::fs::read_to_string(path).unwrap_or_default();
        existing.push_str(&report::github_outputs(plan, version));
        std::fs::write(path, existing)?;
    }
    Ok(())
}

fn threshold_code(plan: &Plan, args: &PlanArgs) -> i32 {
    if report::should_fail(plan.severity, args.fail_on) {
        EXIT_THRESHOLD
    } else {
        0
    }
}
