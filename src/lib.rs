//! Detect change in FedRAMP's machine-readable sources and emit a signed
//! `.aion` chain. See DESIGN.md for the pipeline and its invariants.

pub mod bundle;
pub mod canon;
pub mod chain;
pub mod cli;
pub mod diff;
pub mod mcp;
pub mod obligations;
pub mod plan;
pub mod receipt;
pub mod report;
pub mod severity;
pub mod sources;
pub mod validate;

use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::cli::{
    CaptureArgs, KeygenArgs, ObligationArgs, PlanArgs, ReceiptArgs, ReceiptVerifyArgs, SyncArgs,
    VerifyArgs,
};
use crate::plan::Plan;
use crate::sources::Fetcher;

/// Write to stdout, treating a closed pipe as success rather than a panic.
/// `head` closing the pipe is normal use, not an error.
fn emit(text: &str) -> Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => Ok(other?),
    }
}

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
        emit(&report::changes_markdown(&plan))?;
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
    if args.registry.exists() && !args.append {
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

/// Reads the ruleset from the signed chain by default, so what is listed is
/// what was signed — not whatever is on disk.
pub fn run_obligations(args: &ObligationArgs) -> Result<i32> {
    let rules: serde_json::Value = if let Some(path) = &args.rules {
        canon::canonicalize(&std::fs::read(path)?)?
    } else {
        let bundle = chain::previous_bundle(&args.chain)?
            .ok_or_else(|| anyhow::anyhow!("no chain at {}", args.chain.display()))?;
        bundle
            .section(sources::RULES)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("chain payload has no rules section"))?
    };

    let profile = obligations::Profile {
        role: args.role.clone(),
        class: args.class.clone(),
        cert_type: args.cert_type.clone(),
        path: args.path.clone(),
    };
    let selected: Vec<obligations::Obligation> = obligations::select(&rules, &profile)
        .into_iter()
        .filter(|o| {
            args.force
                .as_ref()
                .is_none_or(|f| o.force.eq_ignore_ascii_case(f))
        })
        .filter(|o| !args.with_schema || o.schema.is_some())
        .collect();

    if args.json {
        return emit(&format!("{}\n", serde_json::to_string_pretty(&selected)?)).map(|()| 0);
    }
    emit(&report::obligations_markdown(&profile, &selected))?;
    Ok(0)
}

/// Signs with the operator's own key so the receipt is attributable to them,
/// not to the feed.
pub fn run_receipt(args: &ReceiptArgs) -> Result<i32> {
    anyhow::ensure!(
        args.operator != args.feed_author,
        "operator {} must differ from the feed author — a receipt signed by the \
         feed attests to nothing",
        args.operator
    );

    let bundle = chain::previous_bundle(&args.chain)?
        .ok_or_else(|| anyhow::anyhow!("no chain at {}", args.chain.display()))?;
    let registry = chain::load_registry(&args.registry)?;
    let report = chain::verify(&args.chain, &registry)?;
    anyhow::ensure!(
        report.is_valid,
        "refusing to issue a receipt against an invalid chain"
    );

    let rules = bundle
        .section(sources::RULES)
        .ok_or_else(|| anyhow::anyhow!("chain payload has no rules section"))?;
    let profile = obligations::Profile {
        role: args.role.clone(),
        class: args.class.clone(),
        cert_type: args.cert_type.clone(),
        path: args.path.clone(),
    };
    let mut selected = obligations::select(rules, &profile);
    if !args.obligations.is_empty() {
        let wanted: std::collections::BTreeSet<&str> =
            args.obligations.iter().map(String::as_str).collect();
        let found: Vec<String> = selected.iter().map(|o| o.id.clone()).collect();
        for id in &wanted {
            anyhow::ensure!(
                found.iter().any(|f| f == id),
                "{id} is not an obligation for {} — a receipt cannot cite a rule \
                 that does not apply",
                profile.label()
            );
        }
        selected.retain(|o| wanted.contains(o.id.as_str()));
    }

    let evidence: Vec<receipt::EvidenceRef> = args
        .evidence
        .iter()
        .map(|p| receipt::evidence_ref(p))
        .collect::<Result<_>>()?;

    let signer = chain::Signer {
        author: args.operator,
        key: args.key,
        keystore_dir: args.keystore.clone(),
        secret_hex: args.signing_key.clone(),
    };
    let sealed = receipt::create(
        &receipt::Inputs {
            action: &args.action,
            decision: receipt::parse_decision(&args.decision)?,
            operator: args.operator,
            receipt_version: args.receipt_version,
            profile: &profile,
            obligations: &selected,
            evidence: &evidence,
            bundle: &bundle,
            file_id: report.file_id.0,
            chain_version: report.version_count,
        },
        &signer.load_key()?,
        args.feed_author,
    )?;

    std::fs::write(&args.out, serde_json::to_vec_pretty(&sealed)?)?;
    println!(
        "receipt written to {} — {} obligation(s), chain v{}, operator {}",
        args.out.display(),
        sealed.claim.obligations.len(),
        sealed.claim.rules.chain_version,
        args.operator
    );
    Ok(0)
}

pub fn run_receipt_verify(args: &ReceiptVerifyArgs) -> Result<i32> {
    let sealed: receipt::Receipt = serde_json::from_slice(&std::fs::read(&args.receipt)?)
        .with_context(|| format!("reading {}", args.receipt.display()))?;
    let registry = chain::load_registry(&args.registry)?;

    let chain_context = if args.no_chain {
        None
    } else {
        let bundle = chain::previous_bundle(&args.chain)?
            .ok_or_else(|| anyhow::anyhow!("no chain at {}", args.chain.display()))?;
        let report = chain::verify(&args.chain, &registry)?;
        Some((bundle, report.file_id.0, report.version_count))
    };
    let verdict = receipt::verify(
        &sealed,
        &registry,
        chain_context.as_ref().map(|(b, f, v)| (b, *f, *v)),
    )?;

    if args.json {
        emit(&format!("{}\n", serde_json::to_string_pretty(&verdict)?))?;
    } else {
        emit(&receipt::verdict_markdown(&sealed, &verdict))?;
    }
    Ok(i32::from(!verdict.is_valid()))
}

/// Serve MCP on stdio. The chain is loaded and verified once, so every answer
/// in a session cites the same signed version.
pub fn run_mcp(args: &cli::McpArgs) -> Result<i32> {
    let server = mcp::Server::load(&args.chain, &args.registry)?;
    mcp::serve(&server)?;
    Ok(0)
}

/// Validate a package offline against the signed schemas, optionally sealing
/// the verdict into a receipt.
pub fn run_validate(args: &cli::ValidateArgs) -> Result<i32> {
    let bundle = chain::previous_bundle(&args.chain)?
        .ok_or_else(|| anyhow::anyhow!("no chain at {}", args.chain.display()))?;
    let schemas = validate::SchemaSet::from_bundle(&bundle)?;

    if args.list_schemas {
        emit(&format!("{}\n", schemas.names().join("\n")))?;
        return Ok(0);
    }

    let package_bytes = std::fs::read(&args.package)
        .with_context(|| format!("reading {}", args.package.display()))?;
    let package: serde_json::Value = serde_json::from_slice(&package_bytes)
        .with_context(|| format!("{} is not valid JSON", args.package.display()))?;
    let schema_name = schemas.resolve_name(args.schema.as_deref(), &package)?;

    let report = validate::validate(
        &schemas,
        bundle.section(sources::RULES),
        &schema_name,
        &package_bytes,
        &args.package.display().to_string(),
    )?;

    if args.json {
        emit(&format!("{}\n", serde_json::to_string_pretty(&report)?))?;
    } else {
        emit(&validate::report_markdown(&report))?;
    }

    if let Some(path) = &args.receipt {
        issue_validation_receipt(args, &bundle, &report, path)?;
    }
    Ok(if report.valid { 0 } else { EXIT_THRESHOLD })
}

/// The receipt cites the rules that require the artifact, so the verdict is a
/// compliance statement rather than a syntax check.
fn issue_validation_receipt(
    args: &cli::ValidateArgs,
    bundle: &bundle::Bundle,
    report: &validate::Report,
    out: &Path,
) -> Result<()> {
    let (Some(operator), Some(key)) = (args.operator, args.key) else {
        bail!("--receipt requires --operator and --key");
    };
    let registry = chain::load_registry(&args.registry)?;
    let chain_report = chain::verify(&args.chain, &registry)?;

    let profile = obligations::Profile {
        role: args.role.clone(),
        class: args.class.clone(),
        cert_type: args.cert_type.clone(),
        path: None,
    };
    let cited: Vec<obligations::Obligation> = bundle
        .section(sources::RULES)
        .map(|rules| obligations::select(rules, &profile))
        .unwrap_or_default()
        .into_iter()
        .filter(|o| report.required_by.contains(&o.id))
        .collect();

    let signer = chain::Signer {
        author: operator,
        key,
        keystore_dir: args.keystore.clone(),
        secret_hex: args.signing_key.clone(),
    };
    let sealed = receipt::create(
        &receipt::Inputs {
            action: &format!(
                "Validated {} against {} — {}",
                report.package,
                report.schema,
                if report.valid {
                    "conformant"
                } else {
                    "non-conformant"
                }
            ),
            decision: if report.valid {
                receipt::Decision::Satisfied
            } else {
                receipt::Decision::NotSatisfied
            },
            operator,
            receipt_version: 1,
            profile: &profile,
            obligations: &cited,
            evidence: &[receipt::EvidenceRef {
                name: report.package.clone(),
                blake3: crate::canon::hex(blake3::hash(&std::fs::read(&args.package)?).as_bytes()),
                bytes: report.bytes,
            }],
            bundle,
            file_id: chain_report.file_id.0,
            chain_version: chain_report.version_count,
        },
        &signer.load_key()?,
        args.feed_author,
    )?;
    std::fs::write(out, serde_json::to_vec_pretty(&sealed)?)?;
    println!(
        "receipt written to {} — citing {} rule(s)",
        out.display(),
        cited.len()
    );
    Ok(())
}

/// FedRAMP amends 800-53 controls without restating them; this joins the two
/// halves from the same signed payload.
pub fn run_control(args: &cli::ControlArgs) -> Result<i32> {
    let bundle = chain::previous_bundle(&args.chain)?
        .ok_or_else(|| anyhow::anyhow!("no chain at {}", args.chain.display()))?;
    let catalog = bundle
        .section(sources::OSCAL)
        .ok_or_else(|| anyhow::anyhow!("chain has no oscal section; re-sync to add it"))?;
    let id = diff::oscal::normalise_id(&args.id);
    let controls = diff::oscal::flatten(catalog);
    let control = controls
        .get(&id)
        .ok_or_else(|| anyhow::anyhow!("no 800-53 control `{id}`"))?;

    let rules = bundle.section(sources::RULES);
    let referenced = rules.map(|r| diff::oscal::referenced_controls(r).contains(&id));

    if args.json {
        emit(&format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "id": id, "control": control, "referenced_by_fedramp": referenced
            }))?
        ))?;
        return Ok(0);
    }

    let title = control
        .get("title")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(untitled)");
    let mut out = format!("# {id} — {title}\n\n");
    if referenced == Some(true) {
        out.push_str("FedRAMP references this control.\n\n");
    }
    for part in control
        .get("parts")
        .and_then(serde_json::Value::as_array)
        .unwrap_or(&Vec::new())
    {
        if let Some(prose) = part.get("prose").and_then(serde_json::Value::as_str) {
            out.push_str(prose);
            out.push_str("\n\n");
        }
    }
    emit(&out)?;
    Ok(0)
}

/// FedRAMP requires action on known exploited vulnerabilities but does not
/// carry the list; this joins CISA's catalog to the rules that govern it.
pub fn run_kev(args: &cli::KevArgs) -> Result<i32> {
    let bundle = chain::previous_bundle(&args.chain)?
        .ok_or_else(|| anyhow::anyhow!("no chain at {}", args.chain.display()))?;
    let catalog = bundle
        .section(sources::KEV)
        .ok_or_else(|| anyhow::anyhow!("chain has no kev section; re-sync to add it"))?;
    let entries = diff::kev::flatten(catalog);
    let governing = bundle
        .section(sources::RULES)
        .map(diff::kev::governing_rules)
        .unwrap_or_default();

    if let Some(cve) = &args.cve {
        let entry = entries
            .get(&cve.to_ascii_uppercase())
            .ok_or_else(|| anyhow::anyhow!("{cve} is not in the signed KEV catalog"))?;
        let payload = serde_json::json!({
            "cve": cve.to_ascii_uppercase(),
            "entry": entry,
            "governed_by": governing,
        });
        if args.json {
            emit(&format!("{}\n", serde_json::to_string_pretty(&payload)?))?;
        } else {
            let field = |k: &str| {
                entry
                    .get(k)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("—")
            };
            emit(&format!(
                "# {} — known exploited\n\n{} {}\n{}\n\ndue: {}\nransomware: {}\nrequired action: {}\n\ngoverned by: {}\n",
                cve.to_ascii_uppercase(),
                field("vendorProject"),
                field("product"),
                field("vulnerabilityName"),
                field("dueDate"),
                field("knownRansomwareCampaignUse"),
                field("requiredAction"),
                if governing.is_empty() { "—".to_string() } else { governing.join(", ") },
            ))?;
        }
        return Ok(0);
    }

    let due: Vec<&String> = args
        .due_before
        .as_ref()
        .map(|cutoff| {
            entries
                .iter()
                .filter(|(_, e)| {
                    e.get("dueDate")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|d| d <= cutoff.as_str())
                })
                .map(|(id, _)| id)
                .collect()
        })
        .unwrap_or_default();
    emit(&format!(
        "{} known exploited vulnerabilities in the signed catalog\ngoverned by: {}\n{}",
        entries.len(),
        if governing.is_empty() {
            "—".to_string()
        } else {
            governing.join(", ")
        },
        args.due_before.as_ref().map_or(String::new(), |c| format!(
            "{} due on or before {}\n",
            due.len(),
            c
        )),
    ))?;
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
