//! End-to-end pipeline: genesis, no-op reruns, classified changes, tamper
//! detection. Runs entirely offline against fixture snapshots.

use std::path::PathBuf;

use fedramp_aion::cli::{PlanArgs, SourceArgs, SyncArgs, VerifyArgs};
use fedramp_aion::{chain, severity::Severity};
use serde_json::{json, Value};

struct Workspace {
    root: PathBuf,
    secret: String,
}

impl Workspace {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("fedramp-aion-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("upstream")).unwrap();
        let mut workspace = Self {
            root,
            secret: String::new(),
        };
        workspace.secret = chain::keygen(
            42,
            42,
            Some(&workspace.root.join("keys")),
            &workspace.root.join("registry.json"),
        )
        .unwrap();
        workspace
    }

    fn path(&self, rest: &str) -> PathBuf {
        self.root.join(rest)
    }

    fn publish(&self, rules: &Value, schemas: &Value, marketplace: &Value) {
        for (name, value) in [
            ("rules", rules),
            ("schemas", schemas),
            ("marketplace", marketplace),
            ("oscal", &oscal()),
            ("kev", &kev()),
        ] {
            std::fs::write(
                self.path(&format!("upstream/{name}.json")),
                serde_json::to_vec(value).unwrap(),
            )
            .unwrap();
        }
    }

    fn sync(&self) -> SyncArgs {
        SyncArgs {
            plan: PlanArgs {
                sources: SourceArgs {
                    from_dir: Some(self.path("upstream")),
                    token: None,
                },
                chain: self.path("fedramp.aion"),
                json: false,
                outputs: Some(self.path("outputs.txt")),
                report: Some(self.path("CHANGES.md")),
                fail_on: None,
            },
            author: 42,
            key: 42,
            registry: self.path("registry.json"),
            data_dir: self.path("data"),
            keystore: Some(self.path("keys")),
            signing_key: None,
            force: false,
            dry_run: false,
        }
    }

    fn run_sync(&self) -> i32 {
        let _ = std::fs::remove_file(self.path("outputs.txt"));
        fedramp_aion::run_sync(&self.sync()).unwrap()
    }

    fn outputs(&self) -> String {
        std::fs::read_to_string(self.path("outputs.txt")).unwrap()
    }

    fn chain_version(&self) -> u64 {
        let registry = chain::load_registry(&self.path("registry.json")).unwrap();
        chain::verify(&self.path("fedramp.aion"), &registry)
            .unwrap()
            .version_count
    }

    fn verify(&self) -> anyhow::Result<i32> {
        fedramp_aion::run_verify(&VerifyArgs {
            chain: self.path("fedramp.aion"),
            registry: self.path("registry.json"),
            data_dir: self.path("data"),
            chain_only: false,
        })
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn rules(version: &str, force: &str) -> Value {
    json!({
        "info": {"version": version, "last_updated": "2026-07-14"},
        "CPO": {"info": {"subsets": {}}},
        "FRD": {"data": {"all": {"FRD-ACV": {"term": "Accepted Vulnerability", "definition": "d"}}}},
        "FRR": {"VDR": {
            "info": {"name": "Vulnerability Detection and Response", "status": "stable"},
            "data": {"all": {"FRP": {"VDR-FRP-ONE": {"statement": "s", "force": force}}}}}},
        "KSI": {"CED": {"status": "stable", "indicators": {"KSI-CED-RAT": {"statement": "x"}}}},
        "CTL": {"AC": {"AC-20": {"guidance": ["g"]}}}
    })
}

fn schemas() -> Value {
    json!({"fedramp-incident-report-schema-2026-06-24.json": {
        "$id": "https://fedramp.gov/schemas/fedramp-incident-report-schema-2026-06-24.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["incident_id"],
        "properties": {"incident_id": {"type": "string"}}}})
}

/// A minimal 800-53 catalog carrying the control the fixture rules reference.
fn oscal() -> Value {
    json!({"catalog": {
        "uuid": "11111111-1111-1111-1111-111111111111",
        "metadata": {"version": "5.2.0", "last-modified": "2026-05-11T16:01:09.00000-00:00",
                     "oscal-version": "1.2.2"},
        "groups": [{"id": "cp", "title": "Contingency Planning", "controls": [
            {"id": "cp-3", "title": "Contingency Training"}]}]}})
}

fn kev() -> Value {
    json!({"catalogVersion": "2026.07.29", "dateReleased": "2026-07-29T18:45:59.5809Z", "count": 1,
           "vulnerabilities": [{"cveID": "CVE-2026-20316", "vendorProject": "Cisco",
                                "dueDate": "2026-08-19", "knownRansomwareCampaignUse": "Unknown"}]})
}

fn marketplace(last_change: &str, reuse: i64, status: &str) -> Value {
    json!({
        "meta": {"last_change": last_change, "produced_by": "General Services Administration"},
        "data": {
            "Metrics": {"ready": 69, "total": 530},
            "Products": [{"id": "F1", "name": "Salesforce", "status": status, "reuse": reuse}],
            "ReuseMapping": [{"id": "AG", "agency_id": 1}, {"id": "AG", "agency_id": 1}]
        }
    })
}

fn severity_of(outputs: &str) -> Severity {
    outputs
        .lines()
        .find_map(|line| line.strip_prefix("severity="))
        .unwrap()
        .parse()
        .unwrap()
}

fn changed(outputs: &str) -> bool {
    outputs.contains("changed=true")
}

#[test]
fn genesis_then_daily_rewrites_then_real_changes() {
    let workspace = Workspace::new("lifecycle");

    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();
    assert_eq!(workspace.chain_version(), 1);
    assert!(workspace.outputs().contains("genesis=true"));
    workspace.verify().unwrap();

    // A rerun against identical upstream must not append a version.
    workspace.run_sync();
    assert_eq!(workspace.chain_version(), 1);
    assert!(!changed(&workspace.outputs()));

    // The daily marketplace rewrite with no content movement is a no-op.
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-24T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();
    assert_eq!(workspace.chain_version(), 1);

    // A counter tick is real but routine.
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-25T06:27:00Z", 314, "Authorized"),
    );
    workspace.run_sync();
    assert_eq!(workspace.chain_version(), 2);
    assert_eq!(severity_of(&workspace.outputs()), Severity::Routine);

    // A force transition outranks concurrent marketplace churn.
    workspace.publish(
        &rules("2026.08.01.01", "MUST"),
        &schemas(),
        &marketplace("2026-07-26T06:27:00Z", 315, "Authorized"),
    );
    workspace.run_sync();
    assert_eq!(workspace.chain_version(), 3);
    let outputs = workspace.outputs();
    assert_eq!(severity_of(&outputs), Severity::Major);
    assert!(outputs.contains("rules_changed=true"));

    let report = std::fs::read_to_string(workspace.path("CHANGES.md")).unwrap();
    assert!(report.contains("`SHOULD` → `MUST`"));
    assert!(report.contains("was `2026.07.14.01`"));

    workspace.verify().unwrap();
}

#[test]
fn marketplace_status_change_is_minor_not_routine() {
    let workspace = Workspace::new("status");
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "In Process"),
    );
    workspace.run_sync();
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-24T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();
    assert_eq!(severity_of(&workspace.outputs()), Severity::Minor);
    assert_eq!(workspace.chain_version(), 2);
}

#[test]
fn schema_revision_is_major() {
    let workspace = Workspace::new("schemas");
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &json!({"fedramp-incident-report-schema-2026-09-01.json": {
            "type": "object", "required": ["incident_id", "reported_at"]}}),
        &marketplace("2026-07-24T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();
    assert_eq!(severity_of(&workspace.outputs()), Severity::Major);
    assert!(std::fs::read_to_string(workspace.path("CHANGES.md"))
        .unwrap()
        .contains("2026-09-01"));
}

#[test]
fn edited_snapshot_fails_verification() {
    let workspace = Workspace::new("tamper");
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();
    workspace.verify().unwrap();

    let snapshot = workspace.path("data/rules.json");
    let edited = std::fs::read_to_string(&snapshot)
        .unwrap()
        .replace("SHOULD", "MUST");
    std::fs::write(&snapshot, edited).unwrap();

    let error = workspace.verify().unwrap_err().to_string();
    assert!(
        error.contains("disagrees with the signed payload"),
        "{error}"
    );
}

#[test]
fn a_missing_source_aborts_without_committing() {
    let workspace = Workspace::new("missing");
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();
    std::fs::remove_file(workspace.path("upstream/marketplace.json")).unwrap();

    let error = fedramp_aion::run_sync(&workspace.sync()).unwrap_err();
    assert!(error.to_string().contains("marketplace.json"), "{error}");
    assert_eq!(workspace.chain_version(), 1);
}

#[test]
fn malformed_upstream_json_aborts_without_committing() {
    let workspace = Workspace::new("malformed");
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();
    std::fs::write(
        workspace.path("upstream/rules.json"),
        b"<!doctype html><html>rate limited</html>",
    )
    .unwrap();

    let error = fedramp_aion::run_sync(&workspace.sync()).unwrap_err();
    assert!(error.to_string().contains("not valid JSON"), "{error}");
    assert_eq!(workspace.chain_version(), 1);
}

#[test]
fn fail_on_threshold_signals_without_blocking_the_commit() {
    let workspace = Workspace::new("threshold");
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();

    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-24T06:27:00Z", 314, "Authorized"),
    );
    let mut args = workspace.sync();
    args.plan.fail_on = Some(Severity::Minor);
    assert_eq!(fedramp_aion::run_sync(&args).unwrap(), 0);

    args.plan.fail_on = Some(Severity::Routine);
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-25T06:27:00Z", 315, "Authorized"),
    );
    assert_eq!(
        fedramp_aion::run_sync(&args).unwrap(),
        fedramp_aion::EXIT_THRESHOLD
    );
    assert_eq!(workspace.chain_version(), 3);
}

#[test]
fn revealed_secret_matches_the_pinned_registry_and_signs() {
    let workspace = Workspace::new("reveal");
    let revealed = chain::reveal_secret(
        42,
        42,
        Some(workspace.path("keys")),
        &workspace.path("registry.json"),
    )
    .unwrap();
    assert_eq!(revealed, workspace.secret);

    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );
    let mut args = workspace.sync();
    args.keystore = None;
    args.signing_key = Some(revealed);
    fedramp_aion::run_sync(&args).unwrap();
    workspace.verify().unwrap();
}

#[test]
fn revealing_a_key_the_registry_does_not_pin_is_refused() {
    let workspace = Workspace::new("reveal-mismatch");
    chain::keygen(
        99,
        99,
        Some(&workspace.path("keys")),
        &workspace.path("other-registry.json"),
    )
    .unwrap();

    // Key 99 exists, but the committed registry pins author 42's key only.
    let error = chain::reveal_secret(
        99,
        42,
        Some(workspace.path("keys")),
        &workspace.path("registry.json"),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("does not match any epoch"), "{error}");
}

/// A rule change must report who it lands on, not merely that it happened.
#[test]
fn a_rule_change_reports_the_affected_profiles() {
    let workspace = Workspace::new("obligations");
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();

    workspace.publish(
        &rules("2026.08.01.01", "MUST"),
        &schemas(),
        &marketplace("2026-07-24T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();

    let report = std::fs::read_to_string(workspace.path("CHANGES.md")).unwrap();
    assert!(report.contains("## Who this affects"), "{report}");
    // The SHOULD -> MUST must surface as a binding shift on a real profile row,
    // not merely as a header.
    let row = report
        .lines()
        .find(|l| l.starts_with("| Providers, class B, type Rev5 |"))
        .unwrap_or_else(|| panic!("no provider row in:\n{report}"));
    assert!(
        row.ends_with("| 1 |"),
        "expected one binding shift, got: {row}"
    );
}

/// Marketplace-only churn must not produce an obligation section at all.
#[test]
fn marketplace_churn_reports_no_obligation_impact() {
    let workspace = Workspace::new("obligations-quiet");
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();

    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-24T06:27:00Z", 314, "Authorized"),
    );
    workspace.run_sync();

    let report = std::fs::read_to_string(workspace.path("CHANGES.md")).unwrap();
    assert!(!report.contains("## Who this affects"), "{report}");
}

// ---- validator ------------------------------------------------------------

/// The published schemas reference definitions by a path that 404s. Validation
/// must resolve them offline and record the deviation.
#[test]
fn validation_resolves_the_broken_refs_offline_and_records_repairs() {
    let workspace = seeded_workspace("validate");
    let bundle = fedramp_aion::chain::previous_bundle(&workspace.path("fedramp.aion"))
        .unwrap()
        .unwrap();
    let schemas = fedramp_aion::validate::SchemaSet::from_bundle(&bundle).unwrap();

    let package = serde_json::to_vec(&json!({"incident_id": "INC-1"})).unwrap();
    let report = fedramp_aion::validate::validate(
        &schemas,
        bundle.section("rules"),
        "fedramp-incident-report-schema-2026-06-24.json",
        &package,
        "incident.json",
    )
    .unwrap();
    assert!(report.valid, "{:?}", report.findings);
    assert_eq!(report.package_sha256.len(), 64);
}

#[test]
fn a_nonconformant_package_reports_findings_by_pointer() {
    let workspace = seeded_workspace("validate-bad");
    let bundle = fedramp_aion::chain::previous_bundle(&workspace.path("fedramp.aion"))
        .unwrap()
        .unwrap();
    let schemas = fedramp_aion::validate::SchemaSet::from_bundle(&bundle).unwrap();

    let package = serde_json::to_vec(&json!({})).unwrap();
    let report = fedramp_aion::validate::validate(
        &schemas,
        None,
        "fedramp-incident-report-schema-2026-06-24.json",
        &package,
        "empty.json",
    )
    .unwrap();
    assert!(!report.valid);
    assert!(!report.findings.is_empty());
    assert!(report.findings[0].message.contains("incident_id"));
}

// ---- receipts -------------------------------------------------------------

fn issue_receipt(
    workspace: &Workspace,
    operator: u64,
    action: &str,
) -> fedramp_aion::receipt::Receipt {
    let bundle = fedramp_aion::chain::previous_bundle(&workspace.path("fedramp.aion"))
        .unwrap()
        .unwrap();
    let registry = fedramp_aion::chain::load_registry(&workspace.path("registry.json")).unwrap();
    let report = fedramp_aion::chain::verify(&workspace.path("fedramp.aion"), &registry).unwrap();
    let profile = fedramp_aion::obligations::Profile {
        role: "Providers".into(),
        class: Some("B".into()),
        cert_type: Some("Rev5".into()),
        path: None,
    };
    let rules = bundle.section("rules").unwrap().clone();
    let selected = fedramp_aion::obligations::select(&rules, &profile);
    let signer = fedramp_aion::chain::Signer {
        author: operator,
        key: operator,
        keystore_dir: Some(workspace.path("keys")),
        secret_hex: None,
    };
    fedramp_aion::receipt::create(
        &fedramp_aion::receipt::Inputs {
            action,
            decision: fedramp_aion::receipt::Decision::Satisfied,
            operator,
            receipt_version: 1,
            profile: &profile,
            obligations: &selected,
            evidence: &[],
            bundle: &bundle,
            file_id: report.file_id.0,
            chain_version: report.version_count,
        },
        &signer.load_key().unwrap(),
        42,
    )
    .unwrap()
}

fn seeded_workspace(name: &str) -> Workspace {
    let workspace = Workspace::new(name);
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );
    workspace.run_sync();
    workspace
}

#[test]
fn a_receipt_binds_an_action_to_the_signed_rules() {
    let workspace = seeded_workspace("receipt-ok");
    fedramp_aion::chain::keygen(
        7,
        7,
        Some(&workspace.path("keys")),
        &workspace.path("registry.json"),
    )
    .unwrap();

    let receipt = issue_receipt(&workspace, 7, "Filed the quarterly report");
    let registry = fedramp_aion::chain::load_registry(&workspace.path("registry.json")).unwrap();
    let bundle = fedramp_aion::chain::previous_bundle(&workspace.path("fedramp.aion"))
        .unwrap()
        .unwrap();
    let report = fedramp_aion::chain::verify(&workspace.path("fedramp.aion"), &registry).unwrap();

    let verdict = fedramp_aion::receipt::verify(
        &receipt,
        &registry,
        Some((&bundle, report.file_id.0, report.version_count)),
    )
    .unwrap();
    assert!(verdict.is_valid(), "{:?}", verdict.problems);
    assert!(verdict.signature_valid && verdict.claim_bound);
    assert_eq!(verdict.matches_chain, Some(true));
    assert_eq!(verdict.obligations_reproduced, Some(true));
}

#[test]
fn editing_the_claim_invalidates_the_receipt() {
    let workspace = seeded_workspace("receipt-tamper");
    fedramp_aion::chain::keygen(
        7,
        7,
        Some(&workspace.path("keys")),
        &workspace.path("registry.json"),
    )
    .unwrap();
    let mut receipt = issue_receipt(&workspace, 7, "Filed the quarterly report");
    receipt.claim.action = "Filed something else entirely".into();

    let registry = fedramp_aion::chain::load_registry(&workspace.path("registry.json")).unwrap();
    let verdict = fedramp_aion::receipt::verify(&receipt, &registry, None).unwrap();
    assert!(!verdict.is_valid());
    assert!(!verdict.claim_bound);
}

/// A receipt signed by a key the registry does not pin proves nothing.
#[test]
fn an_unregistered_operator_is_rejected() {
    let workspace = seeded_workspace("receipt-unregistered");
    fedramp_aion::chain::keygen(
        9,
        9,
        Some(&workspace.path("keys")),
        &workspace.path("stray-registry.json"),
    )
    .unwrap();
    let receipt = issue_receipt(&workspace, 9, "Signed by a stranger");

    let registry = fedramp_aion::chain::load_registry(&workspace.path("registry.json")).unwrap();
    let verdict = fedramp_aion::receipt::verify(&receipt, &registry, None).unwrap();
    assert!(!verdict.signature_valid);
    assert!(!verdict.is_valid());
}

/// CI has no keyring and cannot decrypt a copied key file, so it signs from a
/// seed held in a secret. That path must satisfy the same registry.
#[test]
fn signing_from_an_env_seed_satisfies_the_registry() {
    let workspace = Workspace::new("env-seed");
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );

    let mut args = workspace.sync();
    args.keystore = None;
    args.signing_key = Some(workspace.secret.clone());
    fedramp_aion::run_sync(&args).unwrap();

    workspace.verify().unwrap();
    assert_eq!(workspace.chain_version(), 1);
}

#[test]
fn a_malformed_env_seed_is_rejected_before_signing() {
    let workspace = Workspace::new("bad-seed");
    workspace.publish(
        &rules("2026.07.14.01", "SHOULD"),
        &schemas(),
        &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
    );

    let mut args = workspace.sync();
    args.keystore = None;
    args.signing_key = Some("not-hex".to_string());
    let error = fedramp_aion::run_sync(&args).unwrap_err().to_string();
    assert!(error.contains("hex"), "{error}");
    assert!(!workspace.path("fedramp.aion").exists());
}

/// The signed payload must be a pure function of the pinned upstream commits.
#[test]
fn two_runs_from_identical_upstream_produce_identical_payloads() {
    let build = |name: &str| -> String {
        let workspace = Workspace::new(name);
        workspace.publish(
            &rules("2026.07.14.01", "SHOULD"),
            &schemas(),
            &marketplace("2026-07-23T06:27:00Z", 313, "Authorized"),
        );
        workspace.run_sync();
        workspace
            .outputs()
            .lines()
            .find_map(|line| line.strip_prefix("bundle_sha256="))
            .unwrap()
            .to_string()
    };
    assert_eq!(build("determinism-a"), build("determinism-b"));
}
