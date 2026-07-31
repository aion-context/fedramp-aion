//! Human and machine reports. `CHANGES.md` becomes the PR body; the commit
//! message is the one-line version of the same thing.

use std::fmt::Write as _;

use crate::diff::Delta;
use crate::plan::Plan;
use crate::severity::Severity;

const MAX_LISTED: usize = 25;

pub fn commit_message(plan: &Plan) -> String {
    let mut message = plan.headline();
    if plan.genesis {
        return message;
    }
    let counts: Vec<String> = plan
        .deltas
        .iter()
        .filter(|d| d.changed)
        .map(|d| {
            format!(
                "{}: +{} -{} ~{}",
                d.source,
                d.added.len(),
                d.removed.len(),
                d.modified.len()
            )
        })
        .collect();
    if !counts.is_empty() {
        let _ = write!(message, " [{}]", counts.join("; "));
    }
    message
}

pub fn changes_markdown(plan: &Plan) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# {}\n", plan.headline());
    let _ = writeln!(out, "| | |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(out, "| severity | `{}` |", plan.severity);
    let _ = writeln!(
        out,
        "| upstream rules version | `{}`{} |",
        plan.upstream_version,
        plan.previous_upstream_version
            .as_deref()
            .filter(|previous| *previous != plan.upstream_version)
            .map_or(String::new(), |previous| format!(" (was `{previous}`)"))
    );
    let _ = writeln!(out, "| bundle digest | `{}` |", plan.bundle_sha256);
    for (id, record) in &plan.bundle.sources {
        let _ = writeln!(out, "| pinned `{id}` | {} |", pin(record));
    }
    out.push('\n');

    if plan.genesis {
        let _ = writeln!(
            out,
            "Genesis version — the full FedRAMP ruleset, submission schemas, and \
             marketplace snapshot are signed for the first time. Nothing to diff against.\n"
        );
    }

    let highlights: Vec<_> = plan.deltas.iter().flat_map(|d| &d.highlights).collect();
    if !highlights.is_empty() {
        let _ = writeln!(out, "## Requires attention\n");
        for highlight in highlights.iter().take(MAX_LISTED) {
            let _ = writeln!(
                out,
                "- **{}** `{}` — `{}` → `{}`",
                highlight.id, highlight.field, highlight.from, highlight.to
            );
        }
        if highlights.len() > MAX_LISTED {
            let _ = writeln!(out, "- …and {} more", highlights.len() - MAX_LISTED);
        }
        out.push('\n');
    }

    for delta in &plan.deltas {
        out.push_str(&source_section(delta));
    }

    let drift: Vec<_> = plan.deltas.iter().flat_map(|d| &d.drift).collect();
    if !drift.is_empty() {
        let _ = writeln!(out, "## Upstream drift\n");
        for note in drift {
            let _ = writeln!(out, "- {note}");
        }
        out.push('\n');
    }
    out
}

/// Offline replays carry a synthetic commit id, which must not be rendered as
/// a GitHub link a reviewer could follow to nothing.
fn pin(record: &crate::bundle::SourceRecord) -> String {
    let commit = &record.provenance.commit;
    if commit.starts_with("offline-") {
        return format!("`{commit}` (offline replay)");
    }
    let short = &commit[..commit.len().min(8)];
    format!(
        "[`{short}`](https://github.com/{}/commit/{commit}) @ {}",
        record.provenance.repo, record.provenance.committed_at
    )
}

fn source_section(delta: &Delta) -> String {
    let mut out = String::new();
    if !delta.changed {
        let _ = writeln!(out, "## {} — unchanged\n", delta.source);
        return out;
    }
    let _ = writeln!(
        out,
        "## {} — {} ({} added, {} removed, {} modified)\n",
        delta.source,
        delta.severity,
        delta.added.len(),
        delta.removed.len(),
        delta.modified.len()
    );
    list(&mut out, "Added", &delta.added);
    list(&mut out, "Removed", &delta.removed);

    if !delta.modified.is_empty() {
        let _ = writeln!(out, "**Modified**\n");
        for entry in delta.modified.iter().take(MAX_LISTED) {
            let fields: Vec<&str> = entry.fields.iter().map(|f| f.field.as_str()).collect();
            let _ = writeln!(out, "- `{}` — {}", entry.id, fields.join(", "));
            for field in entry.fields.iter().take(4) {
                let _ = writeln!(
                    out,
                    "  - `{}`: `{}` → `{}`",
                    field.field, field.from, field.to
                );
            }
        }
        if delta.modified.len() > MAX_LISTED {
            let _ = writeln!(out, "- …and {} more", delta.modified.len() - MAX_LISTED);
        }
        out.push('\n');
    }

    if !delta.counts.is_empty() {
        let _ = writeln!(out, "**Counts**\n");
        for (key, value) in &delta.counts {
            let _ = writeln!(out, "- `{key}`: {value}");
        }
        out.push('\n');
    }
    out
}

fn list(out: &mut String, label: &str, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    let _ = writeln!(out, "**{label}**\n");
    for id in ids.iter().take(MAX_LISTED) {
        let _ = writeln!(out, "- `{id}`");
    }
    if ids.len() > MAX_LISTED {
        let _ = writeln!(out, "- …and {} more", ids.len() - MAX_LISTED);
    }
    out.push('\n');
}

/// `key=value` lines for `$GITHUB_OUTPUT`.
pub fn github_outputs(plan: &Plan, chain_version: Option<u64>) -> String {
    let mut out = String::new();
    // `changed` says upstream moved; `committed` says a version was signed.
    // They diverge under `--force`, and a workflow that keys the publish step
    // on `changed` would throw the forced version away.
    let _ = writeln!(out, "changed={}", plan.changed);
    let _ = writeln!(out, "committed={}", chain_version.is_some());
    let _ = writeln!(out, "severity={}", plan.severity);
    let _ = writeln!(out, "genesis={}", plan.genesis);
    let _ = writeln!(out, "upstream_version={}", plan.upstream_version);
    let _ = writeln!(out, "bundle_sha256={}", plan.bundle_sha256);
    let _ = writeln!(out, "headline={}", plan.headline());
    if let Some(version) = chain_version {
        let _ = writeln!(out, "chain_version={version}");
    }
    for delta in &plan.deltas {
        let _ = writeln!(out, "{}_changed={}", delta.source, delta.changed);
    }
    out
}

pub fn should_fail(severity: Severity, threshold: Option<Severity>) -> bool {
    threshold.is_some_and(|threshold| severity >= threshold && severity > Severity::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{FieldChange, Highlight, Modified};

    fn plan_fixture() -> Plan {
        let mut rules = Delta::new("rules");
        rules.changed = true;
        rules.severity = Severity::Major;
        rules.added = vec!["FRR/VDR/all/FRP/VDR-FRP-TWO".into()];
        rules.modified = vec![Modified {
            id: "FRR/VDR/all/FRP/VDR-FRP-ONE".into(),
            fields: vec![FieldChange {
                field: "force".into(),
                from: "SHOULD".into(),
                to: "MUST".into(),
            }],
        }];
        rules.highlights = vec![Highlight {
            kind: "rule".into(),
            id: "FRR/VDR/all/FRP/VDR-FRP-ONE".into(),
            field: "force".into(),
            from: "SHOULD".into(),
            to: "MUST".into(),
        }];
        let marketplace = Delta::new("marketplace");
        Plan {
            genesis: false,
            changed: true,
            severity: Severity::Major,
            upstream_version: "2026.08.01.01".into(),
            previous_upstream_version: Some("2026.07.14.01".into()),
            bundle_sha256: "abc123".into(),
            deltas: vec![rules, marketplace],
            bundle: crate::bundle::Bundle {
                schema: crate::bundle::SCHEMA.into(),
                upstream_version: "2026.08.01.01".into(),
                sources: std::collections::BTreeMap::new(),
                content: std::collections::BTreeMap::new(),
            },
        }
    }

    #[test]
    fn commit_message_leads_with_severity_and_counts() {
        let message = commit_message(&plan_fixture());
        assert!(message.starts_with("RULES CHANGED"));
        assert!(message.contains("rules: +1 -0 ~1"));
    }

    #[test]
    fn markdown_promotes_force_transitions_to_the_top() {
        let markdown = changes_markdown(&plan_fixture());
        let attention = markdown.find("## Requires attention").unwrap();
        let detail = markdown.find("## rules —").unwrap();
        assert!(attention < detail);
        assert!(markdown.contains("`SHOULD` → `MUST`"));
        assert!(markdown.contains("## marketplace — unchanged"));
    }

    #[test]
    fn outputs_are_shell_safe_key_values() {
        let outputs = github_outputs(&plan_fixture(), Some(7));
        assert!(outputs.contains("changed=true"));
        assert!(outputs.contains("committed=true"));
        assert!(outputs.contains("severity=major"));
        assert!(outputs.contains("chain_version=7"));
        assert!(outputs.contains("rules_changed=true"));
        assert!(outputs.lines().all(|line| line.contains('=')));
    }

    #[test]
    fn committed_is_false_when_no_version_was_signed() {
        let outputs = github_outputs(&plan_fixture(), None);
        assert!(outputs.contains("committed=false"));
    }

    #[test]
    fn fail_threshold_ignores_quieter_changes() {
        assert!(should_fail(Severity::Major, Some(Severity::Major)));
        assert!(!should_fail(Severity::Routine, Some(Severity::Major)));
        assert!(!should_fail(Severity::Major, None));
        assert!(!should_fail(Severity::None, Some(Severity::None)));
    }
}
