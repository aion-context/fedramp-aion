//! Package validation against the signed schemas.
//!
//! FedRAMP's published schemas cannot be validated as they stand: their
//! cross-schema `$ref`s are written as paths rather than URI fragments —
//! `…common-definitions-….json/$defs/nRating` — and that URL 404s. A validator
//! that resolves over the network therefore fails at reference resolution
//! before checking a single constraint.
//!
//! Resolution here is **offline and signed**: every schema comes from the chain
//! payload, the path form is repaired to the subschema it plainly means, and
//! each repair is recorded so the receipt never claims we validated against
//! exactly what was published. A URI outside the signed set is an error, never
//! a fetch — a verdict whose meaning depends on what a server returned today
//! cannot be a durable receipt.

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::bundle::Bundle;

/// The prefix every published FedRAMP schema `$id` shares.
const SCHEMA_BASE: &str = "https://fedramp.gov/schemas/";
const DEFS_MARKER: &str = "/$defs/";

/// The schemas as signed, keyed by filename.
pub struct SchemaSet {
    schemas: BTreeMap<String, Value>,
}

impl SchemaSet {
    pub fn from_bundle(bundle: &Bundle) -> Result<Self> {
        let section = bundle
            .section(crate::sources::SCHEMAS)
            .context("chain payload has no schemas section")?;
        let map = section
            .as_object()
            .context("schemas section is not an object")?;
        Ok(Self {
            schemas: map
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        })
    }

    pub fn names(&self) -> Vec<&str> {
        self.schemas.keys().map(String::as_str).collect()
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.schemas.get(name)
    }

    /// A package declares its schema with `$schema`, or names it directly.
    pub fn resolve_name(&self, requested: Option<&str>, package: &Value) -> Result<String> {
        if let Some(name) = requested {
            anyhow::ensure!(
                self.schemas.contains_key(name),
                "no signed schema named `{name}`. Available: {}",
                self.names().join(", ")
            );
            return Ok(name.to_string());
        }
        let declared = package
            .get("$schema")
            .and_then(Value::as_str)
            .and_then(|uri| uri.rsplit('/').next())
            .filter(|name| self.schemas.contains_key(*name));
        declared.map(str::to_string).context(
            "package does not declare a recognised `$schema`; pass --schema with one of the \
             signed schema names",
        )
    }
}

/// Resolves `$ref`s from the signed set only, repairing the published path form.
struct SignedRetriever {
    schemas: BTreeMap<String, Value>,
    repairs: Mutex<Vec<String>>,
}

/// A cloneable handle so the caller can read back the repairs the retriever
/// recorded while the validator held it.
#[derive(Clone)]
struct RetrieverHandle(std::sync::Arc<SignedRetriever>);

impl referencing::Retrieve for RetrieverHandle {
    fn retrieve(
        &self,
        uri: &referencing::Uri<String>,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.0.retrieve(uri)
    }
}

impl SignedRetriever {
    fn retrieve(
        &self,
        uri: &referencing::Uri<String>,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let text = uri.as_str();
        let rest = text.strip_prefix(SCHEMA_BASE).ok_or_else(|| {
            format!("refusing to resolve `{text}`: outside the signed schema set")
        })?;

        let (file, pointer) = match rest.split_once(DEFS_MARKER) {
            Some((file, pointer)) => (file, Some(pointer)),
            None => (rest, None),
        };
        let schema = self
            .schemas
            .get(file)
            .ok_or_else(|| format!("`{file}` is not in the signed schema set"))?;

        let Some(pointer) = pointer else {
            return Ok(schema.clone());
        };
        // The published form names a resource that does not exist; treat it as
        // the fragment it evidently means, and record the deviation.
        let target = schema
            .get("$defs")
            .and_then(|defs| defs.get(pointer))
            .ok_or_else(|| format!("`{file}` has no $defs/{pointer}"))?;
        if let Ok(mut repairs) = self.repairs.lock() {
            let note = format!("{file}{DEFS_MARKER}{pointer} → {file}#/$defs/{pointer}");
            if !repairs.contains(&note) {
                repairs.push(note);
            }
        }
        let mut resolved = target.clone();
        if let Some(object) = resolved.as_object_mut() {
            object.insert("$id".to_string(), Value::String(text.to_string()));
        }
        Ok(resolved)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    /// JSON pointer into the package.
    pub pointer: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub package: String,
    pub package_sha256: String,
    pub bytes: u64,
    pub schema: String,
    pub schema_sha256: String,
    pub valid: bool,
    pub findings: Vec<Finding>,
    /// Deviations from the published bytes that were required to resolve.
    pub repairs: Vec<String>,
    /// Rule ids that require this artifact, from the same signed ruleset.
    pub required_by: Vec<String>,
}

/// Validate `package` against a signed schema. Never touches the network.
pub fn validate(
    schemas: &SchemaSet,
    rules: Option<&Value>,
    schema_name: &str,
    package_bytes: &[u8],
    package_label: &str,
) -> Result<Report> {
    let package: Value =
        serde_json::from_slice(package_bytes).context("package is not valid JSON")?;
    let schema = schemas
        .get(schema_name)
        .with_context(|| format!("no signed schema named `{schema_name}`"))?;

    let retriever = RetrieverHandle(std::sync::Arc::new(SignedRetriever {
        schemas: schemas.schemas.clone(),
        repairs: Mutex::new(Vec::new()),
    }));
    let validator = jsonschema::options()
        .with_retriever(retriever.clone())
        .build(schema)
        .map_err(|e| anyhow::anyhow!("schema `{schema_name}` could not be compiled: {e}"))?;

    let mut findings: Vec<Finding> = validator
        .iter_errors(&package)
        .map(|error| Finding {
            pointer: {
                let pointer = error.instance_path().to_string();
                if pointer.is_empty() {
                    "/".to_string()
                } else {
                    pointer
                }
            },
            message: error.to_string(),
        })
        .collect();
    findings.sort_by(|a, b| a.pointer.cmp(&b.pointer).then(a.message.cmp(&b.message)));

    let repairs = retriever
        .0
        .repairs
        .lock()
        .map(|r| r.clone())
        .unwrap_or_default();

    Ok(Report {
        package: package_label.to_string(),
        package_sha256: crate::canon::sha256_hex(package_bytes),
        bytes: package_bytes.len() as u64,
        schema: schema_name.to_string(),
        schema_sha256: crate::canon::digest_value(schema)?,
        valid: findings.is_empty(),
        findings,
        repairs,
        required_by: rules
            .map(|r| binding_rules(r, schema_name))
            .unwrap_or_default(),
    })
}

/// Which rules require this artifact. The rules bind schemas by URL, so the
/// filename is the join key — that is what makes a validation verdict a
/// compliance statement rather than a syntax check.
pub fn binding_rules(rules: &Value, schema_name: &str) -> Vec<String> {
    let (leaves, _) = crate::diff::rules::flatten(rules);
    let mut ids: Vec<String> = leaves
        .iter()
        .filter(|(_, leaf)| {
            leaf.pointer("/schema/url")
                .and_then(Value::as_str)
                .is_some_and(|url| url.rsplit('/').next() == Some(schema_name))
        })
        .filter_map(|(path, _)| path.rsplit('/').next().map(str::to_string))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

pub fn report_markdown(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# {} — {}\n",
        report.package,
        if report.valid { "VALID" } else { "INVALID" }
    );
    let _ = writeln!(out, "| | |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(out, "| schema | `{}` |", report.schema);
    let _ = writeln!(out, "| schema digest | `{}` |", report.schema_sha256);
    let _ = writeln!(out, "| package digest | `{}` |", report.package_sha256);
    let _ = writeln!(out, "| findings | {} |", report.findings.len());
    if !report.required_by.is_empty() {
        let _ = writeln!(out, "| required by | {} |", report.required_by.join(", "));
    }
    out.push('\n');

    if !report.findings.is_empty() {
        let _ = writeln!(out, "## Findings\n");
        for finding in &report.findings {
            let _ = writeln!(out, "- `{}` — {}", finding.pointer, finding.message);
        }
        out.push('\n');
    }
    if !report.repairs.is_empty() {
        let _ = writeln!(
            out,
            "## Reference repairs\n\nThe published schemas reference definitions by a path that \
             does not resolve. Validation applied these repairs:\n"
        );
        for repair in &report.repairs {
            let _ = writeln!(out, "- `{repair}`");
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schemas() -> SchemaSet {
        let common = json!({
            "$id": "https://fedramp.gov/schemas/fedramp-common-definitions-schema-2026-06-24.json",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": {
                "certificationPackageOverviewUri": {"type": "string", "format": "uri"},
                "reportPeriodDate": {
                    "type": "object",
                    "properties": {"startDate": {"type": "string"}, "endDate": {"type": "string"}},
                    "required": ["startDate", "endDate"]
                }
            }
        });
        // Exactly the published shape: a path-form $ref, not a fragment.
        let report = json!({
            "$id": "https://fedramp.gov/schemas/fedramp-ongoing-certification-report-schema-2026-06-24.json",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "certificationPackageOverviewUri": {"$ref": "https://fedramp.gov/schemas/fedramp-common-definitions-schema-2026-06-24.json/$defs/certificationPackageOverviewUri"},
                "reportPeriod": {"$ref": "https://fedramp.gov/schemas/fedramp-common-definitions-schema-2026-06-24.json/$defs/reportPeriodDate"}
            },
            "required": ["certificationPackageOverviewUri", "reportPeriod"]
        });
        SchemaSet {
            schemas: BTreeMap::from([
                (
                    "fedramp-common-definitions-schema-2026-06-24.json".to_string(),
                    common,
                ),
                (
                    "fedramp-ongoing-certification-report-schema-2026-06-24.json".to_string(),
                    report,
                ),
            ]),
        }
    }

    const REPORT_SCHEMA: &str = "fedramp-ongoing-certification-report-schema-2026-06-24.json";

    fn valid_package() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "certificationPackageOverviewUri": "https://example.gov/pkg.json",
            "reportPeriod": {"startDate": "2026-07-01", "endDate": "2026-09-30"}
        }))
        .unwrap()
    }

    /// The whole point: the published path-form ref resolves offline.
    #[test]
    fn a_conformant_package_validates_despite_the_broken_refs() {
        let report = validate(
            &schemas(),
            None,
            REPORT_SCHEMA,
            &valid_package(),
            "pkg.json",
        )
        .unwrap();
        assert!(report.valid, "{:?}", report.findings);
        assert_eq!(report.repairs.len(), 2, "both refs should be repaired");
        assert!(report.repairs[0].contains("#/$defs/"));
    }

    #[test]
    fn a_missing_required_field_is_reported_by_pointer() {
        let package = serde_json::to_vec(&json!({
            "reportPeriod": {"startDate": "2026-07-01", "endDate": "2026-09-30"}
        }))
        .unwrap();
        let report = validate(&schemas(), None, REPORT_SCHEMA, &package, "pkg.json").unwrap();
        assert!(!report.valid);
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0]
            .message
            .contains("certificationPackageOverviewUri"));
    }

    /// A violation inside a repaired reference must still be caught — proving
    /// the ref resolved to the real subschema rather than being skipped.
    #[test]
    fn a_violation_behind_a_repaired_ref_is_caught() {
        let package = serde_json::to_vec(&json!({
            "certificationPackageOverviewUri": "https://example.gov/pkg.json",
            "reportPeriod": {"startDate": "2026-07-01"}
        }))
        .unwrap();
        let report = validate(&schemas(), None, REPORT_SCHEMA, &package, "pkg.json").unwrap();
        assert!(!report.valid);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.pointer.contains("reportPeriod")),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn findings_are_sorted_so_output_is_stable() {
        let package = serde_json::to_vec(&json!({})).unwrap();
        let first = validate(&schemas(), None, REPORT_SCHEMA, &package, "p").unwrap();
        let second = validate(&schemas(), None, REPORT_SCHEMA, &package, "p").unwrap();
        assert_eq!(first.findings, second.findings);
        let pointers: Vec<&str> = first.findings.iter().map(|f| f.pointer.as_str()).collect();
        let mut sorted = pointers.clone();
        sorted.sort_unstable();
        assert_eq!(pointers, sorted);
    }

    #[test]
    fn a_schema_outside_the_signed_set_is_refused() {
        let error = validate(&schemas(), None, "not-a-schema.json", &valid_package(), "p")
            .unwrap_err()
            .to_string();
        assert!(error.contains("no signed schema named"), "{error}");
    }

    #[test]
    fn the_schema_name_is_inferred_from_the_package() {
        let package = json!({"$schema": format!("https://fedramp.gov/schemas/{REPORT_SCHEMA}")});
        assert_eq!(
            schemas().resolve_name(None, &package).unwrap(),
            REPORT_SCHEMA
        );
        assert!(schemas().resolve_name(None, &json!({})).is_err());
    }

    #[test]
    fn binding_rules_join_schema_to_the_rules_that_require_it() {
        let rules = json!({"FRR": {"CCM": {"data": {"all": {"OCR": {
            "CCM-OCR-AVL": {"schema": {"name": "Ongoing Certification Report",
                "url": format!("https://fedramp.gov/schemas/{REPORT_SCHEMA}")}},
            "CCM-OCR-OTH": {"statement": "unrelated"}}}}}}});
        assert_eq!(binding_rules(&rules, REPORT_SCHEMA), vec!["CCM-OCR-AVL"]);
    }
}
