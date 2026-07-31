//! MCP server — agents query FedRAMP obligations and get answers that cite
//! their source.
//!
//! Every tool result carries the chain version, bundle digest, and upstream
//! commit that produced it. An agent's claim about what FedRAMP requires is
//! then checkable against a signed artifact rather than trusted because a model
//! said it. That is the whole reason this surface exists.
//!
//! Newline-delimited JSON-RPC 2.0 over stdio, no async runtime.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;

use crate::bundle::Bundle;
use crate::obligations::{self, Profile};

pub const PROTOCOL_VERSION: &str = "2025-03-26";

/// The signed state the server answers from, loaded and verified once at
/// startup so every answer in a session cites the same version.
pub struct Server {
    bundle: Bundle,
    chain_version: u64,
    file_id: u64,
    chain_valid: bool,
}

impl Server {
    pub fn load(chain: &Path, registry: &Path) -> Result<Self> {
        let bundle = crate::chain::previous_bundle(chain)?
            .ok_or_else(|| anyhow::anyhow!("no chain at {}", chain.display()))?;
        let registry = crate::chain::load_registry(registry)?;
        let report = crate::chain::verify(chain, &registry)?;
        Ok(Self {
            bundle,
            chain_version: report.version_count,
            file_id: report.file_id.0,
            chain_valid: report.is_valid,
        })
    }

    fn rules(&self) -> Result<&Value> {
        self.bundle
            .section(crate::sources::RULES)
            .ok_or_else(|| anyhow::anyhow!("chain payload has no rules section"))
    }

    /// The citation attached to every answer.
    fn provenance(&self) -> Value {
        let source = self.bundle.sources.get(crate::sources::RULES);
        json!({
            "chain_version": self.chain_version,
            "chain_file_id": self.file_id.to_string(),
            "chain_verified": self.chain_valid,
            "bundle_sha256": self.bundle.digest().unwrap_or_default(),
            "upstream_version": self.bundle.upstream_version,
            "rules_commit": source.map(|s| s.provenance.commit.clone()),
            "rules_committed_at": source.map(|s| s.provenance.committed_at.clone()),
        })
    }

    pub fn handle(&self, request: &Value) -> Option<Value> {
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));

        // Notifications carry no id and must not be answered.
        let id = id?;

        Some(match method {
            "initialize" => success(
                &id,
                json!({
                    "protocolVersion": params
                        .get("protocolVersion")
                        .and_then(Value::as_str)
                        .unwrap_or(PROTOCOL_VERSION),
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "fedramp-aion",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                }),
            ),
            "ping" => success(&id, json!({})),
            "tools/list" => success(&id, json!({"tools": tool_definitions()})),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                match self.call(name, &arguments) {
                    Ok(value) => success(&id, tool_result(&value)),
                    Err(e) => success(&id, tool_error(&e.to_string())),
                }
            }
            other => error(&id, -32601, &format!("unknown method `{other}`")),
        })
    }

    fn call(&self, name: &str, arguments: &Value) -> Result<Value> {
        match name {
            "fedramp_status" => Ok(self.provenance()),
            "fedramp_obligations" => self.obligations(arguments),
            "fedramp_rule" => self.rule(arguments),
            "fedramp_search" => self.search(arguments),
            "fedramp_control" => self.control(arguments),
            "fedramp_kev" => self.kev(arguments),
            other => anyhow::bail!("unknown tool `{other}`"),
        }
    }

    fn profile_from(arguments: &Value) -> Profile {
        let text = |key: &str| {
            arguments
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        Profile {
            role: text("role").unwrap_or_else(|| "Providers".to_string()),
            class: text("class"),
            cert_type: text("type"),
            path: text("path"),
        }
    }

    fn obligations(&self, arguments: &Value) -> Result<Value> {
        let profile = Self::profile_from(arguments);
        let force = arguments.get("force").and_then(Value::as_str);
        let binding_only = arguments
            .get("binding_only")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let selected: Vec<obligations::Obligation> = obligations::select(self.rules()?, &profile)
            .into_iter()
            .filter(|o| force.is_none_or(|f| o.force.eq_ignore_ascii_case(f)))
            .filter(|o| !binding_only || o.is_binding())
            .collect();

        Ok(json!({
            "profile": profile.label(),
            "count": selected.len(),
            "binding": selected.iter().filter(|o| o.is_binding()).count(),
            "obligations": selected,
            "provenance": self.provenance(),
        }))
    }

    fn rule(&self, arguments: &Value) -> Result<Value> {
        let id = arguments
            .get("id")
            .and_then(Value::as_str)
            .context("`id` is required")?;
        let (leaves, _) = crate::diff::rules::flatten(self.rules()?);
        let matches: Vec<Value> = leaves
            .iter()
            .filter(|(path, _)| path.rsplit('/').next() == Some(id))
            .map(|(path, leaf)| json!({"path": path, "rule": leaf}))
            .collect();
        anyhow::ensure!(!matches.is_empty(), "no rule with id `{id}`");
        Ok(json!({
            "id": id,
            "matches": matches,
            "provenance": self.provenance(),
        }))
    }

    /// The 800-53 control text behind a FedRAMP reference, from the signed
    /// catalog. FedRAMP amends controls without restating them, so an agent
    /// answering from the ruleset alone is answering from half the source.
    fn control(&self, arguments: &Value) -> Result<Value> {
        let requested = arguments
            .get("id")
            .and_then(Value::as_str)
            .context("`id` is required")?;
        let id = crate::diff::oscal::normalise_id(requested);
        let catalog = self
            .bundle
            .section(crate::sources::OSCAL)
            .context("chain payload has no oscal section; re-sync to add it")?;
        let controls = crate::diff::oscal::flatten(catalog);
        let control = controls
            .get(&id)
            .with_context(|| format!("no 800-53 control `{id}`"))?;

        let rules = self.rules()?;
        let fedramp_overlay = rules
            .get("CTL")
            .and_then(Value::as_object)
            .and_then(|families| {
                families.values().find_map(|controls| {
                    controls.as_object()?.iter().find_map(|(key, value)| {
                        (crate::diff::oscal::normalise_id(key) == id).then(|| value.clone())
                    })
                })
            });
        Ok(json!({
            "id": id,
            "requested": requested,
            "control": control,
            "fedramp_overlay": fedramp_overlay,
            "referenced_by_fedramp": crate::diff::oscal::referenced_controls(rules).contains(&id),
            "provenance": self.provenance(),
        }))
    }

    /// Whether a CVE is known-exploited, and which FedRAMP rules govern the
    /// response. FedRAMP defines the term but never carries the list.
    fn kev(&self, arguments: &Value) -> Result<Value> {
        let catalog = self
            .bundle
            .section(crate::sources::KEV)
            .context("chain payload has no kev section; re-sync to add it")?;
        let entries = crate::diff::kev::flatten(catalog);
        let governed_by = crate::diff::kev::governing_rules(self.rules()?);

        let Some(cve) = arguments.get("cve").and_then(Value::as_str) else {
            return Ok(json!({
                "count": entries.len(),
                "governed_by": governed_by,
                "provenance": self.provenance(),
            }));
        };
        let id = cve.to_ascii_uppercase();
        Ok(json!({
            "cve": id,
            "known_exploited": entries.contains_key(&id),
            "entry": entries.get(&id),
            "governed_by": governed_by,
            "provenance": self.provenance(),
        }))
    }

    fn search(&self, arguments: &Value) -> Result<Value> {
        let query = arguments
            .get("query")
            .and_then(Value::as_str)
            .context("`query` is required")?
            .to_lowercase();
        anyhow::ensure!(query.len() >= 3, "query must be at least 3 characters");
        let limit = arguments
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(20)
            .min(100) as usize;

        let (leaves, _) = crate::diff::rules::flatten(self.rules()?);
        let mut hits = Vec::new();
        for (path, leaf) in &leaves {
            let haystack = serde_json::to_string(leaf)?.to_lowercase();
            if haystack.contains(&query) {
                hits.push(json!({
                    "path": path,
                    "id": path.rsplit('/').next().unwrap_or(path),
                    "name": leaf.get("name"),
                    "force": leaf.get("force"),
                    "statement": leaf.get("statement"),
                }));
            }
            if hits.len() >= limit {
                break;
            }
        }
        Ok(json!({
            "query": query,
            "count": hits.len(),
            "truncated": hits.len() >= limit,
            "hits": hits,
            "provenance": self.provenance(),
        }))
    }
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "fedramp_status",
            "description": "Which signed FedRAMP ruleset this server answers from: chain version, \
                            bundle digest, upstream commit, and whether the chain verified.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "fedramp_obligations",
            "description": "FedRAMP rules that apply to a given profile, with the class-specific \
                            variant resolved. Returns the obligation list plus the chain version \
                            it came from.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "role": {"type": "string", "description": "Providers, Agencies, Assessors, Advisors, FedRAMP. Default Providers."},
                    "class": {"type": "string", "description": "Certification class A, B, C, or D."},
                    "type": {"type": "string", "description": "Certification type: 20x or Rev5."},
                    "path": {"type": "string", "description": "Authorization path: Program or Agency."},
                    "force": {"type": "string", "description": "Filter to one force, e.g. MUST."},
                    "binding_only": {"type": "boolean", "description": "Only MUST / MUST NOT."}
                },
            },
        },
        {
            "name": "fedramp_rule",
            "description": "One rule by its FedRAMP id, e.g. CCM-OCR-AVL or KSI-CED-RAT.",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            },
        },
        {
            "name": "fedramp_control",
            "description": "The NIST 800-53 control text behind a FedRAMP reference, from the \
                            signed catalog, plus any FedRAMP overlay (parameters or guidance) \
                            for it. Accepts either id form: AC-06-01 or ac-6.1.",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            },
        },
        {
            "name": "fedramp_kev",
            "description": "Whether a CVE is in CISA's Known Exploited Vulnerabilities catalog, \
                            with its due date and required action, plus the FedRAMP rules that \
                            govern the response. Omit `cve` for a catalog summary.",
            "inputSchema": {
                "type": "object",
                "properties": {"cve": {"type": "string", "description": "e.g. CVE-2026-20316"}},
            },
        },
        {
            "name": "fedramp_search",
            "description": "Full-text search across the signed ruleset. Returns matching rule ids \
                            and statements, so an answer can cite rules rather than paraphrase.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "description": "Default 20, max 100."}
                },
                "required": ["query"],
            },
        },
    ])
}

#[allow(clippy::needless_pass_by_value)]
fn success(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id.clone(), "result": result})
}

fn error(id: &Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id.clone(), "error": {"code": code, "message": message}})
}

fn tool_result(value: &Value) -> Value {
    json!({
        "content": [{"type": "text", "text": serde_json::to_string_pretty(value).unwrap_or_default()}],
        "isError": false,
    })
}

fn tool_error(message: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": message}],
        "isError": true,
    })
}

/// Read JSON-RPC from stdin, write responses to stdout, one per line.
pub fn serve(server: &Server) -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => server.handle(&request),
            Err(e) => Some(error(&Value::Null, -32700, &format!("parse error: {e}"))),
        };
        if let Some(response) = response {
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::Provenance;
    use std::collections::BTreeMap;

    fn server() -> Server {
        let rules = json!({
            "info": {"version": "2026.07.14.01"},
            "FRR": {"CCM": {
                "info": {"subsets": {"OCR": {"applicability": {
                    "affects": ["Providers"], "classes": ["B","C","D"],
                    "paths": ["Program","Agency"], "types": ["20x","Rev5"]}}}},
                "data": {"all": {"OCR": {"CCM-OCR-AVL": {
                    "affects": ["Providers"], "force": "MUST",
                    "statement": "Report availability of the ongoing certification report."}}}}}}
        });
        let mut sources = BTreeMap::new();
        sources.insert(
            crate::sources::RULES.to_string(),
            crate::bundle::SourceRecord {
                provenance: Provenance {
                    repo: "FedRAMP/rules".into(),
                    path: "fedramp-consolidated-rules.json".into(),
                    commit: "083137da".into(),
                    committed_at: "2026-07-14T21:11:57Z".into(),
                    raw_sha256: "raw".into(),
                    bytes: 1,
                    files: BTreeMap::new(),
                },
                content_sha256: "c".into(),
                substance_sha256: "s".into(),
            },
        );
        let mut content = BTreeMap::new();
        content.insert(crate::sources::RULES.to_string(), rules);
        Server {
            bundle: Bundle {
                schema: crate::bundle::SCHEMA.into(),
                upstream_version: "2026.07.14.01".into(),
                sources,
                content,
            },
            chain_version: 7,
            file_id: 6_675_964_335_526_256_880,
            chain_valid: true,
        }
    }

    fn call(tool: &str, arguments: &Value) -> Value {
        let response = server()
            .handle(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": tool, "arguments": arguments.clone()}
            }))
            .unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn initialize_echoes_the_client_protocol_version() {
        let response = server()
            .handle(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"}
            }))
            .unwrap();
        assert_eq!(response["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(response["result"]["serverInfo"]["name"], "fedramp-aion");
    }

    #[test]
    fn notifications_get_no_response() {
        assert!(server()
            .handle(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .is_none());
    }

    #[test]
    fn unknown_method_is_a_jsonrpc_error() {
        let response = server()
            .handle(&json!({"jsonrpc": "2.0", "id": 3, "method": "resources/read"}))
            .unwrap();
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn every_tool_is_listed_with_a_schema() {
        let response = server()
            .handle(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
            .unwrap();
        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 6);
        for tool in tools {
            assert!(tool["name"].is_string());
            assert!(tool["description"].is_string());
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
    }

    /// The reason this surface exists: an agent's answer must be checkable.
    #[test]
    fn every_answer_cites_the_signed_version() {
        for (tool, arguments) in [
            ("fedramp_status", json!({})),
            ("fedramp_obligations", json!({"class": "B", "type": "Rev5"})),
            ("fedramp_rule", json!({"id": "CCM-OCR-AVL"})),
            ("fedramp_search", json!({"query": "availability"})),
        ] {
            let value = call(tool, &arguments);
            let provenance = if tool == "fedramp_status" {
                value.clone()
            } else {
                value["provenance"].clone()
            };
            assert_eq!(provenance["chain_version"], 7, "{tool} lost its citation");
            assert_eq!(provenance["rules_commit"], "083137da", "{tool}");
            assert_eq!(
                provenance["chain_file_id"], "6675964335526256880",
                "{tool} rounded the file id"
            );
        }
    }

    #[test]
    fn obligations_resolve_for_the_requested_profile() {
        let value = call(
            "fedramp_obligations",
            &json!({"class": "B", "type": "Rev5"}),
        );
        assert_eq!(value["count"], 1);
        assert_eq!(value["binding"], 1);
        assert_eq!(value["obligations"][0]["id"], "CCM-OCR-AVL");

        // Class A is excluded by the subset, so the agent must be told nothing
        // applies rather than being handed a rule that does not.
        let value = call(
            "fedramp_obligations",
            &json!({"class": "A", "type": "Rev5"}),
        );
        assert_eq!(value["count"], 0);
    }

    #[test]
    fn a_missing_rule_is_an_error_not_an_empty_answer() {
        let response = server()
            .handle(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "fedramp_rule", "arguments": {"id": "NOPE-1"}}
            }))
            .unwrap();
        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("no rule with id"));
    }

    #[test]
    fn search_rejects_queries_too_short_to_be_meaningful() {
        let response = server()
            .handle(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "fedramp_search", "arguments": {"query": "a"}}
            }))
            .unwrap();
        assert_eq!(response["result"]["isError"], true);
    }
}
