//! Source registry, pinned fetch, and offline replay.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

use crate::canon;

pub const RULES: &str = "rules";
pub const SCHEMAS: &str = "schemas";
pub const MARKETPLACE: &str = "marketplace";
pub const OSCAL: &str = "oscal";

/// Where a source lives and how its substance projection is taken.
pub struct SourceSpec {
    pub id: &'static str,
    pub repo: &'static str,
    pub path: &'static str,
    /// Directory sources fetch every `*.json` under `path`.
    pub is_dir: bool,
    /// Fields stripped before the gate digest (DESIGN.md §3.4). Each entry is
    /// a path; NIST's OSCAL publishes churn in more than one place.
    pub volatile: &'static [&'static [&'static str]],
}

pub const SOURCES: &[SourceSpec] = &[
    SourceSpec {
        id: RULES,
        repo: "FedRAMP/rules",
        path: "fedramp-consolidated-rules.json",
        is_dir: false,
        volatile: &[&["info", "last_updated"]],
    },
    SourceSpec {
        id: SCHEMAS,
        repo: "FedRAMP/schemas",
        path: "",
        is_dir: true,
        volatile: &[],
    },
    // NIST republishes with a fresh document uuid, a new last-modified, and a
    // bumped oscal-version while the control text is byte-identical. Gating on
    // those would report an 800-53 change on a publish that changed nothing.
    SourceSpec {
        id: OSCAL,
        repo: "usnistgov/oscal-content",
        path: "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog-min.json",
        is_dir: false,
        volatile: &[
            &["catalog", "uuid"],
            &["catalog", "metadata", "last-modified"],
            &["catalog", "metadata", "oscal-version"],
        ],
    },
    SourceSpec {
        id: MARKETPLACE,
        repo: "FedRAMP/marketplace-fedramp-gov-data",
        path: "data.json",
        is_dir: false,
        volatile: &[&["meta"]],
    },
];

pub fn spec(id: &str) -> &'static SourceSpec {
    SOURCES
        .iter()
        .find(|s| s.id == id)
        .unwrap_or_else(|| panic!("unknown source {id}"))
}

/// Immutable pin describing exactly which upstream bytes produced a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    pub repo: String,
    pub path: String,
    pub commit: String,
    pub committed_at: String,
    pub raw_sha256: String,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
}

/// A canonicalized source at a pinned commit.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: String,
    pub provenance: Provenance,
    pub content: Value,
    pub content_sha256: String,
    pub substance_sha256: String,
}

impl Snapshot {
    fn build(id: &str, provenance: Provenance, content: Value) -> Result<Self> {
        let substance = canon::without_all(&content, spec(id).volatile);
        Ok(Self {
            id: id.to_string(),
            provenance,
            content_sha256: canon::digest_value(&content)?,
            substance_sha256: canon::digest_value(&substance)?,
            content,
        })
    }
}

/// Fetches source bytes. `Http` pins `main` to a commit; `Dir` replays a
/// captured snapshot so the logic can be exercised offline.
pub enum Fetcher {
    Http { token: Option<String> },
    Dir { root: std::path::PathBuf },
}

impl Fetcher {
    pub fn snapshot(&self, spec: &SourceSpec) -> Result<Snapshot> {
        match self {
            Self::Http { token } => http_snapshot(spec, token.as_deref()),
            Self::Dir { root } => dir_snapshot(spec, root),
        }
    }
}

fn get(url: &str, token: Option<&str>) -> Result<Vec<u8>> {
    let mut request = ureq::get(url)
        .set("User-Agent", "fedramp-aion")
        .set("Accept", "application/vnd.github+json");
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let response = request.call().with_context(|| format!("GET {url}"))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .with_context(|| format!("reading body of {url}"))?;
    Ok(body)
}

/// Resolve `main` to the commit that last touched `path` (empty path = repo tip).
fn resolve_commit(repo: &str, path: &str, token: Option<&str>) -> Result<(String, String)> {
    let url = if path.is_empty() {
        format!("https://api.github.com/repos/{repo}/commits?per_page=1")
    } else {
        format!("https://api.github.com/repos/{repo}/commits?path={path}&per_page=1")
    };
    let body = get(&url, token)?;
    let commits: Value = serde_json::from_slice(&body)
        .with_context(|| format!("commit listing for {repo} was not JSON"))?;
    let head = commits
        .get(0)
        .with_context(|| format!("no commits found for {repo}:{path}"))?;
    let sha = head["sha"]
        .as_str()
        .context("commit listing had no sha")?
        .to_string();
    let date = head["commit"]["committer"]["date"]
        .as_str()
        .context("commit listing had no committer date")?
        .to_string();
    Ok((sha, date))
}

fn http_snapshot(spec: &SourceSpec, token: Option<&str>) -> Result<Snapshot> {
    let (commit, committed_at) = resolve_commit(spec.repo, spec.path, token)?;
    if spec.is_dir {
        return http_dir_snapshot(spec, &commit, &committed_at, token);
    }
    let raw = get(
        &format!(
            "https://raw.githubusercontent.com/{}/{commit}/{}",
            spec.repo, spec.path
        ),
        token,
    )?;
    let provenance = Provenance {
        repo: spec.repo.to_string(),
        path: spec.path.to_string(),
        commit,
        committed_at,
        raw_sha256: canon::sha256_hex(&raw),
        bytes: raw.len() as u64,
        files: BTreeMap::new(),
    };
    Snapshot::build(spec.id, provenance, canon::canonicalize(&raw)?)
}

/// Directory sources become `{ "<filename>": <canonical json> }`.
fn http_dir_snapshot(
    spec: &SourceSpec,
    commit: &str,
    committed_at: &str,
    token: Option<&str>,
) -> Result<Snapshot> {
    let listing: Value = serde_json::from_slice(&get(
        &format!(
            "https://api.github.com/repos/{}/contents/?ref={commit}",
            spec.repo
        ),
        token,
    )?)?;
    let entries = listing
        .as_array()
        .context("contents listing was not an array")?;

    let mut content = serde_json::Map::new();
    let mut files = BTreeMap::new();
    let mut bytes = 0u64;
    for entry in entries {
        let name = entry["name"].as_str().unwrap_or_default();
        if entry["type"] != "file"
            || !std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            continue;
        }
        let raw = get(
            &format!(
                "https://raw.githubusercontent.com/{}/{commit}/{name}",
                spec.repo
            ),
            token,
        )?;
        bytes += raw.len() as u64;
        files.insert(name.to_string(), canon::sha256_hex(&raw));
        content.insert(name.to_string(), canon::canonicalize(&raw)?);
    }
    if content.is_empty() {
        bail!("{} exposed no .json files at {commit}", spec.repo);
    }
    let provenance = Provenance {
        repo: spec.repo.to_string(),
        path: "*.json".to_string(),
        commit: commit.to_string(),
        committed_at: committed_at.to_string(),
        raw_sha256: canon::sha256_hex(&canon::canonical_bytes(&Value::Object(content.clone()))?),
        bytes,
        files,
    };
    Snapshot::build(spec.id, provenance, Value::Object(content))
}

/// Offline replay: `<root>/<id>.json` plus `<root>/<id>.provenance.json`.
fn dir_snapshot(spec: &SourceSpec, root: &Path) -> Result<Snapshot> {
    let content_path = root.join(format!("{}.json", spec.id));
    let raw = std::fs::read(&content_path)
        .with_context(|| format!("reading {}", content_path.display()))?;
    let provenance_path = root.join(format!("{}.provenance.json", spec.id));
    let provenance = if provenance_path.exists() {
        serde_json::from_slice(&std::fs::read(&provenance_path)?)?
    } else {
        Provenance {
            repo: spec.repo.to_string(),
            path: spec.path.to_string(),
            commit: format!("offline-{}", &canon::sha256_hex(&raw)[..12]),
            committed_at: "1970-01-01T00:00:00Z".to_string(),
            raw_sha256: canon::sha256_hex(&raw),
            bytes: raw.len() as u64,
            files: BTreeMap::new(),
        }
    };
    Snapshot::build(spec.id, provenance, canon::canonicalize(&raw)?)
}
