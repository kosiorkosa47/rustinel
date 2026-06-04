//! Standards-based interchange output: SBOM (CycloneDX, SPDX), OSV and OpenVEX.
//!
//! These let rustinel plug into the wider ecosystem and compliance tooling
//! (e.g. EU Cyber Resilience Act / US EO 14028 SBOM requirements, osv.dev,
//! code-scanning dashboards).
//!
//! All builders are pure and deterministic: inputs are sorted, no randomness or
//! wall-clock is introduced here (timestamps flow in via the report), and every
//! string is emitted through `serde_json`, so untrusted package names/titles are
//! safely JSON-encoded with no injection surface.

use crate::lockfile::{LockfileModel, Package};
use crate::report::RustinelReport;
use crate::signals::{RiskSignal, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Per-package declared license (SPDX expression), recovered from the
/// `license_detected` findings produced when source was scanned. Enables the
/// per-component "License" field required by the 2025 CISA SBOM minimum elements.
fn license_map(report: &RustinelReport) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for f in &report.findings {
        if f.id == "license_detected" {
            if let Some(lic) = f
                .evidence
                .iter()
                .find_map(|e| e.summary.strip_prefix("declared license: "))
            {
                m.insert(f.package.clone(), lic.to_string());
            }
        }
    }
    m
}

/// Interchange formats understood by the `export` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    CycloneDx,
    Spdx,
    Osv,
    OpenVex,
}

impl ExportFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExportFormat::CycloneDx => "cyclonedx",
            ExportFormat::Spdx => "spdx",
            ExportFormat::Osv => "osv",
            ExportFormat::OpenVex => "openvex",
        }
    }
}

const TOOL: &str = "rustinel";

fn tool_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Package URL for a Cargo crate (Package URL spec, `cargo` type).
fn purl(pkg: &Package) -> String {
    format!("pkg:cargo/{}@{}", pkg.id.name, pkg.id.version)
}

/// Advisory findings only (the ones representing real, identified vulnerabilities).
fn advisory_findings(report: &RustinelReport) -> Vec<&RiskSignal> {
    let mut v: Vec<&RiskSignal> = report
        .findings
        .iter()
        .filter(|f| f.id.starts_with("advisory_"))
        .collect();
    v.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.package.cmp(&b.package)));
    v
}

fn advisory_id(finding: &RiskSignal) -> &str {
    finding.id.strip_prefix("advisory_").unwrap_or(&finding.id)
}

fn finding_summary(finding: &RiskSignal) -> String {
    finding
        .evidence
        .first()
        .map(|e| e.summary.clone())
        .unwrap_or_else(|| finding.id.clone())
}

/// Render the requested interchange format as pretty JSON.
pub fn render(
    format: ExportFormat,
    lock: &LockfileModel,
    report: &RustinelReport,
) -> Result<String, serde_json::Error> {
    let value = match format {
        ExportFormat::CycloneDx => cyclonedx(lock, report),
        ExportFormat::Spdx => spdx(lock, report),
        ExportFormat::Osv => osv(lock, report),
        ExportFormat::OpenVex => openvex(lock, report),
    };
    serde_json::to_string_pretty(&value)
}

/// Registry dependencies in deterministic order (the local root is handled
/// separately by each exporter, e.g. CycloneDX `metadata.component` / SPDX root).
fn sorted_components(lock: &LockfileModel) -> Vec<&Package> {
    let mut comps: Vec<&Package> = lock.registry_packages().collect();
    comps.sort_by(|a, b| a.id.cmp(&b.id));
    comps
}

fn root_component(lock: &LockfileModel) -> Option<&Package> {
    lock.packages.iter().find(|p| p.id.is_local())
}

// --- CycloneDX 1.5 -----------------------------------------------------------

fn cdx_severity(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

pub fn cyclonedx(lock: &LockfileModel, report: &RustinelReport) -> Value {
    let licenses = license_map(report);
    let components: Vec<Value> = sorted_components(lock)
        .iter()
        .map(|p| {
            let mut c = json!({
                "type": "library",
                "name": p.id.name,
                "version": p.id.version,
                "purl": purl(p),
                "bom-ref": purl(p),
            });
            // Cargo records SHA-256 checksums — emit them (NTIA/CRA "component hash").
            if let Some(sum) = &p.checksum {
                c["hashes"] = json!([{ "alg": "SHA-256", "content": sum }]);
            }
            // Per-component license (CISA 2025 minimum element), as an SPDX expression.
            if let Some(lic) = licenses.get(&p.id.to_string()) {
                c["licenses"] = json!([{ "expression": lic }]);
            }
            c
        })
        .collect();

    let vulnerabilities: Vec<Value> = advisory_findings(report)
        .iter()
        .map(|f| {
            json!({
                "id": advisory_id(f),
                "source": { "name": "RustSec" },
                "ratings": [ { "severity": cdx_severity(f.severity) } ],
                "description": finding_summary(f),
                "recommendation": f.recommendation,
                "affects": [ { "ref": format!("pkg:cargo/{}", f.package) } ],
            })
        })
        .collect();

    let mut metadata = json!({
        "tools": [ { "vendor": TOOL, "name": TOOL, "version": tool_version() } ],
        // SDLC "generation context" (CISA 2025): this SBOM is produced from a
        // resolved Cargo.lock, i.e. a build-time artifact.
        "lifecycles": [ { "phase": "build" } ],
    });
    if let Some(root) = root_component(lock) {
        metadata["component"] = json!({
            "type": "application",
            "name": root.id.name,
            "version": root.id.version,
            "bom-ref": purl(root),
        });
    }
    if let Some(ts) = &report.analysis.generated_at {
        metadata["timestamp"] = json!(ts);
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "vulnerabilities": vulnerabilities,
    })
}

// --- SPDX 2.3 ----------------------------------------------------------------

pub fn spdx(lock: &LockfileModel, report: &RustinelReport) -> Value {
    let created = report
        .analysis
        .generated_at
        .clone()
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    let root = root_component(lock);
    let root_name = root
        .map(|p| p.id.name.clone())
        .unwrap_or_else(|| "rustinel-scan-target".to_string());

    let licenses = license_map(report);
    let comps = sorted_components(lock);
    let mut packages = Vec::with_capacity(comps.len() + 1);
    let mut relationships = Vec::new();

    // The analyzed project (local root), when present, is the document's primary
    // subject: DOCUMENT DESCRIBES it, and it DEPENDS_ON each resolved dependency.
    const ROOT_ID: &str = "SPDXRef-Package-root";
    if let Some(rp) = root {
        packages.push(json!({
            "name": rp.id.name,
            "SPDXID": ROOT_ID,
            "versionInfo": rp.id.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
        }));
        relationships.push(json!({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": ROOT_ID,
            "relationshipType": "DESCRIBES",
        }));
    }

    for (i, p) in comps.iter().enumerate() {
        let spdx_id = format!("SPDXRef-Package-{i}");
        let lic = licenses
            .get(&p.id.to_string())
            .cloned()
            .unwrap_or_else(|| "NOASSERTION".to_string());
        let mut entry = json!({
            "name": p.id.name,
            "SPDXID": spdx_id,
            "versionInfo": p.id.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": lic,
            "externalRefs": [ {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl(p),
            } ],
        });
        if let Some(sum) = &p.checksum {
            entry["checksums"] = json!([{ "algorithm": "SHA256", "checksumValue": sum }]);
        }
        packages.push(entry);
        // With a root present, dependencies hang off it (DEPENDS_ON); without one
        // (a lockfile-only scan) the document describes each dependency directly.
        if root.is_some() {
            relationships.push(json!({
                "spdxElementId": ROOT_ID,
                "relatedSpdxElement": spdx_id,
                "relationshipType": "DEPENDS_ON",
            }));
        } else {
            relationships.push(json!({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": spdx_id,
                "relationshipType": "DESCRIBES",
            }));
        }
    }

    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{root_name}-sbom"),
        // Unique per document (SPDX 2.3 MUST): a deterministic content fingerprint
        // distinguishes distinct package sets and avoids the rootless-scan collision.
        "documentNamespace": format!(
            "https://rustinel.dev/spdx/{root_name}/{}",
            content_fingerprint(&comps)
        ),
        "creationInfo": {
            "created": created,
            "creators": [ format!("Tool: {TOOL}-{}", tool_version()) ],
            "comment": "Generation context: produced from a resolved Cargo.lock (build-time artifact).",
        },
        "packages": packages,
        "relationships": relationships,
    })
}

/// Deterministic content fingerprint of the component set (FNV-1a over the sorted
/// `name@version:checksum` list). Stable for identical input, differs across
/// package sets — makes the SPDX documentNamespace unique without a clock/random.
fn content_fingerprint(comps: &[&Package]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |s: &str| {
        for b in s.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    for p in comps {
        feed(&p.id.to_string());
        feed(":");
        feed(p.checksum.as_deref().unwrap_or(""));
        feed("\n");
    }
    format!("{h:016x}")
}

// --- OSV (osv.dev schema) ----------------------------------------------------

pub fn osv(_lock: &LockfileModel, report: &RustinelReport) -> Value {
    // OSV requires `modified`; keep it deterministic (the analysis timestamp, or a
    // fixed epoch when timestamps are suppressed for byte-identical output).
    let modified = report
        .analysis
        .generated_at
        .clone()
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());
    let records: Vec<Value> = advisory_findings(report)
        .iter()
        .map(|f| {
            // `f.package` is `name@version`.
            let (name, version) = split_pkg(&f.package);
            json!({
                "schema_version": "1.6.0",
                "id": advisory_id(f),
                "modified": modified,
                "summary": finding_summary(f),
                "affected": [ {
                    "package": {
                        "ecosystem": "crates.io",
                        "name": name,
                        "purl": format!("pkg:cargo/{name}@{version}"),
                    },
                    "versions": [ version ],
                } ],
            })
        })
        .collect();
    // A JSON array of OSV vulnerability records, each a valid osv.dev object — not
    // a non-standard `{ "results": [...] }` envelope (which is neither the OSV
    // vulnerability schema nor the OSV-Scanner results shape).
    Value::Array(records)
}

// --- OpenVEX -----------------------------------------------------------------

pub fn openvex(_lock: &LockfileModel, report: &RustinelReport) -> Value {
    let timestamp = report
        .analysis
        .generated_at
        .clone()
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    // Each advisory finding becomes a VEX statement. Advisories waived via
    // policy (`advisories.ignore`) are emitted as `not_affected` with a
    // justification, turning rustinel's "ignore with a reason" into a
    // standards-compliant VEX assertion; the rest are `affected`.
    let ignored = &report.policy.ignored_advisories;
    let statements: Vec<Value> = advisory_findings(report)
        .iter()
        .map(|f| {
            let (name, version) = split_pkg(&f.package);
            let id = advisory_id(f);
            let product = format!("pkg:cargo/{name}@{version}");
            if ignored.iter().any(|i| i == id) {
                // OpenVEX `not_affected` needs a justification OR an impact
                // statement. We cannot assert a specific machine-readable
                // justification (the operator may have ignored the advisory for any
                // reason), so state the waiver as a free-text impact statement
                // rather than claiming, falsely, that the code is unreachable.
                json!({
                    "vulnerability": { "name": id },
                    "products": [ { "@id": product } ],
                    "status": "not_affected",
                    "impact_statement": "waived by rustinel policy (advisories.ignore)",
                })
            } else {
                json!({
                    "vulnerability": { "name": id },
                    "products": [ { "@id": product } ],
                    "status": "affected",
                })
            }
        })
        .collect();

    json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://rustinel.dev/vex/scan",
        "author": format!("{TOOL}-{}", tool_version()),
        "timestamp": timestamp,
        "version": 1,
        "statements": statements,
    })
}

fn split_pkg(pkg: &str) -> (&str, &str) {
    match pkg.rsplit_once('@') {
        Some((name, version)) => (name, version),
        None => (pkg, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Decision, PolicyDecision};
    use crate::report::{AnalysisInfo, RustinelReport, ToolInfo, SCHEMA_VERSION, TOOL_NAME};
    use crate::risk::{level_for_score, ProjectRisk};
    use crate::signals::{Evidence, RiskSignal};
    use std::path::PathBuf;

    fn pkg(name: &str, version: &str, local: bool) -> Package {
        Package {
            id: crate::lockfile::PackageId {
                name: name.into(),
                version: version.into(),
                source: if local {
                    None
                } else {
                    Some("registry+https://github.com/rust-lang/crates.io-index".into())
                },
            },
            checksum: None,
            dependencies: vec![],
        }
    }

    fn fixture() -> (LockfileModel, RustinelReport) {
        let lock = LockfileModel {
            path: PathBuf::from("Cargo.lock"),
            version: Some(3),
            packages: vec![
                pkg("demo", "0.1.0", true),
                pkg("time", "0.2.22", false),
                pkg("serde", "1.0.0", false),
            ],
        };
        let report = RustinelReport {
            schema_version: SCHEMA_VERSION.into(),
            tool: ToolInfo {
                name: TOOL_NAME.into(),
                version: "0.1.0".into(),
            },
            analysis: AnalysisInfo {
                mode: "check".into(),
                generated_at: None,
                offline: true,
            },
            project: ProjectRisk {
                score: 30,
                level: level_for_score(30),
                max_package_score: 30,
                packages: vec![],
            },
            diff: None,
            policy: PolicyDecision {
                decision: Decision::Fail,
                profile: "balanced".into(),
                violations: vec![],
                warnings: vec![],
                review_items: vec![],
                ignored_advisories: vec![],
            },
            packages_count: 3,
            findings: vec![RiskSignal {
                id: "advisory_RUSTSEC-2020-0071".into(),
                package: "time@0.2.22".into(),
                severity: Severity::High,
                weight: 30,
                confidence: 1.0,
                evidence: vec![Evidence::new("advisory", "RUSTSEC-2020-0071: segfault")],
                recommendation: "Update to >= 0.2.23".into(),
            }],
        };
        (lock, report)
    }

    #[test]
    fn cyclonedx_shape() {
        let (lock, report) = fixture();
        let v = cyclonedx(&lock, &report);
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        // 2 registry components (time, serde), sorted.
        assert_eq!(v["components"].as_array().unwrap().len(), 2);
        assert_eq!(v["components"][0]["purl"], "pkg:cargo/serde@1.0.0");
        assert_eq!(v["vulnerabilities"][0]["id"], "RUSTSEC-2020-0071");
        assert_eq!(v["vulnerabilities"][0]["ratings"][0]["severity"], "high");
        assert_eq!(v["metadata"]["component"]["name"], "demo");
    }

    #[test]
    fn spdx_shape() {
        let (lock, report) = fixture();
        let v = spdx(&lock, &report);
        assert_eq!(v["spdxVersion"], "SPDX-2.3");
        assert_eq!(v["SPDXID"], "SPDXRef-DOCUMENT");
        // The analyzed project (root) plus its two registry dependencies.
        let pkgs = v["packages"].as_array().unwrap();
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0]["SPDXID"], "SPDXRef-Package-root");
        assert_eq!(pkgs[0]["name"], "demo");
        // A dependency carries its purl externalRef (serde sorts first -> Package-0).
        assert_eq!(pkgs[1]["SPDXID"], "SPDXRef-Package-0");
        assert_eq!(
            pkgs[1]["externalRefs"][0]["referenceLocator"],
            "pkg:cargo/serde@1.0.0"
        );
        // DOCUMENT DESCRIBES the root; the root DEPENDS_ON its deps.
        let rels = v["relationships"].as_array().unwrap();
        assert!(rels.iter().any(|r| r["spdxElementId"] == "SPDXRef-DOCUMENT"
            && r["relatedSpdxElement"] == "SPDXRef-Package-root"
            && r["relationshipType"] == "DESCRIBES"));
        assert!(rels
            .iter()
            .any(|r| r["spdxElementId"] == "SPDXRef-Package-root"
                && r["relationshipType"] == "DEPENDS_ON"));
        // documentNamespace is unique per content (carries a fingerprint suffix).
        let ns = v["documentNamespace"].as_str().unwrap();
        let prefix = "https://rustinel.dev/spdx/demo/";
        assert!(
            ns.starts_with(prefix) && ns.len() > prefix.len(),
            "ns: {ns}"
        );
    }

    #[test]
    fn osv_shape() {
        let (lock, report) = fixture();
        let v = osv(&lock, &report);
        // A JSON array of OSV vulnerability records, no `results` envelope.
        let recs = v.as_array().unwrap();
        assert_eq!(recs[0]["id"], "RUSTSEC-2020-0071");
        assert_eq!(recs[0]["modified"], "1970-01-01T00:00:00Z");
        assert_eq!(recs[0]["affected"][0]["package"]["name"], "time");
        assert_eq!(recs[0]["affected"][0]["package"]["ecosystem"], "crates.io");
        assert_eq!(recs[0]["affected"][0]["versions"][0], "0.2.22");
    }

    #[test]
    fn openvex_shape() {
        let (lock, report) = fixture();
        let v = openvex(&lock, &report);
        assert_eq!(v["@context"], "https://openvex.dev/ns/v0.2.0");
        assert_eq!(
            v["statements"][0]["vulnerability"]["name"],
            "RUSTSEC-2020-0071"
        );
        assert_eq!(v["statements"][0]["status"], "affected");
    }

    #[test]
    fn openvex_marks_policy_ignored_as_not_affected() {
        let (lock, mut report) = fixture();
        report.policy.ignored_advisories = vec!["RUSTSEC-2020-0071".into()];
        let v = openvex(&lock, &report);
        assert_eq!(v["statements"][0]["status"], "not_affected");
        assert_eq!(
            v["statements"][0]["impact_statement"],
            "waived by rustinel policy (advisories.ignore)"
        );
        // Must not assert a specific (and likely false) machine-readable justification.
        assert!(v["statements"][0]["justification"].is_null());
    }

    #[test]
    fn sbom_embeds_checksums() {
        let (mut lock, report) = fixture();
        // give `time` a checksum and confirm it surfaces in both SBOM formats
        for p in lock.packages.iter_mut() {
            if p.id.name == "time" {
                p.checksum = Some("abc123".into());
            }
        }
        let cdx = cyclonedx(&lock, &report);
        let time = cdx["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "time")
            .unwrap();
        assert_eq!(time["hashes"][0]["alg"], "SHA-256");
        assert_eq!(time["hashes"][0]["content"], "abc123");

        let spdx_doc = spdx(&lock, &report);
        let has_checksum = spdx_doc["packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["checksums"][0]["checksumValue"] == "abc123");
        assert!(has_checksum);
    }

    #[test]
    fn sbom_embeds_per_component_license_and_context() {
        let (lock, mut report) = fixture();
        report.findings.push(RiskSignal {
            id: "license_detected".into(),
            package: "time@0.2.22".into(),
            severity: Severity::Info,
            weight: 0,
            confidence: 1.0,
            evidence: vec![Evidence::new(
                "manifest",
                "declared license: MIT OR Apache-2.0",
            )],
            recommendation: String::new(),
        });
        let cdx = cyclonedx(&lock, &report);
        // generation context (CISA 2025)
        assert_eq!(cdx["metadata"]["lifecycles"][0]["phase"], "build");
        let time = cdx["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "time")
            .unwrap();
        assert_eq!(time["licenses"][0]["expression"], "MIT OR Apache-2.0");

        let spdx_doc = spdx(&lock, &report);
        assert!(spdx_doc["creationInfo"]["comment"]
            .as_str()
            .unwrap()
            .contains("Generation context"));
        let time_pkg = spdx_doc["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "time")
            .unwrap();
        assert_eq!(time_pkg["licenseDeclared"], "MIT OR Apache-2.0");
    }

    #[test]
    fn deterministic_render() {
        let (lock, report) = fixture();
        let a = render(ExportFormat::CycloneDx, &lock, &report).unwrap();
        let b = render(ExportFormat::CycloneDx, &lock, &report).unwrap();
        assert_eq!(a, b);
    }
}
