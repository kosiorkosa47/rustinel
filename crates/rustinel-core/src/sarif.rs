//! SARIF 2.1.0 serialization for the analysis findings.
//!
//! Output is deterministic and safe to publish to code-scanning dashboards.
//! Message text is plain (SARIF consumers render it as text, not HTML), but we
//! still flatten control characters defensively.

use crate::report::RustinelReport;
use crate::signals::{RiskSignal, Severity};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifText,
    help: SarifText,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifText,
}

#[derive(Serialize)]
struct SarifText {
    text: String,
}

fn level_for(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn flatten(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

pub fn build(report: &RustinelReport) -> SarifLog {
    // One rule per distinct finding id, in deterministic order.
    let mut rules_map: BTreeMap<String, SarifRule> = BTreeMap::new();
    for finding in &report.findings {
        rules_map
            .entry(finding.id.clone())
            .or_insert_with(|| SarifRule {
                id: finding.id.clone(),
                name: rule_name(finding),
                short_description: SarifText {
                    text: rule_name(finding),
                },
                help: SarifText {
                    text: flatten(&finding.recommendation),
                },
            });
    }
    let rules: Vec<SarifRule> = rules_map.into_values().collect();

    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(|f| {
            let detail = f
                .evidence
                .first()
                .map(|e| flatten(&e.summary))
                .unwrap_or_else(|| f.id.clone());
            SarifResult {
                rule_id: f.id.clone(),
                level: level_for(f.severity).to_string(),
                message: SarifText {
                    text: flatten(&format!("{}: {}", f.package, detail)),
                },
            }
        })
        .collect();

    SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json".into(),
        version: "2.1.0".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: report.tool.name.clone(),
                    version: report.tool.version.clone(),
                    information_uri: "https://github.com/kosiorkosa47/rustinel".into(),
                    rules,
                },
            },
            results,
        }],
    }
}

fn rule_name(finding: &RiskSignal) -> String {
    match finding.id.as_str() {
        "native_ffi_detected" => "Native FFI dependency detected".into(),
        "build_script_present" => "Build script present".into(),
        "build_script_suspicious" => "Suspicious build script (network / payload)".into(),
        "suspicious_source_exfil" => "Source matches secret-exfiltration malware pattern".into(),
        "unsafe_present" => "Unsafe code present".into(),
        "multiple_versions_same_crate" => "Multiple versions of the same crate".into(),
        "possible_typosquat" => "Possible typosquat of a popular crate".into(),
        "yanked_crate" => "Yanked crate version".into(),
        "license_unknown" => "Unknown license".into(),
        "license_detected" => "License detected".into(),
        id if id.starts_with("advisory_") => "Known security advisory".into(),
        other => other.to_string(),
    }
}
