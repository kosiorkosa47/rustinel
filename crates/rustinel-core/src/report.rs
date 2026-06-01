use crate::diff::LockfileDiff;
use crate::lockfile::LockfileModel;
use crate::markdown;
use crate::policy::{Decision, PolicyDecision};
use crate::risk::ProjectRisk;
use crate::sarif;
use crate::signals::{RiskSignal, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Markdown,
    Sarif,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisInfo {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    pub offline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffInfo {
    pub base_score: u8,
    pub head_score: u8,
    pub delta: i32,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelReport {
    pub schema_version: String,
    pub tool: ToolInfo,
    pub analysis: AnalysisInfo,
    pub project: ProjectRisk,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<DiffInfo>,
    pub policy: PolicyDecision,
    pub packages_count: usize,
    pub findings: Vec<RiskSignal>,
}

pub const TOOL_NAME: &str = "rustinel";
pub const SCHEMA_VERSION: &str = "1.0";

fn tool_info() -> ToolInfo {
    ToolInfo {
        name: TOOL_NAME.into(),
        version: env!("CARGO_PKG_VERSION").into(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_check_report(
    lock: LockfileModel,
    findings: Vec<RiskSignal>,
    risk: ProjectRisk,
    policy: PolicyDecision,
    offline: bool,
    generated_at: Option<String>,
) -> SentinelReport {
    SentinelReport {
        schema_version: SCHEMA_VERSION.into(),
        tool: tool_info(),
        analysis: AnalysisInfo {
            mode: "check".into(),
            generated_at,
            offline,
        },
        project: risk,
        diff: None,
        policy,
        packages_count: lock.packages.len(),
        findings,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_diff_report(
    head_lock: LockfileModel,
    findings: Vec<RiskSignal>,
    head_risk: ProjectRisk,
    base_score: u8,
    diff: LockfileDiff,
    policy: PolicyDecision,
    offline: bool,
    generated_at: Option<String>,
) -> SentinelReport {
    let head_score = head_risk.score;
    let diff_info = DiffInfo {
        base_score,
        head_score,
        delta: head_score as i32 - base_score as i32,
        added: diff.added,
        removed: diff.removed,
        changed: diff.changed,
    };
    SentinelReport {
        schema_version: SCHEMA_VERSION.into(),
        tool: tool_info(),
        analysis: AnalysisInfo {
            mode: "diff".into(),
            generated_at,
            offline,
        },
        project: head_risk,
        diff: Some(diff_info),
        policy,
        packages_count: head_lock.packages.len(),
        findings,
    }
}

fn severity_tag(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED ",
        Severity::Low => "LOW ",
        Severity::Info => "INFO",
    }
}

/// A 20-cell unicode gauge for a 0–100 score, e.g. `[█████████████░░░░░░░]`.
pub fn score_bar(score: u8) -> String {
    let filled = ((score as usize) * 20 / 100).min(20);
    format!("[{}{}]", "█".repeat(filled), "░".repeat(20 - filled))
}

pub fn to_human(report: &SentinelReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("{} {}\n\n", report.tool.name, report.tool.version));
    if let Some(diff) = &report.diff {
        out.push_str(&format!(
            "Supply-chain risk: {} -> {} ({:+}, {})\n",
            diff.base_score,
            diff.head_score,
            diff.delta,
            report.project.level.as_str().to_uppercase()
        ));
    } else {
        out.push_str(&format!(
            "Project risk: {}/100 {}\n",
            report.project.score,
            report.project.level.as_str().to_uppercase()
        ));
    }
    out.push_str(&format!("  {}\n", score_bar(report.project.score)));
    out.push_str(&format!("Policy: {}\n", report.policy.profile));
    out.push_str(&format!(
        "Decision: {}\n",
        report.policy.decision.as_str().to_uppercase()
    ));
    out.push_str(&format!("Packages: {}\n", report.packages_count));

    let shown: Vec<&RiskSignal> = report
        .findings
        .iter()
        .filter(|f| f.severity > Severity::Info)
        .take(10)
        .collect();
    if !shown.is_empty() {
        out.push_str("\nTop findings:\n");
        for f in shown {
            let detail = f
                .evidence
                .first()
                .map(|e| e.summary.as_str())
                .unwrap_or(&f.id);
            out.push_str(&format!(
                "  [{}] {}: {}\n",
                severity_tag(f.severity),
                f.package,
                first_line(detail)
            ));
            if let Some(path) = path_evidence(f) {
                out.push_str(&format!("        ↳ {path}\n"));
            }
        }
    }

    if !report.policy.violations.is_empty() {
        out.push_str("\nPolicy violations:\n");
        for v in &report.policy.violations {
            out.push_str(&format!("  - {v}\n"));
        }
    }
    if !report.policy.review_items.is_empty() {
        out.push_str("\nReview required:\n");
        for v in &report.policy.review_items {
            out.push_str(&format!("  - {v}\n"));
        }
    }
    out
}

pub fn to_json(report: &SentinelReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

pub fn to_sarif(report: &SentinelReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&sarif::build(report))
}

// Plain-text, monochrome markers — readable in any terminal, diff, or code
// review, and free of emoji. The level marker is a rising block glyph that
// matches the `score_bar` visual language; status/severity use bracketed,
// fixed-width tags that read like linter/compiler output.
fn level_marker(level: crate::risk::RiskLevel) -> &'static str {
    use crate::risk::RiskLevel::*;
    match level {
        Low => "▁",
        Medium => "▃",
        High => "▅",
        Critical => "▇",
    }
}

fn decision_marker(d: Decision) -> &'static str {
    match d {
        Decision::Pass => "[ok]",
        Decision::Warn => "[warn]",
        Decision::ReviewRequired => "[review]",
        Decision::Fail => "[fail]",
    }
}

fn severity_marker(sev: Severity) -> &'static str {
    // Fixed six-column width so list items stay aligned in a monospace view.
    match sev {
        Severity::Critical => "[crit]",
        Severity::High => "[high]",
        Severity::Medium => "[med] ",
        Severity::Low => "[low] ",
        Severity::Info => "[info]",
    }
}

/// Render a GitHub-PR-ready Markdown comment. All untrusted strings (package
/// names, finding details) are escaped — see [`crate::markdown`].
pub fn to_markdown(report: &SentinelReport) -> String {
    let mut out = String::new();
    let level = report.project.level;
    out.push_str("## rustinel — supply-chain risk\n\n");

    if let Some(diff) = &report.diff {
        out.push_str(&format!(
            "{} **{} → {} ({:+})** · {} · Decision: {} **{}**\n\n",
            level_marker(level),
            diff.base_score,
            diff.head_score,
            diff.delta,
            level.as_str().to_uppercase(),
            decision_marker(report.policy.decision),
            report.policy.decision.as_str().replace('_', " ")
        ));
    } else {
        out.push_str(&format!(
            "{} **{}/100 {}** · Decision: {} **{}**\n\n",
            level_marker(level),
            report.project.score,
            level.as_str().to_uppercase(),
            decision_marker(report.policy.decision),
            report.policy.decision.as_str().replace('_', " ")
        ));
    }
    out.push_str(&format!(
        "`{}`  ·  policy: **{}**  ·  {} packages\n\n",
        score_bar(report.project.score),
        markdown::escape(&report.policy.profile),
        report.packages_count
    ));

    let contributors: Vec<&RiskSignal> = report
        .findings
        .iter()
        .filter(|f| f.severity > Severity::Info)
        .take(10)
        .collect();
    if !contributors.is_empty() {
        out.push_str("### Top risk contributors\n\n");
        for f in contributors.iter() {
            let detail = f
                .evidence
                .first()
                .map(|e| e.summary.as_str())
                .unwrap_or(&f.id);
            out.push_str(&format!(
                "- {} `{}` — {}\n",
                severity_marker(f.severity),
                markdown::escape_code(&f.package),
                markdown::escape(first_line(detail))
            ));
            if let Some(path) = path_evidence(f) {
                out.push_str(&format!("  - {}\n", markdown::escape(path)));
            }
        }
        out.push('\n');
    }

    if !report.policy.violations.is_empty() {
        out.push_str("### Blocking items\n\n");
        for v in &report.policy.violations {
            out.push_str(&format!("- {}\n", markdown::escape(v)));
        }
        out.push('\n');
    }
    if !report.policy.review_items.is_empty() {
        out.push_str("### Review required\n\n");
        for v in &report.policy.review_items {
            out.push_str(&format!("- {}\n", markdown::escape(v)));
        }
        out.push('\n');
    }

    // Suggested actions: unique recommendations from shown findings.
    let mut actions: Vec<String> = Vec::new();
    for f in report
        .findings
        .iter()
        .filter(|f| f.severity > Severity::Info)
    {
        let rec = f.recommendation.trim();
        if !rec.is_empty() && !actions.iter().any(|a| a == rec) {
            actions.push(rec.to_string());
        }
    }
    if !actions.is_empty() {
        out.push_str("### Suggested actions\n\n");
        for a in actions.iter().take(6) {
            out.push_str(&format!("- {}\n", markdown::escape(a)));
        }
        out.push('\n');
    }

    if let Some(diff) = &report.diff {
        out.push_str("<details>\n<summary>Dependency changes</summary>\n\n");
        render_list(&mut out, "Added", &diff.added);
        render_list(&mut out, "Changed", &diff.changed);
        render_list(&mut out, "Removed", &diff.removed);
        out.push_str("</details>\n");
    }

    out
}

fn render_list(out: &mut String, title: &str, items: &[String]) {
    out.push_str(&format!("{title}:\n\n"));
    if items.is_empty() {
        out.push_str("- none\n\n");
    } else {
        for item in items {
            out.push_str(&format!("- `{}`\n", markdown::escape_code(item)));
        }
        out.push('\n');
    }
}

pub fn render(report: &SentinelReport, format: OutputFormat) -> Result<String, serde_json::Error> {
    Ok(match format {
        OutputFormat::Human => to_human(report),
        OutputFormat::Json => to_json(report)?,
        OutputFormat::Markdown => to_markdown(report),
        OutputFormat::Sarif => to_sarif(report)?,
    })
}

/// True when the policy decision should cause a non-zero exit code.
pub fn is_failing(report: &SentinelReport, fail_on_review_required: bool) -> bool {
    match report.policy.decision {
        Decision::Fail => true,
        Decision::ReviewRequired => fail_on_review_required,
        Decision::Warn | Decision::Pass => false,
    }
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or(s)
}

/// A human-readable "how was this score computed" breakdown, appended to the
/// `check`/`diff` report when `--explain` is set.
pub fn score_explanation(report: &SentinelReport) -> String {
    let ex = crate::risk::explain(&report.findings);
    let mut out = String::from("\nScore breakdown:\n");
    if ex.critical_pin {
        out.push_str("  pinned to 100 by a critical advisory\n");
    }
    if ex.contributions.is_empty() {
        out.push_str("  (no risk-contributing signals)\n");
    }
    for (label, points) in &ex.contributions {
        out.push_str(&format!("  {:>5.1}  {}\n", points, label));
    }
    out.push_str(&format!(
        "  -----\n  {:>5}  total ({}/100)\n",
        "=", ex.total
    ));
    out
}

/// The dependency-path evidence summary, if present.
fn path_evidence(finding: &RiskSignal) -> Option<&str> {
    finding
        .evidence
        .iter()
        .find(|e| e.kind == "path")
        .map(|e| e.summary.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::{level_for_score, PackageRisk, RiskLevel};
    use crate::signals::Evidence;

    fn sample_report() -> SentinelReport {
        SentinelReport {
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
                score: 32,
                level: level_for_score(32),
                max_package_score: 32,
                packages: vec![PackageRisk {
                    package: "openssl-sys@0.9.99".into(),
                    score: 32,
                    level: RiskLevel::Medium,
                }],
            },
            diff: None,
            policy: PolicyDecision {
                decision: Decision::ReviewRequired,
                profile: "balanced".into(),
                violations: vec![],
                warnings: vec![],
                review_items: vec!["`openssl-sys@0.9.99` is a native/FFI dependency".into()],
                ignored_advisories: vec![],
            },
            packages_count: 4,
            findings: vec![RiskSignal {
                id: "native_ffi_detected".into(),
                package: "openssl-sys@0.9.99".into(),
                severity: Severity::High,
                weight: 20,
                confidence: 0.9,
                evidence: vec![Evidence::new("heuristic", "native FFI dependency detected")],
                recommendation: "Review the native dependency before merging.".into(),
            }],
        }
    }

    #[test]
    fn json_has_schema_version() {
        let json = to_json(&sample_report()).unwrap();
        assert!(json.contains("\"schema_version\": \"1.0\""));
        assert!(json.contains("\"name\": \"rustinel\""));
    }

    #[test]
    fn sarif_is_valid_json_and_maps_levels() {
        let sarif = to_sarif(&sample_report()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn markdown_escapes_injection() {
        let mut report = sample_report();
        report.findings[0].package = "<img src=x onerror=alert(1)>@1".into();
        report.findings[0].evidence[0].summary = "</script><h1>pwn</h1>".into();
        let md = to_markdown(&report);
        assert!(!md.contains("<img src=x"));
        assert!(!md.contains("<h1>pwn"));
    }

    #[test]
    fn human_output_mentions_project_risk() {
        let h = to_human(&sample_report());
        assert!(h.contains("rustinel"));
        assert!(h.contains("Decision: REVIEW_REQUIRED"));
    }
}
