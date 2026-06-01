use crate::errors::RustinelError;
use crate::risk::ProjectRisk;
use crate::signals::RiskSignal;
use serde::{Deserialize, Serialize};

/// Raw, on-disk policy as parsed from `rustinel.toml`. All sections are optional
/// and unknown fields are ignored (forward-compatible; see POLICY_SPEC §7).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    pub version: Option<u32>,
    pub profile: Option<PolicyProfile>,
    pub risk: Option<RiskPolicy>,
    pub advisories: Option<AdvisoriesPolicy>,
    pub signals: Option<SignalsPolicy>,
    pub licenses: Option<LicensesPolicy>,
    pub allow: Option<ListPolicy>,
    pub deny: Option<ListPolicy>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyProfile {
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiskPolicy {
    pub max_project_score: Option<u8>,
    pub max_package_score: Option<u8>,
    pub fail_on_delta_above: Option<i32>,
    pub warn_on_delta_above: Option<i32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdvisoriesPolicy {
    #[serde(default)]
    pub fail_on: Vec<String>,
    #[serde(default)]
    pub warn_on: Vec<String>,
    #[serde(default)]
    pub ignore: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignalsPolicy {
    pub fail_on_yanked: Option<bool>,
    pub warn_on_yanked: Option<bool>,
    pub warn_on_build_rs: Option<bool>,
    pub require_review_on_build_rs: Option<bool>,
    pub require_review_on_native_ffi: Option<bool>,
    pub warn_on_unsafe_increase: Option<bool>,
    pub fail_on_denied_license: Option<bool>,
    pub warn_on_unknown_license: Option<bool>,
    pub fail_on_unknown_license: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LicensesPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListPolicy {
    #[serde(default)]
    pub crates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub profile: String,
    pub violations: Vec<String>,
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_items: Vec<String>,
    /// Advisory IDs waived by policy (`advisories.ignore`). Surfaced so a VEX
    /// export can mark them `not_affected` rather than `affected`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored_advisories: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Pass,
    Warn,
    Fail,
    ReviewRequired,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Pass => "pass",
            Decision::Warn => "warn",
            Decision::Fail => "fail",
            Decision::ReviewRequired => "review_required",
        }
    }
}

/// Fully-resolved policy configuration: profile defaults overlaid with any
/// explicit values from the file.
struct Effective {
    profile: String,
    max_project_score: u8,
    max_package_score: u8,
    fail_on_delta_above: i32,
    warn_on_delta_above: i32,
    adv_fail_on: Vec<String>,
    adv_warn_on: Vec<String>,
    adv_ignore: Vec<String>,
    warn_on_build_rs: bool,
    require_review_on_build_rs: bool,
    require_review_on_native_ffi: bool,
    fail_on_yanked: bool,
    fail_on_denied_license: bool,
    warn_on_unknown_license: bool,
    fail_on_unknown_license: bool,
    license_allow: Vec<String>,
    license_deny: Vec<String>,
    allow_crates: Vec<String>,
    deny_crates: Vec<String>,
}

impl Effective {
    fn from(policy: Option<&Policy>) -> Self {
        let profile_name = policy
            .and_then(|p| p.profile.as_ref())
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "balanced".into());
        let mut eff = Self::defaults_for(&profile_name);

        let Some(policy) = policy else { return eff };

        if let Some(r) = &policy.risk {
            if let Some(v) = r.max_project_score {
                eff.max_project_score = v;
            }
            if let Some(v) = r.max_package_score {
                eff.max_package_score = v;
            }
            if let Some(v) = r.fail_on_delta_above {
                eff.fail_on_delta_above = v;
            }
            if let Some(v) = r.warn_on_delta_above {
                eff.warn_on_delta_above = v;
            }
        }
        if let Some(a) = &policy.advisories {
            if !a.fail_on.is_empty() {
                eff.adv_fail_on = a.fail_on.clone();
            }
            if !a.warn_on.is_empty() {
                eff.adv_warn_on = a.warn_on.clone();
            }
            eff.adv_ignore = a.ignore.clone();
        }
        if let Some(s) = &policy.signals {
            if let Some(v) = s.warn_on_build_rs {
                eff.warn_on_build_rs = v;
            }
            if let Some(v) = s.require_review_on_build_rs {
                eff.require_review_on_build_rs = v;
            }
            if let Some(v) = s.require_review_on_native_ffi {
                eff.require_review_on_native_ffi = v;
            }
            if let Some(v) = s.fail_on_yanked {
                eff.fail_on_yanked = v;
            }
            if let Some(v) = s.fail_on_denied_license {
                eff.fail_on_denied_license = v;
            }
            if let Some(v) = s.warn_on_unknown_license {
                eff.warn_on_unknown_license = v;
            }
            if let Some(v) = s.fail_on_unknown_license {
                eff.fail_on_unknown_license = v;
            }
        }
        if let Some(l) = &policy.licenses {
            eff.license_allow = l.allow.clone();
            eff.license_deny = l.deny.clone();
        }
        if let Some(a) = &policy.allow {
            eff.allow_crates = a.crates.clone();
        }
        if let Some(d) = &policy.deny {
            eff.deny_crates = d.crates.clone();
        }
        eff
    }

    fn defaults_for(profile: &str) -> Self {
        // Common baseline; tuned per profile below.
        let base = Self {
            profile: profile.to_string(),
            max_project_score: 70,
            max_package_score: 85,
            fail_on_delta_above: 35,
            warn_on_delta_above: 10,
            adv_fail_on: vec!["critical".into(), "high".into()],
            adv_warn_on: vec!["medium".into(), "low".into()],
            adv_ignore: vec![],
            // build.rs presence is ubiquitous — don't warn by default; the
            // suspicious-intent scanner is what drives the decision.
            warn_on_build_rs: false,
            require_review_on_build_rs: false,
            require_review_on_native_ffi: true,
            fail_on_yanked: true,
            fail_on_denied_license: true,
            warn_on_unknown_license: true,
            fail_on_unknown_license: false,
            license_allow: vec![],
            license_deny: vec!["GPL-3.0".into(), "AGPL-3.0".into()],
            allow_crates: vec![],
            deny_crates: vec![],
        };
        match profile {
            "strict" => Self {
                max_project_score: 50,
                max_package_score: 70,
                fail_on_delta_above: 20,
                warn_on_delta_above: 5,
                adv_fail_on: vec!["critical".into(), "high".into(), "medium".into()],
                adv_warn_on: vec!["low".into()],
                require_review_on_build_rs: true,
                warn_on_unknown_license: false,
                fail_on_unknown_license: true,
                ..base
            },
            "permissive" => Self {
                max_project_score: 90,
                max_package_score: 95,
                fail_on_delta_above: 60,
                warn_on_delta_above: 25,
                adv_fail_on: vec!["critical".into()],
                adv_warn_on: vec!["high".into(), "medium".into(), "low".into()],
                require_review_on_native_ffi: false,
                fail_on_yanked: false,
                license_deny: vec!["AGPL-3.0".into()],
                ..base
            },
            _ => base, // "balanced" and any custom name
        }
    }
}

/// Evaluate the policy against the project risk, the collected signals, and an
/// optional score delta (present for `diff`, absent for `check`).
pub fn evaluate(
    risk: &ProjectRisk,
    signals: &[RiskSignal],
    delta: Option<i32>,
    policy: Option<&Policy>,
) -> Result<PolicyDecision, RustinelError> {
    let eff = Effective::from(policy);

    let mut violations = Vec::new();
    let mut warnings = Vec::new();
    let mut review_items = Vec::new();
    let mut ignored_advisories: Vec<String> = Vec::new();

    // --- Score thresholds ---
    if risk.score > eff.max_project_score {
        violations.push(format!(
            "project risk score {} exceeds threshold {}",
            risk.score, eff.max_project_score
        ));
    }
    if risk.max_package_score > eff.max_package_score {
        if let Some(top) = risk.packages.iter().max_by_key(|p| p.score) {
            violations.push(format!(
                "package `{}` score {} exceeds per-package threshold {}",
                top.package, top.score, eff.max_package_score
            ));
        }
    }

    // --- Diff delta ---
    if let Some(delta) = delta {
        if delta > eff.fail_on_delta_above {
            violations.push(format!(
                "risk score increased by {delta}, above fail threshold {}",
                eff.fail_on_delta_above
            ));
        } else if delta > eff.warn_on_delta_above {
            warnings.push(format!(
                "risk score increased by {delta}, above warn threshold {}",
                eff.warn_on_delta_above
            ));
        }
    }

    // --- Per-signal policy ---
    for signal in signals {
        let crate_name = crate_name_of(&signal.package);
        let allowlisted = eff.allow_crates.iter().any(|c| c == crate_name);

        if eff.deny_crates.iter().any(|c| c == crate_name) {
            violations.push(format!(
                "dependency `{crate_name}` is on the policy deny list"
            ));
        }

        if signal.id.starts_with("advisory_") {
            let advisory_id = signal.id.trim_start_matches("advisory_");
            if eff.adv_ignore.iter().any(|i| i == advisory_id) {
                warnings.push(format!(
                    "advisory {advisory_id} for `{}` is ignored by policy",
                    signal.package
                ));
                ignored_advisories.push(advisory_id.to_string());
                continue;
            }
            let sev = signal.severity.as_str().to_string();
            if eff.adv_fail_on.contains(&sev) && !allowlisted {
                violations.push(format!("{} ({}) on `{}`", advisory_id, sev, signal.package));
            } else if eff.adv_warn_on.contains(&sev) || allowlisted {
                warnings.push(format!("{} ({}) on `{}`", advisory_id, sev, signal.package));
            }
            continue;
        }

        // Findings downgraded to Info by the known-good baseline (or otherwise
        // purely informational) must not drive the decision — except
        // `license_detected`, which is Info but still feeds the deny-license check.
        let is_baseline_info =
            signal.severity == crate::signals::Severity::Info && signal.id != "license_detected";
        if is_baseline_info {
            continue;
        }

        match signal.id.as_str() {
            // Runtime secret-exfiltration fingerprint — treat like a build-script
            // malware signal: strict fails, otherwise always demands review.
            "suspicious_source_exfil" => {
                if eff.profile == "strict" && !allowlisted {
                    violations.push(format!(
                        "`{}` source matches a secret-exfiltration malware pattern",
                        signal.package
                    ));
                } else {
                    review_items.push(format!(
                        "`{}` source matches a secret-exfiltration malware pattern",
                        signal.package
                    ));
                }
            }
            // A build script with network/payload intent is a malware vector:
            // under strict it fails, otherwise it always demands review.
            "build_script_suspicious" => {
                if eff.profile == "strict" && !allowlisted {
                    violations.push(format!(
                        "`{}` has a suspicious build script (network/payload)",
                        signal.package
                    ));
                } else {
                    review_items.push(format!(
                        "`{}` has a suspicious build script (network/payload)",
                        signal.package
                    ));
                }
            }
            // Likely typosquat / impersonation — always demands a human look.
            "possible_typosquat" => {
                if eff.profile == "strict" && !allowlisted {
                    violations.push(format!(
                        "`{}` looks like a typosquat of a popular crate",
                        signal.package
                    ));
                } else {
                    review_items.push(format!(
                        "`{}` looks like a typosquat of a popular crate",
                        signal.package
                    ));
                }
            }
            "build_script_present" => {
                if eff.require_review_on_build_rs && !allowlisted {
                    review_items.push(format!("`{}` ships a build script", signal.package));
                } else if eff.warn_on_build_rs {
                    warnings.push(format!("`{}` ships a build script", signal.package));
                }
            }
            "native_ffi_detected" => {
                if eff.require_review_on_native_ffi && !allowlisted {
                    review_items.push(format!("`{}` is a native/FFI dependency", signal.package));
                } else {
                    warnings.push(format!("`{}` is a native/FFI dependency", signal.package));
                }
            }
            "license_unknown" => {
                if eff.fail_on_unknown_license && !allowlisted {
                    violations.push(format!("`{}` has an unknown license", signal.package));
                } else if eff.warn_on_unknown_license {
                    warnings.push(format!("`{}` has an unknown license", signal.package));
                }
            }
            "license_detected" => {
                if let Some(license) = license_from_signal(signal) {
                    match license_verdict(&license, &eff.license_allow, &eff.license_deny) {
                        LicenseVerdict::Denied => {
                            if eff.fail_on_denied_license && !allowlisted {
                                violations.push(format!(
                                    "`{}` uses denied license {license}",
                                    signal.package
                                ));
                            } else {
                                warnings.push(format!(
                                    "`{}` uses denied license {license}",
                                    signal.package
                                ));
                            }
                        }
                        LicenseVerdict::NotAllowed => {
                            warnings.push(format!(
                                "`{}` license {license} is not on the allow list",
                                signal.package
                            ));
                        }
                        LicenseVerdict::Ok => {}
                    }
                }
            }
            "yanked_crate" => {
                if eff.fail_on_yanked && !allowlisted {
                    violations.push(format!("`{}` is yanked", signal.package));
                } else {
                    warnings.push(format!("`{}` is yanked", signal.package));
                }
            }
            _ => {}
        }
    }

    dedup(&mut violations);
    dedup(&mut warnings);
    dedup(&mut review_items);
    dedup(&mut ignored_advisories);

    let decision = if !violations.is_empty() {
        Decision::Fail
    } else if !review_items.is_empty() {
        Decision::ReviewRequired
    } else if !warnings.is_empty() {
        Decision::Warn
    } else {
        Decision::Pass
    };

    Ok(PolicyDecision {
        decision,
        profile: eff.profile,
        violations,
        warnings,
        review_items,
        ignored_advisories,
    })
}

fn dedup(items: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    items.retain(|i| seen.insert(i.clone()));
}

fn crate_name_of(package: &str) -> &str {
    package.split('@').next().unwrap_or(package)
}

const LICENSE_PREFIX: &str = "declared license: ";

fn license_from_signal(signal: &RiskSignal) -> Option<String> {
    signal.evidence.iter().find_map(|e| {
        e.summary
            .strip_prefix(LICENSE_PREFIX)
            .map(|s| s.to_string())
    })
}

/// Build the canonical license-detected evidence summary (kept in sync with the
/// parser above).
pub fn license_summary(license: &str) -> String {
    format!("{LICENSE_PREFIX}{license}")
}

#[derive(Debug, PartialEq, Eq)]
enum LicenseVerdict {
    Ok,
    NotAllowed,
    Denied,
}

/// Evaluate an SPDX license expression against allow/deny lists with correct
/// boolean semantics (so `MIT OR GPL-3.0` is fine when MIT is allowed even if
/// GPL-3.0 is denied — you can satisfy the OR with MIT).
fn license_verdict(expr: &str, allow: &[String], deny: &[String]) -> LicenseVerdict {
    let contains = |list: &[String], lic: &str| list.iter().any(|x| x.eq_ignore_ascii_case(lic));

    // Denied iff the expression cannot be satisfied while avoiding denied licenses.
    if !deny.is_empty() && !satisfiable(expr, &|lic| !contains(deny, lic)) {
        return LicenseVerdict::Denied;
    }
    // Not-allowed iff an allow list exists but the expression can't be satisfied
    // using only allowed licenses.
    if !allow.is_empty() && !satisfiable(expr, &|lic| contains(allow, lic)) {
        return LicenseVerdict::NotAllowed;
    }
    LicenseVerdict::Ok
}

/// True if the SPDX expression can be satisfied when each license leaf is
/// evaluated by `pred`. Falls back to "any token satisfies pred" on parse error.
pub(crate) fn satisfiable(expr: &str, pred: &dyn Fn(&str) -> bool) -> bool {
    let toks = tokenize_spdx(expr);
    if toks.is_empty() {
        return true; // no constraint
    }
    let mut p = SpdxParser {
        toks: &toks,
        pos: 0,
    };
    match p.parse_expr(pred) {
        Some(v) if p.pos == p.toks.len() => v,
        // Malformed expression: conservative OR over the license tokens.
        _ => toks.iter().any(|t| matches!(t, SpdxTok::Lic(l) if pred(l))),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SpdxTok {
    LParen,
    RParen,
    And,
    Or,
    With,
    Lic(String),
}

fn tokenize_spdx(expr: &str) -> Vec<SpdxTok> {
    let mut toks = Vec::new();
    let mut word = String::new();
    let flush = |word: &mut String, toks: &mut Vec<SpdxTok>| {
        if !word.is_empty() {
            match word.as_str() {
                "OR" => toks.push(SpdxTok::Or),
                "AND" => toks.push(SpdxTok::And),
                "WITH" => toks.push(SpdxTok::With),
                _ => toks.push(SpdxTok::Lic(std::mem::take(word))),
            }
            word.clear();
        }
    };
    for ch in expr.chars() {
        match ch {
            '(' => {
                flush(&mut word, &mut toks);
                toks.push(SpdxTok::LParen);
            }
            ')' => {
                flush(&mut word, &mut toks);
                toks.push(SpdxTok::RParen);
            }
            c if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '+' || c == '_' => {
                word.push(c);
            }
            _ => flush(&mut word, &mut toks),
        }
    }
    flush(&mut word, &mut toks);
    toks
}

struct SpdxParser<'a> {
    toks: &'a [SpdxTok],
    pos: usize,
}

impl<'a> SpdxParser<'a> {
    fn peek(&self) -> Option<&SpdxTok> {
        self.toks.get(self.pos)
    }

    // expr := term (OR term)*
    fn parse_expr(&mut self, pred: &dyn Fn(&str) -> bool) -> Option<bool> {
        let mut acc = self.parse_term(pred)?;
        while matches!(self.peek(), Some(SpdxTok::Or)) {
            self.pos += 1;
            let rhs = self.parse_term(pred)?;
            acc = acc || rhs;
        }
        Some(acc)
    }

    // term := factor (AND factor)*
    fn parse_term(&mut self, pred: &dyn Fn(&str) -> bool) -> Option<bool> {
        let mut acc = self.parse_factor(pred)?;
        while matches!(self.peek(), Some(SpdxTok::And)) {
            self.pos += 1;
            let rhs = self.parse_factor(pred)?;
            acc = acc && rhs;
        }
        Some(acc)
    }

    // factor := '(' expr ')' | license ('WITH' exception)?
    fn parse_factor(&mut self, pred: &dyn Fn(&str) -> bool) -> Option<bool> {
        match self.peek() {
            Some(SpdxTok::LParen) => {
                self.pos += 1;
                let v = self.parse_expr(pred)?;
                if matches!(self.peek(), Some(SpdxTok::RParen)) {
                    self.pos += 1;
                    Some(v)
                } else {
                    None
                }
            }
            Some(SpdxTok::Lic(name)) => {
                let v = pred(name);
                self.pos += 1;
                // `license WITH exception` — exception doesn't change allow/deny.
                if matches!(self.peek(), Some(SpdxTok::With)) {
                    self.pos += 1;
                    if matches!(self.peek(), Some(SpdxTok::Lic(_))) {
                        self.pos += 1;
                    }
                }
                Some(v)
            }
            _ => None,
        }
    }
}

pub fn parse_policy_toml(input: &str) -> Result<Policy, RustinelError> {
    toml::from_str(input).map_err(|e| RustinelError::InvalidPolicy(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::{PackageRisk, RiskLevel};
    use crate::signals::{Evidence, Severity};

    fn risk(score: u8, max_pkg: u8) -> ProjectRisk {
        ProjectRisk {
            score,
            level: crate::risk::level_for_score(score),
            max_package_score: max_pkg,
            packages: vec![PackageRisk {
                package: "x@1".into(),
                score: max_pkg,
                level: RiskLevel::Low,
            }],
        }
    }

    #[test]
    fn fails_above_project_threshold() {
        let policy = parse_policy_toml("[risk]\nmax_project_score = 10\n").unwrap();
        let d = evaluate(&risk(40, 0), &[], None, Some(&policy)).unwrap();
        assert_eq!(d.decision, Decision::Fail);
        assert!(!d.violations.is_empty());
    }

    #[test]
    fn passes_below_threshold() {
        let policy = parse_policy_toml("[risk]\nmax_project_score = 90\n").unwrap();
        let d = evaluate(&risk(40, 50), &[], None, Some(&policy)).unwrap();
        assert_eq!(d.decision, Decision::Pass);
    }

    #[test]
    fn native_ffi_requires_review_under_balanced() {
        let sig = RiskSignal {
            id: "native_ffi_detected".into(),
            package: "openssl-sys@0.9.99".into(),
            severity: Severity::High,
            weight: 20,
            confidence: 0.9,
            evidence: vec![],
            recommendation: String::new(),
        };
        let d = evaluate(&risk(20, 20), std::slice::from_ref(&sig), None, None).unwrap();
        assert_eq!(d.decision, Decision::ReviewRequired);
    }

    #[test]
    fn advisory_high_fails_balanced() {
        let sig = RiskSignal {
            id: "advisory_RUSTSEC-2099-0001".into(),
            package: "vuln@1.0.0".into(),
            severity: Severity::High,
            weight: 30,
            confidence: 1.0,
            evidence: vec![],
            recommendation: String::new(),
        };
        let d = evaluate(&risk(30, 30), std::slice::from_ref(&sig), None, None).unwrap();
        assert_eq!(d.decision, Decision::Fail);
    }

    #[test]
    fn ignored_advisory_downgrades_to_warning() {
        let policy = parse_policy_toml("[advisories]\nignore = [\"RUSTSEC-2099-0001\"]\n").unwrap();
        let sig = RiskSignal {
            id: "advisory_RUSTSEC-2099-0001".into(),
            package: "vuln@1.0.0".into(),
            severity: Severity::High,
            weight: 30,
            confidence: 1.0,
            evidence: vec![],
            recommendation: String::new(),
        };
        let d = evaluate(
            &risk(30, 30),
            std::slice::from_ref(&sig),
            None,
            Some(&policy),
        )
        .unwrap();
        assert_eq!(d.decision, Decision::Warn);
    }

    #[test]
    fn denied_license_fails() {
        let sig = RiskSignal {
            id: "license_detected".into(),
            package: "gpl-crate@1.0.0".into(),
            severity: Severity::Info,
            weight: 0,
            confidence: 1.0,
            evidence: vec![Evidence::new("manifest", license_summary("GPL-3.0"))],
            recommendation: String::new(),
        };
        let d = evaluate(&risk(0, 0), std::slice::from_ref(&sig), None, None).unwrap();
        assert_eq!(d.decision, Decision::Fail);
    }

    #[test]
    fn spdx_expression_semantics() {
        let deny = vec!["GPL-3.0".to_string(), "AGPL-3.0".to_string()];
        let allow = vec![
            "MIT".to_string(),
            "Apache-2.0".to_string(),
            "BSD-3-Clause".to_string(),
        ];
        // OR with an allowed escape is NOT denied (the FP the old code had).
        assert_eq!(
            license_verdict("MIT OR GPL-3.0", &[], &deny),
            LicenseVerdict::Ok
        );
        // Pure denied license is denied.
        assert_eq!(
            license_verdict("GPL-3.0", &[], &deny),
            LicenseVerdict::Denied
        );
        // AND requiring a denied license is denied (can't avoid it).
        assert_eq!(
            license_verdict("MIT AND GPL-3.0", &[], &deny),
            LicenseVerdict::Denied
        );
        // Allow-list: satisfiable with allowed licenses.
        assert_eq!(
            license_verdict("MIT OR Apache-2.0", &allow, &deny),
            LicenseVerdict::Ok
        );
        // Allow-list: a license not on the list -> NotAllowed.
        assert_eq!(
            license_verdict("WTFPL", &allow, &deny),
            LicenseVerdict::NotAllowed
        );
        // Parentheses + WITH exception parse and evaluate.
        assert_eq!(
            license_verdict("(MIT OR Apache-2.0) AND BSD-3-Clause", &allow, &deny),
            LicenseVerdict::Ok
        );
        assert_eq!(
            license_verdict("Apache-2.0 WITH LLVM-exception", &allow, &deny),
            LicenseVerdict::Ok
        );
    }

    #[test]
    fn allowlisted_crate_downgrades_advisory() {
        let policy = parse_policy_toml("[allow]\ncrates = [\"vuln\"]\n").unwrap();
        let sig = RiskSignal {
            id: "advisory_RUSTSEC-2099-0001".into(),
            package: "vuln@1.0.0".into(),
            severity: Severity::High,
            weight: 30,
            confidence: 1.0,
            evidence: vec![],
            recommendation: String::new(),
        };
        let d = evaluate(
            &risk(30, 30),
            std::slice::from_ref(&sig),
            None,
            Some(&policy),
        )
        .unwrap();
        assert_eq!(d.decision, Decision::Warn);
    }

    #[test]
    fn delta_fail_threshold() {
        let policy = parse_policy_toml("[risk]\nfail_on_delta_above = 10\n").unwrap();
        let d = evaluate(&risk(0, 0), &[], Some(45), Some(&policy)).unwrap();
        assert_eq!(d.decision, Decision::Fail);
    }
}
