//! Markdown output helpers.
//!
//! Untrusted content (crate names, advisory titles, license strings) flows into
//! PR comments. To prevent Markdown/HTML injection we escape such content before
//! interpolation. This is a defensive output-encoding concern, not cosmetics.

/// Escape a string for safe inline rendering inside Markdown.
///
/// The goal is injection safety, not escaping every punctuation mark. We:
/// - entity-encode HTML specials (`<`, `>`, `&`) so raw HTML can never be
///   injected into a rendered comment;
/// - backslash-escape the Markdown characters that let attacker text *break out*
///   of inline context — code spans (`` ` ``), emphasis (`*`, `_`), links/images
///   (`[`, `]`), tables (`|`), and a literal backslash;
/// - flatten control characters (including CR/LF) that could forge new lines or
///   block-level constructs, and Unicode text-spoofing characters (bidi
///   overrides, zero-widths) that could visually reorder or hide text.
///
/// Cosmetic-only characters (`. - ! + # ( ) { }`) are left as-is: with newlines
/// stripped they cannot start a block, so escaping them only produces noise.
pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\\' | '`' | '*' | '_' | '[' | ']' | '|' => {
                out.push('\\');
                out.push(ch);
            }
            // Strip control characters (including CR/LF) that could be used to
            // forge new Markdown lines/sections, and Trojan-Source spoofers.
            c if c.is_control() || is_text_spoofing(c) => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Trojan-Source defense (CVE-2021-42574): bidirectional-override and
/// zero-width characters are category `Cf` (format), NOT control characters,
/// so an `is_control()` filter passes them straight through — letting a crate
/// name or advisory title visually reorder or hide text in a PR comment or a
/// code-scanning alert.
pub(crate) fn is_text_spoofing(c: char) -> bool {
    matches!(
        c,
        // Bidi embeddings/overrides + isolates (LRE..RLO, LRI..PDI).
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        // Implicit direction marks + Arabic letter mark.
        | '\u{200E}' | '\u{200F}' | '\u{061C}'
        // Zero-width characters (ZWSP/ZWNJ/ZWJ, word joiner, BOM-as-ZWNBSP).
        | '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}'
    )
}

/// Escape for use inside an inline code span (backticks).
///
/// Backticks terminate the span, so they are replaced. Angle brackets and
/// ampersands are entity-encoded as defense-in-depth: a Markdown code span
/// renders its content literally, but we never want raw `<script>`-style text to
/// reach a consumer that might mis-handle it. Newlines are flattened.
pub fn escape_code(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '`' => out.push('\''),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            c if c.is_control() || is_text_spoofing(c) => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutralizes_html() {
        let out = escape("<img src=x onerror=alert(1)>");
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
        assert!(out.contains("&lt;img"));
    }

    #[test]
    fn strips_newlines() {
        let out = escape("line1\n## injected heading");
        assert!(!out.contains('\n'));
    }

    #[test]
    fn code_span_safe() {
        let out = escape_code("evil`code`span");
        assert!(!out.contains('`'));
    }

    #[test]
    fn strips_bidi_and_zero_width_spoofers() {
        // U+202E (RLO) is Cf, not Cc — `is_control()` alone passes it through.
        let s = "safe\u{202E}desrever\u{2066}x\u{200B}y\u{FEFF}z";
        for out in [escape(s), escape_code(s)] {
            assert!(!out.contains('\u{202E}'), "RLO survived: {out:?}");
            assert!(!out.contains('\u{2066}'), "LRI survived: {out:?}");
            assert!(!out.contains('\u{200B}'), "ZWSP survived: {out:?}");
            assert!(!out.contains('\u{FEFF}'), "ZWNBSP survived: {out:?}");
        }
    }
}
