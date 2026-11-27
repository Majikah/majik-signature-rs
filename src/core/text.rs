//! ECMAScript-compatible trimming used to keep Rust validation behavior aligned with TypeScript.

/// Return true for the exact whitespace and line-terminator code points removed by
/// JavaScript's String.prototype.trim().
///
/// This deliberately does not use Rust's native char::is_whitespace/str::trim,
/// whose Unicode classification differs from ECMAScript (for example U+0085).
fn is_ecmascript_trim_character(ch: char) -> bool {
    matches!(
        ch,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

/// Trim both ends using the same whitespace set as ECMAScript String.prototype.trim().
pub(crate) fn trim_ecmascript_whitespace(value: &str) -> &str {
    value.trim_matches(is_ecmascript_trim_character)
}

#[cfg(test)]
mod tests {
    use super::trim_ecmascript_whitespace;

    #[test]
    fn matches_ecmascript_whitespace_membership() {
        assert_eq!(trim_ecmascript_whitespace("\u{feff}value\u{feff}"), "value");
        assert_eq!(trim_ecmascript_whitespace("\u{0085}value\u{0085}"), "\u{0085}value\u{0085}");
        assert_eq!(trim_ecmascript_whitespace("\u{00a0}value\u{3000}"), "value");
        assert_eq!(trim_ecmascript_whitespace("\u{2028}value\u{2029}"), "value");
    }
}
