//! Rust-only helper: a stand-in for JS `String.prototype.localeCompare` restricted to the
//! alphabet that actually reaches it — base64 fingerprints (`A-Z a-z 0-9 + / =`).
//!
//! The TS library orders signers with `a.signerId.localeCompare(b.signerId)` before hashing
//! allowlists and seals. V8's `localeCompare` uses ICU (CLDR root collation), which is **not**
//! byte order: punctuation sorts before digits before letters, letters compare
//! case-insensitively first, and a lowercase letter sorts before its uppercase twin only as a
//! tie-break. Plain Rust `str::cmp` would therefore produce different seal hashes. This
//! comparator reproduces the CLDR root order for the base64 alphabet (and falls back to code
//! point order for anything else, ranked after letters).

use std::cmp::Ordering;

/// Primary weight: symbols `/ + =` < digits < letters (case-insensitive) < everything else.
fn primary(c: char) -> (u8, u32) {
    match c {
        '/' => (0, 0),
        '+' => (0, 1),
        '=' => (0, 2),
        '0'..='9' => (1, c as u32),
        'a'..='z' => (2, c as u32),
        'A'..='Z' => (2, c.to_ascii_lowercase() as u32),
        other => (3, other as u32),
    }
}

/// Tertiary weight: lowercase before uppercase.
fn tertiary(c: char) -> u8 {
    if c.is_ascii_uppercase() {
        1
    } else {
        0
    }
}

/// `a.localeCompare(b)` for base64-ish strings.
pub fn locale_compare(a: &str, b: &str) -> Ordering {
    // Level 1: primary weights over the whole string.
    let mut ia = a.chars();
    let mut ib = b.chars();
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => break,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let o = primary(x).cmp(&primary(y));
                if o != Ordering::Equal {
                    return o;
                }
            }
        }
    }
    // Level 3: first case difference decides (lowercase first).
    for (x, y) in a.chars().zip(b.chars()) {
        let o = tertiary(x).cmp(&tertiary(y));
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbols_digits_letters() {
        assert_eq!(locale_compare("/", "+"), Ordering::Less);
        assert_eq!(locale_compare("+", "0"), Ordering::Less);
        assert_eq!(locale_compare("9", "a"), Ordering::Less);
    }

    #[test]
    fn case_is_secondary() {
        // byte order would put "B" < "a"; ICU puts "a" < "B"
        assert_eq!(locale_compare("a", "B"), Ordering::Less);
        // same letters: lowercase first
        assert_eq!(locale_compare("a", "A"), Ordering::Less);
        assert_eq!(locale_compare("Ab", "aB"), Ordering::Greater);
    }
}
