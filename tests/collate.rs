use majik_signature::core::collate::locale_compare;

/// `localeCompare` ordering captured from V8/ICU (`arr.sort((a, b) => a.localeCompare(b))`).
#[test]
fn matches_v8_locale_compare_on_base64_strings() {
    let v: serde_json::Value = serde_json::from_str(include_str!("fixtures/locale_sorted.json")).unwrap();
    let mut input: Vec<String> =
        v["input"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
    let expected: Vec<String> =
        v["sorted"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
    input.sort_by(|a, b| locale_compare(a, b));
    assert_eq!(input, expected);
}
