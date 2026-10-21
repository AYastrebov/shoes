//! Known-answer vectors, written by the reference implementations themselves
//! (`tests/data/kat/gen`) and read by the tests beside the code each one
//! checks. A round trip through shoes alone passes when both halves share a
//! misreading; a vector the reference computed does not.

use serde_json::Value;

/// `tests/data/kat/<protocol>/vectors.json`.
pub fn vectors(protocol: &str) -> Value {
    let path = format!(
        "{}/tests/data/kat/{protocol}/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The array under `key`, which every vector file uses for its cases.
pub fn cases<'a>(vectors: &'a Value, key: &str) -> &'a [Value] {
    vectors[key]
        .as_array()
        .unwrap_or_else(|| panic!("no array {key:?} in the vectors"))
}

pub fn hex(value: &Value) -> Vec<u8> {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("{value} is not a hex string"));
    assert!(text.len().is_multiple_of(2), "odd-length hex {text:?}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{value} is not a string"))
}

pub fn number(value: &Value) -> u64 {
    value
        .as_u64()
        .unwrap_or_else(|| panic!("{value} is not a number"))
}
