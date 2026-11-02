// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Byte-exact Go `encoding/json` behaviour for the shapes the HTTP surface
//! uses.
//!
//! Encoding: `json.NewEncoder(w).Encode(v)` writes compact JSON plus a
//! trailing `\n`, map keys sorted, struct fields in declaration order, and
//! HTML-safe string escaping (`<`, `>`, `&`, U+2028, U+2029 as `\u…`).
//!
//! Decoding: `json.NewDecoder(r).Decode(&v)` reads the first JSON value and
//! ignores what follows it, matches object keys to fields exactly or else
//! case-insensitively, leaves a field at its zero value for `null`, and
//! rejects a type mismatch.

use std::fmt::Write as _;

use serde_json::{Map, Value};

/// Appends `s` as a Go-escaped JSON string literal.
pub fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A JSON object written field by field, in the caller's order.
#[derive(Debug, Default)]
pub struct Obj {
    buf: String,
    first: bool,
}

impl Obj {
    /// Starts an object.
    pub fn new() -> Self {
        Self { buf: String::from("{"), first: true }
    }

    fn key(&mut self, k: &str) {
        if !self.first {
            self.buf.push(',');
        }
        self.first = false;
        push_str(&mut self.buf, k);
        self.buf.push(':');
    }

    /// A string field.
    pub fn str(mut self, k: &str, v: &str) -> Self {
        self.key(k);
        push_str(&mut self.buf, v);
        self
    }

    /// An unsigned integer field.
    pub fn num(mut self, k: &str, v: u64) -> Self {
        self.key(k);
        let _ = write!(self.buf, "{v}");
        self
    }

    /// A boolean field.
    pub fn bool(mut self, k: &str, v: bool) -> Self {
        self.key(k);
        self.buf.push_str(if v { "true" } else { "false" });
        self
    }

    /// The object's text, without a newline.
    pub fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }
}

/// `Encode` of an object: the text plus `\n`.
pub fn line(obj: Obj) -> String {
    let mut s = obj.finish();
    s.push('\n');
    s
}

/// `Encode` of an array of already-encoded objects: `[a,b]\n`.
pub fn array_line(items: impl IntoIterator<Item = String>) -> String {
    let mut s = String::from("[");
    for (i, it) in items.into_iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&it);
    }
    s.push_str("]\n");
    s
}

/// gov5's `{"error":"<msg>"}\n`.
pub fn error_body(msg: &str) -> String {
    line(Obj::new().str("error", msg))
}

/// Decoding a request body failed (gov5 answers `bad json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadJson;

/// The object a Go `Decode` into a struct sees: `Ok(None)` for `null`.
pub fn decode_object(body: &[u8]) -> Result<Option<Map<String, Value>>, BadJson> {
    let mut stream = serde_json::Deserializer::from_slice(body).into_iter::<Value>();
    match stream.next() {
        Some(Ok(Value::Object(m))) => Ok(Some(m)),
        Some(Ok(Value::Null)) => Ok(None),
        _ => Err(BadJson),
    }
}

/// Go's field lookup: an exact key first, else a case-insensitive one.
fn field<'a>(obj: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    obj.get(name).or_else(|| obj.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v))
}

/// A Go `string` field: absent or `null` → `""`.
pub fn get_string(obj: Option<&Map<String, Value>>, name: &str) -> Result<String, BadJson> {
    match obj.and_then(|o| field(o, name)) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(BadJson),
    }
}

/// A Go `uint64` field: absent or `null` → 0; anything but a non-negative
/// integer literal that fits is an error.
pub fn get_u64(obj: Option<&Map<String, Value>>, name: &str) -> Result<u64, BadJson> {
    match obj.and_then(|o| field(o, name)) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n.as_u64().ok_or(BadJson),
        Some(_) => Err(BadJson),
    }
}

/// gov5 `hexInto`: strips one lowercase `0x`, hex-decodes, requires exactly
/// `N` bytes.
pub fn hex_into<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// `0x` + lowercase hex.
pub fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_go() {
        let mut s = String::new();
        push_str(&mut s, "a<b>&\"\\\n\u{1}\u{2028}é");
        assert_eq!(s, r#""a\u003cb\u003e\u0026\"\\\n\u0001\u2028é""#);
        assert_eq!(error_body("POST only"), "{\"error\":\"POST only\"}\n");
    }

    #[test]
    fn decodes_like_go() {
        let o = decode_object(br#"{"PUBKEY":"ab","n":5} trailing"#).unwrap();
        assert_eq!(get_string(o.as_ref(), "pubkey").unwrap(), "ab");
        assert_eq!(get_u64(o.as_ref(), "n").unwrap(), 5);
        assert_eq!(get_u64(o.as_ref(), "missing").unwrap(), 0);
        assert_eq!(decode_object(b"null").unwrap(), None);
        assert!(decode_object(b"").is_err());
        assert!(decode_object(b"[1]").is_err());
        let o = decode_object(br#"{"n":1.0,"s":5,"neg":-1}"#).unwrap();
        assert!(get_u64(o.as_ref(), "n").is_err());
        assert!(get_u64(o.as_ref(), "neg").is_err());
        assert!(get_string(o.as_ref(), "s").is_err());
        assert_eq!(hex_into::<2>("0xabCD"), Some([0xab, 0xcd]));
        assert_eq!(hex_into::<2>("abcd"), Some([0xab, 0xcd]));
        assert_eq!(hex_into::<2>("0Xabcd"), None);
        assert_eq!(hex_into::<2>("abc"), None);
    }
}
