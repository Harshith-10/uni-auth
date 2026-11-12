//! Canonical URL and percent-encoding utilities.

/// Percent-encodes a string according to RFC 3986 unreserved characters (`a-z`, `A-Z`, `0-9`, `-`, `_`, `.`, `~`).
///
/// Encodes spaces as `%20` (not `+`) so it is safe in both URL path segments, query values, and headers.
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

/// Decodes percent-encoded bytes `%XX` in a string.
///
/// Preserves literal `+` characters (does not convert them to space), making this
/// safe for decoding signed Base64 tokens and cookies.
pub fn url_decode(input: &str) -> String {
    if !input.contains('%') {
        return input.to_string();
    }
    let mut out = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(hex_nibble);
            let lo = bytes.next().and_then(hex_nibble);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4) | l);
                continue;
            }
            return input.to_string();
        }
        out.push(b);
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode_and_decode() {
        let original = "hello world / & ? = +";
        let encoded = url_encode(original);
        assert_eq!(encoded, "hello%20world%20%2F%20%26%20%3F%20%3D%20%2B");
        let decoded = url_decode(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_url_decode_preserves_plus_in_base64() {
        let b64 = "abc+def/123==";
        let percent_encoded = "abc+def/123%3D%3D";
        assert_eq!(url_decode(percent_encoded), b64);
        assert_eq!(url_decode(b64), b64);
    }
}
