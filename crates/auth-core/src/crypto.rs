//! Cryptographic primitives for Better Auth wire and storage compatibility.
//!
//! - Non-blocking Argon2id password hashing and verification inside `tokio::task::spawn_blocking`.
//! - Legacy Better Auth `scrypt` (`<salt>:<hex_key>`, N=16384, r=16, p=1, dkLen=64, NFKC-normalized)
//!   verification for zero-downtime migration from TypeScript Better Auth databases.
//! - HKDF-SHA256 key derivation and raw-secret HMAC-SHA256 verification from `BETTER_AUTH_SECRET`/`UNI_AUTH_SECRET`.
//! - HMAC-SHA256 token and cookie signing matching Better Auth format (`token.signature`).
//! - Constant-time signature verification (`subtle::ConstantTimeEq`).
//! - Cryptographically secure token generation (`rand::rngs::OsRng`).

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;

type HmacSha256 = Hmac<Sha256>;

/// Returns `true` if the stored password hash uses Better Auth's `<salt>:<hex_key>` scrypt format.
pub fn is_legacy_scrypt_hash(hash: &str) -> bool {
    !hash.starts_with("$argon2") && hash.contains(':')
}

/// Hashes a password asynchronously using Argon2id without blocking Tokio worker threads.
pub async fn hash_password(password: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let normalized: String = password.nfkc().collect();
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(normalized.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| format!("Password hashing failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task join error during password hashing: {e}"))?
}

/// Verifies a password against either an Argon2id PHC string (`$argon2id$...`) or
/// a Better Auth TypeScript `scrypt` hash (`<salt>:<64_byte_hex_key>`) inside `spawn_blocking`.
pub async fn verify_password(hash: String, password: String) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || {
        if is_legacy_scrypt_hash(&hash) {
            return match verify_scrypt_better_auth(&hash, &password) {
                Ok(valid) => Ok(valid),
                Err(e) => {
                    tracing::warn!("Malformed scrypt hash encountered: {e}");
                    let normalized: String = password.nfkc().collect();
                    let dummy_salt = SaltString::generate(&mut OsRng);
                    let _ = Argon2::default().hash_password(normalized.as_bytes(), &dummy_salt);
                    Ok(false)
                }
            };
        }
        let parsed_hash = match PasswordHash::new(&hash) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("Malformed password hash format encountered: {e}");
                let normalized: String = password.nfkc().collect();
                let dummy_salt = SaltString::generate(&mut OsRng);
                let _ = Argon2::default().hash_password(normalized.as_bytes(), &dummy_salt);
                return Ok(false);
            }
        };
        let normalized: String = password.nfkc().collect();
        let argon2 = Argon2::default();
        Ok(argon2
            .verify_password(normalized.as_bytes(), &parsed_hash)
            .is_ok())
    })
    .await
    .map_err(|e| format!("Task join error during password verification: {e}"))?
}

/// Hashes a password using Better Auth's TypeScript `scrypt` parameters (`N=16384, r=16, p=1, dkLen=64`)
/// with Unicode `NFKC` normalization and returns `<salt>:<hex_key>`.
///
/// Reference: `.reference/better-auth/packages/better-auth/src/crypto/password.test.ts` lines 72-78
pub fn hash_scrypt_better_auth(salt: &str, password: &str) -> Result<String, String> {
    let normalized: String = password.nfkc().collect();
    let dk = scrypt_derive(normalized.as_bytes(), salt.as_bytes(), 16384, 16, 1, 64)?;
    Ok(format!("{salt}:{}", hex_encode(&dk)))
}

fn verify_scrypt_better_auth(hash: &str, password: &str) -> Result<bool, String> {
    let (salt, expected_hex) = hash
        .split_once(':')
        .ok_or_else(|| "Invalid scrypt hash format: missing ':'".to_string())?;
    let expected_bytes = hex_decode(expected_hex)?;
    if expected_bytes.is_empty() {
        return Err("Invalid scrypt derived key length".to_string());
    }
    let normalized: String = password.nfkc().collect();
    let derived = scrypt_derive(
        normalized.as_bytes(),
        salt.as_bytes(),
        16384,
        16,
        1,
        expected_bytes.len(),
    )?;
    Ok(derived.ct_eq(&expected_bytes).into())
}

/// Pure-Rust RFC 7914 `scrypt` key derivation (`PBKDF2-HMAC-SHA256` + `ROMix` + `Salsa20/8`).
fn scrypt_derive(
    password: &[u8],
    salt: &[u8],
    n: usize,
    r: usize,
    p: usize,
    dk_len: usize,
) -> Result<Vec<u8>, String> {
    if n == 0 || (n & (n - 1)) != 0 {
        return Err("scrypt N must be a power of 2".to_string());
    }
    let block_size = 128 * r;
    let mut b = pbkdf2_hmac_sha256(password, salt, 1, p * block_size);
    let mut v = vec![0u32; n * 32 * r];
    let mut xy = vec![0u32; 64 * r];

    for chunk in b.chunks_exact_mut(block_size) {
        scrypt_ro_mix(chunk, r, n, &mut v, &mut xy);
    }

    Ok(pbkdf2_hmac_sha256(password, &b, 1, dk_len))
}

fn scrypt_ro_mix(b: &mut [u8], r: usize, n: usize, v: &mut [u32], xy: &mut [u32]) {
    let words_per_block = 32 * r;
    let (x, y) = xy.split_at_mut(words_per_block);

    for (i, chunk) in b.chunks_exact(4).enumerate() {
        x[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    for i in 0..n {
        v[i * words_per_block..(i + 1) * words_per_block].copy_from_slice(x);
        scrypt_block_mix(x, y, r);
    }

    for _ in 0..n {
        let j = (x[words_per_block - 16] as usize) & (n - 1);
        let v_slice = &v[j * words_per_block..(j + 1) * words_per_block];
        for k in 0..words_per_block {
            x[k] ^= v_slice[k];
        }
        scrypt_block_mix(x, y, r);
    }

    for (i, chunk) in b.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&x[i].to_le_bytes());
    }
}

fn scrypt_block_mix(x: &mut [u32], y: &mut [u32], r: usize) {
    let mut b_last = [0u32; 16];
    b_last.copy_from_slice(&x[(2 * r - 1) * 16..2 * r * 16]);

    for i in 0..(2 * r) {
        let block = &x[i * 16..(i + 1) * 16];
        for k in 0..16 {
            b_last[k] ^= block[k];
        }
        salsa20_8(&mut b_last);
        let dest_idx = (i / 2) + (i % 2) * r;
        y[dest_idx * 16..(dest_idx + 1) * 16].copy_from_slice(&b_last);
    }

    x.copy_from_slice(y);
}

fn salsa20_8(b: &mut [u32; 16]) {
    let mut x = *b;
    for _ in 0..4 {
        x[4] ^= x[0].wrapping_add(x[12]).rotate_left(7);
        x[8] ^= x[4].wrapping_add(x[0]).rotate_left(9);
        x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
        x[0] ^= x[12].wrapping_add(x[8]).rotate_left(18);

        x[9] ^= x[5].wrapping_add(x[1]).rotate_left(7);
        x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
        x[1] ^= x[13].wrapping_add(x[9]).rotate_left(13);
        x[5] ^= x[1].wrapping_add(x[13]).rotate_left(18);

        x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
        x[2] ^= x[14].wrapping_add(x[10]).rotate_left(9);
        x[6] ^= x[2].wrapping_add(x[14]).rotate_left(13);
        x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);

        x[3] ^= x[15].wrapping_add(x[11]).rotate_left(7);
        x[7] ^= x[3].wrapping_add(x[15]).rotate_left(9);
        x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
        x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);

        x[1] ^= x[0].wrapping_add(x[3]).rotate_left(7);
        x[2] ^= x[1].wrapping_add(x[0]).rotate_left(9);
        x[3] ^= x[2].wrapping_add(x[1]).rotate_left(13);
        x[0] ^= x[3].wrapping_add(x[2]).rotate_left(18);

        x[6] ^= x[5].wrapping_add(x[4]).rotate_left(7);
        x[7] ^= x[6].wrapping_add(x[5]).rotate_left(9);
        x[4] ^= x[7].wrapping_add(x[6]).rotate_left(13);
        x[5] ^= x[4].wrapping_add(x[7]).rotate_left(18);

        x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
        x[8] ^= x[11].wrapping_add(x[10]).rotate_left(9);
        x[9] ^= x[8].wrapping_add(x[11]).rotate_left(13);
        x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);

        x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
        x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
        x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
        x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
    }
    for i in 0..16 {
        b[i] = b[i].wrapping_add(x[i]);
    }
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], c: u32, dk_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(dk_len);
    let blocks = (dk_len + 31) / 32;
    for block_idx in 1..=(blocks as u32) {
        let mut mac = HmacSha256::new_from_slice(password).expect("HMAC accepts any key size");
        mac.update(salt);
        mac.update(&block_idx.to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut t = u;
        for _ in 1..c {
            let mut m = HmacSha256::new_from_slice(password).expect("HMAC accepts any key size");
            m.update(&u);
            u = m.finalize().into_bytes();
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= *ui;
            }
        }
        let remaining = dk_len - out.len();
        let take = remaining.min(32);
        out.extend_from_slice(&t[..take]);
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex.trim();
    if trimmed.len() % 2 != 0 {
        return Err("Odd-length hex string".to_string());
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or_else(|| "Invalid hex character".to_string())?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| "Invalid hex character".to_string())?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Generates a cryptographically secure random token of the specified byte length,
/// encoded as unpadded base64url.
pub fn generate_random_token(byte_len: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; byte_len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Generates a standard 32-byte (256-bit) session token encoded as unpadded base64url.
pub fn generate_session_token() -> String {
    generate_random_token(32)
}

/// Derives a 32-byte signing key from the secret using HKDF-SHA256 with the given info context.
pub fn derive_signing_key(secret: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is valid length for HKDF-SHA256");
    okm
}

/// Signs a token string using raw-secret HMAC-SHA256 with standard padded Base64 (`=`),
/// matching Better Auth and `better-call`'s `serializeSignedCookie` / `makeSignature`.
///
/// Output format: `<token>.<base64_signature>`
pub fn sign_token(secret: &[u8], token: &str) -> String {
    sign_cookie_better_call(secret, token)
}

/// Signs a token string using HKDF-derived key and base64urlnopad.
/// Retained for backward-compatibility testing with legacy uni-auth tokens.
pub fn sign_token_hkdf(secret: &[u8], token: &str) -> String {
    let key = derive_signing_key(secret, b"better-auth-token-signing");
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{token}.{signature}")
}

/// Signs a token string using raw-secret HMAC-SHA256 (`base64urlnopad`), matching
/// `@better-auth/utils/hmac` (`createHMAC("SHA-256", "base64urlnopad")`).
///
/// Reference: `.reference/better-auth/packages/better-auth/src/plugins/bearer/index.ts` lines 81-87
pub fn sign_token_better_auth(secret: &[u8], token: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{token}.{signature}")
}

/// Signs a cookie token using raw-secret HMAC-SHA256 with standard padded Base64 (`=`),
/// matching `better-call`'s `serializeSignedCookie` / `makeSignature`.
///
/// Reference: `.reference/better-auth/packages/better-auth/src/crypto/index.ts` lines 104-114
pub fn sign_cookie_better_call(secret: &[u8], token: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let signature = STANDARD.encode(mac.finalize().into_bytes());
    format!("{token}.{signature}")
}

/// Verifies an HMAC-SHA256 signature against the raw token using constant-time comparison.
///
/// Accepts:
/// 1. `uni-auth` HKDF-derived `base64urlnopad` signatures (`derive_signing_key(secret, "better-auth-token-signing")`),
/// 2. Upstream `@better-auth/utils/hmac` raw-secret `base64urlnopad` signatures, and
/// 3. Upstream `better-call` raw-secret standard padded Base64 signatures (including URL-encoded `%3D`/`%2B`/`%2F`).
pub fn verify_signature(secret: &[u8], token: &str, signature: &str) -> bool {
    let decoded_sig = auth_proto::url_decode(signature);
    let sig_bytes = decoded_sig.as_bytes();

    // 1. Check HKDF-derived key signature (uni-auth native)
    let hkdf_key = derive_signing_key(secret, b"better-auth-token-signing");
    let hkdf_matches = if let Ok(mut mac) = HmacSha256::new_from_slice(&hkdf_key) {
        mac.update(token.as_bytes());
        let expected_url = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        bool::from(expected_url.as_bytes().ct_eq(sig_bytes))
    } else {
        false
    };

    // 2. Check raw-secret HMAC-SHA256 (upstream Better Auth / better-call)
    let raw_matches = if let Ok(mut mac) = HmacSha256::new_from_slice(secret) {
        mac.update(token.as_bytes());
        let raw_mac = mac.finalize().into_bytes();
        let expected_url = URL_SAFE_NO_PAD.encode(raw_mac);
        let expected_std = STANDARD.encode(raw_mac);
        let url_ok = bool::from(expected_url.as_bytes().ct_eq(sig_bytes));
        let std_ok = bool::from(expected_std.as_bytes().ct_eq(sig_bytes));
        url_ok || std_ok
    } else {
        false
    };

    hkdf_matches || raw_matches
}

/// Strictly verifies a signed `<token>.<signature>` string, rejecting any unsigned input.
///
/// Used for verifying `better-auth.session_token` cookies and strict Bearer tokens.
pub fn extract_and_verify_signed_token(secret: &[u8], signed_token: &str) -> Option<String> {
    let (token, signature) = signed_token.split_once('.')?;
    if token.is_empty() || signature.is_empty() {
        return None;
    }
    if verify_signature(secret, token, signature) {
        Some(token.to_string())
    } else {
        None
    }
}

/// Extracts and verifies the raw token from a signed or raw token string.
///
/// - If `signed_or_raw` contains a `.`, it is verified as `<token>.<signature>`.
/// - If `require_signature` is `true`, unsigned tokens (without `.`) are rejected (`None`).
/// - If `require_signature` is `false` (default Better Auth Bearer plugin behavior),
///   an unsigned token is returned as `Some(raw_token)` for database lookup.
pub fn extract_and_verify_token_with_policy(
    secret: &[u8],
    signed_or_raw: &str,
    require_signature: bool,
) -> Option<String> {
    if signed_or_raw.contains('.') {
        extract_and_verify_signed_token(secret, signed_or_raw)
    } else if require_signature || signed_or_raw.is_empty() {
        None
    } else {
        Some(signed_or_raw.to_string())
    }
}

/// Extracts and verifies the raw token from a potentially signed token string.
pub fn extract_and_verify_token(secret: &[u8], signed_or_raw: &str) -> Option<String> {
    extract_and_verify_token_with_policy(secret, signed_or_raw, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_password_hash_and_verify() {
        let password = "my-secret-password-123".to_string();
        let hash = hash_password(password.clone()).await.unwrap();

        assert!(hash.starts_with("$argon2"));
        assert!(verify_password(hash.clone(), password).await.unwrap());
        assert!(
            !verify_password(hash, "wrong-password".to_string())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_legacy_scrypt_better_auth_password_verify() {
        let salt = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let password = "better-auth-ts-password";
        let scrypt_hash = hash_scrypt_better_auth(salt, password).unwrap();

        assert!(is_legacy_scrypt_hash(&scrypt_hash));
        assert!(
            verify_password(scrypt_hash.clone(), password.to_string())
                .await
                .unwrap()
        );
        assert!(
            !verify_password(scrypt_hash, "wrong-password".to_string())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_legacy_scrypt_unicode_nfkc_normalization() {
        let salt = "0123456789abcdef0123456789abcdef";
        // Decomposed 'é' (e + combining acute accent U+0301) vs precomposed 'é' (U+00E9)
        let nfd_password = "cafe\u{0301}-password-123";
        let nfc_password = "caf\u{00e9}-password-123";

        let scrypt_hash = hash_scrypt_better_auth(salt, nfc_password).unwrap();
        assert!(
            verify_password(scrypt_hash.clone(), nfd_password.to_string())
                .await
                .unwrap(),
            "Decomposed UTF-8 password must verify against NFKC-normalized Better Auth scrypt hash"
        );

        // Compatibility characters (fullwidth Latin 'ＡＢＣ' -> 'ABC' under NFKC)
        let fullwidth_pw = "\u{ff21}\u{ff22}\u{ff23}-secret-99";
        let ascii_pw = "ABC-secret-99";
        let fw_hash = hash_scrypt_better_auth(salt, fullwidth_pw).unwrap();
        assert!(
            verify_password(fw_hash, ascii_pw.to_string())
                .await
                .unwrap()
        );
    }

    #[test]
    fn test_sign_and_verify_token() {
        let secret = b"super-secret-auth-key-32-bytes-long";
        let token = generate_session_token();

        let signed = sign_token(secret, &token);
        assert!(signed.starts_with(&token));
        assert!(signed.contains('.'));

        let verified = extract_and_verify_token(secret, &signed);
        assert_eq!(verified.as_deref(), Some(token.as_str()));
        assert_eq!(
            extract_and_verify_signed_token(secret, &signed).as_deref(),
            Some(token.as_str())
        );

        // Tampered token fails
        let tampered = format!("tampered_{signed}");
        assert_eq!(extract_and_verify_token(secret, &tampered), None);
        assert_eq!(extract_and_verify_signed_token(secret, &tampered), None);

        // Unsigned raw token rejected by strict signed verifier
        assert_eq!(extract_and_verify_signed_token(secret, &token), None);
        assert_eq!(
            extract_and_verify_token_with_policy(secret, &token, true),
            None
        );

        // Unsigned raw token passes through when require_signature is false
        assert_eq!(
            extract_and_verify_token(secret, &token),
            Some(token.clone())
        );
    }

    #[test]
    fn test_upstream_better_auth_raw_hmac_and_better_call_cookie_compat() {
        let secret = b"shared-ts-and-rust-better-auth-secret";
        let token = generate_session_token();

        // 1. Upstream @better-auth/utils/hmac base64urlnopad format
        let upstream_bearer = sign_token_better_auth(secret, &token);
        assert_eq!(
            extract_and_verify_signed_token(secret, &upstream_bearer).as_deref(),
            Some(token.as_str())
        );

        // 2. Upstream better-call serializeSignedCookie format (standard Base64 with '=' padding)
        let better_call_cookie = sign_cookie_better_call(secret, &token);
        assert!(better_call_cookie.ends_with('='));
        assert_eq!(
            extract_and_verify_signed_token(secret, &better_call_cookie).as_deref(),
            Some(token.as_str())
        );

        // 3. URL-encoded cookie value (where '=' is '%3D', '+' is '%2B', '/' is '%2F')
        let url_encoded_cookie = better_call_cookie
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        assert_eq!(
            extract_and_verify_signed_token(secret, &url_encoded_cookie).as_deref(),
            Some(token.as_str())
        );

        // 4. Legacy HKDF-derived signature backward compatibility
        let legacy_hkdf = sign_token_hkdf(secret, &token);
        assert_eq!(
            extract_and_verify_signed_token(secret, &legacy_hkdf).as_deref(),
            Some(token.as_str())
        );
    }
}
