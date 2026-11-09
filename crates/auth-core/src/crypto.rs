//! Cryptographic primitives for Better Auth wire and storage compatibility.
//!
//! - Non-blocking Argon2id password hashing and verification inside `tokio::task::spawn_blocking`.
//! - HKDF-SHA256 key derivation from `BETTER_AUTH_SECRET`/`UNI_AUTH_SECRET`.
//! - HMAC-SHA256 token and cookie signing matching Better Auth format (`token.signature`).
//! - Constant-time signature verification (`subtle::ConstantTimeEq`).
//! - Cryptographically secure token generation (`rand::rngs::OsRng`).

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Hashes a password asynchronously using Argon2id without blocking Tokio worker threads.
pub async fn hash_password(password: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| format!("Password hashing failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task join error during password hashing: {e}"))?
}

/// Verifies a password against an Argon2id hash asynchronously inside `spawn_blocking`.
pub async fn verify_password(hash: String, password: String) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || {
        let parsed_hash = match PasswordHash::new(&hash) {
            Ok(h) => h,
            Err(e) => return Err(format!("Invalid password hash format: {e}")),
        };
        let argon2 = Argon2::default();
        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    })
    .await
    .map_err(|e| format!("Task join error during password verification: {e}"))?
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

/// Signs a token string using HMAC-SHA256 with a key derived from `secret`.
///
/// Output format: `<token>.<base64url_signature>`
///
/// This matches Better Auth's `set-auth-token` and signed cookie wire convention:
/// Reference: `.reference/better-auth/packages/better-auth/src/plugins/bearer/index.ts` lines 81-85
pub fn sign_token(secret: &[u8], token: &str) -> String {
    let key = derive_signing_key(secret, b"better-auth-token-signing");
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{token}.{signature}")
}

/// Verifies an HMAC-SHA256 signature against the raw token using constant-time comparison.
pub fn verify_signature(secret: &[u8], token: &str, signature: &str) -> bool {
    let key = derive_signing_key(secret, b"better-auth-token-signing");
    let mut mac = match HmacSha256::new_from_slice(&key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(token.as_bytes());
    let expected_signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    expected_signature
        .as_bytes()
        .ct_eq(signature.as_bytes())
        .into()
}

/// Extracts and verifies the raw token from a potentially signed token string.
///
/// If `signed_or_raw` contains a `.`, it is verified as `<token>.<signature>`.
/// If valid, `Some(raw_token)` is returned.
/// If invalid signature, `None` is returned.
/// If `signed_or_raw` contains no `.`, it is returned as `Some(raw_token)` directly.
pub fn extract_and_verify_token(secret: &[u8], signed_or_raw: &str) -> Option<String> {
    if let Some((token, signature)) = signed_or_raw.split_once('.') {
        if verify_signature(secret, token, signature) {
            Some(token.to_string())
        } else {
            None
        }
    } else {
        Some(signed_or_raw.to_string())
    }
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
        assert!(!verify_password(hash, "wrong-password".to_string())
            .await
            .unwrap());
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

        // Tampered token fails
        let tampered = format!("tampered_{signed}");
        assert_eq!(extract_and_verify_token(secret, &tampered), None);

        // Unsigned raw token passes through
        assert_eq!(
            extract_and_verify_token(secret, &token),
            Some(token.clone())
        );
    }
}
