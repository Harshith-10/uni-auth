//! RFC 6238 Time-Based One-Time Password (TOTP) helper for the Better Auth `two-factor` plugin.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::any::Any;
use time::OffsetDateTime;

use super::BetterAuthPlugin;

type HmacSha256 = Hmac<Sha256>;

/// RFC 6238 Time-Based One-Time Password (TOTP) helper for the Better Auth `two-factor` plugin.
#[derive(Debug, Clone)]
pub struct TotpValidator {
    /// Time step in seconds (standard: 30s).
    pub period_secs: u64,
    /// Number of digits (standard: 6).
    pub digits: u32,
}

impl Default for TotpValidator {
    fn default() -> Self {
        Self {
            period_secs: 30,
            digits: 6,
        }
    }
}

impl TotpValidator {
    /// Generates a 6-digit TOTP code for the given secret and timestamp.
    pub fn generate_at(&self, secret: &[u8], timestamp_secs: u64) -> String {
        let counter = timestamp_secs / self.period_secs;
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
        mac.update(&counter.to_be_bytes());
        let hash = mac.finalize().into_bytes();
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let binary = ((u32::from(hash[offset] & 0x7f)) << 24)
            | ((u32::from(hash[offset + 1])) << 16)
            | ((u32::from(hash[offset + 2])) << 8)
            | u32::from(hash[offset + 3]);
        let modulo = 10u32.pow(self.digits);
        format!("{:0width$}", binary % modulo, width = self.digits as usize)
    }

    /// Verifies a TOTP code allowing a `+-1` time-step drift window.
    pub fn verify(&self, secret: &[u8], code: &str) -> bool {
        use subtle::ConstantTimeEq;
        let code_trimmed = code.trim();
        let now_secs = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
        let mut valid = false;
        for step_offset in [-1i64, 0, 1] {
            let ts = (now_secs as i64 + step_offset * (self.period_secs as i64)).max(0) as u64;
            let expected = self.generate_at(secret, ts);
            if expected.len() == code_trimmed.len()
                && bool::from(expected.as_bytes().ct_eq(code_trimmed.as_bytes()))
            {
                valid = true;
            }
        }
        valid
    }
}

impl BetterAuthPlugin for TotpValidator {
    fn id(&self) -> &'static str {
        "two-factor"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
