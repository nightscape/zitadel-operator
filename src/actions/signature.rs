use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Header Zitadel signs its target payloads with.
pub const SIGNING_HEADER: &str = "ZITADEL-Signature";

/// Verifies `ZITADEL-Signature: t=<unix>,v1=<hex>` over `<unix>.<body>`,
/// HMAC-SHA256 keyed with the target's signing key.
///
/// The timestamp is not checked against a tolerance: the value this guards is
/// the grant effect, and a replayed grant is the grant the payload already asked
/// for.
pub fn verify(header: &str, body: &[u8], signing_key: &str) -> bool {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        match part.split_once('=') {
            Some(("t", value)) => timestamp = Some(value),
            Some(("v1", value)) => {
                if let Ok(bytes) = hex::decode(value) {
                    signatures.push(bytes);
                }
            }
            _ => {}
        }
    }

    let Some(timestamp) = timestamp else {
        return false;
    };

    signatures.iter().any(|signature| {
        let mut mac = Hmac::<Sha256>::new_from_slice(signing_key.as_bytes())
            .expect("HMAC accepts a key of any length");
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(body);
        mac.verify_slice(signature).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(timestamp: &str, body: &[u8], key: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(body);
        format!("t={timestamp},v1={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn accepts_a_signature_zitadel_would_send() {
        let body = br#"{"request":{}}"#;
        assert!(verify(&sign("1756800000", body, "s3cr3t"), body, "s3cr3t"));
    }

    #[test]
    fn rejects_a_wrong_key_body_or_timestamp() {
        let body = br#"{"request":{}}"#;
        let header = sign("1756800000", body, "s3cr3t");
        assert!(!verify(&header, body, "other"));
        assert!(!verify(&header, br#"{"request":{"a":1}}"#, "s3cr3t"));
        // A timestamp rewritten after signing: the signature covers it.
        let tampered = header.replace("t=1756800000", "t=1756800001");
        assert!(!verify(&tampered, body, "s3cr3t"));
    }

    #[test]
    fn rejects_a_header_without_a_signature() {
        let body = br#"{}"#;
        assert!(!verify("t=1756800000", body, "s3cr3t"));
        assert!(!verify("", body, "s3cr3t"));
        assert!(!verify("v1=00", body, "s3cr3t"));
    }

    #[test]
    fn accepts_any_of_several_signatures_during_key_rotation() {
        let body = br#"{}"#;
        let old = sign("1756800000", body, "old");
        let new = sign("1756800000", body, "new");
        let combined = format!("{old},{}", new.split_once(',').unwrap().1);
        assert!(verify(&combined, body, "old"));
        assert!(verify(&combined, body, "new"));
    }
}
