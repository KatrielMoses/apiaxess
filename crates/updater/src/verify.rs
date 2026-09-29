//! Integrity checks: the SHA-256 of a downloaded asset (always required) and
//! the ed25519 signature over the raw manifest bytes (required once a public
//! key is embedded).

use std::{
    fs::File,
    io::{self, Read as _},
    path::Path,
};

use sha2::{Digest as _, Sha256};

/// The release-signing public key (base64 of the 32-byte ed25519 key), once it
/// is embedded. While this is `None` the manifest is trusted on HTTPS alone and
/// no `.sig` is fetched; as soon as it is set, every manifest must carry a
/// valid detached signature or it is refused.
pub const EMBEDDED_PUBLIC_KEY: Option<&str> = None;

/// Lowercase hex SHA-256 of a file's bytes.
///
/// # Errors
///
/// Returns the read error.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Lowercase hex of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Decodes a base64 ed25519 public key.
///
/// # Errors
///
/// Returns why the key is unusable.
pub fn decode_public_key(encoded: &str) -> Result<[u8; 32], String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|error| format!("the update public key is not base64: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| "the update public key is not 32 bytes".to_owned())
}

/// The public key manifests must be signed with: the embedded key, or — only
/// while none is embedded — `APIAXESS_UPDATE_PUBLIC_KEY`, so the signing path
/// can be exercised before release. An override can only make verification
/// stricter; it is ignored once a key is embedded.
///
/// # Errors
///
/// Returns why a configured key is unusable.
pub fn manifest_public_key() -> Result<Option<[u8; 32]>, String> {
    if let Some(embedded) = EMBEDDED_PUBLIC_KEY {
        return decode_public_key(embedded).map(Some);
    }
    match std::env::var("APIAXESS_UPDATE_PUBLIC_KEY") {
        Ok(value) if !value.trim().is_empty() => decode_public_key(&value).map(Some),
        _ => Ok(None),
    }
}

/// Checks a detached signature file (base64 of the 64-byte ed25519 signature)
/// over the exact manifest bytes that were served.
///
/// # Errors
///
/// Returns why the signature does not verify.
#[cfg(feature = "client")]
pub fn verify_manifest_signature(
    manifest: &[u8],
    signature_file: &[u8],
    public_key: &[u8; 32],
) -> Result<(), String> {
    use base64::Engine as _;
    let text = std::str::from_utf8(signature_file)
        .map_err(|_| "the manifest signature is not text".to_owned())?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| "the manifest signature is not base64".to_owned())?;
    if signature.len() != 64 {
        return Err("the manifest signature is not an ed25519 signature".to_owned());
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(manifest, &signature)
        .map_err(|_| "the manifest signature does not match the release key".to_owned())
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use base64::Engine as _;
    use ring::signature::KeyPair as _;

    use super::*;

    fn keypair() -> ring::signature::Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    #[test]
    fn a_signature_over_the_raw_bytes_verifies_and_any_change_fails() {
        let pair = keypair();
        let key: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
        let manifest = br#"{"version":"0.1.1"}"#;
        let signature = base64::engine::general_purpose::STANDARD.encode(pair.sign(manifest));
        assert!(
            verify_manifest_signature(manifest, format!("{signature}\n").as_bytes(), &key).is_ok()
        );
        // Same JSON, different bytes: raw-byte signing means this must fail.
        let reformatted = br#"{ "version": "0.1.1" }"#;
        assert!(verify_manifest_signature(reformatted, signature.as_bytes(), &key).is_err());
        let other: [u8; 32] = keypair().public_key().as_ref().try_into().unwrap();
        assert!(verify_manifest_signature(manifest, signature.as_bytes(), &other).is_err());
        assert!(verify_manifest_signature(manifest, b"not base64!", &key).is_err());
        assert!(verify_manifest_signature(manifest, b"AAAA", &key).is_err());
    }

    #[test]
    fn keys_and_hashes_decode() {
        assert!(
            decode_public_key(&base64::engine::general_purpose::STANDARD.encode([7_u8; 32]))
                .is_ok()
        );
        assert!(decode_public_key("AAAA").is_err());
        let path = std::env::temp_dir().join(format!("apiaxess-sha-{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_file(path);
    }
}
