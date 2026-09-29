//! Release-manifest signing for the in-app updater.
//!
//! `latest.json.sig` is the base64 ed25519 signature over the exact bytes of
//! `latest.json` as served: no canonical JSON, so signer and verifier can never
//! disagree about whitespace or key order. The public half goes into
//! `crates/updater/src/verify.rs` (`EMBEDDED_PUBLIC_KEY`); from then on the app
//! refuses any manifest without a valid signature.

use std::{error::Error, fs, path::Path};

use base64::Engine as _;
use ring::signature::KeyPair as _;

/// `cargo xtask update-keygen <private-key.pk8>`: creates the signing key
/// (PKCS#8) and prints the public key to embed. Refuses to overwrite a key.
pub fn keygen(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let [path] = arguments else {
        return Err("usage: cargo xtask update-keygen <private-key.pk8>".into());
    };
    let path = Path::new(path);
    if path.exists() {
        return Err(format!(
            "{} already exists; not overwriting a signing key",
            path.display()
        )
        .into());
    }
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| "could not generate an ed25519 key")?;
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| "the generated key did not load")?;
    fs::write(path, pkcs8.as_ref())?;
    println!(
        "Private key written to {} (keep it offline; it is never committed).",
        path.display()
    );
    println!(
        "Public key to embed as EMBEDDED_PUBLIC_KEY: {}",
        base64::engine::general_purpose::STANDARD.encode(pair.public_key().as_ref())
    );
    Ok(())
}

/// `cargo xtask sign-manifest <private-key.pk8> <latest.json>`: writes
/// `<latest.json>.sig` beside it and checks it verifies.
pub fn sign(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let [key, manifest] = arguments else {
        return Err("usage: cargo xtask sign-manifest <private-key.pk8> <latest.json>".into());
    };
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&fs::read(key)?)
        .map_err(|_| format!("{key} is not an ed25519 PKCS#8 key"))?;
    let bytes = fs::read(manifest)?;
    looks_like_manifest(&bytes)?;
    let signature = pair.sign(&bytes);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pair.public_key().as_ref())
        .verify(&bytes, signature.as_ref())
        .map_err(|_| "the signature did not verify")?;
    let output = format!("{manifest}.sig");
    fs::write(
        &output,
        format!(
            "{}\n",
            base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
        ),
    )?;
    println!("Signed {} bytes of {manifest} -> {output}", bytes.len());
    println!(
        "Public key: {}",
        base64::engine::general_purpose::STANDARD.encode(pair.public_key().as_ref())
    );
    Ok(())
}

/// A light sanity check that the file is the manifest (a JSON object with a
/// version), so the wrong file is not signed by mistake.
fn looks_like_manifest(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let text = std::str::from_utf8(bytes).map_err(|_| "the manifest is not UTF-8")?;
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if text.starts_with('\u{feff}') {
        return Err("the manifest starts with a byte-order mark; write it without one".into());
    }
    if !trimmed.starts_with('{') || !trimmed.contains("\"version\"") {
        return Err("this does not look like latest.json".into());
    }
    Ok(())
}
