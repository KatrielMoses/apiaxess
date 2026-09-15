//! In-memory, per-session certificate authority.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use md5::Md5;
use hudsucker::{
    certificate_authority::CertificateAuthority,
    rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, string::Ia5String,
    },
    rustls::{self, ServerConfig, crypto::CryptoProvider, pki_types::CertificateDer},
};
use sha2::{Digest, Sha256};

const ROOT_COMMON_NAME: &str = "APIaxess ephemeral interception CA";

struct CachedLeaf {
    certificate_der: Vec<u8>,
    server_config: Arc<ServerConfig>,
}

struct SessionCaInner {
    issuer: CertifiedIssuer<'static, KeyPair>,
    root_der: Vec<u8>,
    root_pem: String,
    fingerprint: Box<str>,
    provider: Arc<CryptoProvider>,
    leaves: Mutex<BTreeMap<String, CachedLeaf>>,
}

/// A unique CA owned by one live `APIaxess` session.
///
/// The signing key is held only in this value and its clones. No constructor
/// or default operation writes it to disk or changes a system trust store.
#[derive(Clone)]
pub struct SessionCa(Arc<SessionCaInner>);

impl std::fmt::Debug for SessionCa {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionCa")
            .field("fingerprint", &self.fingerprint())
            .field("cached_leaf_count", &self.cached_leaf_count())
            .finish_non_exhaustive()
    }
}

impl SessionCa {
    /// Creates a new CA with a fresh keypair and a fresh root certificate.
    ///
    /// # Errors
    ///
    /// Returns the canonical CA-generation diagnostic if the cryptographic
    /// provider or certificate generator cannot create the session CA.
    pub fn generate() -> Result<Self, Diagnostic> {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let mut params = CertificateParams::default();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, ROOT_COMMON_NAME);
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let signing_key = KeyPair::generate().map_err(|error| ca_generation_diagnostic(&error))?;
        let issuer = CertifiedIssuer::self_signed(params, signing_key)
            .map_err(|error| ca_generation_diagnostic(&error))?;
        let root_der = issuer.der().to_vec();
        let root_pem = issuer.pem();
        let fingerprint = fingerprint(&root_der);

        Ok(Self(Arc::new(SessionCaInner {
            issuer,
            root_der,
            root_pem,
            fingerprint,
            provider: Arc::new(provider),
            leaves: Mutex::new(BTreeMap::new()),
        })))
    }

    /// Returns the root CA certificate in DER form without exposing the key.
    #[must_use]
    pub fn root_certificate_der(&self) -> &[u8] {
        &self.0.root_der
    }

    /// Returns the root CA certificate in PEM form without exposing the key.
    #[must_use]
    pub fn root_certificate_pem(&self) -> &str {
        &self.0.root_pem
    }

    /// Returns the SHA-256 fingerprint used by audit and recovery tooling.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.0.fingerprint
    }

    /// Returns OpenSSL's legacy `subject_hash_old` of the root CA subject, as the
    /// 8-hex-digit lowercase string Android uses for the `<hash>.0` filename in
    /// the pre-14 `/system/etc/security/cacerts` trust store.
    ///
    /// This reproduces OpenSSL's `X509_NAME_hash_old`: the MD5 of the DER-encoded
    /// subject `Name`, with the first four digest bytes read little-endian.
    /// Computing it in-process removes the runtime dependency on a host `openssl`
    /// binary, so system-CA provisioning works in a self-contained install.
    ///
    /// # Errors
    ///
    /// Returns the canonical CA-generation diagnostic if the root certificate
    /// cannot be parsed.
    pub fn android_subject_hash_old(&self) -> Result<String, Diagnostic> {
        let (_, certificate) = x509_parser::parse_x509_certificate(&self.0.root_der)
            .map_err(|error| ca_generation_diagnostic_text(&error.to_string()))?;
        let subject_der = certificate.tbs_certificate.subject.as_raw();
        let digest = Md5::digest(subject_der);
        let value = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        Ok(format!("{value:08x}"))
    }

    /// Number of cached per-host leaf configurations.
    #[must_use]
    pub fn cached_leaf_count(&self) -> usize {
        self.0
            .leaves
            .lock()
            .map(|leaves| leaves.len())
            .unwrap_or_default()
    }

    /// Returns a cached/generated leaf certificate for inspection or tests.
    ///
    /// # Errors
    ///
    /// Returns a CA-generation diagnostic when the host name is invalid or
    /// leaf certificate generation fails.
    pub fn leaf_certificate_der(&self, host: &str) -> Result<Vec<u8>, Diagnostic> {
        let host = normalize_host(host).ok_or_else(|| {
            let mut context = DiagnosticContext::new();
            context.insert("host".to_owned(), DiagnosticValue::String(host.to_owned()));
            catalogue::PROXY_CA_GENERATION_FAILED.instantiate(context)
        })?;
        self.leaf_certificate_der_for_host(&host)
    }

    /// Explicitly exports the CA certificate and private key to a temporary
    /// directory. The private key is never written before this call.
    ///
    /// # Errors
    ///
    /// Returns a CA-export diagnostic if the temporary directory or either
    /// export file cannot be created or written.
    pub fn export_to_temp(&self) -> Result<CaExport, Diagnostic> {
        let directory = export_directory(self.fingerprint())?;
        let certificate_path = directory.join("apiaxess-session-ca.pem");
        let key_path = directory.join("apiaxess-session-ca-key.pem");
        let key_pem = self.0.issuer.key().serialize_pem();

        write_export(&certificate_path, self.root_certificate_pem())?;
        if let Err(error) = write_export(&key_path, &key_pem) {
            let _ = fs::remove_dir_all(&directory);
            return Err(error);
        }

        Ok(CaExport {
            directory,
            certificate_path,
            key_path,
            fingerprint: self.fingerprint().to_owned(),
        })
    }

    fn leaf_certificate_der_for_host(&self, host: &str) -> Result<Vec<u8>, Diagnostic> {
        let mut leaves = self
            .0
            .leaves
            .lock()
            .map_err(|_| ca_generation_diagnostic_text("leaf cache lock is poisoned"))?;
        if let Some(leaf) = leaves.get(host) {
            return Ok(leaf.certificate_der.clone());
        }
        let leaf = self.build_leaf(host)?;
        let certificate_der = leaf.certificate_der.clone();
        leaves.insert(host.to_owned(), leaf);
        Ok(certificate_der)
    }

    fn build_leaf(&self, host: &str) -> Result<CachedLeaf, Diagnostic> {
        let key = KeyPair::generate().map_err(|error| ca_generation_diagnostic(&error))?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names.push(if let Ok(ip) = host.parse() {
            SanType::IpAddress(ip)
        } else {
            SanType::DnsName(
                Ia5String::try_from(host).map_err(|error| ca_generation_diagnostic(&error))?,
            )
        });
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let certificate = params
            .signed_by(&key, &self.0.issuer)
            .map_err(|error| ca_generation_diagnostic(&error))?;
        let certificate_der = certificate.der().to_vec();
        let private_key = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
        );
        let mut server_config = ServerConfig::builder_with_provider(Arc::clone(&self.0.provider))
            .with_safe_default_protocol_versions()
            .map_err(|error| ca_generation_diagnostic(&error))?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate_der.clone())],
                private_key,
            )
            .map_err(|error| ca_generation_diagnostic(&error))?;
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(CachedLeaf {
            certificate_der,
            server_config: Arc::new(server_config),
        })
    }
}

impl CertificateAuthority for SessionCa {
    async fn gen_server_config(
        &self,
        authority: &hudsucker::hyper::http::uri::Authority,
    ) -> Arc<ServerConfig> {
        let host = normalize_host(authority.host()).unwrap_or_else(|| "invalid.local".to_owned());
        let mut leaves = self
            .0
            .leaves
            .lock()
            .expect("CA leaf cache lock is poisoned");
        if let Some(leaf) = leaves.get(&host) {
            return Arc::clone(&leaf.server_config);
        }
        let leaf = self
            .build_leaf(&host)
            .expect("validated authority must produce a leaf certificate");
        let server_config = Arc::clone(&leaf.server_config);
        leaves.insert(host, leaf);
        server_config
    }
}

/// Explicit CA export paths. Dropping the value removes the temporary export.
#[derive(Debug)]
pub struct CaExport {
    directory: PathBuf,
    /// Temporary PEM certificate path.
    pub certificate_path: PathBuf,
    /// Temporary PEM private-key path.
    pub key_path: PathBuf,
    /// Fingerprint of the exported root certificate.
    pub fingerprint: String,
}

impl CaExport {
    /// Directory containing the explicit export.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Removes the export immediately and returns a structured diagnostic on failure.
    ///
    /// # Errors
    ///
    /// Returns a CA-export diagnostic if the temporary export directory cannot
    /// be removed.
    pub fn purge(mut self) -> Result<(), Diagnostic> {
        let result = fs::remove_dir_all(&self.directory).map_err(|error| {
            let mut context = DiagnosticContext::new();
            context.insert(
                "directory".to_owned(),
                DiagnosticValue::String(self.directory.display().to_string()),
            );
            context.insert(
                "error".to_owned(),
                DiagnosticValue::String(error.to_string()),
            );
            catalogue::PROXY_CA_EXPORT_FAILED.instantiate(context)
        });
        self.directory = PathBuf::new();
        result
    }
}

impl Drop for CaExport {
    fn drop(&mut self) {
        if !self.directory.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}

fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host.len() > 253 || host.bytes().any(|byte| byte.is_ascii_control()) {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn fingerprint(der: &[u8]) -> Box<str> {
    let digest = Sha256::digest(der);
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(result, "{byte:02x}");
    }
    result.into_boxed_str()
}

fn export_directory(fingerprint: &str) -> Result<PathBuf, Diagnostic> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let directory = std::env::temp_dir().join(format!("apiaxess-ca-{fingerprint}-{nonce}"));
    fs::create_dir(&directory).map_err(|error| {
        let mut context = DiagnosticContext::new();
        context.insert(
            "directory".to_owned(),
            DiagnosticValue::String(directory.display().to_string()),
        );
        context.insert(
            "error".to_owned(),
            DiagnosticValue::String(error.to_string()),
        );
        catalogue::PROXY_CA_EXPORT_FAILED.instantiate(context)
    })?;
    Ok(directory)
}

fn write_export(path: &Path, contents: &str) -> Result<(), Diagnostic> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| export_diagnostic(path, &error))?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.flush())
        .map_err(|error| export_diagnostic(path, &error))
}

fn export_diagnostic(path: &Path, error: &std::io::Error) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "path".to_owned(),
        DiagnosticValue::String(path.display().to_string()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_string()),
    );
    catalogue::PROXY_CA_EXPORT_FAILED.instantiate(context)
}

fn ca_generation_diagnostic(error: &impl std::fmt::Display) -> Diagnostic {
    ca_generation_diagnostic_text(&error.to_string())
}

fn ca_generation_diagnostic_text(error: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_owned()),
    );
    catalogue::PROXY_CA_GENERATION_FAILED.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::SessionCa;

    #[test]
    fn generates_unique_in_memory_cas_and_caches_leaf_certificates() {
        let first = SessionCa::generate().expect("first CA");
        let second = SessionCa::generate().expect("second CA");
        assert_ne!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.cached_leaf_count(), 0);
        let first_leaf = first.leaf_certificate_der("Example.com").expect("leaf");
        let second_leaf = first
            .leaf_certificate_der("example.com")
            .expect("cached leaf");
        assert_eq!(first_leaf, second_leaf);
        assert_eq!(first.cached_leaf_count(), 1);
    }

    #[test]
    fn subject_hash_old_matches_openssl_for_the_fixed_subject() {
        // Authoritative cross-check: `openssl x509 -subject_hash_old` on the real
        // rcgen-issued root cert yields exactly this value (the subject is the
        // fixed common name `APIaxess ephemeral interception CA`, UTF8String), so
        // the in-process MD5 computation must reproduce it byte-for-byte. Pinning
        // the literal turns any drift in the algorithm or the CA subject into a
        // test failure instead of a silent trust-store mismatch on device.
        const OPENSSL_SUBJECT_HASH_OLD: &str = "b335eae3";
        let first = SessionCa::generate().expect("first CA");
        let second = SessionCa::generate().expect("second CA");
        let hash = first.android_subject_hash_old().expect("subject hash");
        assert_eq!(hash, OPENSSL_SUBJECT_HASH_OLD, "hash was {hash:?}");
        // The subject is constant, so the hash is stable across sessions even
        // though each CA has a distinct key and fingerprint.
        assert_ne!(first.fingerprint(), second.fingerprint());
        assert_eq!(
            hash,
            second.android_subject_hash_old().expect("second hash")
        );
    }

    #[test]
    fn private_key_is_only_created_by_explicit_export() {
        let ca = SessionCa::generate().expect("CA");
        let export = ca.export_to_temp().expect("export");
        assert!(export.certificate_path.is_file());
        assert!(export.key_path.is_file());
        let directory = export.directory().to_owned();
        export.purge().expect("purge");
        assert!(!directory.exists());
    }
}
