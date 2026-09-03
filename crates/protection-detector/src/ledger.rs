//! Audited clean-room provenance gate for enabled signatures.
//!
//! These records establish the independently observed structural seed for an
//! enabled signature. They are not the Phase 7.4 real-sample coverage state;
//! that state is maintained in `docs/protection/corpus/verification-manifest.toml`.

/// One immutable provenance record required before a signature is enabled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerEntry {
    /// Stable signature ID.
    pub signature_id: &'static str,
    /// SHA-256 of the clean-room corpus sample containing the observation.
    pub sample_sha256: &'static str,
    /// Byte offset within the sample.
    pub byte_offset: u64,
    /// Independent source or corpus record.
    pub source: &'static str,
    /// License/provenance classification.
    pub license: &'static str,
}

/// Version of the checked-in clean-room ledger.
pub const LEDGER_VERSION: &str = "clean-room-ledger-v1";

/// Only signatures in this ledger may produce a protection verdict.
pub const ENTRIES: &[LedgerEntry] = &[
    LedgerEntry {
        signature_id: "r8.compiler-marker",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 192,
        source: "AOSP R8/D8 documentation plus in-house structural corpus",
        license: "BSD-3-Clause/AOSP",
    },
    LedgerEntry {
        signature_id: "jiagu.native-loader",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 219,
        source: "in-house structural corpus fixture",
        license: "in-house clean-room observation",
    },
    LedgerEntry {
        signature_id: "legu.native-loader",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 257,
        source: "in-house structural corpus fixture",
        license: "in-house clean-room observation",
    },
    LedgerEntry {
        signature_id: "bangcle.native-loader",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 303,
        source: "in-house structural corpus fixture",
        license: "in-house clean-room observation",
    },
    LedgerEntry {
        signature_id: "aliprotect.native-loader",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 346,
        source: "in-house structural corpus fixture",
        license: "in-house clean-room observation",
    },
    LedgerEntry {
        signature_id: "ijiami.native-loader",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 394,
        source: "in-house structural corpus fixture",
        license: "in-house clean-room observation",
    },
    LedgerEntry {
        signature_id: "dexprotector.native-loader",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 438,
        source: "in-house structural corpus fixture",
        license: "in-house clean-room observation",
    },
    LedgerEntry {
        signature_id: "baidu.native-loader",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 496,
        source: "in-house structural corpus fixture",
        license: "in-house clean-room observation",
    },
    LedgerEntry {
        signature_id: "android.dynamic-loader",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 546,
        source: "Android InMemoryDexClassLoader API reference",
        license: "Android Developers content license",
    },
    LedgerEntry {
        signature_id: "android.native-loader-api",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 626,
        source: "Android SDK System.loadLibrary contract",
        license: "Android SDK permissive reference",
    },
    LedgerEntry {
        signature_id: "payload.opaque-asset",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 653,
        source: "in-house structural corpus fixture",
        license: "in-house clean-room observation",
    },
    LedgerEntry {
        signature_id: "rasp.integrity-marker",
        sample_sha256: "DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B",
        byte_offset: 708,
        source: "CC-BY protection literature and in-house corpus",
        license: "CC-BY research reference",
    },
];

pub fn contains(signature_id: &str) -> bool {
    ENTRIES
        .iter()
        .any(|entry| entry.signature_id == signature_id)
}
