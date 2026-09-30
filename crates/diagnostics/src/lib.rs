//! Canonical structured diagnostics for every `APIaxess` boundary.
//!
//! A diagnostic always answers what happened, why it happened, and exactly how
//! the user can remedy it. Stable IDs and typed context allow the same value to
//! be rendered in the GUI, serialized in an audit trail, logged, or consumed by
//! a future integration without scraping prose.

use std::{collections::BTreeMap, error::Error, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current standalone diagnostic schema version.
pub const CURRENT_DIAGNOSTIC_SCHEMA_VERSION: u32 = 1;

/// Stable failure/warning area used for presentation and routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCategory {
    /// Declared engagement scope and scope assessment.
    AuthorizationScope,
    /// Host runtime capability availability.
    HostCapability,
    /// Plugin permission or capability negotiation.
    PluginCapability,
    /// Session lifecycle and invariant failures.
    Session,
    /// Durable artifact encoding, decoding, or version failures.
    Persistence,
    /// Canonical API model validation failures.
    DataModel,
    /// Static-analysis detection, routing, and recoverability observations.
    StaticAnalysis,
    /// External tool presence, execution, or result failures.
    ExternalTool,
    /// Sandbox backend availability or operation failures.
    Sandbox,
    /// Unexpected engine failures that need a bug report.
    Internal,
}

/// Presentation severity; it never doubles as an authorization decision.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// Informational state requiring no action.
    Info,
    /// The operation continued, but the user should review the condition.
    Warning,
    /// The requested operation could not complete.
    Error,
    /// Core correctness or integrity may be compromised.
    Critical,
}

/// A typed diagnostic context value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum DiagnosticValue {
    /// Textual identifier or explanation.
    String(String),
    /// Signed numeric value.
    Integer(i64),
    /// Boolean value.
    Boolean(bool),
    /// Ordered textual values.
    StringList(Vec<String>),
}

/// Structured key/value context attached to a diagnostic.
pub type DiagnosticContext = BTreeMap<String, DiagnosticValue>;

/// A canonical, serializable what/why/fix diagnostic.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Standalone diagnostic schema version.
    pub schema_version: u32,
    /// Stable catalogue identifier; prose may improve without changing it.
    pub id: Box<str>,
    /// Stable failure area.
    pub category: DiagnosticCategory,
    /// Presentation severity.
    pub severity: DiagnosticSeverity,
    /// Concise description of what happened.
    pub what: Box<str>,
    /// Concrete explanation of why it happened.
    pub why: Box<str>,
    /// Exact action the user should take.
    pub fix: Box<str>,
    /// Typed, non-prose details needed to act or integrate.
    pub context: DiagnosticContext,
}

impl Diagnostic {
    /// Validates the schema, stable ID, prose, and context-key invariants.
    ///
    /// # Errors
    ///
    /// Returns the first structural defect. Catalogue tests should catch these
    /// as programmer errors before a release.
    pub fn validate(&self) -> Result<(), DiagnosticValidationError> {
        if self.schema_version != CURRENT_DIAGNOSTIC_SCHEMA_VERSION {
            return Err(DiagnosticValidationError::UnsupportedSchema {
                found: self.schema_version,
                expected: CURRENT_DIAGNOSTIC_SCHEMA_VERSION,
            });
        }
        validate_stable_key("diagnostic ID", &self.id)?;
        for (field, value) in [
            ("what", self.what.as_ref()),
            ("why", self.why.as_ref()),
            ("fix", self.fix.as_ref()),
        ] {
            if value.trim().is_empty() {
                return Err(DiagnosticValidationError::EmptyProse { field });
            }
        }
        for key in self.context.keys() {
            validate_stable_key("context key", key)?;
        }
        Ok(())
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {} Why: {} Fix: {}",
            self.id, self.what, self.why, self.fix
        )
    }
}

impl Error for Diagnostic {}

/// Bounds a diagnostics list for status/response surfaces without dropping
/// distinct low-volume signal behind high-volume repeated evidence.
///
/// A naive `take(total)` on a stage-ordered list silently hides the terminal
/// stages (e.g. the dynamic-capture and crawl-coverage diagnostics) whenever an
/// earlier stage emits `total` or more repeated evidence diagnostics. This keeps
/// at most `per_id` occurrences of each diagnostic id and at most `total`
/// diagnostics overall, preserving order — so the repeated evidence is capped
/// while every distinct diagnostic still reaches the operator. The durable
/// session artifact retains the full, unbounded list.
#[must_use]
pub fn bounded_status_diagnostics(
    diagnostics: &[Diagnostic],
    per_id: usize,
    total: usize,
) -> Vec<Diagnostic> {
    let mut per_id_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    let mut bounded = Vec::new();
    for diagnostic in diagnostics {
        if bounded.len() >= total {
            break;
        }
        let count = per_id_counts.entry(diagnostic.id.as_ref()).or_insert(0);
        if *count >= per_id {
            continue;
        }
        *count += 1;
        bounded.push(diagnostic.clone());
    }
    bounded
}

/// Static catalogue definition used to create a canonical diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticDefinition {
    /// Stable catalogue identifier.
    pub id: &'static str,
    /// Stable failure area.
    pub category: DiagnosticCategory,
    /// Default presentation severity.
    pub severity: DiagnosticSeverity,
    /// Canonical description of what happened.
    pub what: &'static str,
    /// Canonical explanation of why it happened.
    pub why: &'static str,
    /// Canonical user remedy.
    pub fix: &'static str,
}

impl DiagnosticDefinition {
    /// Instantiates the definition with typed occurrence context.
    #[must_use]
    pub fn instantiate(self, context: DiagnosticContext) -> Diagnostic {
        Diagnostic {
            schema_version: CURRENT_DIAGNOSTIC_SCHEMA_VERSION,
            id: self.id.into(),
            category: self.category,
            severity: self.severity,
            what: self.what.into(),
            why: self.why.into(),
            fix: self.fix.into(),
            context,
        }
    }
}

/// Structural error in a diagnostic definition or serialized diagnostic.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DiagnosticValidationError {
    /// The reader cannot interpret this standalone diagnostic schema.
    #[error("unsupported diagnostic schema version {found}; expected {expected}")]
    UnsupportedSchema {
        /// Version found in the value.
        found: u32,
        /// Version supported by this crate.
        expected: u32,
    },
    /// A stable machine key is malformed.
    #[error(
        "invalid {kind} `{value}`; use lowercase ASCII segments separated by dots, dashes, or underscores"
    )]
    InvalidStableKey {
        /// Kind of key being checked.
        kind: &'static str,
        /// Invalid value.
        value: String,
    },
    /// A required what/why/fix field is empty.
    #[error("diagnostic `{field}` must not be empty")]
    EmptyProse {
        /// Empty field name.
        field: &'static str,
    },
}

fn validate_stable_key(kind: &'static str, value: &str) -> Result<(), DiagnosticValidationError> {
    let valid = !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
        && value.bytes().any(|byte| byte.is_ascii_lowercase());
    if valid {
        Ok(())
    } else {
        Err(DiagnosticValidationError::InvalidStableKey {
            kind,
            value: value.to_owned(),
        })
    }
}

/// Built-in catalogue entries required by the phase 0.4 foundations.
pub mod catalogue {
    use super::{DiagnosticCategory, DiagnosticDefinition, DiagnosticSeverity};

    /// An action is outside the user-declared engagement scope; execution is not blocked.
    pub const SCOPE_OUTSIDE_DECLARATION: DiagnosticDefinition = DiagnosticDefinition {
        id: "scope.outside-declaration",
        category: DiagnosticCategory::AuthorizationScope,
        severity: DiagnosticSeverity::Warning,
        what: "The action targets a host outside the declared engagement scope.",
        why: "No allowed-target rule in this session matches the recorded action target.",
        fix: "Confirm authorization and add the exact host or domain rule to the session scope before continuing.",
    };

    /// An action target cannot be assessed against the declared scope.
    pub const SCOPE_UNDETERMINED: DiagnosticDefinition = DiagnosticDefinition {
        id: "scope.assessment-undetermined",
        category: DiagnosticCategory::AuthorizationScope,
        severity: DiagnosticSeverity::Warning,
        what: "The action could not be classified against the declared engagement scope.",
        why: "The action target does not contain enough normalized identity information for a scope match.",
        fix: "Record a concrete session target or network host and port, then review the scope before continuing.",
    };

    /// A required host capability is not fully available.
    pub const HOST_CAPABILITY_GAP: DiagnosticDefinition = DiagnosticDefinition {
        id: "host-capability.requirement-unsatisfied",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The host cannot provide a capability required by this operation.",
        why: "Capability detection reported the requirement as degraded, unavailable, or unknown.",
        fix: "Apply the capability-specific remediation or select a reported fallback capability tier.",
    };

    /// A requested plugin permission was not granted.
    pub const PLUGIN_PERMISSION_DENIED: DiagnosticDefinition = DiagnosticDefinition {
        id: "plugin-capability.permission-denied",
        category: DiagnosticCategory::PluginCapability,
        severity: DiagnosticSeverity::Error,
        what: "The plugin was not granted a permission required by the requested operation.",
        why: "The permission was absent from the negotiated grant set or its granted scope was too narrow.",
        fix: "Review the named permission and scope, then grant it explicitly or choose an operation that does not require it.",
    };

    /// A caller attempted an invalid session lifecycle transition.
    pub const SESSION_INVALID_TRANSITION: DiagnosticDefinition = DiagnosticDefinition {
        id: "session.invalid-transition",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The requested session lifecycle transition is invalid.",
        why: "The current and requested states are not connected by an allowed transition.",
        fix: "Activate a newly created session before use and close only an active session; closed sessions are terminal.",
    };

    /// A session or nested model invariant failed.
    pub const SESSION_INVARIANT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "session.invariant-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The session failed structural validation.",
        why: "One or more lifecycle, identity, scope, audit, workbench-slot, or nested data-model invariants are invalid.",
        fix: "Use the named context path to repair the producer or restore the session from a known-good artifact.",
    };

    /// The nested 0.2 API model is invalid.
    pub const SESSION_API_MODEL_INVALID: DiagnosticDefinition = DiagnosticDefinition {
        id: "session.api-model-invalid",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "The session contains an invalid API data-model document.",
        why: "The embedded 0.2 model version or one of its evidence-preserving invariants failed validation.",
        fix: "Repair the named model defect or load a session artifact produced by a compatible APIaxess version.",
    };

    /// The durable session format version is unsupported.
    pub const SESSION_FORMAT_UNSUPPORTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "persistence.session-format-unsupported",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "This APIaxess build cannot read the session artifact format.",
        why: "The artifact format version is not the exact version supported by this reader.",
        fix: "Open the artifact with a compatible APIaxess version or run an explicit supported migration.",
    };

    /// Session JSON is malformed or cannot represent the canonical schema.
    pub const SESSION_JSON_INVALID: DiagnosticDefinition = DiagnosticDefinition {
        id: "persistence.session-json-invalid",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The session artifact is not valid canonical JSON.",
        why: "JSON decoding or encoding failed before the session could be validated.",
        fix: "Restore an unmodified session artifact or correct the reported JSON location and try again.",
    };

    /// Unknown fields would be discarded by this reader.
    pub const SESSION_UNKNOWN_FIELDS: DiagnosticDefinition = DiagnosticDefinition {
        id: "persistence.session-unknown-fields",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The session artifact contains fields this reader does not understand.",
        why: "Loading it would risk silently discarding session, scope, audit, or evidence data.",
        fix: "Use the APIaxess version that produced the artifact or an explicit supported migration.",
    };

    /// The artifact family or archive shape is not supported by the target handler.
    pub const ARTIFACT_UNSUPPORTED_FORMAT: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.unsupported-format",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The supplied artifact format is not supported by this target handler.",
        why: "The intake probe could not route the input to a supported installable APK or split-bundle path.",
        fix: "Provide a valid APK, AAB, APKS, APKM, XAPK, or split ZIP artifact, or choose a target handler that supports this format.",
    };

    /// The supplied artifact path does not point at a readable file.
    pub const ARTIFACT_NOT_FOUND: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.not-found",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The artifact file was not found.",
        why: "No regular file exists at the supplied path — it is missing, a directory, or not readable.",
        fix: "Check the path and provide an existing APK, AAB, APKS, APKM, XAPK, or split ZIP file.",
    };

    /// The input archive is corrupt or unsafe to unpack.
    pub const ARTIFACT_MALFORMED_ARCHIVE: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.malformed-archive",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The artifact archive could not be read safely.",
        why: "The archive is truncated, corrupt, or contains an unsafe path that would escape the intake workspace.",
        fix: "Re-export the artifact and verify its checksum before importing it again.",
    };

    /// A split bundle could not be converted to standalone APKs.
    pub const ARTIFACT_BUNDLE_RESOLUTION_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.bundle-resolution-failed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The Android split or bundle artifact could not be resolved into installable APKs.",
        why: "The bundle resolver failed, returned no APKs, or produced an invalid split archive.",
        fix: "Install a compatible bundletool release and retry with a complete AAB or APKS file.",
    };

    /// A required external tool is absent or cannot be started.
    pub const EXTERNAL_TOOL_MISSING: DiagnosticDefinition = DiagnosticDefinition {
        id: "external-tool.missing",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "A required external analysis tool is unavailable.",
        why: "The configured executable was not found or could not be started by the tool boundary.",
        fix: "Install the named tool, place it on PATH, or configure its exact executable path.",
    };

    /// A bundled runtime component is missing or corrupt on disk.
    ///
    /// Distinct from `external-tool.missing`: that reports a tool the operator
    /// was expected to supply, whereas this reports that a component `APIaxess`
    /// ships and owns (the private Java runtime, apktool, jadx, or ffuf) is
    /// absent or unreadable in the installation tree. It is an install-integrity
    /// failure, never a host prerequisite the operator forgot to install.
    pub const INSTALL_COMPONENT_MISSING: DiagnosticDefinition = DiagnosticDefinition {
        id: "install.component-missing",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "A bundled APIaxess runtime component is missing or corrupt.",
        why: "A component APIaxess ships and owns (its private Java runtime, apktool, jadx, or ffuf) was not present at its expected install path.",
        fix: "Reinstall APIaxess so its verified, bundled runtime is restored; the diagnostic context names the component and the path that was checked.",
    };

    /// An external tool is present but outside the supported version range.
    pub const EXTERNAL_TOOL_VERSION_INCOMPATIBLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "external-tool.version-incompatible",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "An external analysis tool is incompatible with this adapter.",
        why: "The detected tool version is older than the adapter's minimum supported version.",
        fix: "Install the required tool version and retry; the diagnostic context names the detected and required versions.",
    };

    /// An external tool ran but did not produce a successful result.
    pub const EXTERNAL_TOOL_INVOCATION_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "external-tool.invocation-failed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "An external analysis tool failed during artifact processing.",
        why: "The tool exited unsuccessfully, timed out, or returned an unusable process result.",
        fix: "Review the named tool's bounded output, repair the artifact or tool installation, and retry.",
    };

    /// Structural unpacking failed.
    pub const ARTIFACT_UNPACK_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.unpack-failed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "Authoritative APK structural unpacking failed.",
        why: "apktool could not produce a complete manifest, smali, or resource tree for an installable APK.",
        fix: "Use a compatible apktool release and retry with an intact APK; inspect the tool output in the diagnostic context.",
    };

    /// Java-source decompilation failed.
    pub const ARTIFACT_DECOMPILATION_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.decompilation-failed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "Java-source decompilation failed.",
        why: "jadx could not produce its convenience source tree for the APK.",
        fix: "Install a compatible jadx release or repair the APK; structural apktool output remains authoritative only when complete.",
    };

    /// Java-source decompilation completed only partially (best-effort).
    pub const ARTIFACT_DECOMPILATION_PARTIAL: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.decompilation-partial",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Warning,
        what: "jadx decompilation finished with errors; its Java source tree is partial.",
        why: "jadx exited non-zero after failing to decompile a fraction of classes (common on large or complex apps) but still produced usable output. jadx is a best-effort, supplementary source; the authoritative apktool smali extraction is unaffected, so analysis continues with a complete structural model and a partial convenience-source tree.",
        fix: "No action required for correctness. To improve jadx coverage, use a newer jadx release or raise the per-tool timeout (APIAXESS_TOOL_TIMEOUT_SECS); the missing Java sources are convenience-only and do not change the extracted API surface.",
    };

    /// Programmatic DEX access could not be established.
    pub const ARTIFACT_DEX_ACCESS_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.dex-access-unavailable",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "Programmatic DEX access is unavailable for the unpacked artifact.",
        why: "No classes.dex file was present or no supported DEX parser handoff could be recorded.",
        fix: "Provide an installable APK containing DEX bytecode and enable the configured androguard or dexlib2 adapter.",
    };

    /// A protection signature was detected but no handler is available yet.
    pub const ARTIFACT_PROTECTION_UNHANDLED: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.protection-unhandled",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Warning,
        what: "The artifact contains a detected protection or obfuscation signature that is not handled yet.",
        why: "Intake recorded the protection metadata, but downstream static-analysis confidence may be reduced.",
        fix: "Review the protection signatures and select a compatible downstream analysis strategy; do not treat missing findings as absence.",
    };

    /// The in-house protection detector could not provide a result.
    pub const ARTIFACT_PROTECTION_DETECTOR_UNAVAILABLE: DiagnosticDefinition =
        DiagnosticDefinition {
            id: "artifact.protection-detector-unavailable",
            category: DiagnosticCategory::ExternalTool,
            severity: DiagnosticSeverity::Warning,
            what: "The in-house protection detector could not provide a detection result.",
            why: "The normalized artifact did not expose the structures required by the clean-room detector or the detector encountered a bounded read failure.",
            fix: "Retain the target as protection-unknown, review the intake diagnostic, and use dynamic capture if static recovery matters.",
        };

    /// A protection system was identified by the clean-room detector.
    pub const ARTIFACT_PROTECTION_DETECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.protection-detected",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Info,
        what: "The clean-room protection detector identified a protection system.",
        why: "Independent structural signals crossed the detector's evidence threshold.",
        fix: "Use the recorded tier and recoverability vector to weight static findings; no unpacking was attempted in Phase 1.1.1.",
    };

    /// Protection is suspected, but no clean identity met the evidence gate.
    pub const ARTIFACT_PROTECTION_SUSPECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.protection-suspected",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Warning,
        what: "Protection is suspected but not identifiable with orthogonal evidence.",
        why: "No named protection fingerprint met the independent structure-plus-payload/loader signal gate.",
        fix: "Treat static recovery as bounded and use dynamic capture to identify the protected loading path.",
    };

    /// Heavy protection materially limits static recovery.
    pub const ARTIFACT_PROTECTION_HEAVY: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.protection-heavy",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Warning,
        what: "Heavy protection limits static recovery.",
        why: "The quantified vector indicates packing, native boundaries, encrypted strings, or heavy control-flow/RASP signals.",
        fix: "Use dynamic capture for protected payload and loader paths; do not interpret static silence as absence.",
    };

    /// A protection signature lacks an auditable clean-room provenance entry.
    pub const ARTIFACT_PROTECTION_LEDGER_GAP: DiagnosticDefinition = DiagnosticDefinition {
        id: "artifact.protection-ledger-gap",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Error,
        what: "A protection signature was rejected because its provenance ledger entry is incomplete.",
        why: "The clean-room detector permits only signatures with a sample hash, byte offset, and permissive source record.",
        fix: "Add an audited clean-room corpus/provenance entry before enabling the signature; do not copy rules from GPL sources.",
    };

    /// The normalized artifact has no installable resolution strategy.
    pub const INTAKE_RESOLUTION_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "intake.resolution-unavailable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The artifact could not be routed to an install strategy.",
        why: "Content intake completed without a recognized standalone APK or complete split set that the sandbox can install.",
        fix: "Provide a valid universal APK or the complete base-plus-split set; supported bundle formats are resolved before this boundary.",
    };

    /// A base APK requires split members that were not supplied.
    pub const INTAKE_BASE_ONLY_SPLITS_MISSING: DiagnosticDefinition = DiagnosticDefinition {
        id: "intake.base-only-splits-missing",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The artifact is a base-only APK with required splits missing.",
        why: "The installer reported that ABI or density split APKs are required, but intake has no additional split members to install.",
        fix: "Provide the full base-plus-ABI/density split set, the original AAB/APKM/APKS/XAPK bundle, or a universal APK.",
    };

    /// A supplied split set was present but did not match its base APK.
    pub const INTAKE_SPLIT_SET_INCOMPLETE: DiagnosticDefinition = DiagnosticDefinition {
        id: "intake.split-set-incomplete",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The supplied split set is incomplete or incompatible with its base APK.",
        why: "The complete normalized set was installed together, but Android still reported a required split missing.",
        fix: "Re-export the bundle with every required ABI and density split, or provide a universal APK; APIaxess will not guess or fetch absent splits.",
    };

    /// The package has no native code compatible with the selected emulator.
    pub const INTAKE_NO_MATCHING_ABI: DiagnosticDefinition = DiagnosticDefinition {
        id: "intake.no-matching-abi",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The package has no native ABI matching the selected emulator.",
        why: "The installer found native code, but none targets the emulator architecture available to this sandbox.",
        fix: "Use an emulator image matching the package ABI, provide an APK containing the required ABI, or rebuild the application for x86_64.",
    };

    /// The package requires a newer Android API level than the runtime.
    pub const INTAKE_ANDROID_API_TOO_OLD: DiagnosticDefinition = DiagnosticDefinition {
        id: "intake.android-api-too-old",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The package requires a newer Android API level than the emulator.",
        why: "The installer rejected the package because the runtime API is below the package's minimum or target SDK requirement.",
        fix: "Rebuild/select an HQarroum image at the required API level using the API_LEVEL=34+ rebuild path, then retry installation.",
    };

    /// The package signature or verification state is not acceptable.
    pub const INTAKE_SIGNATURE_INVALID: DiagnosticDefinition = DiagnosticDefinition {
        id: "intake.signature-invalid",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The package signature or APK verification failed.",
        why: "Android rejected the package certificate, signature, verification record, or update compatibility.",
        fix: "Provide an intact APK set signed consistently by the original application, or reinstall after removing the conflicting package; do not silently resign intake artifacts.",
    };

    /// The runtime lacks enough storage for installation.
    pub const INTAKE_STORAGE_INSUFFICIENT: DiagnosticDefinition = DiagnosticDefinition {
        id: "intake.storage-insufficient",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The Android runtime lacks enough storage to install the artifact.",
        why: "The installer could not allocate space for the package or its extracted native/resources payload.",
        fix: "Tear down stale leases or use a fresh runtime with more writable storage, then retry the same resolved artifact.",
    };

    /// An installer failure was recognized but has no narrower safe diagnosis.
    pub const INTAKE_INSTALL_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "intake.install-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The resolved artifact could not be installed.",
        why: "Android rejected the resolved package set for an installer condition that APIaxess cannot safely repair automatically.",
        fix: "Review the recognized package shape and provide a corrected artifact or compatible emulator; the installer signal was translated into this diagnostic rather than exposed raw.",
    };

    /// Every Phase 3.1.3 intake-resolution definition.
    pub const PHASE_3_1_3: &[DiagnosticDefinition] = &[
        INTAKE_RESOLUTION_UNAVAILABLE,
        INTAKE_BASE_ONLY_SPLITS_MISSING,
        INTAKE_SPLIT_SET_INCOMPLETE,
        INTAKE_NO_MATCHING_ABI,
        INTAKE_ANDROID_API_TOO_OLD,
        INTAKE_SIGNATURE_INVALID,
        INTAKE_STORAGE_INSUFFICIENT,
        INTAKE_INSTALL_FAILED,
    ];

    /// Networking usage was found but no supported library identity matched.
    pub const NETWORKING_USAGE_UNIDENTIFIED: DiagnosticDefinition = DiagnosticDefinition {
        id: "networking.usage-unidentified",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Warning,
        what: "Networking usage was detected but its library could not be identified.",
        why: "Generic networking signatures were present without a reliable supported-library match.",
        fix: "Review the listed smali or DEX locations and use dynamic capture or a community protocol-decoder plugin.",
    };

    /// Protection metadata indicates that static networking locations may be hidden.
    pub const NETWORKING_PROTECTION_OBSCURES_MAP: DiagnosticDefinition = DiagnosticDefinition {
        id: "networking.protection-obscures-map",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Warning,
        what: "Detected protection may obscure the networking API map.",
        why: "Commercial protection, encrypted strings, or native migration reduces the reliability of static localization.",
        fix: "Treat static findings as lower-confidence and plan dynamic capture; review protection metadata before extraction.",
    };

    /// A normalized artifact location expected by routing is unavailable.
    pub const NETWORKING_ARTIFACT_LOCATION_UNAVAILABLE: DiagnosticDefinition =
        DiagnosticDefinition {
            id: "networking.artifact-location-unavailable",
            category: DiagnosticCategory::StaticAnalysis,
            severity: DiagnosticSeverity::Error,
            what: "A normalized artifact location required for networking detection is unavailable.",
            why: "The 1.1 handoff points to a missing or unreadable smali, source, or DEX location.",
            fix: "Re-run artifact intake and verify the normalized workspace is intact before routing libraries.",
        };

    /// A library signature is present but its localization evidence is ambiguous.
    pub const NETWORKING_SIGNATURE_AMBIGUOUS: DiagnosticDefinition = DiagnosticDefinition {
        id: "networking.signature-ambiguous",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Warning,
        what: "A networking signature was found, but its structural localization is ambiguous.",
        why: "The signature may be repackaged, partially obfuscated, or present only in lossy convenience output.",
        fix: "Keep the detection recorded, inspect all candidate locations, and use dynamic capture if extraction cannot establish ownership.",
    };

    /// An endpoint or operation was recovered only partially by bounded analysis.
    pub const EXTRACTION_PARTIAL_RECOVERY: DiagnosticDefinition = DiagnosticDefinition {
        id: "extraction.partial-recovery",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Warning,
        what: "A network API finding was only partially recovered.",
        why: "The bounded extractor found a structural call site but runtime composition escaped the supported analysis boundary.",
        fix: "Retain the partial finding and use dynamic capture to recover the runtime-complete endpoint or payload.",
    };

    /// A static candidate could not be bound to a structural endpoint.
    pub const EXTRACTION_UNBOUND_STRING_CANDIDATE: DiagnosticDefinition = DiagnosticDefinition {
        id: "extraction.unbound-string-candidate",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Info,
        what: "A plaintext networking string was retained without endpoint binding.",
        why: "The candidate survived in the DEX/source string pool but no bounded structural extractor linked it to an operation.",
        fix: "Review it as a low-confidence candidate or confirm its use through dynamic capture.",
    };

    /// Low-value packaged data was classified as noise instead of becoming a
    /// loose finding; the classification remains visible as one aggregate.
    pub const EXTRACTION_LOOSE_FINDINGS_FILTERED: DiagnosticDefinition = DiagnosticDefinition {
        id: "extraction.loose-findings-filtered",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Info,
        what: "Low-value packaged data was classified as static-analysis noise.",
        why: "The string came from a packaged resource, archive metadata, or binary support table rather than a code or API-bearing source.",
        fix: "Review the recorded reason counts and examples; retain the source as an explicit candidate if the classification is not appropriate for a target artifact.",
    };

    /// A routed decoder has no Phase 1.3 extractor yet.
    pub const EXTRACTION_DECODER_DEFERRED: DiagnosticDefinition = DiagnosticDefinition {
        id: "extraction.decoder-deferred",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Warning,
        what: "A detected protocol decoder has no Phase 1.3 extractor on this host.",
        why: "The routed library remains present, but extraction support is deferred or supplied by a future community decoder.",
        fix: "Use the retained locations for dynamic capture or install a compatible protocol-decoder extractor plugin.",
    };

    /// The assembled extraction document failed canonical API-model validation.
    pub const EXTRACTION_MODEL_INVALID: DiagnosticDefinition = DiagnosticDefinition {
        id: "extraction.model-invalid",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Error,
        what: "The extracted API surface failed canonical model validation.",
        why: "An extractor produced facts that did not satisfy the evidence-preserving 0.2 invariants.",
        fix: "Review the named extractor output and correct the producer before consuming the extraction report.",
    };

    /// The static pass produced an explicit handoff for dynamic capture.
    pub const STATIC_PASS_DYNAMIC_HANDOFF: DiagnosticDefinition = DiagnosticDefinition {
        id: "static-pass.dynamic-handoff",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Warning,
        what: "Static analysis marked a boundary for dynamic capture.",
        why: "The static pass could not establish a complete runtime API fact within its declared analysis boundary.",
        fix: "Run dynamic capture at the named location and feed the observation into the later fusion phase.",
    };

    /// Protection metadata materially limits static completeness.
    pub const STATIC_PASS_PROTECTION_LIMIT: DiagnosticDefinition = DiagnosticDefinition {
        id: "static-pass.protection-limit",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Warning,
        what: "Protection metadata limits the completeness of the static pass.",
        why: "Commercial obfuscation, encrypted strings, or protected code paths can hide the API map from bounded static analysis.",
        fix: "Retain static findings as bounded evidence and use dynamic capture for the protected or encrypted locations.",
    };

    /// Native networking logic is outside the static Phase 1 boundary.
    pub const STATIC_PASS_NATIVE_LOGIC: DiagnosticDefinition = DiagnosticDefinition {
        id: "static-pass.native-logic",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Warning,
        what: "Networking logic was identified in native code outside the static pass.",
        why: "Phase 1 does not perform native or Ghidra analysis, so the native portion remains a known static gap.",
        fix: "Use dynamic capture for the native call path; schedule native analysis only in the later analysis phase.",
    };

    /// The target's static coverage is materially incomplete or silent.
    pub const STATIC_PASS_COVERAGE_LIMIT: DiagnosticDefinition = DiagnosticDefinition {
        id: "static-pass.coverage-limit",
        category: DiagnosticCategory::StaticAnalysis,
        severity: DiagnosticSeverity::Info,
        what: "The static pass coverage signal is incomplete or silent for part of the target.",
        why: "One or more detected libraries were partial, deferred, protected, or produced no structurally bound static finding.",
        fix: "Use the machine-readable handoff markers to focus dynamic capture; silence is not evidence that the API is absent.",
    };

    /// The session-scoped proxy could not bind its loopback listener.
    pub const PROXY_PORT_IN_USE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.port-in-use",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The session proxy could not bind its listener.",
        why: "The requested loopback address is already in use or the host rejected the bind.",
        fix: "Stop the process using the address or choose an ephemeral/available loopback port, then retry.",
    };

    /// The embedded proxy backend could not be started or terminated unexpectedly.
    pub const PROXY_BACKEND_START_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.backend-start-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The session proxy backend failed to start or stay alive.",
        why: "The embedded protocol engine returned an initialization or task failure.",
        fix: "Review the backend error context, close any previous session cleanly, and retry with the reported alternate route if one is approved.",
    };

    /// A saved setting was invalid at startup and its default was used.
    pub const SETTINGS_SAVED_VALUE_IGNORED: DiagnosticDefinition = DiagnosticDefinition {
        id: "settings.saved-value-ignored",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Warning,
        what: "A saved setting was invalid, so APIaxess started with its default instead.",
        why: "The value saved in the settings file would be refused at startup.",
        fix: "Open Settings, correct the named setting (or clear it to use the default), save, and restart APIaxess.",
    };

    /// An in-app update action could not be carried out.
    pub const UPDATE_REFUSED: DiagnosticDefinition = DiagnosticDefinition {
        id: "update.refused",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Warning,
        what: "The update could not be started.",
        why: "The update is not ready, or this install is updated outside the app.",
        fix: "Check for updates again from Settings, or update with your package manager.",
    };

    /// An update install was requested while work is running.
    pub const UPDATE_SESSION_BUSY: DiagnosticDefinition = DiagnosticDefinition {
        id: "update.session-busy",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Warning,
        what: "The update will not install in the middle of an engagement.",
        why: "Installing restarts APIaxess, which would interrupt what is running.",
        fix: "Finish or stop it first, or choose \"Install on next launch\" to install when this session ends.",
    };

    /// An add-on download or install could not start or finish.
    pub const ADDON_REFUSED: DiagnosticDefinition = DiagnosticDefinition {
        id: "addon.refused",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Warning,
        what: "The add-on was not downloaded.",
        why: "The catalog could not be fetched, the disk is too full, or the add-on is in use or managed outside the app.",
        fix: "Read the reason, fix it, and click Download again; nothing was installed.",
    };

    /// A proxy was requested for a non-active session.
    pub const PROXY_SESSION_NOT_ACTIVE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.session-not-active",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The session proxy cannot start for an inactive session.",
        why: "Proxy listeners and their in-memory CA are owned by the active session lifecycle.",
        fix: "Activate the session before starting the proxy, or close and recreate an invalid session.",
    };

    /// A web-only action (discovery, capture browser) was requested without an
    /// active web-target session.
    pub const WEB_TARGET_REQUIRED: DiagnosticDefinition = DiagnosticDefinition {
        id: "web.target-required",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "This action needs an active web capture session.",
        why: "Discovery and the capture browser run against a declared web target, and the current session has none.",
        fix: "Start a web session on the Web capture surface (enter a target and affirm authorization), then retry.",
    };

    /// A discovery run named a wordlist that is not bundled.
    pub const DISCOVERY_WORDLIST_UNKNOWN: DiagnosticDefinition = DiagnosticDefinition {
        id: "discovery.wordlist-unknown",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The requested discovery wordlist is not available.",
        why: "Only the bundled wordlists (small, medium, large) or an explicit custom list can be run.",
        fix: "Choose one of the bundled wordlists and retry.",
    };

    /// A second discovery run was requested while one is still active.
    pub const DISCOVERY_ALREADY_ACTIVE: DiagnosticDefinition = DiagnosticDefinition {
        id: "discovery.already-active",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "A discovery run is already active.",
        why: "Only one discovery run probes a target at a time, so a second run cannot start while one is in progress.",
        fix: "Cancel the active run first, then start another.",
    };

    /// Cancel was requested but no discovery run is active.
    pub const DISCOVERY_NONE_ACTIVE: DiagnosticDefinition = DiagnosticDefinition {
        id: "discovery.none-active",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "There is no active discovery run to cancel.",
        why: "Cancel stops an in-progress discovery run, and none is currently running.",
        fix: "Start a discovery run before cancelling.",
    };

    /// The per-session CA could not be generated.
    pub const PROXY_CA_GENERATION_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.ca-generation-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Critical,
        what: "The session interception CA could not be generated.",
        why: "The cryptographic provider or X.509 generator rejected the CA or leaf certificate inputs.",
        fix: "Use a supported APIaxess build and cryptographic provider, then start a fresh session; no trust-store changes were made.",
    };

    /// An explicit CA export could not be written or removed.
    pub const PROXY_CA_EXPORT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.ca-export-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The explicitly requested session CA export failed.",
        why: "The temporary export directory or one of its certificate/key files could not be created, written, or purged.",
        fix: "Check temporary-directory permissions and remove the named export directory after verifying its fingerprint.",
    };

    /// An upstream connection failed after a request reached the proxy.
    pub const PROXY_UPSTREAM_UNREACHABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.upstream-unreachable",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The proxy could not reach the upstream target.",
        why: "The upstream connection failed or was refused while forwarding the observed request.",
        fix: "Verify target reachability, DNS, routing, and the declared engagement host/port, then retry.",
    };

    /// A client or upstream TLS negotiation failed.
    pub const PROXY_TLS_HANDSHAKE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.tls-handshake-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "A proxied TLS handshake failed.",
        why: "The client hello, generated leaf certificate, upstream TLS policy, or negotiated protocol was rejected.",
        fix: "Trust the CA only in the dedicated client context, check the target's TLS policy, and review the ALPN evidence.",
    };

    /// The negotiated ALPN did not match the requested protocol.
    pub const PROXY_ALPN_MISMATCH: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.alpn-mismatch",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The proxied TLS ALPN negotiation did not match the requested protocol.",
        why: "The client and upstream selected different protocol capabilities or the backend could not preserve the negotiated ALPN.",
        fix: "Confirm the client and upstream offer compatible ALPN protocols and retry; do not downgrade silently.",
    };

    /// A protocol case is not supported by the embedded proxy backend.
    pub const PROXY_PROTOCOL_UNSUPPORTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.protocol-unsupported",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The embedded proxy backend cannot handle this protocol case.",
        why: "The case is outside the backend's accepted HTTP, WebSocket, streaming, or trailer semantics.",
        fix: "Use a supported transport for this case, or stop the session and report the gap.",
    };

    /// RFC 8441 WebSocket-over-HTTP/2 was observed at a protocol boundary.
    pub const PROXY_WEBSOCKET_HTTP2_UNSUPPORTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.websocket-http2-unsupported",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "RFC 8441 WebSocket-over-HTTP/2 was detected, but this transport is not supported.",
        why: "The HTTP/2 peer sent an extended CONNECT with :protocol=websocket; the embedded proxy backend does not intercept this transport.",
        fix: "Use an HTTP/1.1 WebSocket transport where possible. If telemetry shows a real target requires RFC 8441, reopen dedicated backend work for that target.",
    };

    /// A dedicated client profile could not receive the public session CA.
    pub const PROXY_CLIENT_PROFILE_PROVISIONING_FAILED: DiagnosticDefinition =
        DiagnosticDefinition {
            id: "proxy.client-profile-provisioning-failed",
            category: DiagnosticCategory::Session,
            severity: DiagnosticSeverity::Error,
            what: "The dedicated client profile could not be provisioned with the session CA.",
            why: "The isolated profile directory was unavailable or already contained a different CA.",
            fix: "Use a disposable dedicated profile with writable storage, remove its stale APIaxess CA, and retry; the host system store was not touched.",
        };

    /// The NSS tooling needed to modify a browser profile is unavailable.
    pub const PROXY_NSS_TOOL_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.nss-tool-unavailable",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The NSS certutil tool required for browser-profile trust is unavailable.",
        why: "The configured NSS certutil executable could not be started or could not complete a profile operation.",
        fix: "Install the NSS tools and configure the NSS certutil executable; APIaxess will not fall back to a system-store CA install.",
    };

    /// The NSS certutil tool cannot operate on modern Firefox profile databases.
    pub const PROXY_NSS_VERSION_UNSUPPORTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.nss-version-unsupported",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The NSS certutil version is too old for this Firefox profile format.",
        why: "The configured certutil did not demonstrate support for the modern SQL-backed cert9.db/key4.db database used by current Firefox.",
        fix: "Install a current Mozilla NSS build with modern SQLite profile support (NSS 3.14 or newer), configure APIAXESS_NSS_CERTUTIL to its certutil executable, and retry.",
    };

    /// The selected browser/platform cannot provide client-scoped trust.
    pub const PROXY_BROWSER_PLATFORM_UNSUPPORTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.browser-platform-unsupported",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The selected browser and platform do not provide an APIaxess client-scoped trust path.",
        why: "Windows Chromium uses Windows/Chrome-managed trust inputs rather than a disposable profile-local NSS database. Its CACertificates policy is an enterprise-managed policy input, not a portable profile store that APIaxess can provision and tear down.",
        fix: "On Windows, use Firefox with the dedicated NSS profile. On Linux, Chromium can use the isolated NSS shared database. APIaxess will not install this CA in the Windows system store.",
    };

    /// The dedicated browser profile is absent, malformed, or locked.
    pub const PROXY_BROWSER_PROFILE_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.browser-profile-unavailable",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The dedicated browser profile is unavailable for trust provisioning.",
        why: "The profile path is missing or a running browser holds its NSS database lock.",
        fix: "Close the browser using the dedicated profile, use a disposable isolated profile path, and retry; the user's primary profile was not modified.",
    };

    /// A browser profile NSS operation failed after the tool was available.
    pub const PROXY_BROWSER_PROFILE_PROVISIONING_FAILED: DiagnosticDefinition =
        DiagnosticDefinition {
            id: "proxy.browser-profile-provisioning-failed",
            category: DiagnosticCategory::Session,
            severity: DiagnosticSeverity::Error,
            what: "The session CA could not be provisioned into the browser's NSS profile database.",
            why: "NSS certutil rejected the profile, certificate, database, or trust attributes.",
            fix: "Use a fresh isolated profile with no running browser, inspect the operation context, and retry; no system trust-store installation was attempted.",
        };

    /// A browser-profile trust record could not be removed during teardown.
    pub const PROXY_BROWSER_PROFILE_TEARDOWN_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.browser-profile-teardown-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Critical,
        what: "The session CA could not be removed from the dedicated browser profile.",
        why: "NSS certutil could not delete or verify removal of the exact session CA record, or ephemeral profile state could not be removed.",
        fix: "Close the dedicated browser, run the recorded browser-profile purge for the session marker, and verify the profile database no longer contains the APIaxess CA.",
    };

    /// The bundled browser could not be started or placed under ownership.
    pub const PROXY_BUNDLED_BROWSER_LAUNCH_FAILURE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.bundled-browser-launch-failure",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The bundled APIaxess browser could not be launched.",
        why: "The verified browser executable was missing, could not be spawned, or could not be placed in its disposable process boundary.",
        fix: "Reinstall the APIaxess browser runtime and retry with a writable temporary directory; no host trust-store change was attempted.",
    };

    /// The loopback `DevTools` endpoint could not be reached or used.
    pub const PROXY_CDP_CONNECT_FAILURE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.cdp-connect-failure",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The dedicated browser's loopback CDP endpoint could not be connected.",
        why: "The browser did not publish a usable DevToolsActivePort endpoint or rejected the page-control websocket.",
        fix: "Close the failed browser instance, retry with the bundled runtime, and inspect the launch context; the CDP port is never exposed beyond loopback.",
    };

    /// A browser request did not produce an observed proxy flow.
    pub const PROXY_CAPTURE_NOT_FLOWING: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.capture-not-flowing",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The dedicated browser is running, but its traffic is not reaching capture.",
        why: "The browser proxy route, certificate exception, or session capture observer is not carrying requests into the workbench store.",
        fix: "Verify the session proxy is active and use Firefox for a clean profile trust path; inspect the stored flow count before retrying.",
    };

    /// Browser process/profile teardown was not fully verified.
    pub const PROXY_TEARDOWN_INCOMPLETE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.teardown-incomplete",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Critical,
        what: "The dedicated browser session did not fully tear down.",
        why: "A browser process boundary, disposable profile, CDP endpoint, or client-scoped trust record remained after shutdown.",
        fix: "Close the dedicated browser, remove only the APIaxess-owned profile marked for this session, and verify no child process or trust record remains.",
    };

    /// A recorded exceptional trust-store removal failed.
    pub const PROXY_TRUST_PURGE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.trust-purge-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Critical,
        what: "A recorded interception CA could not be purged from its trust store.",
        why: "The platform adapter did not confirm removal of the exact recorded marker, fingerprint, serial, or location.",
        fix: "Run the standalone --purge-cas recovery command with the named store adapter and inspect the exact record before retrying.",
    };

    /// The live workbench WebSocket could not complete its session transport.
    pub const PROXY_LIVE_TRANSPORT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.live-transport-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The live workbench transport failed.",
        why: "The session WebSocket closed, could not be decoded, or lost its control-channel state.",
        fix: "Reconnect the live workbench in the active session; inspect the transport diagnostic before retrying an intercept action.",
    };

    /// A live workbench connection failed its session authentication check.
    pub const PROXY_LIVE_AUTH_REJECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.live-auth-rejected",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The live workbench authentication token was rejected.",
        why: "The WebSocket did not present the random token belonging to this active session.",
        fix: "Reload the active APIaxess session UI; never reuse a token from a prior session or share it with another local process.",
    };

    /// A live workbench connection failed the loopback Origin check.
    pub const PROXY_LIVE_ORIGIN_REJECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.live-origin-rejected",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The live workbench Origin was rejected.",
        why: "The browser did not identify the expected local API origin and the control surface refuses cross-origin local connections.",
        fix: "Open the GUI from the active 127.0.0.1 session URL and reconnect; do not disable the Origin check.",
    };

    /// A paused request exceeded the configured live intercept wait.
    pub const PROXY_INTERCEPT_TIMEOUT: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.intercept-timeout",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Warning,
        what: "A held request timed out and was forwarded unmodified.",
        why: "No forward, modify, or drop decision arrived before the intercept timeout elapsed, so the original request went upstream; any edits in progress were not applied.",
        fix: "Decide on held requests within the timeout, or raise it with Auto-forward after (next to Intercept, up to 10 minutes) for long investigations.",
    };

    /// The live editor supplied an invalid method, header, or body edit.
    pub const PROXY_INTERCEPT_EDIT_INVALID: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.intercept-edit-invalid",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "A live intercept edit was rejected as malformed.",
        why: "The edited method or header was not valid HTTP syntax, so the proxy retained the original request.",
        fix: "Correct the method/header syntax and submit the edit again; malformed edits never reach the upstream server.",
    };

    /// The bounded telemetry channel shed updates under load.
    pub const PROXY_TELEMETRY_BACKPRESSURE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.telemetry-backpressure",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Warning,
        what: "The live telemetry channel shed or coalesced flow updates.",
        why: "The bounded display firehose was behind a traffic burst; the reliable intercept control channel remains independent.",
        fix: "Reconnect or refresh the live flow list for current summaries; select flows to fetch their in-memory details.",
    };

    /// The GUI and engine disagreed about a live intercept action.
    pub const PROXY_LIVE_DESYNC: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.live-desync",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The live workbench is out of sync with the active session.",
        why: "An action referenced a missing, completed, or already-decided flow.",
        fix: "Refresh the live session and act only on a currently paused flow; the proxy keeps the flow outcome authoritative.",
    };

    /// The device-pairing CA endpoint was queried before a session CA exists.
    pub const PAIRING_CA_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "pairing.ca-unavailable",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The session interception CA is not available yet.",
        why: "A device requested the pairing CA before the workbench finished provisioning the per-session root certificate.",
        fix: "Wait for the workbench to report ready, then retry the pairing request; the CA is provisioned once at session startup.",
    };

    /// A device presented an invalid, expired, or already-used pairing token.
    pub const PAIRING_TOKEN_REJECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "pairing.token-rejected",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The device pairing token was rejected.",
        why: "The presented one-time pairing token is unknown, has expired, or was already exchanged for a session token.",
        fix: "Generate a fresh pairing token from the workbench and pair the device again before it expires; each token is single-use.",
    };

    /// A device control connection presented no valid session bearer token.
    pub const PAIRING_DEVICE_AUTH_REJECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "pairing.device-auth-rejected",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The device control connection was not authenticated.",
        why: "The connection did not present a valid, unexpired session bearer token issued by the pairing exchange for this session.",
        fix: "Re-run device pairing to obtain a current session token; a device cannot open the control channel without one.",
    };

    /// Manual pairing was requested for the app's own managed Android target.
    pub const PAIRING_MANAGED_TARGET: DiagnosticDefinition = DiagnosticDefinition {
        id: "pairing.managed-target",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The app's own Android target can't be paired manually.",
        why: "This device is the Android target APIaxess manages; APIaxess provisions it itself, so it is never armed for manual pairing.",
        fix: "Use the Android target view to drive and capture it, or arm a different device.",
    };

    /// Every device-pairing (phase C1) definition, used by conformance tests.
    pub const PHASE_C1: &[DiagnosticDefinition] = &[
        PAIRING_CA_UNAVAILABLE,
        PAIRING_TOKEN_REJECTED,
        PAIRING_DEVICE_AUTH_REJECTED,
        PAIRING_MANAGED_TARGET,
    ];

    /// Every phase 0.4 definition, used by catalogue conformance tests.
    pub const PHASE_0_4: &[DiagnosticDefinition] = &[
        SCOPE_OUTSIDE_DECLARATION,
        SCOPE_UNDETERMINED,
        HOST_CAPABILITY_GAP,
        PLUGIN_PERMISSION_DENIED,
        SESSION_INVALID_TRANSITION,
        SESSION_INVARIANT_FAILED,
        SESSION_API_MODEL_INVALID,
        SESSION_FORMAT_UNSUPPORTED,
        SESSION_JSON_INVALID,
        SESSION_UNKNOWN_FIELDS,
    ];

    /// Every Phase 1.1 artifact-intake definition.
    pub const PHASE_1_1: &[DiagnosticDefinition] = &[
        ARTIFACT_UNSUPPORTED_FORMAT,
        ARTIFACT_NOT_FOUND,
        ARTIFACT_MALFORMED_ARCHIVE,
        ARTIFACT_BUNDLE_RESOLUTION_FAILED,
        EXTERNAL_TOOL_MISSING,
        EXTERNAL_TOOL_VERSION_INCOMPATIBLE,
        EXTERNAL_TOOL_INVOCATION_FAILED,
        ARTIFACT_UNPACK_FAILED,
        ARTIFACT_DECOMPILATION_FAILED,
        ARTIFACT_DECOMPILATION_PARTIAL,
        ARTIFACT_DEX_ACCESS_UNAVAILABLE,
        ARTIFACT_PROTECTION_UNHANDLED,
        ARTIFACT_PROTECTION_DETECTOR_UNAVAILABLE,
        ARTIFACT_PROTECTION_DETECTED,
        ARTIFACT_PROTECTION_SUSPECTED,
        ARTIFACT_PROTECTION_HEAVY,
        ARTIFACT_PROTECTION_LEDGER_GAP,
    ];

    /// Every Phase 1.2 networking-routing definition.
    pub const PHASE_1_2: &[DiagnosticDefinition] = &[
        NETWORKING_USAGE_UNIDENTIFIED,
        NETWORKING_PROTECTION_OBSCURES_MAP,
        NETWORKING_ARTIFACT_LOCATION_UNAVAILABLE,
        NETWORKING_SIGNATURE_AMBIGUOUS,
    ];

    /// Every Phase 1.3 extraction definition.
    pub const PHASE_1_3: &[DiagnosticDefinition] = &[
        EXTRACTION_PARTIAL_RECOVERY,
        EXTRACTION_UNBOUND_STRING_CANDIDATE,
        EXTRACTION_LOOSE_FINDINGS_FILTERED,
        EXTRACTION_DECODER_DEFERRED,
        EXTRACTION_MODEL_INVALID,
    ];

    /// Every Phase 1.4 normalization and honesty-layer definition.
    pub const PHASE_1_4: &[DiagnosticDefinition] = &[
        STATIC_PASS_DYNAMIC_HANDOFF,
        STATIC_PASS_PROTECTION_LIMIT,
        STATIC_PASS_NATIVE_LOGIC,
        STATIC_PASS_COVERAGE_LIMIT,
    ];

    /// Every Phase 2.1 proxy-core definition.
    pub const PHASE_2_1: &[DiagnosticDefinition] = &[
        PROXY_PORT_IN_USE,
        PROXY_BACKEND_START_FAILED,
        SETTINGS_SAVED_VALUE_IGNORED,
        UPDATE_REFUSED,
        UPDATE_SESSION_BUSY,
        ADDON_REFUSED,
        PROXY_SESSION_NOT_ACTIVE,
        WEB_TARGET_REQUIRED,
        DISCOVERY_WORDLIST_UNKNOWN,
        DISCOVERY_ALREADY_ACTIVE,
        DISCOVERY_NONE_ACTIVE,
        PROXY_CA_GENERATION_FAILED,
        PROXY_CA_EXPORT_FAILED,
        PROXY_UPSTREAM_UNREACHABLE,
        PROXY_TLS_HANDSHAKE_FAILED,
        PROXY_ALPN_MISMATCH,
        PROXY_PROTOCOL_UNSUPPORTED,
        PROXY_WEBSOCKET_HTTP2_UNSUPPORTED,
        PROXY_CLIENT_PROFILE_PROVISIONING_FAILED,
        PROXY_NSS_TOOL_UNAVAILABLE,
        PROXY_NSS_VERSION_UNSUPPORTED,
        PROXY_BROWSER_PLATFORM_UNSUPPORTED,
        PROXY_BROWSER_PROFILE_UNAVAILABLE,
        PROXY_BROWSER_PROFILE_PROVISIONING_FAILED,
        PROXY_BROWSER_PROFILE_TEARDOWN_FAILED,
        PROXY_TRUST_PURGE_FAILED,
    ];

    /// Every Phase 2.2 live workbench definition.
    pub const PHASE_2_2: &[DiagnosticDefinition] = &[
        PROXY_LIVE_TRANSPORT_FAILED,
        PROXY_LIVE_AUTH_REJECTED,
        PROXY_LIVE_ORIGIN_REJECTED,
        PROXY_INTERCEPT_TIMEOUT,
        PROXY_INTERCEPT_EDIT_INVALID,
        PROXY_TELEMETRY_BACKPRESSURE,
        PROXY_LIVE_DESYNC,
    ];

    /// The durable workbench `SQLite` runtime store could not be opened.
    pub const PROXY_STORE_OPEN_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.store-open-failed",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The session traffic store could not be opened.",
        why: "The SQLite database or its session directory could not be created, opened, or configured for durable writes.",
        fix: "Use writable session storage, close another process holding the store, and retry; captured traffic was not silently redirected elsewhere.",
    };

    /// The durable traffic store failed an integrity check.
    pub const PROXY_STORE_CORRUPT: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.store-corrupt",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Critical,
        what: "The session traffic store failed its integrity check.",
        why: "SQLite reported an inconsistent database after reopen or during recovery.",
        fix: "Stop using the damaged runtime cache, recover from the canonical JSON session, and retain the diagnostic for investigation.",
    };

    /// A durable flow or content-addressed body could not be committed.
    pub const PROXY_STORE_WRITE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.store-write-failed",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "Captured traffic could not be committed to the durable store.",
        why: "A metadata transaction or content-addressed body write failed, including disk-full and permission failures.",
        fix: "Free or repair the session storage volume and retry; inspect the store diagnostic before continuing capture.",
    };

    /// The internal traffic store could not be normalized into the session JSON.
    pub const PROXY_STORE_SESSION_COMMIT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.store-session-commit-failed",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "Traffic could not be committed to the canonical JSON session.",
        why: "The normalized workbench payload failed serialization or the session invariant-checked commit path rejected it.",
        fix: "Keep the SQLite runtime store intact, inspect the named invariant or serialization error, and retry session serialization.",
    };

    /// HAR interchange input or output could not be parsed or encoded.
    pub const PROXY_HAR_INTERCHANGE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.har-interchange-failed",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "HAR traffic interchange failed.",
        why: "The supplied HAR did not match the supported interchange shape or could not be encoded.",
        fix: "Validate the HAR log and retry; HAR is an interchange adapter, never the primary session store.",
    };

    /// A HAR file was larger than the import accepts.
    pub const PROXY_HAR_IMPORT_TOO_LARGE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.har-import-too-large",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The HAR file is too large to import.",
        why: "It exceeds the HAR import size limit (see the limit in the diagnostic context). The file itself may be valid.",
        fix: "Export a smaller HAR (fewer requests or without large response bodies), or split it into several files and import each.",
    };

    /// A HAR upload could not be read.
    pub const PROXY_HAR_IMPORT_UNREADABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.har-import-unreadable",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The HAR file could not be read.",
        why: "The upload did not arrive in full, so its contents were never parsed.",
        fix: "Retry the import; if it keeps failing, check the file can be opened and is not still being written.",
    };

    /// A HAR upload was not a HAR log.
    pub const PROXY_HAR_IMPORT_MALFORMED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.har-import-malformed",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The file is not a HAR log APIaxess can import.",
        why: "It is not valid JSON, or it lacks the HAR log shape (log.entries with request and response); the parse error in the diagnostic context names where.",
        fix: "Export the HAR again from the browser or tool, or correct the file at the reported location, then import it.",
    };

    /// The canonical session did not contain a compatible traffic payload.
    pub const PROXY_STORE_RESUME_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.store-resume-failed",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The traffic runtime could not resume from the canonical session.",
        why: "The committed workbench traffic schema was absent, unsupported, or failed rehydration into SQLite.",
        fix: "Use a compatible session artifact or start a fresh runtime store; do not treat a partial rehydration as complete.",
    };

    /// The requested canonical session artifact could not be found or read.
    pub const PROXY_SESSION_ARTIFACT_NOT_FOUND: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.session-artifact-not-found",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The requested session artifact could not be opened.",
        why: "The supplied path does not identify a readable canonical session artifact.",
        fix: "Check the artifact path and permissions, then open a saved session.json or start a new session.",
    };

    /// The live session could not be committed to its canonical artifact.
    pub const PROXY_SESSION_SAVE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.session-save-failed",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The active session could not be saved.",
        why: "The workbench snapshot or atomic canonical-artifact write failed.",
        fix: "Keep the runtime store intact, repair session storage, and retry save before exiting.",
    };

    /// A named session would reuse an existing runtime identity.
    pub const PROXY_SESSION_ID_COLLISION: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.session-id-collision",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The requested session identity is already in use.",
        why: "Starting a new session with that identity would reuse another session's SQLite directory.",
        fix: "Resume the named session explicitly or omit the identity and start a fresh session.",
    };

    /// A workbench action could not be appended to the canonical audit trail.
    pub const PROXY_SESSION_AUDIT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.session-audit-failed",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The workbench action could not be recorded in the session audit trail.",
        why: "The active session could not accept or retain the action record.",
        fix: "Keep the workbench result visible, repair session state, and retry the operation or save.",
    };

    /// No active session engagement scope is available for classification.
    pub const PROXY_SESSION_SCOPE_NOT_SET: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.session-scope-not-set",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Warning,
        what: "The session has no engagement scope available for classification.",
        why: "The request reached the workbench before a session scope was attached.",
        fix: "Create or open a session, then declare its target and allowed network targets before continuing.",
    };

    /// Every Phase 2.3 durable workbench definition.
    pub const PHASE_2_3: &[DiagnosticDefinition] = &[
        PROXY_STORE_OPEN_FAILED,
        PROXY_STORE_CORRUPT,
        PROXY_STORE_WRITE_FAILED,
        PROXY_STORE_SESSION_COMMIT_FAILED,
        PROXY_HAR_INTERCHANGE_FAILED,
        PROXY_HAR_IMPORT_TOO_LARGE,
        PROXY_HAR_IMPORT_UNREADABLE,
        PROXY_HAR_IMPORT_MALFORMED,
        PROXY_STORE_RESUME_FAILED,
        PROXY_SESSION_ARTIFACT_NOT_FOUND,
        PROXY_SESSION_SAVE_FAILED,
        PROXY_SESSION_ID_COLLISION,
        PROXY_SESSION_AUDIT_FAILED,
        PROXY_SESSION_SCOPE_NOT_SET,
    ];

    /// A resend request could not be parsed or sent through the proxy path.
    pub const PROXY_RESEND_REQUEST_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.resend-request-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The resend request was rejected or could not be sent.",
        why: "The edited method, URL, headers, body, proxy transport, TLS setup, or upstream exchange was invalid or unavailable.",
        fix: "Correct the request fields, ensure the session proxy is running, and retry; the original captured request remains unchanged.",
    };

    /// Resend history could not be durably persisted.
    pub const PROXY_RESEND_HISTORY_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.resend-history-failed",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The resend revision could not be saved.",
        why: "The append-only context or revision record could not be committed to the session traffic store.",
        fix: "Keep the edited request visible, repair session storage, and retry persistence; no revision is reported as saved until the commit succeeds.",
    };

    /// A resend request was attempted outside the declared engagement scope.
    pub const PROXY_RESEND_OUTSIDE_SCOPE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.resend-outside-scope",
        category: DiagnosticCategory::AuthorizationScope,
        severity: DiagnosticSeverity::Warning,
        what: "The resend request targets outside the declared engagement scope.",
        why: "The honor-system scope assessment classified the edited request host as outside the session declaration.",
        fix: "Confirm authorization and the target before continuing; the attempt is recorded and is not silently blocked.",
    };

    /// No running routed proxy was available for a resend send.
    pub const PROXY_RESEND_TRANSPORT_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.resend-transport-unavailable",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "Resend has no running session proxy transport.",
        why: "A resend must go through the active routed ProxyBackend, but no sender has been attached to this workbench session.",
        fix: "Start the session proxy and attach its sender before retrying; a resend will not fall back to a direct request.",
    };

    /// A resend got no response within its send timeout.
    pub const PROXY_RESEND_TIMED_OUT: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.resend-timed-out",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The resend got no response before its send timeout.",
        why: "The upstream accepted or stalled the exchange but did not answer within the configured timeout, so the send was abandoned.",
        fix: "Check that the target is responsive, or raise the Resend timeout and retry; the attempt is kept in history.",
    };

    /// The operator cancelled a resend while it was in flight.
    pub const PROXY_RESEND_CANCELLED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.resend-cancelled",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Warning,
        what: "The resend was cancelled before a response arrived.",
        why: "The operator stopped the send; the request may already have reached the target.",
        fix: "Resend when ready; the cancelled attempt is kept in history.",
    };

    /// Every Phase 2.4 resend definition.
    pub const PHASE_2_4: &[DiagnosticDefinition] = &[
        PROXY_RESEND_REQUEST_FAILED,
        PROXY_RESEND_HISTORY_FAILED,
        PROXY_RESEND_OUTSIDE_SCOPE,
        PROXY_RESEND_TRANSPORT_UNAVAILABLE,
        PROXY_RESEND_TIMED_OUT,
        PROXY_RESEND_CANCELLED,
    ];

    /// ffuf is required for a selected stateless bulk attack but is unavailable.
    pub const PROXY_FUZZER_FFUF_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.fuzzer-ffuf-unavailable",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The stateless fuzzer engine is unavailable.",
        why: "The configured ffuf executable is missing, incompatible, or failed its version probe.",
        fix: "Install a supported ffuf release or configure its executable path; choose a stateful/native attack only when the attack actually needs that tier.",
    };

    /// ffuf exited unsuccessfully or emitted invalid structured output.
    pub const PROXY_FUZZER_FFUF_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.fuzzer-ffuf-failed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The stateless fuzzer process failed.",
        why: "ffuf did not complete successfully or its JSON result could not be decoded.",
        fix: "Inspect the structured process diagnostic, verify the wordlist and target request, then retry or use a native stateful job.",
    };

    /// A directory-discovery run was stopped before every candidate was probed.
    pub const WEB_DISCOVERY_STOPPED: DiagnosticDefinition = DiagnosticDefinition {
        id: "web.discovery-stopped",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Info,
        what: "The discovery run was stopped.",
        why: "It was stopped (or the session closed) before every candidate was probed; the hits found so far are kept.",
        fix: "Run discovery again to probe the remaining candidates.",
    };

    /// Observed request rate reported after a stateless discovery/fuzzer run,
    /// so the pre-run estimate can be judged honestly against reality.
    pub const WEB_DISCOVERY_RATE_OBSERVED: DiagnosticDefinition = DiagnosticDefinition {
        id: "web.discovery-rate-observed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Info,
        what: "The discovery run's actual request rate was measured.",
        why: "End-to-end throughput through the routed proxy is latency-bound; the actual rate is reported so the estimate can be calibrated rather than trusted blindly.",
        fix: "If the actual rate differs materially from the estimate, set APIAXESS_DISCOVERY_RATE to the observed value for future estimates.",
    };

    /// A fuzzer attack's actual request rate was measured.
    pub const PROXY_FUZZER_RATE_OBSERVED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.fuzzer-rate-observed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Info,
        what: "The fuzz attack's actual request rate was measured.",
        why: "End-to-end throughput through the routed proxy is latency-bound; the actual rate is reported so the configured throttle can be judged against reality rather than trusted blindly.",
        fix: "If the actual rate differs materially from the configured rate, adjust the attack's delay/rate setting for future runs.",
    };

    /// A fuzzer payload set or position configuration is malformed.
    pub const PROXY_FUZZER_CONFIG_INVALID: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.fuzzer-config-invalid",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The fuzzer attack configuration is invalid.",
        why: "Payload sets, positions, attack mode, limits, or sequence steps do not form a usable request attack.",
        fix: "Correct the marked positions and payload sets, then retry configuration validation.",
    };

    /// A native fuzzer sequence failed at a specific step.
    pub const PROXY_FUZZER_SEQUENCE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.fuzzer-sequence-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The stateful fuzzer sequence stopped before completion.",
        why: "Authentication, a prior request, token extraction, or token injection failed at the named sequence step.",
        fix: "Inspect the step diagnostic and response, correct the extractor or pre-flight request, and retry from the failed sequence.",
    };

    /// A fuzzer job was stopped or cancelled cleanly.
    pub const PROXY_FUZZER_CANCELLED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.fuzzer-cancelled",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Info,
        what: "The Fuzz attack was stopped.",
        why: "The attack was cancelled, or the session closed, while work was in progress.",
        fix: "Resume the job or start a new attack if more payloads are authorized.",
    };

    /// A fuzzer attack target was outside the declared engagement scope.
    pub const PROXY_FUZZER_OUTSIDE_SCOPE: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.fuzzer-outside-scope",
        category: DiagnosticCategory::AuthorizationScope,
        severity: DiagnosticSeverity::Warning,
        what: "The fuzzer attack targets outside the declared engagement scope.",
        why: "The attack host was classified outside the session declaration.",
        fix: "Confirm authorization before continuing; this warning is recorded and the honor-system model does not silently block it.",
    };

    /// Fuzzer result or configuration persistence failed.
    pub const PROXY_FUZZER_PERSISTENCE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "proxy.fuzzer-persistence-failed",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "The fuzzer job or result could not be saved.",
        why: "The durable workbench store rejected the attack configuration or result revision.",
        fix: "Repair session storage and retry; unsaved results are not reported as durable findings.",
    };

    /// The selected sandbox cannot use the host's virtualization provider.
    pub const SANDBOX_VIRTUALIZATION_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.virtualization-unavailable",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The selected Android sandbox cannot use hardware virtualization.",
        why: "The required KVM, WHPX, or AEHD capability was not available on this host.",
        fix: "Enable hardware virtualization and the named hypervisor capability, or select the remote-offload backend.",
    };

    /// A Windows Android emulator hypervisor driver is absent.
    pub const SANDBOX_HYPERVISOR_DRIVER_MISSING: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.hypervisor-driver-missing",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The Android emulator hypervisor driver is missing.",
        why: "Neither a usable WHPX platform nor the Android Emulator Hypervisor Driver was detected.",
        fix: "Enable WHPX or install AEHD, then rerun capability detection; use remote-offload when Windows virtualization remains unavailable.",
    };

    /// Docker is absent or its daemon cannot be used for redroid.
    pub const SANDBOX_DOCKER_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.docker-unavailable",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The redroid sandbox cannot use Docker on this host.",
        why: "Docker was absent, its daemon was unreachable, or the configured Docker probe failed.",
        fix: "Install and start Docker, confirm the current user can access its daemon, or select AVD or remote-offload.",
    };

    /// Docker's privileged container requirement was not satisfied.
    pub const SANDBOX_DOCKER_PRIVILEGE_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.docker-privilege-unavailable",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The redroid sandbox cannot start its required privileged container.",
        why: "The Docker daemon or host kernel does not permit the --privileged redroid runtime contract.",
        fix: "Use a compatible Linux Docker host with --privileged access, or select the stronger AVD or remote-offload backend.",
    };

    /// An Android image or redroid image could not be acquired.
    pub const SANDBOX_IMAGE_ACQUISITION_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.image-acquisition-failed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The selected Android sandbox image is unavailable.",
        why: "The required AVD system image or redroid container image could not be found or downloaded.",
        fix: "Check the configured asset source, network access, disk space, and digest; acquire the named image and retry.",
    };

    /// An Android runtime process could not be started.
    pub const SANDBOX_BOOT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.boot-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The Android sandbox failed during boot.",
        why: "The selected emulator, container, or remote runtime exited or reported a failed boot.",
        fix: "Inspect the named runtime evidence, repair the image or runtime installation, and retry or use a reported fallback tier.",
    };

    /// Insufficient free disk for the Android sandbox userdata image.
    pub const SANDBOX_INSUFFICIENT_DISK: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.insufficient-disk",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "There is not enough free disk space to boot the Android sandbox.",
        why: "The bundled emulator writes a fresh userdata image on each cold boot and needs several GB free on the runtime volume; the volume has less free space than that, so a boot would fail partway with a misleading runtime error.",
        fix: "Free space on the runtime volume (or point the analysis runtime and temp directory at a larger volume via TMPDIR/%TEMP%) so the reported required amount is available, then retry.",
    };

    /// Android boot did not complete before the configured deadline.
    pub const SANDBOX_READINESS_TIMEOUT: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.readiness-timeout",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The Android sandbox did not become ready before the deadline.",
        why: "The runtime process started but did not expose a boot-complete, reachable Android control endpoint in time.",
        fix: "Increase the boot deadline only after checking runtime health; repair virtualization, the image, or remote connectivity and retry.",
    };

    /// ADB could not reach the ready Android environment.
    pub const SANDBOX_ADB_UNREACHABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.adb-unreachable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The Android sandbox is not reachable through its control channel.",
        why: "ADB could not connect to the selected local or secured remote runtime after it was started.",
        fix: "Check the runtime process and serial, keep ADB bound to the approved local or encrypted transport, and retry.",
    };

    /// A remote sandbox host could not be reached.
    pub const SANDBOX_REMOTE_UNREACHABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.remote-unreachable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The remote sandbox host could not be reached.",
        why: "The encrypted remote transport could not establish a connection to the configured Linux host.",
        fix: "Check the host name, network route, firewall, and SSH service, or choose a local sandbox tier.",
    };

    /// A remote sandbox transport failed authentication or host-key validation.
    pub const SANDBOX_REMOTE_AUTH_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.remote-auth-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The remote sandbox transport rejected authentication.",
        why: "SSH credentials or strict host-key verification did not authenticate the configured remote host.",
        fix: "Install the intended key, verify the pinned known-hosts entry, and retry; raw unauthenticated ADB is not supported.",
    };

    /// A remote sandbox was configured with an unsafe unauthenticated transport.
    pub const SANDBOX_REMOTE_TRANSPORT_INSECURE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.remote-transport-insecure",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "The remote sandbox transport is not an authenticated encrypted channel.",
        why: "The remote runtime configuration attempted to expose or control ADB without SSH, WireGuard, or an equivalent authenticated channel.",
        fix: "Configure strict SSH host-key and key authentication or an approved encrypted transport; raw ADB-over-TCP is rejected.",
    };

    /// A sandbox cleanup operation did not complete.
    pub const SANDBOX_TEARDOWN_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.teardown-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "The Android sandbox did not tear down completely.",
        why: "The runtime process, container, remote lease, or ephemeral state could not be stopped and verified as removed.",
        fix: "Run the recorded cleanup for the named lease, remove only its runtime state, and verify no process, volume, or listener remains.",
    };

    /// An AVD clean baseline could not be restored.
    pub const SANDBOX_SNAPSHOT_REVERT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.snapshot-revert-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "The AVD clean baseline snapshot could not be restored.",
        why: "The emulator did not save or reload the session's declared clean snapshot during teardown.",
        fix: "Stop the named emulator, restore or recreate its clean baseline snapshot, and do not reuse the affected AVD until verified.",
    };

    /// A sandbox operation was requested outside an active session.
    pub const SANDBOX_SESSION_NOT_ACTIVE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.session-not-active",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The sandbox operation was requested outside an active session.",
        why: "Sandbox leases are session-scoped and cannot be created for a created or closed session.",
        fix: "Activate the session before starting the sandbox and close it only after the lease has been torn down.",
    };

    /// A sandbox backend could not satisfy its declared plan.
    pub const SANDBOX_BACKEND_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.backend-unavailable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The selected sandbox backend cannot run on the available host.",
        why: "Capability planning found a missing requirement and no usable local or remote fallback was selected.",
        fix: "Apply the named capability remediation, choose AVD, redroid, or remote-offload according to the reported tradeoff, and retry.",
    };

    /// The emulator's functional acceleration probe failed.
    pub const SANDBOX_ACCELERATION_CHECK_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.acceleration-check-failed",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "Android emulator hardware acceleration is not usable.",
        why: "The emulator's functional acceleration probe did not confirm KVM or WHPX operation.",
        fix: "Run APIaxess on the native host, enable KVM or WHPX, or select remote-offload; do not infer support from the VM/CPU label alone.",
    };

    /// AEHD was found as a transitional Windows accelerator.
    pub const SANDBOX_AEHD_TRANSITIONAL: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.aehd-transitional",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Warning,
        what: "The Android emulator is using the transitional AEHD accelerator.",
        why: "WHPX was not confirmed and AEHD is a sunset-path Windows dependency.",
        fix: "Enable Windows Hypervisor Platform for the durable native path; use AEHD only as a temporary fallback or select remote-offload.",
    };

    /// The runtime appears virtualized or otherwise lacks a trustworthy native posture.
    pub const SANDBOX_VM_GUIDANCE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.vm-guidance",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Warning,
        what: "The host appears virtualized or local acceleration is unavailable.",
        why: "Functional host evidence indicates that Android virtualization may be nested or unavailable; CPU hypervisor labels are not used as the sole gate.",
        fix: "Run APIaxess on the native host for the local dynamic tier, or select the secured remote-offload backend.",
    };

    /// The Linux kernel does not expose the redroid device prerequisites.
    pub const SANDBOX_REDOID_KERNEL_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.redroid-kernel-unavailable",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The Linux kernel cannot provide the redroid runtime prerequisites.",
        why: "Binder/binderfs and the required ashmem or memfd-backed Android device support were not confirmed.",
        fix: "Use AVD, load the supported binder and memory modules on a native Linux host, or select remote-offload; redroid is not a Windows tier.",
    };

    /// redroid is intentionally unavailable on Windows.
    pub const SANDBOX_REDOID_WINDOWS_UNSUPPORTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.redroid-windows-unsupported",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Info,
        what: "redroid is not offered on Windows.",
        why: "redroid requires a native Linux kernel contract; Docker Desktop would add another virtualization layer and is not the supported fast tier.",
        fix: "Use the native Windows AVD tier, or select remote-offload when WHPX/AVD is unavailable.",
    };

    /// The redroid host-ADB loopback contract failed.
    pub const SANDBOX_REDOID_ADB_CONTRACT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.redroid-adb-contract-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The redroid host-ADB loopback contract could not be established.",
        why: "The per-lease loopback port, host ADB client, or Android readiness/authentication evidence was unavailable.",
        fix: "Use a supported native Linux redroid image, keep ADB bound to 127.0.0.1, verify host-key authentication, and retry or choose AVD/remote-offload.",
    };

    /// ADB host-key authentication could not be established.
    pub const SANDBOX_ADB_AUTH_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.adb-auth-unavailable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "ADB host-key authentication could not be established.",
        why: "The session did not have a usable per-lease adbkey or the Android endpoint remained unauthorized.",
        fix: "Regenerate the session-scoped adbkey, verify the runtime accepts authenticated ADB, and never expose the endpoint beyond loopback or the encrypted remote channel.",
    };

    /// The runtime trust policy found a present vulnerability whose controls
    /// make it unreachable under the active profile.
    pub const SANDBOX_RUNTIME_TRUST_FINDINGS: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.runtime-trust-findings",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "The Android runtime is allowed with explained trust findings.",
        why: "One or more policy findings are present, but the declared loopback, authenticated, ephemeral runtime controls mitigate their exploitability.",
        fix: "Review the policy, posture facts, and VEX justification in the session diagnostics; update the image when a patched build is available.",
    };

    /// A reachable runtime-trust finding requires explicit scoped acceptance.
    pub const SANDBOX_RUNTIME_TRUST_ACCEPTANCE_REQUIRED: DiagnosticDefinition =
        DiagnosticDefinition {
            id: "sandbox.runtime-trust-acceptance-required",
            category: DiagnosticCategory::Sandbox,
            severity: DiagnosticSeverity::Error,
            what: "The runtime trust policy requires explicit acceptance.",
            why: "A vulnerability remains reachable under the selected runtime profile and no valid finding-scoped acceptance was supplied.",
            fix: "Provide a non-expired acceptance scoped to the exact finding IDs, image digest, profile, reason, threat model, and user, or correct the runtime posture.",
        };

    /// Runtime trust failed at a non-overridable integrity boundary.
    pub const SANDBOX_RUNTIME_TRUST_DENIED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.runtime-trust-denied",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "The runtime trust policy denied startup.",
        why: "An image-integrity, policy-integrity, containment, or other non-overridable runtime-trust condition failed.",
        fix: "Use the expected digest and verified policy bundle, restore containment, or select a runtime profile that satisfies the trust policy; integrity failures cannot be waived.",
    };

    /// Windows Home cannot provide the durable WHPX/Hyper-V AVD path.
    pub const SANDBOX_WINDOWS_HOME_UNSUPPORTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.windows-home-unsupported",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Warning,
        what: "Windows Home cannot provide the durable local AVD acceleration path.",
        why: "The required Windows Hypervisor Platform/Hyper-V capability is unavailable on this Windows edition.",
        fix: "Use remote-offload, or run APIaxess on a supported native Windows Pro/Enterprise or Linux host.",
    };

    /// Windows-on-ARM is outside the supported local AVD matrix.
    pub const SANDBOX_WINDOWS_ARM_UNSUPPORTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.windows-arm-unsupported",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Warning,
        what: "Windows-on-ARM is outside the local AVD support matrix.",
        why: "The configured Android emulator runtime requires the supported x86_64 native-host path.",
        fix: "Use remote-offload or run APIaxess on a supported native x86_64 Windows/Linux host.",
    };

    /// Local dynamic analysis is not yet available on macOS.
    pub const SANDBOX_MACOS_DYNAMIC_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.macos-dynamic-unavailable",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Warning,
        what: "Dynamic analysis is not yet available on macOS.",
        why: "This build has no macOS Android emulator runtime or Hypervisor.framework acceleration path yet; static analysis, web capture, Fuzz and Resend are unaffected.",
        fix: "Use remote-offload, or run dynamic analysis on a supported Windows or Linux host.",
    };

    /// The runtime planner selected a backend and recorded its reason.
    pub const SANDBOX_RUNTIME_SELECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.runtime-selected",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Info,
        what: "The sandbox runtime was selected from functional host capabilities.",
        why: "The planner chose the default, opt-in fast tier, or secured fallback for the observed host posture.",
        fix: "Review the selected tier and capability evidence before starting a dynamic session.",
    };

    /// The `HQarroum` image resolved to a different immutable digest.
    pub const SANDBOX_HQARROUM_IMAGE_DIGEST_MISMATCH: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.hqarroum-image-digest-mismatch",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Critical,
        what: "The HQarroum image digest does not match the approved pin.",
        why: "The image was pulled or inspected successfully, but Docker reported an immutable image ID different from the configured digest.",
        fix: "Remove the unexpected image, use the approved digest or a deliberately configured rebuild, and retry.",
    };

    /// `HQarroum`'s emulator did not demonstrate KVM acceleration.
    pub const SANDBOX_HQARROUM_TCG_FALLBACK: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.hqarroum-tcg-fallback",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Critical,
        what: "The HQarroum emulator did not demonstrate KVM acceleration.",
        why: "The container could not expose an active KVM VM/vCPU descriptor, so boot may be using TCG or another unusably slow fallback.",
        fix: "Enable BIOS virtualization, WSL2 nested KVM, Docker /dev/kvm passthrough, and the WSL kvm-group permission fix; route to remote-offload rather than silently using TCG.",
    };

    /// `HQarroum` did not expose the required root/debuggable userdebug posture.
    pub const SANDBOX_HQARROUM_ROOT_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.hqarroum-root-unavailable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "The HQarroum runtime is not rootable as required.",
        why: "The image did not report userdebug/ro.debuggable=1 or adb root failed.",
        fix: "Use the approved google_apis userdebug image and verify adb root before starting dynamic capture; do not continue with a production/user image.",
    };

    /// `HQarroum` could not make the system CA target writable.
    pub const SANDBOX_HQARROUM_SYSTEM_NOT_WRITABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.hqarroum-system-not-writable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "The HQarroum system image is not writable.",
        why: "The diagnostic context identifies the failed operation: verity disablement, reboot/remount, directory permissions, marker creation, marker visibility, or marker cleanup.",
        fix: "Use EXTRA_FLAGS=-writable-system, disable verity, reboot and wait for sys.boot_completed=1, then run adb root/remount; use the reported operation and reason to select another image or runtime tier if the CA store remains blocked.",
    };

    /// The `HQarroum` host-side loopback ADB contract failed.
    pub const SANDBOX_HQARROUM_ADB_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.hqarroum-adb-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "The HQarroum host-side authenticated loopback ADB contract failed.",
        why: "The disposable container did not provide an authenticated ADB endpoint on a 127.0.0.1-only published port.",
        fix: "Keep SKIP_AUTH=false, use the per-lease host adbkey, bind only 127.0.0.1, and retry or select remote-offload.",
    };

    /// The bundled analysis runtime (Android emulator payload) is not installed.
    ///
    /// The emulator is a separate, optional ~2 GB download, not part of the base
    /// install. This reports that dynamic analysis was requested but the payload
    /// is absent — an actionable prompt, not a crash.
    pub const SANDBOX_ANALYSIS_RUNTIME_MISSING: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.analysis-runtime-missing",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The APIaxess analysis runtime (Android emulator) is not installed.",
        why: "Dynamic analysis uses a bundled QEMU + owned Android image shipped as a separate, optional download that is not part of the base application.",
        fix: "Download the analysis runtime in Settings → Add-ons (it comes from apiaxess.dev and is SHA-256-verified), or point APIAXESS_ANALYSIS_RUNTIME at an installed copy; static and web workflows do not require it.",
    };

    /// Hardware virtualization was detected; the bundled emulator runs accelerated.
    pub const SANDBOX_ACCELERATED_MODE_ACTIVE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.accelerated-mode-active",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Info,
        what: "Hardware virtualization is available; dynamic analysis runs accelerated.",
        why: "The host exposes usable KVM (Linux) or WHPX/Hyper-V (Windows), so the bundled emulator boots with hardware acceleration.",
        fix: "No action needed; this is the fast path for dynamic analysis.",
    };

    /// No hardware virtualization; the bundled emulator falls back to software mode.
    ///
    /// Unlike the Docker/HQarroum path (which rejects TCG as unusably slow), the
    /// bundled emulator deliberately supports a software-mode (TCG) fallback that
    /// runs everywhere. This is a graceful, honest degradation, not a failure.
    pub const SANDBOX_SOFTWARE_MODE_ACTIVE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.software-mode-active",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Warning,
        what: "No hardware virtualization detected; dynamic analysis will run in slow software mode.",
        why: "The host exposes no usable KVM (Linux) or WHPX/Hyper-V (Windows), so the bundled emulator boots under QEMU TCG emulation, which is correct but substantially slower.",
        fix: "For full speed, enable host virtualization (BIOS/firmware + KVM or WHPX/Hyper-V) or run on a virtualization-capable host; software mode remains fully functional, just slow.",
    };

    /// Every Phase 11.5 bundled-dynamic-runtime definition.
    pub const PHASE_11_5: &[DiagnosticDefinition] = &[
        SANDBOX_ANALYSIS_RUNTIME_MISSING,
        SANDBOX_ACCELERATED_MODE_ACTIVE,
        SANDBOX_SOFTWARE_MODE_ACTIVE,
    ];

    /// Every Phase 3.1 sandbox definition.
    pub const PHASE_3_1: &[DiagnosticDefinition] = &[
        SANDBOX_VIRTUALIZATION_UNAVAILABLE,
        SANDBOX_HYPERVISOR_DRIVER_MISSING,
        SANDBOX_DOCKER_UNAVAILABLE,
        SANDBOX_DOCKER_PRIVILEGE_UNAVAILABLE,
        SANDBOX_IMAGE_ACQUISITION_FAILED,
        SANDBOX_BOOT_FAILED,
        SANDBOX_INSUFFICIENT_DISK,
        SANDBOX_READINESS_TIMEOUT,
        SANDBOX_ADB_UNREACHABLE,
        SANDBOX_REMOTE_UNREACHABLE,
        SANDBOX_REMOTE_AUTH_FAILED,
        SANDBOX_REMOTE_TRANSPORT_INSECURE,
        SANDBOX_TEARDOWN_FAILED,
        SANDBOX_SNAPSHOT_REVERT_FAILED,
        SANDBOX_SESSION_NOT_ACTIVE,
        SANDBOX_BACKEND_UNAVAILABLE,
        SANDBOX_ACCELERATION_CHECK_FAILED,
        SANDBOX_AEHD_TRANSITIONAL,
        SANDBOX_VM_GUIDANCE,
        SANDBOX_REDOID_KERNEL_UNAVAILABLE,
        SANDBOX_REDOID_WINDOWS_UNSUPPORTED,
        SANDBOX_REDOID_ADB_CONTRACT_FAILED,
        SANDBOX_ADB_AUTH_UNAVAILABLE,
        SANDBOX_RUNTIME_TRUST_FINDINGS,
        SANDBOX_RUNTIME_TRUST_ACCEPTANCE_REQUIRED,
        SANDBOX_RUNTIME_TRUST_DENIED,
        SANDBOX_WINDOWS_HOME_UNSUPPORTED,
        SANDBOX_WINDOWS_ARM_UNSUPPORTED,
        SANDBOX_MACOS_DYNAMIC_UNAVAILABLE,
        SANDBOX_RUNTIME_SELECTED,
        SANDBOX_HQARROUM_IMAGE_DIGEST_MISMATCH,
        SANDBOX_HQARROUM_TCG_FALLBACK,
        SANDBOX_HQARROUM_ROOT_UNAVAILABLE,
        SANDBOX_HQARROUM_SYSTEM_NOT_WRITABLE,
        SANDBOX_HQARROUM_ADB_FAILED,
    ];

    /// The sandbox could not establish transparent L3 redirection.
    pub const SANDBOX_L3_REDIRECTION_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.l3-redirection-unavailable",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The sandbox cannot provide transparent L3 traffic redirection.",
        why: "The selected iptables, nftables, or TUN mechanism is unavailable in the Android runtime.",
        fix: "Use a userdebug/writable runtime with the required packet tooling, or select a sandbox tier that supports transparent routing.",
    };

    /// Transparent L3 rules could not be installed.
    pub const SANDBOX_L3_REDIRECTION_SETUP_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.l3-redirection-setup-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "Transparent L3 traffic redirection could not be installed.",
        why: "The sandbox rejected one or more rules needed to send outbound TCP traffic to the session proxy.",
        fix: "Check runtime root/packet-filter privileges and the proxy endpoint, then retry or select remote-offload.",
    };

    /// Transparent L3 rules could not be removed.
    pub const SANDBOX_L3_REDIRECTION_TEARDOWN_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.l3-redirection-teardown-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "Transparent L3 traffic-redirection rules could not be removed.",
        why: "The sandbox control channel did not verify removal of the session's packet-filter rules.",
        fix: "Run the recorded session cleanup on the named runtime and verify no APIaxess NAT, filter, or TUN rule remains.",
    };

    /// The required UDP/443 QUIC drop could not be installed.
    pub const SANDBOX_QUIC_DROP_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.quic-drop-unavailable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The sandbox cannot enforce the UDP/443 QUIC drop.",
        why: "The selected packet-filter mechanism could not install the outbound UDP/443 drop required by the TCP proxy path.",
        fix: "Enable packet-filter privileges or use a runtime with nftables/iptables support; HTTP/3 cannot be silently treated as captured.",
    };

    /// A QUIC attempt could not be downgraded to the TCP proxy path.
    pub const SANDBOX_QUIC_DOWNGRADE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.quic-downgrade-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "An app's QUIC traffic could not be confirmed as downgraded.",
        why: "UDP/443 attempts were observed without evidence that the app retried over interceptable TCP.",
        fix: "Inspect the app's HTTP/3 behavior and packet-filter counters; pinning or protocol-specific behavior may require a later phase.",
    };

    /// The Android system trust store cannot be modified for this runtime.
    pub const SANDBOX_CA_SYSTEM_STORE_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.ca-system-store-unavailable",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The sandbox cannot provide system-level CA trust.",
        why: "The Android system partition or the runtime's overlay trust mechanism is unavailable or read-only.",
        fix: "Use a userdebug writable AVD, a redroid overlay/Magisk-capable image, or select a compatible remote runtime.",
    };

    /// ADB remount or system-partition preparation failed.
    pub const SANDBOX_CA_REMOUNT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.ca-remount-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The Android system trust partition could not be prepared for the session CA.",
        why: "ADB root/remount or the selected overlay mount operation failed before certificate installation.",
        fix: "Use a userdebug/writable-system runtime or a compatible redroid overlay path; inspect the remount evidence and retry.",
    };

    /// The session CA could not be injected into the system trust store.
    pub const SANDBOX_CA_INJECTION_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.ca-injection-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The session CA could not be installed into Android system trust.",
        why: "The hashed certificate file could not be copied, labeled, permissioned, or verified in the selected trust path.",
        fix: "Check the CA hash, runtime root permissions, and trust-store path, then retry with a clean disposable runtime.",
    };

    /// Installed system trust did not verify.
    pub const SANDBOX_CA_TRUST_VERIFICATION_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.ca-trust-verification-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "Android did not verify the session CA in system trust.",
        why: "The expected hashed certificate file or trust-store visibility check failed after injection.",
        fix: "Repair the selected system/overlay trust mechanism and retry; captured TLS is not reported as decryptable without verification.",
    };

    /// The session CA or overlay trust state could not be removed.
    pub const SANDBOX_CA_TEARDOWN_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.ca-teardown-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "The session CA trust modification could not be removed.",
        why: "The exact certificate file, overlay mount, or trust helper state was not removed or verified during teardown.",
        fix: "Run the recorded trust cleanup on the disposable runtime and verify no session CA or overlay mount remains.",
    };

    /// Remote traffic could not be streamed over the secured transport.
    pub const SANDBOX_REMOTE_TRAFFIC_STREAM_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.remote-traffic-stream-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "Remote sandbox traffic could not reach the local proxy path.",
        why: "The secured remote helper or encrypted stream failed before captured traffic was delivered locally.",
        fix: "Check the SSH helper, stream lease, remote packet capture, and local proxy listener; raw unauthenticated traffic transport is unsupported.",
    };

    /// The proxy endpoint was not reachable from the sandbox.
    pub const SANDBOX_PROXY_UNREACHABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.proxy-unreachable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The sandbox could not reach the session proxy endpoint.",
        why: "Transparent redirection was configured, but the Android runtime could not connect to the local or secured remote proxy listener.",
        fix: "Bind the proxy on the sandbox-reachable interface, verify the gateway/port, and retry the capture setup.",
    };

    /// The topology-specific guest-to-proxy bridge could not be established.
    pub const SANDBOX_CAPTURE_BRIDGE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.capture-bridge-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The sandbox-to-proxy capture bridge could not be established.",
        why: "The guest-reachable forwarder failed to start, remain alive, or connect across the sandbox-to-host network boundary.",
        fix: "Verify the tier's bridge image/helper, host-gateway route, and proxy listener; retry or select a tier with a supported capture bridge.",
    };

    /// The guest-reachable capture endpoint was not usable after setup.
    pub const SANDBOX_CAPTURE_ENDPOINT_UNREACHABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.capture-endpoint-unreachable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The Android guest could not reach the capture endpoint.",
        why: "Transparent routing was installed, but the endpoint at the guest's topology boundary did not accept the session connection.",
        fix: "Check the guest endpoint address/port and the container or remote forwarder before involving an application.",
    };

    /// The guest-fetch preflight did not produce a completed captured flow.
    pub const SANDBOX_GUEST_FETCH_PREFLIGHT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.guest-fetch-preflight-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The guest-fetch preflight could not prove outbound capture before app launch.",
        why: "The emulator was offline, the forced request could not reach the guest-visible bridge, or the proxy did not persist a completed flow at launch time.",
        fix: "Wait for guest connectivity, repair the sandbox-to-proxy route, and rerun the preflight; do not attribute zero app traffic to the target until this passes.",
    };

    /// No decryptable traffic was observed after capture setup.
    pub const SANDBOX_NO_DECRYPTABLE_TRAFFIC: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.no-decryptable-traffic",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "The sandbox produced no decryptable traffic after capture setup.",
        why: "The proxy, trust, QUIC downgrade, and runtime signals did not establish a decryptable flow; this is not asserted as app silence.",
        fix: "Inspect proxy reachability, CA trust, UDP/443 downgrade, and pinning diagnostics before concluding that the app made no requests.",
    };

    /// Every Phase 3.2 sandbox definition.
    pub const PHASE_3_2: &[DiagnosticDefinition] = &[
        SANDBOX_L3_REDIRECTION_UNAVAILABLE,
        SANDBOX_L3_REDIRECTION_SETUP_FAILED,
        SANDBOX_L3_REDIRECTION_TEARDOWN_FAILED,
        SANDBOX_QUIC_DROP_UNAVAILABLE,
        SANDBOX_QUIC_DOWNGRADE_FAILED,
        SANDBOX_CA_SYSTEM_STORE_UNAVAILABLE,
        SANDBOX_CA_REMOUNT_FAILED,
        SANDBOX_CA_INJECTION_FAILED,
        SANDBOX_CA_TRUST_VERIFICATION_FAILED,
        SANDBOX_CA_TEARDOWN_FAILED,
        SANDBOX_REMOTE_TRAFFIC_STREAM_FAILED,
        SANDBOX_PROXY_UNREACHABLE,
        SANDBOX_CAPTURE_BRIDGE_FAILED,
        SANDBOX_CAPTURE_ENDPOINT_UNREACHABLE,
        SANDBOX_GUEST_FETCH_PREFLIGHT_FAILED,
        SANDBOX_NO_DECRYPTABLE_TRAFFIC,
    ];

    /// No rooted adb device was detected for provisioning.
    pub const DEVICE_NOT_DETECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.not-detected",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Warning,
        what: "No adb device is available to provision.",
        why: "adb reported no attached device in the `device` state (a physical device or same-machine emulator).",
        fix: "Connect a rooted device over USB with USB debugging enabled (or start the emulator), then retry setup.",
    };

    /// An adb device is attached but not authorized for control.
    pub const DEVICE_UNAUTHORIZED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.unauthorized",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Warning,
        what: "The attached adb device has not authorized this workbench.",
        why: "adb reports the device as `unauthorized` or `offline`, so no control command can run on it.",
        fix: "On the device, accept the 'Allow USB debugging' prompt for this host's key (revoke and reconnect if you missed it), then retry.",
    };

    /// A rooted adb device was detected and is ready to provision.
    pub const DEVICE_DETECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.detected",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Info,
        what: "A device was detected and is ready to provision.",
        why: "adb reports an attached device in the `device` state that the workbench can drive over the secured control channel.",
        fix: "Continue setup to establish the reverse tunnel and install the session CA; no action is required.",
    };

    /// The adb-reverse tunnel from device loopback to the workbench could not be set.
    pub const DEVICE_REVERSE_TUNNEL_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.reverse-tunnel-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The adb-reverse tunnel to the workbench proxy could not be established.",
        why: "`adb reverse` did not map the device loopback port onto the workbench loopback proxy/control port.",
        fix: "Confirm the device is still connected and the workbench proxy port is bound, then retry; no other transport is used.",
    };

    /// The device's traffic is routed through the workbench MITM.
    pub const DEVICE_CAPTURE_ROUTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.capture-routed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Info,
        what: "The device's app traffic now routes through the workbench capture proxy.",
        why: "The device-wide HTTP proxy points at the adb-reverse tunnel to the workbench MITM, so apps that honor the system proxy are captured and, with the session CA trusted, decrypted.",
        fix: "Drive the app; its requests appear in Live traffic. The proxy is cleared when the target stops.",
    };

    /// The device's traffic could not be routed through the workbench MITM.
    pub const DEVICE_CAPTURE_NOT_ROUTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.capture-not-routed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Warning,
        what: "The device's app traffic is not routed through the workbench capture proxy.",
        why: "Setting or verifying the device-wide HTTP proxy failed, so apps on the device reach the network directly and nothing is captured.",
        fix: "Stop and relaunch the target. If it persists, check the target's adb connection; the context names the failing step.",
    };

    /// The adb-reverse tunnel is set and the device loopback reaches the workbench.
    pub const DEVICE_TUNNEL_READY: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.tunnel-ready",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Info,
        what: "The device now tunnels to the workbench over adb.",
        why: "`adb reverse` mapped the device loopback port onto the workbench loopback proxy/control port, so no LAN exposure is required.",
        fix: "Continue setup; no action is required.",
    };

    /// The device's Android version could not be determined or is unsupported.
    pub const DEVICE_ANDROID_VERSION_UNSUPPORTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.android-version-unsupported",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The device's Android version could not be used for auto CA install.",
        why: "`getprop ro.build.version.sdk` returned no parseable API level, or the level is below the minimum the CA-install paths support.",
        fix: "Use a device running a supported Android version (API 24+) with a readable build fingerprint, then retry.",
    };

    /// The version-appropriate system-CA install path was selected.
    pub const DEVICE_TRUST_PATH_SELECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.trust-path-selected",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Info,
        what: "The correct system-trust install path was chosen for this Android version.",
        why: "The device's API level was detected, so the workbench routes to the legacy cacerts path (<=13) or the Conscrypt APEX path (14+).",
        fix: "Continue setup; no action is required.",
    };

    /// The device refused `adb root`, so system trust cannot be modified.
    pub const DEVICE_ROOT_REFUSED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.root-refused",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The device did not grant root to the adb daemon.",
        why: "`adb root` was refused or the shell did not become uid=0, so the read-only system/APEX trust store cannot be remounted.",
        fix: "Use a userdebug/eng build or a root manager that permits `adb root` (or restarts adbd as root), then retry.",
    };

    /// The Android 14+ Conscrypt APEX trust bind-mount branch failed.
    pub const DEVICE_APEX_TRUST_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.apex-trust-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The session CA could not be installed into the Conscrypt APEX trust store.",
        why: "Staging the APEX cacerts, mounting the tmpfs over `/apex/com.android.conscrypt/cacerts`, or binding it into the zygote mount namespaces failed on this Android 14+ device.",
        fix: "Confirm the device is rooted with a writable init mount namespace and that `mount`/`nsenter` are available, then retry.",
    };

    /// The session CA was installed and verified in the device system trust store.
    pub const DEVICE_CA_INSTALLED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.ca-installed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Info,
        what: "The session CA is installed and verified in the device system trust store.",
        why: "The version-appropriate install path placed and verified the hashed CA where Android's system trust anchors are read.",
        fix: "The device now trusts the session CA for interception; no action is required.",
    };

    /// The optional device frida-server was started for later pinned-app bypass.
    pub const DEVICE_FRIDA_SERVER_STARTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.frida-server-started",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Info,
        what: "frida-server is running on the device.",
        why: "Provisioning deployed and started the bundled frida-server so a later phase can bypass certificate pinning.",
        fix: "No action is required; per-app Frida targeting is applied when a pinned app is analyzed.",
    };

    /// The optional device frida-server could not be started (non-fatal at C2).
    pub const DEVICE_FRIDA_SERVER_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.frida-server-unavailable",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Warning,
        what: "The optional device frida-server could not be started.",
        why: "Deploying or launching the bundled frida-server failed, but CA-based interception was already provisioned.",
        fix: "Retry provisioning if you need pinned-app bypass; unpinned HTTPS is already interceptable through the installed CA.",
    };

    /// The device chosen for a pinned-app Frida bypass is not connected.
    pub const DEVICE_FRIDA_TARGET_NOT_FOUND: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.frida-target-not-found",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The device selected for the pinning bypass is not connected.",
        why: "The requested adb serial is not among the attached, authorized devices, so the workbench cannot forward to its frida-server.",
        fix: "Reconnect the device (and re-run provisioning), then choose it again; when several devices are attached, the serial selects which one.",
    };

    /// Pinning was detected but is beyond the automated bypass (honest boundary).
    pub const DEVICE_PINNING_UNBEATABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.pinning-unbeatable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "This app's certificate pinning is beyond the automated bypass.",
        why: "The pinning is enforced in native code (Flutter/BoringSSL) that ignores the system store, or the app actively resists instrumentation, so the OkHttp/Java bypass lanes cannot unpin it.",
        fix: "Capture is limited to this app's unpinned endpoints; native/anti-instrumentation cases need target-specific reverse-engineering and may not be beatable — this is disclosed, not a defect.",
    };

    /// Every phase C4 (per-device Frida targeting) definition, for conformance tests.
    pub const PHASE_C4: &[DiagnosticDefinition] =
        &[DEVICE_FRIDA_TARGET_NOT_FOUND, DEVICE_PINNING_UNBEATABLE];

    /// The operator declined the device's request to connect (the human gate).
    pub const DEVICE_PAIRING_DECLINED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.pairing-declined",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Warning,
        what: "The workbench operator declined this device's connection.",
        why: "A person at the workbench chose Decline on the accept/decline prompt, so no session token was issued and the device was not provisioned.",
        fix: "Ask the operator to accept the connection, or re-scan a fresh pairing QR and try again.",
    };

    /// The pending pairing request is unknown or expired before a decision.
    pub const DEVICE_PAIRING_REQUEST_EXPIRED: DiagnosticDefinition = DiagnosticDefinition {
        id: "device.pairing-request-expired",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Warning,
        what: "The pairing request expired before it was accepted.",
        why: "The operator did not accept or decline within the pairing window, or the workbench was restarted, so the pending request is no longer valid.",
        fix: "Scan a fresh pairing QR (or re-enter the token) to start a new request; each request and its token are short-lived.",
    };

    /// Every phase C5 (accept/decline + QR pairing) definition, for conformance tests.
    pub const PHASE_C5: &[DiagnosticDefinition] =
        &[DEVICE_PAIRING_DECLINED, DEVICE_PAIRING_REQUEST_EXPIRED];

    /// Every phase C2 (device provisioning) definition, used by conformance tests.
    pub const PHASE_C2: &[DiagnosticDefinition] = &[
        DEVICE_NOT_DETECTED,
        DEVICE_UNAUTHORIZED,
        DEVICE_DETECTED,
        DEVICE_REVERSE_TUNNEL_FAILED,
        DEVICE_TUNNEL_READY,
        DEVICE_CAPTURE_ROUTED,
        DEVICE_CAPTURE_NOT_ROUTED,
        DEVICE_ANDROID_VERSION_UNSUPPORTED,
        DEVICE_TRUST_PATH_SELECTED,
        DEVICE_ROOT_REFUSED,
        DEVICE_APEX_TRUST_FAILED,
        DEVICE_CA_INSTALLED,
        DEVICE_FRIDA_SERVER_STARTED,
        DEVICE_FRIDA_SERVER_UNAVAILABLE,
    ];

    /// The GUI Android target add-on (slim AOSP emulator payload) is not installed.
    ///
    /// The GUI target is a separate, optional download, not part of the base
    /// install. This reports that a GUI Android target was requested but the
    /// add-on payload is absent — an actionable prompt, not a crash.
    pub const ANDROID_TARGET_MISSING: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-target-missing",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The GUI Android target add-on is not installed.",
        why: "A GUI-drivable Android target runs a slim no-GApps AOSP emulator shipped as a separate, optional download that is not part of the base application.",
        fix: "Download the Android target in Settings → Add-ons (or from the Android target panel), or point APIAXESS_ANDROID_TARGET at an installed copy; static, web, and autonomous-dynamic workflows do not require it.",
    };

    /// The installed GUI Android target add-on predates what this engine needs.
    ///
    /// The add-on is versioned separately from the application and the installer
    /// never updates it, so an older payload can sit under a newer `APIaxess`. Its
    /// `payloadVersion` is compared with the version the engine requires; the
    /// context carries both.
    pub const ANDROID_TARGET_OUTDATED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-target-outdated",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The installed GUI Android target add-on is out of date.",
        why: "It is older than this version of APIaxess supports: its screen stream is not built for the path the engine serves the device view under, so the device screen would stay blank. The APIaxess installer does not update the separately installed add-on.",
        fix: "Download the current Android target in Settings → Add-ons (or re-run install-android-target.ps1 / .sh), then launch the Android target again.",
    };

    /// The GUI Android target add-on manifest is missing or malformed.
    pub const ANDROID_TARGET_MANIFEST_INVALID: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-target-manifest-invalid",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The GUI Android target add-on manifest could not be read.",
        why: "android-target-manifest.json is missing, unreadable, or does not match the schema the engine resolver expects.",
        fix: "Re-run the add-on installer to regenerate the manifest; if it persists, the payload is corrupt and should be reinstalled.",
    };

    /// The GUI Android target's first-party client APK was not staged in the payload.
    pub const ANDROID_TARGET_CLIENT_APK_MISSING: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-target-client-apk-missing",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "The GUI Android target add-on does not include the APIaxess client APK.",
        why: "The add-on was assembled without the first-party client APK, so first-boot provisioning cannot install the client the target uses to relay traffic.",
        fix: "Build apps/android and re-run the add-on installer (or pass -ClientApk) so the client APK is staged; the target still boots but cannot pair until it is present.",
    };

    /// The GUI Android target booted headless and is provisioning on first boot.
    pub const ANDROID_TARGET_BOOTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-target-booted",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Info,
        what: "The GUI Android target booted headless and is ready for provisioning.",
        why: "The add-on AVD reached sys.boot_completed and registered with the bundled adb, so first-boot C2/C5 provisioning can proceed.",
        fix: "No action needed; provisioning (client APK, live session CA, frida-server, pairing) follows automatically.",
    };

    /// First-boot provisioning of the GUI Android target completed.
    pub const ANDROID_TARGET_READY: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-target-ready",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Info,
        what: "The GUI Android target is provisioned and ready to drive.",
        why: "First-boot C2/C5 provisioning installed the client APK, the live session CA, and the device-side frida-server, and armed pairing over the adb tunnel.",
        fix: "No action needed; install your target APK and drive it — traffic flows to the workbench.",
    };

    /// The GUI Android target's client APK could not be installed on first boot.
    pub const ANDROID_TARGET_CLIENT_INSTALL_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-target-client-install-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "First-boot provisioning could not install the GUI Android target's client APK.",
        why: "adb install of the staged client APK failed on the booted target (an incompatible ABI, a full data partition, or an adb transport error).",
        fix: "Confirm the target booted (sandbox.android-target-booted) with a x86_64 image and free space, then relaunch; the underlying adb error is attached.",
    };

    /// Every Phase D1 (GUI Android target add-on) definition.
    pub const PHASE_D1: &[DiagnosticDefinition] = &[
        ANDROID_TARGET_MISSING,
        ANDROID_TARGET_OUTDATED,
        ANDROID_TARGET_MANIFEST_INVALID,
        ANDROID_TARGET_CLIENT_APK_MISSING,
        ANDROID_TARGET_BOOTED,
        ANDROID_TARGET_READY,
        ANDROID_TARGET_CLIENT_INSTALL_FAILED,
    ];

    /// The GUI Android target's screen-streaming components are not in the add-on.
    ///
    /// ws-scrcpy + its bundled Node runtime are shipped inside the GUI Android
    /// target add-on. This reports that streaming was requested but those pieces
    /// were not staged — the target still boots and provisions, but its screen
    /// cannot be streamed until the add-on is (re)installed.
    pub const ANDROID_STREAM_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-stream-unavailable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "The GUI Android target add-on does not include the screen-streaming components.",
        why: "ws-scrcpy and its bundled Node runtime were not staged in the add-on, so the target's screen cannot be streamed.",
        fix: "Reinstall the GUI Android target add-on so ws-scrcpy and the Node runtime are staged; the target still boots and captures traffic without streaming.",
    };

    /// ws-scrcpy started, but does not serve the device view where the engine
    /// reverse-proxies it, so the Android screen would be blank.
    pub const ANDROID_STREAM_NOT_SERVED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-stream-not-served",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The Android target's screen stream is not being served.",
        why: "ws-scrcpy started but did not answer with the device view at its base path (the context has what it answered), so the screen would be blank. This happens when the add-on's ws-scrcpy build predates base-path support, or when it failed to start.",
        fix: "Update the GUI Android target add-on (Settings → Add-ons → Download, or re-run install-android-target.ps1 / .sh), then relaunch the target. It still boots and captures traffic without the screen.",
    };

    /// The GUI Android target's screen stream (ws-scrcpy) started on loopback.
    pub const ANDROID_STREAM_STARTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-stream-started",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Info,
        what: "The GUI Android target screen stream is running on loopback.",
        why: "ws-scrcpy started bound to 127.0.0.1 and relays the target's screen over adb; it is reachable only through the authenticated engine reverse-proxy, never directly.",
        fix: "No action needed; open the Android view through the workbench.",
    };

    /// A stream request was made but no GUI Android target stream is running.
    pub const ANDROID_STREAM_NOT_ACTIVE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-stream-not-active",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "No GUI Android target stream is currently running.",
        why: "The Android view was requested through the engine reverse-proxy, but no GUI Android target has been launched with streaming this session.",
        fix: "Launch the GUI Android target first; the stream starts with it.",
    };

    /// The engine reverse-proxy rejected an unauthenticated Android-view request.
    ///
    /// ws-scrcpy has no built-in auth, so the engine is the only reachable listener
    /// and applies the workbench gate (loopback `Origin` + a valid session/device
    /// token) to every Android-view request, including the WebSocket upgrade that
    /// carries the control channel.
    pub const ANDROID_STREAM_AUTH_REJECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-stream-auth-rejected",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "An Android-view request was rejected by the engine reverse-proxy gate.",
        why: "The request did not present the loopback Origin and a valid workbench session or device pairing token, which the engine requires on every Android-view request and WebSocket upgrade.",
        fix: "Open the Android view from the authenticated workbench UI; a random network client cannot reach the stream.",
    };

    /// The engine reverse-proxy could not reach the loopback ws-scrcpy upstream.
    pub const ANDROID_STREAM_UPSTREAM_UNREACHABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-stream-upstream-unreachable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The engine could not reach the loopback ws-scrcpy stream.",
        why: "The authenticated request passed the gate, but the bundled ws-scrcpy process on 127.0.0.1 did not accept the forwarded HTTP/WebSocket connection.",
        fix: "Confirm the GUI Android target stream is still running (it may have exited); relaunch the target to restart it.",
    };

    /// Every Phase D2 (ws-scrcpy streaming + authenticated reverse-proxy) definition.
    pub const PHASE_D2: &[DiagnosticDefinition] = &[
        ANDROID_STREAM_UNAVAILABLE,
        ANDROID_STREAM_NOT_SERVED,
        ANDROID_STREAM_STARTED,
        ANDROID_STREAM_NOT_ACTIVE,
        ANDROID_STREAM_AUTH_REJECTED,
        ANDROID_STREAM_UPSTREAM_UNREACHABLE,
    ];

    /// An action needing a running GUI Android target was requested with none up.
    pub const ANDROID_TARGET_NOT_RUNNING: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-target-not-running",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "No GUI Android target is running.",
        why: "The requested action (such as installing your target APK) needs a launched Android target, but none is up this session.",
        fix: "Launch the Android target from the workbench panel first, then retry.",
    };

    /// Installing the user's target APK onto the running GUI Android target failed.
    pub const ANDROID_TARGET_APK_INSTALL_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-target-apk-install-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "Your target APK could not be installed on the Android target.",
        why: "adb rejected the install (an incompatible ABI or minSdk, a malformed APK, or a full data partition).",
        fix: "Confirm the APK is a valid x86_64-compatible build and the target has free space, then retry; the underlying adb error is attached.",
    };

    /// The installed app could not be opened on the Android target.
    pub const ANDROID_TARGET_APP_OPEN_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.android-target-app-open-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The installed app could not be opened on the Android target.",
        why: "No app is recorded as installed this session, the app has no launcher activity, or the device refused to start it.",
        fix: "Install the APK from this panel first; if it is installed, open it from the device's app drawer on the screen. The reason is attached.",
    };

    /// Every Phase D3 (workbench Android target panel) definition.
    pub const PHASE_D3: &[DiagnosticDefinition] = &[
        ANDROID_TARGET_NOT_RUNNING,
        ANDROID_TARGET_APK_INSTALL_FAILED,
        ANDROID_TARGET_APP_OPEN_FAILED,
    ];

    /// The Frida server could not be deployed to the session runtime.
    pub const SANDBOX_BYPASS_FRIDA_SERVER_DEPLOY_FAILED: DiagnosticDefinition =
        DiagnosticDefinition {
            id: "sandbox.bypass.frida-server-deploy-failed",
            category: DiagnosticCategory::Sandbox,
            severity: DiagnosticSeverity::Error,
            what: "The automated pinning bypass could not deploy its Frida server.",
            why: "The session runtime rejected the session-scoped server artifact, permission change, or startup command.",
            fix: "Use a rooted userdebug runtime with a compatible Frida server, then retry; anti-instrumentation boundaries are diagnosed separately.",
        };

    /// The Frida spawn gate could not start the target before network setup.
    pub const SANDBOX_BYPASS_SPAWN_GATE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.spawn-gate-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The automated pinning bypass could not establish an early spawn gate.",
        why: "The target process did not start under Frida before application initialization and network code ran.",
        fix: "Retry on a compatible rooted runtime; if the process is killed during early instrumentation, review the anti-Frida escalation diagnostic.",
    };

    /// The generated or target-specific unpinner script failed to load.
    pub const SANDBOX_BYPASS_UNPINNER_SCRIPT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.unpinner-script-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The pinning-bypass script could not be loaded or applied.",
        why: "The universal declarative hooks or target-specific hook specifications were not accepted by the running process.",
        fix: "Inspect the named technique and target evidence, add a compatible declarative spec, or use the automated patch lane.",
    };

    /// APK decompilation failed in the no-root fallback lane.
    pub const SANDBOX_BYPASS_DECOMPILE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.decompile-failed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The no-root pinning-bypass lane could not decode an APK.",
        why: "The APK toolchain did not produce a complete session workspace for the selected package or split.",
        fix: "Install a compatible apktool and retry with the original APK; a malformed or protected archive may require manual analysis.",
    };

    /// The no-root APK rewrite or gadget injection failed.
    pub const SANDBOX_BYPASS_PATCH_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.patch-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The no-root pinning-bypass rewrite could not be applied.",
        why: "The manifest, network-security-config, smali initializer, or native gadget injection point was not safely writable.",
        fix: "Use a compatible APK layout or rooted Frida lane; inspect the target-specific evidence before retrying.",
    };

    /// APK rebuilding failed after the no-root rewrite.
    pub const SANDBOX_BYPASS_REBUILD_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.rebuild-failed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The patched APK could not be rebuilt.",
        why: "The APK build tool rejected the session workspace after network trust and gadget changes were applied.",
        fix: "Use a compatible build tool and inspect the named resource or smali evidence; the original artifact remains unchanged.",
    };

    /// Zip alignment failed before signing.
    pub const SANDBOX_BYPASS_ZIPALIGN_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.zipalign-failed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The patched APK could not be zip-aligned.",
        why: "The Android build toolchain did not produce an aligned installable artifact.",
        fix: "Install a compatible zipalign binary and retry; do not install an unaligned intermediate artifact.",
    };

    /// The base APK could not be re-signed.
    pub const SANDBOX_BYPASS_RESIGN_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.resign-failed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The patched base APK could not be re-signed.",
        why: "The configured signing tool rejected the session artifact or signing configuration.",
        fix: "Configure the approved debug signing key and apksigner-compatible build tools, then retry inside a disposable session.",
    };

    /// One or more split APKs could not be signed consistently.
    pub const SANDBOX_BYPASS_SPLIT_SIGNING_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.split-signing-failed",
        category: DiagnosticCategory::ExternalTool,
        severity: DiagnosticSeverity::Error,
        what: "The split APK set could not be signed consistently.",
        why: "At least one configuration or feature split did not receive the same session signing identity and signature scheme.",
        fix: "Use apksigner with the same key for every split and retry; the original split set was not modified.",
    };

    /// The patched application could not be installed in the session runtime.
    pub const SANDBOX_BYPASS_INSTALL_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.install-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The patched application could not be installed.",
        why: "The runtime rejected the session-signed base/split APK set after the patch pipeline completed.",
        fix: "Inspect the install evidence and split compatibility, then retry with a clean disposable runtime.",
    };

    /// A framework-specific native or Mono offset was not covered.
    pub const SANDBOX_BYPASS_FRAMEWORK_OFFSET_MISS: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.framework-offset-miss",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The detected framework requires a specialized pinning hook that is not covered.",
        why: "The Flutter native build or Xamarin/.NET runtime identity did not match a declarative offset/callback specification.",
        fix: "Add a reviewed framework technique spec for this build or use manual reverse-engineering; Java-level trust hooks are not sufficient here.",
    };

    /// A known automation boundary was detected.
    pub const SANDBOX_BYPASS_ESCALATION_BOUNDARY: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.escalation-boundary",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "The target is hardened beyond the automated pinning-bypass boundary.",
        why: "A known hardware-attestation, stripped native, client-mTLS, or anti-Frida RASP signal was detected before bypass execution.",
        fix: "Automated bypass is exhausted for this boundary; manual reverse-engineering and target-specific authorization are required.",
    };

    /// Cleanup of session-scoped bypass state failed.
    pub const SANDBOX_BYPASS_TEARDOWN_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.teardown-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "Session-scoped pinning-bypass state could not be removed completely.",
        why: "A Frida process, device server/artifact, installed patched package, or host workspace remained after teardown.",
        fix: "Run the recorded lease cleanup on the disposable runtime and verify that no bypass process, package, or artifact remains.",
    };

    /// The bypass completed, but no decryptable traffic was observed.
    pub const SANDBOX_BYPASS_NO_DECRYPTABLE_TRAFFIC: DiagnosticDefinition = DiagnosticDefinition {
        id: "sandbox.bypass.no-decryptable-traffic",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "Pinning bypass completed without producing decryptable traffic.",
        why: "The selected bypass lane reported success, but no usable flow reached the Phase-2 proxy; this is distinct from routing/CA failure and app silence.",
        fix: "Review the lane result and app request evidence, then inspect 3.2 routing/CA diagnostics before concluding that the app made no requests.",
    };

    /// Every Phase 3.3 sandbox definition.
    pub const PHASE_3_3: &[DiagnosticDefinition] = &[
        SANDBOX_BYPASS_FRIDA_SERVER_DEPLOY_FAILED,
        SANDBOX_BYPASS_SPAWN_GATE_FAILED,
        SANDBOX_BYPASS_UNPINNER_SCRIPT_FAILED,
        SANDBOX_BYPASS_DECOMPILE_FAILED,
        SANDBOX_BYPASS_PATCH_FAILED,
        SANDBOX_BYPASS_REBUILD_FAILED,
        SANDBOX_BYPASS_ZIPALIGN_FAILED,
        SANDBOX_BYPASS_RESIGN_FAILED,
        SANDBOX_BYPASS_SPLIT_SIGNING_FAILED,
        SANDBOX_BYPASS_INSTALL_FAILED,
        SANDBOX_BYPASS_FRAMEWORK_OFFSET_MISS,
        SANDBOX_BYPASS_ESCALATION_BOUNDARY,
        SANDBOX_BYPASS_TEARDOWN_FAILED,
        SANDBOX_BYPASS_NO_DECRYPTABLE_TRAFFIC,
    ];

    /// The session Frida server could not be deployed.
    pub const INSTRUMENTATION_FRIDA_SERVER_DEPLOY_FAILED: DiagnosticDefinition =
        DiagnosticDefinition {
            id: "instrumentation.frida-server-deploy-failed",
            category: DiagnosticCategory::Sandbox,
            severity: DiagnosticSeverity::Error,
            what: "The hardened instrumentation substrate could not deploy Frida server.",
            why: "The session runtime rejected the session-scoped server artifact, permission change, or launch command.",
            fix: "Use a compatible rooted runtime and baseline Frida server, then retry; detection boundaries are diagnosed separately.",
        };

    /// Frida server IPC health failed.
    pub const INSTRUMENTATION_FRIDA_SERVER_HEALTH_FAILED: DiagnosticDefinition =
        DiagnosticDefinition {
            id: "instrumentation.frida-server-health-failed",
            category: DiagnosticCategory::Sandbox,
            severity: DiagnosticSeverity::Error,
            what: "The Frida server did not pass its IPC health check.",
            why: "The server process or host-side Frida transport was not reachable for controlled instrumentation.",
            fix: "Check the runtime architecture, Frida version pairing, transport, and server process before retrying.",
        };

    /// The target could not be started under an early spawn gate.
    pub const INSTRUMENTATION_SPAWN_GATE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "instrumentation.spawn-gate-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The target did not become instrumented under the early spawn gate.",
        why: "The process was not running with the substrate attached before Application.onCreate and native initialization.",
        fix: "Retry in spawn mode on a compatible rooted runtime; inspect crash-correlation and detection-boundary diagnostics.",
    };

    /// An attach-mode instrumentation request failed.
    pub const INSTRUMENTATION_ATTACH_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "instrumentation.attach-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The instrumentation substrate could not attach to the running target.",
        why: "The requested PID/package was absent or Frida rejected the attach operation.",
        fix: "Verify the target process identity and use spawn mode when hooks must land before app initialization.",
    };

    /// The substrate script could not be loaded.
    pub const INSTRUMENTATION_SCRIPT_LOAD_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "instrumentation.script-load-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The instrumentation script could not be loaded into the target.",
        why: "The session script was unavailable, rejected by Frida, or failed before its readiness marker.",
        fix: "Check the generated script and Frida/runtime compatibility; crypto and signing hooks are not considered active without readiness evidence.",
    };

    /// Java class-loader resolution failed.
    pub const INSTRUMENTATION_CLASS_LOADER_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "instrumentation.class-loader-resolution-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The instrumented process did not expose a usable Java class loader.",
        why: "The substrate could not resolve Java classes after the target was launched.",
        fix: "Use spawn mode and a compatible runtime, then inspect the target's class-loader or RASP behavior.",
    };

    /// DEX enumeration failed.
    pub const INSTRUMENTATION_DEX_RESOLUTION_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "instrumentation.dex-resolution-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The instrumented process did not expose its loaded DEX state.",
        why: "The substrate could not enumerate loaded classes/DEX evidence through the target class loader.",
        fix: "Check split loading, dynamic loaders, and early-process stability before allowing downstream hooks to proceed.",
    };

    /// The watchdog observed a degraded or dead instrumentation session.
    pub const INSTRUMENTATION_WATCHDOG_DEGRADED: DiagnosticDefinition = DiagnosticDefinition {
        id: "instrumentation.watchdog-degraded",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The instrumentation watchdog detected a degraded substrate.",
        why: "Frida IPC, the target process, class-loader/DEX resolution, or script readiness stopped passing health checks.",
        fix: "Stop downstream instrumentation, inspect the correlated evidence, and restart the session substrate from a clean runtime.",
    };

    /// A target crash was correlated with instrumentation.
    pub const INSTRUMENTATION_CRASH_CORRELATED: DiagnosticDefinition = DiagnosticDefinition {
        id: "instrumentation.crash-correlated",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The target crashed while instrumentation was active.",
        why: "Recent runtime logs contain a target crash or fatal signal correlated with substrate startup or health loss.",
        fix: "Inspect the crash evidence; standard instrumentation is not reliable for this target and may require manual mitigation.",
    };

    /// Instrumentation cleanup did not complete.
    pub const INSTRUMENTATION_TEARDOWN_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "instrumentation.teardown-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "The Frida instrumentation substrate could not be removed completely.",
        why: "A host Frida process, device server, or session workspace remained after lease teardown.",
        fix: "Run the recorded lease cleanup on the disposable runtime and verify no Frida process, artifact, or listener remains.",
    };

    /// The selected versioned stealth bundle is invalid.
    pub const STEALTH_BUNDLE_INVALID: DiagnosticDefinition = DiagnosticDefinition {
        id: "stealth.bundle-invalid",
        category: DiagnosticCategory::HostCapability,
        severity: DiagnosticSeverity::Error,
        what: "The selected stealth infrastructure bundle is invalid.",
        why: "The bundle lacks a stable version/provenance or contains an unsupported component declaration.",
        fix: "Install or select a versioned stealth bundle with complete provenance and session-scoped artifacts.",
    };

    /// A stealth artifact could not be deployed.
    pub const STEALTH_DEPLOY_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "stealth.deploy-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The selected stealth infrastructure could not be deployed.",
        why: "A session-scoped root-hiding, integrity-fix, Frida-concealment, or emulator-mitigation artifact was rejected by the runtime.",
        fix: "Check the bundle version, runtime compatibility, and required root capabilities; retry from a clean disposable runtime.",
    };

    /// Root-hiding infrastructure failed.
    pub const STEALTH_ROOT_HIDING_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "stealth.root-hiding-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "Root-hiding stealth infrastructure could not be activated.",
        why: "The selected root-hiding component did not start or report its session readiness marker.",
        fix: "Use a compatible versioned root-hiding component or diagnose the target as beyond standard evasion.",
    };

    /// Integrity-fix infrastructure failed.
    pub const STEALTH_INTEGRITY_FIX_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "stealth.integrity-fix-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "Integrity/attestation-fix stealth infrastructure could not be activated.",
        why: "The selected integrity component did not start or could not satisfy the runtime's session contract.",
        fix: "Use a compatible versioned integrity-fix component; hardware-backed attestation remains an explicit manual boundary.",
    };

    /// Frida concealment infrastructure failed.
    pub const STEALTH_FRIDA_CONCEALMENT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "stealth.frida-concealment-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "Frida artifact and port concealment could not be activated.",
        why: "The session could not apply the configured renamed artifact, concealed path, or transport settings.",
        fix: "Use a compatible stealth bundle and ensure its session-scoped paths are writable before instrumentation starts.",
    };

    /// Emulator fingerprint mitigation failed.
    pub const STEALTH_EMULATOR_FINGERPRINT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "stealth.emulator-fingerprint-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "Emulator-fingerprint mitigation could not be fully activated.",
        why: "The selected session runtime rejected one or more disposable fingerprint adjustments.",
        fix: "Review the target's emulator-detection evidence; use a compatible mitigation bundle or accept the diagnostic.",
    };

    /// Standard stealth coverage was exceeded by a target boundary.
    pub const STEALTH_DETECTION_BOUNDARY: DiagnosticDefinition = DiagnosticDefinition {
        id: "stealth.detection-boundary",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "The target employs detection beyond standard stealth coverage.",
        why: "Hardened RASP, hardware attestation, or custom anti-Frida behavior was detected beyond the versioned ~97% substrate target.",
        fix: "Manual mitigation and reverse-engineering are required; standard stealth does not claim coverage for this target.",
    };

    /// Stealth cleanup did not complete.
    pub const STEALTH_TEARDOWN_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "stealth.teardown-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Critical,
        what: "Session-scoped stealth state could not be removed completely.",
        why: "A stealth artifact, helper process, modified runtime state, or host workspace remained after teardown.",
        fix: "Run the recorded lease cleanup on the disposable runtime and verify no stealth module or modified state remains.",
    };

    /// Phase 4.1 hook installation failed.
    pub const CRYPTO_HOOK_INSTALL_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.hook-install-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "A Phase 4.1 crypto hook could not be installed.",
        why: "The target runtime rejected a Java, Conscrypt, native, encoder, or request-correlation hook.",
        fix: "Review the hook context, use the early-spawn substrate, and retry on a compatible rooted runtime.",
    };

    /// A native crypto symbol or JNI boundary was unavailable.
    pub const CRYPTO_NATIVE_SYMBOL_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.native-symbol-unavailable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "A native crypto symbol or Conscrypt JNI boundary was unavailable.",
        why: "BoringSSL and vendor exports vary by Android release, or the target library is stripped or late-loaded.",
        fix: "Retain Java-layer evidence, scan late-loaded modules, and use JNI/import/call-stack evidence for stripped symbols.",
    };

    /// The target showed an anti-hooking condition during crypto capture.
    pub const CRYPTO_ANTI_HOOKING_DETECTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.anti-hooking-detected",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "The target showed evidence of anti-hooking during crypto capture.",
        why: "The target rejected or concealed an instrumentation boundary, so crypto evidence may be incomplete.",
        fix: "Review the evidence, use the Phase 3 stealth boundary, and do not treat missing operations as proof of absence.",
    };

    /// The Phase 4.1 runtime payload reported a capture failure.
    pub const CRYPTO_CAPTURE_RUNTIME_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.capture-runtime-failed",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Error,
        what: "The Phase 4.1 crypto capture runtime reported a failure.",
        why: "A hook callback, payload transport, or runtime inspection operation did not complete.",
        fix: "Inspect the structured operation context and retry with the Phase 3 substrate health gate green.",
    };

    /// A key is valid but intentionally non-exportable.
    pub const CRYPTO_KEY_NON_EXPORTABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.key-non-exportable",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Info,
        what: "A crypto key is non-exportable.",
        why: "Android Keystore or a hardware-backed provider returned no encoded key bytes by design.",
        fix: "Retain the operation and use device-oracle mode in later signing phases; do not classify this as a missing key.",
    };

    /// Every Phase 4.1 definition.
    pub const PHASE_4_1: &[DiagnosticDefinition] = &[
        CRYPTO_HOOK_INSTALL_FAILED,
        CRYPTO_NATIVE_SYMBOL_UNAVAILABLE,
        CRYPTO_ANTI_HOOKING_DETECTED,
        CRYPTO_CAPTURE_RUNTIME_FAILED,
        CRYPTO_KEY_NON_EXPORTABLE,
    ];

    /// A known signing scheme was recognized from static/runtime evidence.
    pub const CRYPTO_SCHEME_RECOGNIZED: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.scheme-recognized",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Info,
        what: "A known request-signing scheme was recognized.",
        why: "The registered scheme template matched enough static and runtime indicators to provide a reproduction shortcut.",
        fix: "Use the retained scheme template as the Phase 4.3 starting hypothesis and preserve its matched provenance.",
    };

    /// Multiple scheme templates matched with similar confidence.
    pub const CRYPTO_SCHEME_AMBIGUOUS: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.scheme-ambiguous",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "Multiple request-signing scheme templates remain plausible.",
        why: "The top registered templates cleared the recognition threshold but their confidence difference is too small for an honest selection.",
        fix: "Retain all candidates, gather more request/runtime evidence, and let Phase 4.3 proceed only after reviewing the ambiguity.",
    };

    /// No known scheme matched strongly enough.
    pub const CRYPTO_SCHEME_UNRECOGNIZED: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.scheme-unrecognized",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Info,
        what: "No registered request-signing scheme was recognized.",
        why: "The available static and runtime indicators did not clear a known-template threshold; the scheme may be bespoke or evidence may be partial.",
        fix: "Preserve the partial candidates and hand the request to Phase 4.3 generic canonicalization inference; do not force a known scheme.",
    };

    /// Every Phase 4.2 definition.
    pub const PHASE_4_2: &[DiagnosticDefinition] = &[
        CRYPTO_SCHEME_RECOGNIZED,
        CRYPTO_SCHEME_AMBIGUOUS,
        CRYPTO_SCHEME_UNRECOGNIZED,
    ];

    /// Canonicalization reproduced successfully on held-out captures.
    pub const CRYPTO_CANONICALIZATION_RECOVERED: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.canonicalization-recovered",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Info,
        what: "Request canonicalization was reproduced from a ranked hypothesis.",
        why: "The leading candidate matched the captured preimage and reproduced every supplied held-out signature.",
        fix: "Preserve the fixtures and confidence when packaging the signer; remember that unobserved branches remain unproven.",
    };

    /// Canonicalization has a plausible candidate but needs review or more captures.
    pub const CRYPTO_CANONICALIZATION_HYPOTHESIS_REVIEW: DiagnosticDefinition =
        DiagnosticDefinition {
            id: "crypto.canonicalization-hypothesis-needs-review",
            category: DiagnosticCategory::DataModel,
            severity: DiagnosticSeverity::Warning,
            what: "Canonicalization remains a ranked hypothesis rather than a recovered signer.",
            why: "Training correlation, held-out replay, or transform observability is incomplete.",
            fix: "Review the fixtures, add differential and held-out captures, or supply human guidance for bespoke transforms.",
        };

    /// A primitive was observed but request canonicalization could not be correlated.
    pub const CRYPTO_CANONICALIZATION_NOT_RECOVERABLE: DiagnosticDefinition =
        DiagnosticDefinition {
            id: "crypto.canonicalization-not-recoverable",
            category: DiagnosticCategory::DataModel,
            severity: DiagnosticSeverity::Info,
            what: "The signing primitive was observed, but canonicalization was not recoverable.",
            why: "The captured preimage did not correlate to the observable request fields with a supported hypothesis.",
            fix: "Collect richer preimage/request correlation or hand the observed primitive to human-assisted generic inference.",
        };

    /// Canonicalization inference was blocked by insufficient observability.
    pub const CRYPTO_CANONICALIZATION_BLOCKED: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.canonicalization-blocked",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "Canonicalization inference was blocked.",
        why: "Anti-hooking or another observability failure prevented reliable request/preimage evidence.",
        fix: "Review the capture block, improve the instrumentation boundary, and do not infer missing canonicalization from absence of evidence.",
    };

    /// Every Phase 4.3 definition.
    pub const PHASE_4_3: &[DiagnosticDefinition] = &[
        CRYPTO_CANONICALIZATION_RECOVERED,
        CRYPTO_CANONICALIZATION_HYPOTHESIS_REVIEW,
        CRYPTO_CANONICALIZATION_NOT_RECOVERABLE,
        CRYPTO_CANONICALIZATION_BLOCKED,
    ];

    /// A reusable signer artifact was emitted.
    pub const CRYPTO_SIGNER_EMITTED: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.signer-emitted",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Info,
        what: "A reusable signer artifact was emitted.",
        why: "The signer IR carries the observed scheme, canonicalization, primitive, credential boundary, and supporting fixtures.",
        fix: "Pass a credential provider, clock, and nonce source to the generated sign interface; never replace the credential reference with embedded secret material.",
    };

    /// A signer artifact was emitted as a partial hypothesis.
    pub const CRYPTO_SIGNER_NEEDS_REVIEW: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.signer-needs-review",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A signer artifact was emitted as a partial hypothesis.",
        why: "Canonicalization confidence or held-out coverage is incomplete, so the artifact is not a clean reproducible signer.",
        fix: "Review ranked alternatives and fixtures, then gather more captures or provide human guidance before treating it as reusable signing logic.",
    };

    /// A signer requires the original app/device runtime.
    pub const CRYPTO_SIGNER_DEVICE_ORACLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.signer-device-oracle",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Warning,
        what: "The signer artifact requires a device-oracle callback.",
        why: "The signing key is non-exportable, hardware-backed, or white-box protected and must remain inside the original runtime.",
        fix: "Invoke the original-runtime callback at sign time; do not attempt to export or embed the key.",
    };

    /// A signer could not be emitted as reusable signing logic.
    pub const CRYPTO_SIGNER_NOT_RECOVERABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "crypto.signer-not-recoverable",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Info,
        what: "No reusable signer was recovered from the available evidence.",
        why: "Canonicalization was observed only or inference was blocked, so emitting a clean signer would over-claim recovery.",
        fix: "Retain the primitive evidence, add observability or differential captures, and keep the result in observed-only or human-assisted form.",
    };

    /// Every Phase 4.4 definition.
    pub const PHASE_4_4: &[DiagnosticDefinition] = &[
        CRYPTO_SIGNER_EMITTED,
        CRYPTO_SIGNER_NEEDS_REVIEW,
        CRYPTO_SIGNER_DEVICE_ORACLE,
        CRYPTO_SIGNER_NOT_RECOVERABLE,
    ];

    /// The fusion input contained structurally invalid API-model data.
    pub const FUSION_INVALID_INPUT: DiagnosticDefinition = DiagnosticDefinition {
        id: "fusion.invalid-input",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "Static and dynamic facts could not be fused because the input model is invalid.",
        why: "Fusion requires a validated evidence graph and unique endpoint identities before it can preserve every candidate safely.",
        fix: "Repair the named model invariant and rerun fusion; no input fact was discarded.",
    };

    /// Two endpoint records claimed the same canonical identity.
    pub const FUSION_IDENTITY_COLLISION: DiagnosticDefinition = DiagnosticDefinition {
        id: "fusion.identity-collision",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "Fusion found duplicate endpoint identities.",
        why: "Endpoint identity is exactly method plus path-template, so merging colliding records would make provenance attribution ambiguous.",
        fix: "Deduplicate or explicitly reconcile the endpoint records before running fusion again.",
    };

    /// A fact had provenance that could not be classified as static or dynamic.
    pub const FUSION_CONTRADICTORY_PROVENANCE: DiagnosticDefinition = DiagnosticDefinition {
        id: "fusion.contradictory-provenance",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "Fusion found a candidate with unusable provenance.",
        why: "A candidate must trace to static or dynamic leaf evidence; silently classifying an untraceable candidate would lose auditability.",
        fix: "Repair the candidate's provenance links or retain it as an explicit derived fact before rerunning fusion.",
    };

    /// Fusion could not commit its evidence-preserving result.
    pub const FUSION_MODEL_COMMIT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "fusion.model-commit-failed",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "The fused API model failed canonical validation.",
        why: "The merge result would violate a model invariant, so committing it could drop or misrepresent evidence.",
        fix: "Inspect the model path and merge context, repair the fusion adapter, and retry from the pre-fusion document.",
    };

    /// Every Phase 5.1 definition.
    pub const PHASE_5_1: &[DiagnosticDefinition] = &[
        FUSION_INVALID_INPUT,
        FUSION_IDENTITY_COLLISION,
        FUSION_CONTRADICTORY_PROVENANCE,
        FUSION_MODEL_COMMIT_FAILED,
    ];

    /// Phase 5.2 could not score the supplied model.
    pub const CONFIDENCE_INVALID_INPUT: DiagnosticDefinition = DiagnosticDefinition {
        id: "confidence.invalid-input",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "Confidence recomputation could not consume the API model.",
        why: "Scoring requires the validated fused evidence graph and its retained provenance.",
        fix: "Repair the named model or provenance invariant and rerun Phase 5.2.",
    };

    /// A static handoff was matched by dynamic endpoint evidence.
    pub const CONFIDENCE_HANDOFF_RESOLVED: DiagnosticDefinition = DiagnosticDefinition {
        id: "confidence.handoff-resolved",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Info,
        what: "A static-to-dynamic handoff was resolved by captured evidence.",
        why: "Dynamic ground-truth landed for an endpoint corresponding to the static boundary marker.",
        fix: "Review the matched evidence and retain the resolved handoff in the Phase 6 surface.",
    };

    /// A static handoff remains open because dynamic evidence did not land.
    pub const CONFIDENCE_HANDOFF_OPEN: DiagnosticDefinition = DiagnosticDefinition {
        id: "confidence.handoff-open",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Info,
        what: "A static-to-dynamic handoff remains open.",
        why: "No matching dynamic fact was captured; silence is not evidence that the boundary is absent.",
        fix: "Exercise the relevant app workflow or retain the handoff as an explicit open coverage gap.",
    };

    /// A recomputed fact is below the configured review threshold.
    pub const CONFIDENCE_LOW_FACT: DiagnosticDefinition = DiagnosticDefinition {
        id: "confidence.low-fact",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A fused fact has limited confidence.",
        why: "Its retained sample count or source support is insufficient for a strong assertion.",
        fix: "Inspect the evidence and gather additional static or dynamic observations before relying on the fact.",
    };

    /// A fact retained incompatible source assertions.
    pub const CONFIDENCE_TRUE_CONFLICT: DiagnosticDefinition = DiagnosticDefinition {
        id: "confidence.true-conflict",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A fused fact has unresolved source conflict.",
        why: "Static and dynamic candidates disagree, so selecting one cannot be presented as certain.",
        fix: "Review both retained candidates and capture a discriminating observation or resolve the contract manually.",
    };

    /// The confidence summary failed canonical model validation.
    pub const CONFIDENCE_MODEL_COMMIT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "confidence.model-commit-failed",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "The recomputed confidence summary could not be committed.",
        why: "The score, handoff, coverage, or provenance audit would violate a durable model invariant.",
        fix: "Inspect the named summary path and rerun from the pre-scoring document.",
    };

    /// Every Phase 5.2 definition.
    pub const PHASE_5_2: &[DiagnosticDefinition] = &[
        CONFIDENCE_INVALID_INPUT,
        CONFIDENCE_HANDOFF_RESOLVED,
        CONFIDENCE_HANDOFF_OPEN,
        CONFIDENCE_LOW_FACT,
        CONFIDENCE_TRUE_CONFLICT,
        CONFIDENCE_MODEL_COMMIT_FAILED,
    ];

    /// A signer was attached to the API-wide or endpoint-specific surface.
    pub const SURFACE_SIGNER_ATTACHED: DiagnosticDefinition = DiagnosticDefinition {
        id: "surface.signer-attached",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Info,
        what: "A signer was attached to the unified API surface.",
        why: "The signer artifact is now linked to the API-wide contract or a canonical endpoint.",
        fix: "Keep the recorded signer mode and provenance with the attachment when generating Phase 6 artifacts.",
    };

    /// A unified-surface signer is not clean reusable signing logic.
    pub const SURFACE_SIGNER_NEEDS_REVIEW: DiagnosticDefinition = DiagnosticDefinition {
        id: "surface.signer-needs-review",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A unified-surface signer requires review before generation.",
        why: "The attached signer is partial, observed-only, or device-bound rather than reproducible.",
        fix: "Preserve the mode honestly; generate reusable signing code only for a reproducible signer.",
    };

    /// An endpoint has no recovered authentication evidence or signer.
    pub const SURFACE_ENDPOINT_NO_RECOVERED_AUTH: DiagnosticDefinition = DiagnosticDefinition {
        id: "surface.endpoint-no-recovered-auth",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "An endpoint has no recovered authentication contract.",
        why: "The fused endpoint has neither an authentication fact nor an attached signer.",
        fix: "Review the endpoint evidence and retain the missing-auth state rather than assuming the endpoint is public.",
    };

    /// The unified surface has limited dynamic corroboration.
    pub const SURFACE_LOW_COVERAGE: DiagnosticDefinition = DiagnosticDefinition {
        id: "surface.low-coverage",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "The unified API surface has limited dynamic corroboration.",
        why: "A large portion of the surface remains static-only or otherwise unconfirmed.",
        fix: "Exercise the open workflows and keep static-only endpoints explicitly marked for review.",
    };

    /// Phase 5.3 could not assemble a durable unified surface.
    pub const SURFACE_INVALID_INPUT: DiagnosticDefinition = DiagnosticDefinition {
        id: "surface.invalid-input",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "The unified API surface could not be assembled.",
        why: "The fused model, confidence summary, or signer attachment input was invalid or incomplete.",
        fix: "Repair the named model cross-link and rerun Phase 5.3; no evidence was discarded.",
    };

    /// Every Phase 5.3 definition.
    pub const PHASE_5_3: &[DiagnosticDefinition] = &[
        SURFACE_SIGNER_ATTACHED,
        SURFACE_SIGNER_NEEDS_REVIEW,
        SURFACE_ENDPOINT_NO_RECOVERED_AUTH,
        SURFACE_LOW_COVERAGE,
        SURFACE_INVALID_INPUT,
    ];

    /// The Phase 6.1 `OpenAPI` emitter rejected an invalid unified surface.
    pub const OPENAPI_INVALID_INPUT: DiagnosticDefinition = DiagnosticDefinition {
        id: "openapi.invalid-input",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "The OpenAPI document could not be emitted from the unified surface.",
        why: "The input surface failed validation or a required cross-link was not available.",
        fix: "Repair the named unified-surface invariant and rerun OpenAPI emission; no artifact was emitted.",
    };

    /// A model value cannot be represented by a valid `OpenAPI` 3.1 structure.
    pub const OPENAPI_UNREPRESENTABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "openapi.unrepresentable",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "A unified API fact cannot be represented as a valid OpenAPI 3.1 element.",
        why: "OpenAPI reserves the relevant location for a fixed structure and the model value does not satisfy it.",
        fix: "Repair the model value or retain it through the diagnostic and x-apiaxess extensions before retrying emission.",
    };

    /// Standard `OpenAPI` auth metadata was emitted with an explicit caveat.
    pub const OPENAPI_AUTH_REVIEW: DiagnosticDefinition = DiagnosticDefinition {
        id: "openapi.auth-needs-review",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "Authentication metadata was emitted with an OpenAPI review caveat.",
        why: "The unified model identifies authentication, but it does not contain enough endpoint or flow detail for a clean standard mapping.",
        fix: "Review x-apiaxess-authentication and x-apiaxess-signer before using generated authentication code.",
    };

    /// A valid `OpenAPI` placeholder was needed because evidence is incomplete.
    pub const OPENAPI_INCOMPLETE: DiagnosticDefinition = DiagnosticDefinition {
        id: "openapi.incomplete-evidence",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "The OpenAPI document contains a validity-preserving placeholder.",
        why: "OpenAPI requires this element, but the unified surface does not contain enough evidence to specialize it.",
        fix: "Review the attached x-apiaxess extensions and collect the missing endpoint evidence before relying on the placeholder.",
    };

    /// Every Phase 6.1 definition.
    pub const PHASE_6_1: &[DiagnosticDefinition] = &[
        OPENAPI_INVALID_INPUT,
        OPENAPI_UNREPRESENTABLE,
        OPENAPI_AUTH_REVIEW,
        OPENAPI_INCOMPLETE,
    ];

    /// The Phase 6.2 SDK emitter rejected an invalid unified surface.
    pub const PYTHON_SDK_INVALID_INPUT: DiagnosticDefinition = DiagnosticDefinition {
        id: "python-sdk.invalid-input",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "The Python SDK could not be generated from the unified surface.",
        why: "The input surface failed validation or a required SDK cross-link was unavailable.",
        fix: "Repair the named unified-surface invariant and rerun Python SDK generation; no package was emitted.",
    };

    /// A signer was emitted as review-only metadata rather than false auth code.
    pub const PYTHON_SDK_SIGNER_REVIEW: DiagnosticDefinition = DiagnosticDefinition {
        id: "python-sdk.signer-needs-review",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A non-reproducible signer was emitted as a review-only SDK artifact.",
        why: "The signer mode is partial or observed-only, so canonicalization is not safe to present as working auth.",
        fix: "Review the generated hypothesis and collect replay evidence before implementing a working signer.",
    };

    /// A signer requires the original device/runtime callback.
    pub const PYTHON_SDK_SIGNER_DEVICE_ORACLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "python-sdk.signer-device-oracle",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A device-bound signer was emitted as an explicit callback shape.",
        why: "The signing key or operation cannot leave the original app/device runtime.",
        fix: "Provide the instrumented runtime callback at execution time; do not replace it with an invented local key.",
    };

    /// A generated endpoint has no recovered authentication.
    pub const PYTHON_SDK_NO_RECOVERED_AUTH: DiagnosticDefinition = DiagnosticDefinition {
        id: "python-sdk.no-recovered-auth",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "An SDK endpoint has no recovered authentication contract.",
        why: "The unified endpoint has neither standard authentication evidence nor an attached signer.",
        fix: "Review the endpoint evidence and supply authentication manually only after confirming the target contract.",
    };

    /// A schema was emitted with a conservative dynamic type.
    pub const PYTHON_SDK_LOW_CONFIDENCE_SCHEMA: DiagnosticDefinition = DiagnosticDefinition {
        id: "python-sdk.low-confidence-schema",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A low-confidence inferred schema was emitted with a conservative Python type.",
        why: "The available evidence was too thin or widened to support a narrower generated model.",
        fix: "Review the schema docstring and capture more representative samples before relying on the type.",
    };

    /// Every Phase 6.2 definition.
    pub const PHASE_6_2: &[DiagnosticDefinition] = &[
        PYTHON_SDK_INVALID_INPUT,
        PYTHON_SDK_SIGNER_REVIEW,
        PYTHON_SDK_SIGNER_DEVICE_ORACLE,
        PYTHON_SDK_NO_RECOVERED_AUTH,
        PYTHON_SDK_LOW_CONFIDENCE_SCHEMA,
    ];

    /// The Phase 6.3 collection/HAR emitter rejected an invalid unified surface.
    pub const COLLECTIONS_INVALID_INPUT: DiagnosticDefinition = DiagnosticDefinition {
        id: "collections.invalid-input",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "Postman/HAR artifacts could not be emitted from the unified surface.",
        why: "The input surface failed validation or a required collection cross-link was unavailable.",
        fix: "Repair the named unified-surface invariant and rerun collection emission; no artifact was emitted.",
    };

    /// A signer cannot be safely represented as a working Postman script.
    pub const COLLECTIONS_SIGNER_REVIEW: DiagnosticDefinition = DiagnosticDefinition {
        id: "collections.signer-needs-review",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A Postman signer was emitted as a review-only script.",
        why: "The signer is partial, observed-only, or uses a primitive not available in the Postman sandbox.",
        fix: "Review the generated script and collect replay evidence or provide an external signing mechanism.",
    };

    /// A signer requires the original device/runtime callback.
    pub const COLLECTIONS_SIGNER_DEVICE_ORACLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "collections.signer-device-oracle",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A Postman signer requires the original device/runtime.",
        why: "The signing key or operation cannot leave the original app/device runtime.",
        fix: "Run signing through the instrumented runtime; Postman cannot reproduce this signer locally.",
    };

    /// The unified model does not contain captured request/response traffic for HAR.
    pub const COLLECTIONS_NO_CAPTURED_TRAFFIC: DiagnosticDefinition = DiagnosticDefinition {
        id: "collections.no-captured-traffic",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "The HAR export contains no captured traffic entries.",
        why: "The unified surface contains endpoint/schema facts but no preserved request fixture material.",
        fix: "Capture traffic and attach it to the unified surface before relying on the HAR export.",
    };

    /// Every Phase 6.3 definition.
    pub const PHASE_6_3: &[DiagnosticDefinition] = &[
        COLLECTIONS_INVALID_INPUT,
        COLLECTIONS_SIGNER_REVIEW,
        COLLECTIONS_SIGNER_DEVICE_ORACLE,
        COLLECTIONS_NO_CAPTURED_TRAFFIC,
    ];

    /// Every Phase 3.4 definition.
    pub const PHASE_3_4: &[DiagnosticDefinition] = &[
        INSTRUMENTATION_FRIDA_SERVER_DEPLOY_FAILED,
        INSTRUMENTATION_FRIDA_SERVER_HEALTH_FAILED,
        INSTRUMENTATION_SPAWN_GATE_FAILED,
        INSTRUMENTATION_ATTACH_FAILED,
        INSTRUMENTATION_SCRIPT_LOAD_FAILED,
        INSTRUMENTATION_CLASS_LOADER_FAILED,
        INSTRUMENTATION_DEX_RESOLUTION_FAILED,
        INSTRUMENTATION_WATCHDOG_DEGRADED,
        INSTRUMENTATION_CRASH_CORRELATED,
        INSTRUMENTATION_TEARDOWN_FAILED,
        STEALTH_BUNDLE_INVALID,
        STEALTH_DEPLOY_FAILED,
        STEALTH_ROOT_HIDING_FAILED,
        STEALTH_INTEGRITY_FIX_FAILED,
        STEALTH_FRIDA_CONCEALMENT_FAILED,
        STEALTH_EMULATOR_FINGERPRINT_FAILED,
        STEALTH_DETECTION_BOUNDARY,
        STEALTH_TEARDOWN_FAILED,
    ];

    /// The dynamic capture source could not be read.
    pub const DYNAMIC_CAPTURE_SOURCE_UNAVAILABLE: DiagnosticDefinition = DiagnosticDefinition {
        id: "dynamic.capture-source-unavailable",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "Captured traffic could not be read for dynamic extraction.",
        why: "The Phase-2 traffic store or capture path returned an integrity, database, or access failure.",
        fix: "Repair or reopen the session traffic store, then retry dynamic capture; no model facts were inferred from unreadable flows.",
    };

    /// A captured flow was not structurally usable.
    pub const DYNAMIC_INVALID_FLOW: DiagnosticDefinition = DiagnosticDefinition {
        id: "dynamic.invalid-flow",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A captured flow could not identify an HTTP endpoint.",
        why: "The flow is missing a usable method or absolute request path.",
        fix: "Preserve method/path metadata in the Phase-2 capture adapter and rerun extraction for this flow.",
    };

    /// A static route match was ambiguous.
    pub const DYNAMIC_TEMPLATE_MATCH_AMBIGUOUS: DiagnosticDefinition = DiagnosticDefinition {
        id: "dynamic.template-match-ambiguous",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A captured request matched multiple static route templates.",
        why: "Static endpoint identities overlap, so choosing one would create unsupported dynamic attribution.",
        fix: "Disambiguate the static templates or capture a distinguishing route signal before rerunning extraction.",
    };

    /// No static route matched and fallback inference failed.
    pub const DYNAMIC_UNRESOLVED_ROUTE: DiagnosticDefinition = DiagnosticDefinition {
        id: "dynamic.unresolved-route",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A captured request could not be assigned an endpoint identity.",
        why: "The request path did not match a static template and fallback path-template inference could not produce a valid identity.",
        fix: "Inspect the flow path and add a reviewed static handoff/template or improve the capture metadata.",
    };

    /// A structured payload was malformed.
    pub const DYNAMIC_PAYLOAD_PARSE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "dynamic.payload-parse-failed",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A payload advertised as structured JSON could not be parsed.",
        why: "The captured bytes are truncated, encoded differently, or not valid JSON despite their content type.",
        fix: "Verify body retention and content decoding in the proxy capture path, then rerun extraction.",
    };

    /// Schema inference could not produce a model shape.
    pub const DYNAMIC_SCHEMA_INFERENCE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "dynamic.schema-inference-failed",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A structured payload could not be converted into a schema fact.",
        why: "The observed value was unsupported or its inferred shape could not satisfy the 0.2 schema model.",
        fix: "Inspect the payload and inference diagnostic context; retain it as an artifact or add a supported adapter.",
    };

    /// Generic fact extraction failed for one flow or endpoint.
    pub const DYNAMIC_FACT_EXTRACTION_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "dynamic.fact-extraction-failed",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "A captured flow could not be represented as a dynamic API fact.",
        why: "A required model value or provenance record could not be constructed without dropping evidence.",
        fix: "Inspect the flow and model context in this diagnostic, correct the offending adapter input, and rerun capture extraction.",
    };

    /// A dynamic model commit failed validation.
    pub const DYNAMIC_MODEL_COMMIT_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "dynamic.model-commit-failed",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "Dynamic facts were not committed to the session API model.",
        why: "The candidate/provenance graph failed the canonical 0.2 model validation or session commit contract.",
        fix: "Inspect the model validation context, repair the dynamic adapter, and retry; the previous static model remains intact.",
    };

    /// Dynamic traffic was captured but did not exercise every static endpoint.
    pub const DYNAMIC_COVERAGE_PARTIAL: DiagnosticDefinition = DiagnosticDefinition {
        id: "dynamic.coverage-partial",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Info,
        what: "Dynamic endpoint coverage is partial for this capture run.",
        why: "Only endpoints triggered by the session receive dynamic ground-truth; static-only identities remain unexercised, not absent.",
        fix: "Exercise additional app workflows and run another capture when broader dynamic confirmation is needed.",
    };

    /// A capture run had no usable endpoint observations.
    pub const DYNAMIC_NO_OBSERVATIONS: DiagnosticDefinition = DiagnosticDefinition {
        id: "dynamic.no-observations",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Warning,
        what: "The dynamic capture run produced no usable endpoint observations.",
        why: "The store was empty, flows were outside the HTTP extraction boundary, or all endpoint metadata was incomplete.",
        fix: "Confirm the app exercised network workflows and that the Phase-2 route captured method/path metadata.",
    };

    /// The optional dynamic stage was not run because no capture runtime was available.
    pub const PIPELINE_DYNAMIC_SKIPPED: DiagnosticDefinition = DiagnosticDefinition {
        id: "pipeline.dynamic-skipped",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Info,
        what: "Dynamic capture was skipped for this analysis run.",
        why: "Dynamic capture is optional and no usable session capture runtime or traffic was available when the stage was reached.",
        fix: "Run the target in a supported sandbox, exercise its network workflows, and rerun analysis when dynamic confirmation is needed.",
    };

    /// The autonomous app-crawler finished a dynamic exercise; its honest
    /// split-coverage summary is carried in the instantiated diagnostic.
    pub const PIPELINE_DYNAMIC_CRAWL: DiagnosticDefinition = DiagnosticDefinition {
        id: "pipeline.dynamic-crawl",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Info,
        what: "The autonomous crawler exercised the app to surface API traffic.",
        why: "Coverage is reported as states/activities visited and actions fired (pre-auth vs post-auth), never an inferred percentage of the API.",
        fix: "Review captured flows; supply credentials at the sign-in prompt to reach the post-auth surface if it remains behind a wall.",
    };

    /// The dynamic pipeline assessed certificate pinning and engaged (or
    /// honestly declined) the bypass lane; detail is in the instantiated why.
    pub const PIPELINE_DYNAMIC_BYPASS: DiagnosticDefinition = DiagnosticDefinition {
        id: "pipeline.dynamic-bypass",
        category: DiagnosticCategory::Sandbox,
        severity: DiagnosticSeverity::Info,
        what: "Certificate-pinning bypass was assessed before dynamic capture.",
        why: "Pinned apps have pinning bypassed so their traffic reaches the proxy; plain apps skip the lane. When a needed bypass is unavailable the run says so rather than capturing nothing.",
        fix: "If pinning is present but the bypass is unavailable, use the frida-embedded product variant; if it failed, inspect the accompanying lane diagnostic.",
    };

    /// Signer recovery had no Phase 4 runtime evidence to consume.
    pub const PIPELINE_SIGNING_SKIPPED: DiagnosticDefinition = DiagnosticDefinition {
        id: "pipeline.signing-skipped",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Info,
        what: "Signer recovery was skipped for this analysis run.",
        why: "The assembled run had no correlated Phase 4 crypto-capture evidence; static API discovery remains valid without claiming a signer.",
        fix: "Run dynamic capture with crypto evidence enabled, then rerun analysis to attempt signer recovery.",
    };

    /// A pipeline stage could not complete.
    pub const PIPELINE_STAGE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "pipeline.stage-failed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "An analysis pipeline stage failed.",
        why: "The assembled product could not complete one of its typed stage handoffs.",
        fix: "Inspect the stage diagnostic, correct the named artifact, tool, runtime, or model condition, and rerun the analysis.",
    };

    /// The pipeline produced its durable unified surface.
    pub const PIPELINE_COMPLETED: DiagnosticDefinition = DiagnosticDefinition {
        id: "pipeline.completed",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Info,
        what: "The analysis pipeline produced a unified API surface.",
        why: "Intake, static analysis, optional dynamic enrichment, fusion, confidence scoring, and surface assembly completed through the product engine.",
        fix: "Inspect the durable unified surface and its open handoffs before treating inferred values as confirmed.",
    };

    /// A requested pipeline run is not known to the current session.
    pub const PIPELINE_RUN_NOT_FOUND: DiagnosticDefinition = DiagnosticDefinition {
        id: "pipeline.run-not-found",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The requested analysis pipeline run was not found.",
        why: "The run ID is not present in the active session or local pipeline registry.",
        fix: "Check the run ID, open the session that owns it, or start a new analysis run.",
    };

    /// A pipeline surface was requested before completion.
    pub const PIPELINE_SURFACE_NOT_READY: DiagnosticDefinition = DiagnosticDefinition {
        id: "pipeline.surface-not-ready",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Info,
        what: "The unified API surface is not ready yet.",
        why: "The requested pipeline run is still progressing or failed before surface assembly.",
        fix: "Poll the pipeline status endpoint and inspect its retained diagnostics before retrying.",
    };

    /// Every Phase 8.3 pipeline definition.
    pub const PHASE_8_3: &[DiagnosticDefinition] = &[
        PIPELINE_DYNAMIC_SKIPPED,
        PIPELINE_DYNAMIC_CRAWL,
        PIPELINE_DYNAMIC_BYPASS,
        PIPELINE_SIGNING_SKIPPED,
        PIPELINE_STAGE_FAILED,
        PIPELINE_COMPLETED,
    ];

    /// A second analysis run was requested while one is still running.
    pub const PIPELINE_ALREADY_RUNNING: DiagnosticDefinition = DiagnosticDefinition {
        id: "pipeline.already-running",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "An analysis pipeline is already running.",
        why: "Only one APK analysis runs at a time, so a second run cannot start while one is in progress.",
        fix: "Wait for the current run to finish, then start another.",
    };

    /// Every Phase 8.4 CLI/API pipeline-surface definition.
    pub const PHASE_8_4: &[DiagnosticDefinition] = &[
        PIPELINE_RUN_NOT_FOUND,
        PIPELINE_SURFACE_NOT_READY,
        PIPELINE_ALREADY_RUNNING,
    ];

    /// The requested session has no completed unified surface to export.
    pub const EXPORT_SURFACE_NOT_READY: DiagnosticDefinition = DiagnosticDefinition {
        id: "export.surface-not-ready",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The requested session has no completed unified API surface to export.",
        why: "Artifact export is session-scoped and the analysis has not committed a unified surface.",
        fix: "Run or resume the analysis until surface assembly completes, then retry export.",
    };

    /// A Phase 6 emitter rejected the session's unified surface.
    pub const EXPORT_EMITTER_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "export.emitter-failed",
        category: DiagnosticCategory::DataModel,
        severity: DiagnosticSeverity::Error,
        what: "An export emitter could not produce the requested artifact.",
        why: "The selected emitter found an invalid or unrepresentable unified-surface value.",
        fix: "Inspect the emitter diagnostic, repair the named model condition, and retry export; no invalid artifact was written.",
    };

    /// An exported artifact or evidence sidecar could not be written.
    pub const EXPORT_WRITE_FAILED: DiagnosticDefinition = DiagnosticDefinition {
        id: "export.write-failed",
        category: DiagnosticCategory::Persistence,
        severity: DiagnosticSeverity::Error,
        what: "An export artifact could not be written to disk.",
        why: "The output directory or filesystem rejected the artifact write.",
        fix: "Choose a writable output directory, check available disk space and permissions, then retry export.",
    };

    /// The export format or output configuration is invalid.
    pub const EXPORT_INVALID_REQUEST: DiagnosticDefinition = DiagnosticDefinition {
        id: "export.invalid-request",
        category: DiagnosticCategory::Session,
        severity: DiagnosticSeverity::Error,
        what: "The artifact export request is invalid.",
        why: "No supported format or a usable output directory was supplied.",
        fix: "Select openapi, sdk, postman, har, or all and provide a writable output directory.",
    };

    /// Every Phase 8.5 export definition.
    pub const PHASE_8_5: &[DiagnosticDefinition] = &[
        EXPORT_SURFACE_NOT_READY,
        EXPORT_EMITTER_FAILED,
        EXPORT_WRITE_FAILED,
        EXPORT_INVALID_REQUEST,
    ];

    /// Every Phase 11.1 bundled-runtime definition.
    pub const PHASE_11_1: &[DiagnosticDefinition] = &[INSTALL_COMPONENT_MISSING];

    /// Every Phase 3.5 definition.
    pub const PHASE_3_5: &[DiagnosticDefinition] = &[
        DYNAMIC_CAPTURE_SOURCE_UNAVAILABLE,
        DYNAMIC_INVALID_FLOW,
        DYNAMIC_TEMPLATE_MATCH_AMBIGUOUS,
        DYNAMIC_UNRESOLVED_ROUTE,
        DYNAMIC_PAYLOAD_PARSE_FAILED,
        DYNAMIC_SCHEMA_INFERENCE_FAILED,
        DYNAMIC_FACT_EXTRACTION_FAILED,
        DYNAMIC_MODEL_COMMIT_FAILED,
        DYNAMIC_COVERAGE_PARTIAL,
        DYNAMIC_NO_OBSERVATIONS,
    ];

    /// Every Phase 2.5 fuzzer definition.
    pub const PHASE_2_5: &[DiagnosticDefinition] = &[
        PROXY_FUZZER_FFUF_UNAVAILABLE,
        PROXY_FUZZER_FFUF_FAILED,
        WEB_DISCOVERY_RATE_OBSERVED,
        WEB_DISCOVERY_STOPPED,
        PROXY_FUZZER_RATE_OBSERVED,
        PROXY_FUZZER_CONFIG_INVALID,
        PROXY_FUZZER_SEQUENCE_FAILED,
        PROXY_FUZZER_CANCELLED,
        PROXY_FUZZER_OUTSIDE_SCOPE,
        PROXY_FUZZER_PERSISTENCE_FAILED,
    ];

    /// Every Phase 9.2 bundled-browser definition.
    pub const PHASE_9_2: &[DiagnosticDefinition] = &[
        PROXY_BUNDLED_BROWSER_LAUNCH_FAILURE,
        PROXY_CDP_CONNECT_FAILURE,
        PROXY_CAPTURE_NOT_FLOWING,
        PROXY_TEARDOWN_INCOMPLETE,
    ];
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{DiagnosticContext, catalogue};

    #[test]
    fn catalogue_ids_are_unique_and_every_definition_is_actionable() {
        let mut ids = BTreeSet::new();
        for definition in catalogue::PHASE_0_4
            .iter()
            .chain(catalogue::PHASE_1_1)
            .chain(catalogue::PHASE_1_2)
            .chain(catalogue::PHASE_1_3)
            .chain(catalogue::PHASE_1_4)
            .chain(catalogue::PHASE_2_1)
            .chain(catalogue::PHASE_2_2)
            .chain(catalogue::PHASE_2_3)
            .chain(catalogue::PHASE_2_4)
            .chain(catalogue::PHASE_2_5)
            .chain(catalogue::PHASE_9_2)
            .chain(catalogue::PHASE_3_1)
            .chain(catalogue::PHASE_3_1_3)
            .chain(catalogue::PHASE_3_2)
            .chain(catalogue::PHASE_3_3)
            .chain(catalogue::PHASE_3_4)
            .chain(catalogue::PHASE_3_5)
            .chain(catalogue::PHASE_8_3)
            .chain(catalogue::PHASE_8_4)
            .chain(catalogue::PHASE_8_5)
            .chain(catalogue::PHASE_11_1)
            .chain(catalogue::PHASE_11_5)
            .chain(catalogue::PHASE_4_1)
            .chain(catalogue::PHASE_4_2)
            .chain(catalogue::PHASE_4_3)
            .chain(catalogue::PHASE_4_4)
            .chain(catalogue::PHASE_5_1)
            .chain(catalogue::PHASE_5_2)
            .chain(catalogue::PHASE_5_3)
            .chain(catalogue::PHASE_6_1)
            .chain(catalogue::PHASE_6_2)
            .chain(catalogue::PHASE_6_3)
            .chain(catalogue::PHASE_C1)
            .chain(catalogue::PHASE_C2)
            .chain(catalogue::PHASE_C4)
            .chain(catalogue::PHASE_C5)
            .chain(catalogue::PHASE_D1)
            .chain(catalogue::PHASE_D2)
            .chain(catalogue::PHASE_D3)
        {
            let diagnostic = definition.instantiate(DiagnosticContext::new());
            diagnostic.validate().expect("catalogue entry is valid");
            assert!(ids.insert(definition.id), "duplicate ID: {}", definition.id);
            assert!(!diagnostic.what.is_empty());
            assert!(!diagnostic.why.is_empty());
            assert!(!diagnostic.fix.is_empty());
        }
    }
}
