//! Product-level session ownership and durable artifact lifecycle.

use std::{
    fmt,
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_session::{Session, SessionCheckpoint, SessionDocument, SessionId, SessionLifecycle};
use apiaxess_workbench_store::TrafficStore;
use chrono::{DateTime, Utc};
use getrandom::fill;
use serde::Serialize;

/// Product-facing identity and persistence status.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatus {
    /// Stable session identifier.
    pub session_id: String,
    /// Current lifecycle state.
    pub lifecycle: SessionLifecycle,
    /// Canonical JSON artifact path.
    pub artifact_path: String,
    /// Runtime `SQLite` path.
    pub store_path: String,
    /// Number of captured flows currently persisted.
    pub flow_count: usize,
    /// Number of persisted resend contexts.
    pub resend_count: usize,
    /// Number of persisted fuzzer jobs.
    pub fuzzer_count: usize,
    /// Canonical session engagement scope.
    pub scope: apiaxess_session::EngagementScope,
    /// Whether one or more network allow rules are declared.
    pub scope_configured: bool,
    /// Durable analysis-pipeline progress and outcome, when analysis has run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_pipeline: Option<apiaxess_session::AnalysisPipelineState>,
    /// Whether newer compact metadata was recovered over the full artifact.
    pub recovered_from_checkpoint: bool,
    /// Most recent compact checkpoint time in this runtime, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_checkpoint_at: Option<DateTime<Utc>>,
}

/// The one mutable session/store pair used by the assembled product.
pub struct SessionRuntime {
    session: Mutex<Session>,
    store: Arc<TrafficStore>,
    artifact_path: PathBuf,
    recovered_from_checkpoint: AtomicBool,
    checkpoint_dirty: AtomicBool,
    last_checkpoint_at: Mutex<Option<DateTime<Utc>>>,
}

impl fmt::Debug for SessionRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRuntime")
            .field("session_id", &self.session_id())
            .field("store", &self.store.root())
            .field("artifact_path", &self.artifact_path)
            .finish_non_exhaustive()
    }
}

impl SessionRuntime {
    /// Creates a runtime for an already-active session.
    #[must_use]
    pub fn new(session: Session, store: Arc<TrafficStore>, artifact_path: PathBuf) -> Self {
        Self {
            session: Mutex::new(session),
            store,
            artifact_path,
            recovered_from_checkpoint: AtomicBool::new(false),
            checkpoint_dirty: AtomicBool::new(false),
            last_checkpoint_at: Mutex::new(None),
        }
    }

    /// Opens a canonical session artifact and reconstructs its `SQLite` runtime.
    ///
    /// # Errors
    ///
    /// Returns a structured diagnostic when the artifact is missing, invalid,
    /// version-incompatible, or cannot be rehydrated.
    pub fn open(artifact_path: &Path, store_parent: &Path) -> Result<Self, Diagnostic> {
        let bytes = read_recoverable(artifact_path).map_err(|error| {
            let mut context = DiagnosticContext::new();
            context.insert(
                "artifact_path".to_owned(),
                DiagnosticValue::String(artifact_path.display().to_string()),
            );
            context.insert(
                "error".to_owned(),
                DiagnosticValue::String(error.to_string()),
            );
            catalogue::PROXY_SESSION_ARTIFACT_NOT_FOUND.instantiate(context)
        })?;
        let document = SessionDocument::from_json(&bytes).map_err(|mut diagnostic| {
            diagnostic.context.insert(
                "artifact_path".to_owned(),
                DiagnosticValue::String(artifact_path.display().to_string()),
            );
            diagnostic
        })?;
        if document.session.lifecycle() != SessionLifecycle::Active {
            let mut context = DiagnosticContext::new();
            context.insert(
                "artifact_path".to_owned(),
                DiagnosticValue::String(artifact_path.display().to_string()),
            );
            context.insert(
                "lifecycle".to_owned(),
                DiagnosticValue::String(
                    format!("{:?}", document.session.lifecycle()).to_ascii_lowercase(),
                ),
            );
            return Err(catalogue::SESSION_INVALID_TRANSITION.instantiate(context));
        }
        let store = Arc::new(TrafficStore::open(
            store_parent,
            document.session.id().as_str(),
        )?);
        if store_is_empty(&store)? {
            store.resume_from_session(&document.session)?;
        }
        let mut session = document.session;
        let checkpoint_path = checkpoint_path(artifact_path);
        let checkpoint = read_optional_recoverable(&checkpoint_path)?
            .map(|bytes| SessionCheckpoint::from_json(&bytes))
            .transpose()?;
        let recovered = checkpoint
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.session_updated_at > session.updated_at());
        if let Some(checkpoint) = &checkpoint {
            session.apply_checkpoint(checkpoint)?;
        }
        let last_checkpoint_at = checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.checkpointed_at);
        let runtime = Self::new(session, store, artifact_path.to_path_buf());
        runtime
            .recovered_from_checkpoint
            .store(recovered, Ordering::Release);
        *runtime.last_checkpoint_at.lock().map_err(|_| {
            catalogue::PROXY_SESSION_SAVE_FAILED.instantiate(DiagnosticContext::new())
        })? = last_checkpoint_at;
        Ok(runtime)
    }

    /// Stable session ID.
    #[must_use]
    pub fn session_id(&self) -> String {
        self.session.lock().map_or_else(
            |_| "session:unavailable".to_owned(),
            |session| session.id().as_str().to_owned(),
        )
    }

    /// Returns the runtime store shared by all workbench surfaces.
    #[must_use]
    pub fn store(&self) -> Arc<TrafficStore> {
        Arc::clone(&self.store)
    }

    /// Returns a snapshot for proxy configuration and API status.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the runtime session lock is unavailable.
    pub fn session_snapshot(&self) -> Result<Session, Diagnostic> {
        self.session
            .lock()
            .map(|session| session.clone())
            .map_err(|_| catalogue::PROXY_SESSION_SAVE_FAILED.instantiate(DiagnosticContext::new()))
    }

    /// Returns current identity, lifecycle, and persisted workbench counts.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the session or any durable workbench table
    /// cannot be read.
    pub fn status(&self) -> Result<SessionStatus, Diagnostic> {
        let session = self.session_snapshot()?;
        Ok(SessionStatus {
            session_id: session.id().as_str().to_owned(),
            lifecycle: session.lifecycle(),
            artifact_path: self.artifact_path.display().to_string(),
            store_path: self.store.database_path().display().to_string(),
            flow_count: self.store.summaries()?.len(),
            resend_count: self.store.resend_contexts()?.len(),
            fuzzer_count: self.store.fuzzer_jobs()?.len(),
            scope: session.engagement_scope().clone(),
            scope_configured: !session.engagement_scope().allowed_targets.is_empty(),
            analysis_pipeline: session.analysis_pipeline_state().map(|state| {
                let mut state = state.clone();
                // Status consumers need actionable progress diagnostics, not
                // the full high-volume evidence retained by the durable file.
                // Bound per-id so repeated evidence cannot hide the terminal
                // (dynamic-capture/crawl) diagnostics behind a positional cap.
                state.diagnostics =
                    apiaxess_diagnostics::bounded_status_diagnostics(&state.diagnostics, 8, 100);
                state
            }),
            recovered_from_checkpoint: self.recovered_from_checkpoint.load(Ordering::Acquire),
            last_checkpoint_at: *self.last_checkpoint_at.lock().map_err(|_| {
                catalogue::PROXY_SESSION_SAVE_FAILED.instantiate(DiagnosticContext::new())
            })?,
        })
    }

    /// Returns the canonical append-only audit trail.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the runtime session lock is unavailable.
    pub fn audit_trail(&self) -> Result<Vec<apiaxess_session::AuditRecord>, Diagnostic> {
        self.session
            .lock()
            .map(|session| session.audit_trail().to_vec())
            .map_err(|_| {
                catalogue::PROXY_SESSION_AUDIT_FAILED.instantiate(DiagnosticContext::new())
            })
    }

    /// Replaces the in-memory session after an audited operation.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the session identity changes, validation fails,
    /// or the runtime lock is unavailable.
    pub fn replace_session(&self, session: Session) -> Result<(), Diagnostic> {
        let mut current = self.session.lock().map_err(|_| {
            catalogue::PROXY_SESSION_AUDIT_FAILED.instantiate(DiagnosticContext::new())
        })?;
        if current.id() != session.id() {
            let mut context = DiagnosticContext::new();
            context.insert(
                "current_session_id".to_owned(),
                DiagnosticValue::String(current.id().as_str().to_owned()),
            );
            context.insert(
                "requested_session_id".to_owned(),
                DiagnosticValue::String(session.id().as_str().to_owned()),
            );
            return Err(catalogue::PROXY_SESSION_ID_COLLISION.instantiate(context));
        }
        session.validate()?;
        *current = session;
        self.checkpoint_dirty.store(true, Ordering::Release);
        Ok(())
    }

    /// Ensures a small initial canonical artifact exists before live work can
    /// produce compact checkpoints.
    ///
    /// # Errors
    ///
    /// Returns a structured persistence diagnostic if the baseline cannot be
    /// committed.
    pub fn ensure_baseline(&self) -> Result<(), Diagnostic> {
        if self.artifact_path.exists() || recovery_backup(&self.artifact_path).exists() {
            Ok(())
        } else {
            self.save().map(|_| ())
        }
    }

    /// Writes compact metadata without serializing the evidence document or
    /// SQLite-backed workbench snapshot.
    ///
    /// # Errors
    ///
    /// Returns a structured persistence diagnostic when validation or the
    /// crash-safe replacement fails.
    pub fn checkpoint(&self) -> Result<(), Diagnostic> {
        let session = self.session.lock().map_err(|_| {
            catalogue::PROXY_SESSION_SAVE_FAILED.instantiate(DiagnosticContext::new())
        })?;
        session.validate()?;
        let checkpointed_at = Utc::now().max(session.updated_at());
        let bytes = SessionCheckpoint::from_session(&session, checkpointed_at).to_json()?;
        atomic_write(&checkpoint_path(&self.artifact_path), &bytes)?;
        drop(session);
        *self.last_checkpoint_at.lock().map_err(|_| {
            catalogue::PROXY_SESSION_SAVE_FAILED.instantiate(DiagnosticContext::new())
        })? = Some(checkpointed_at);
        Ok(())
    }

    /// Writes a compact checkpoint only when session metadata changed since
    /// the previous checkpoint/full save.
    ///
    /// # Errors
    ///
    /// Returns a structured persistence diagnostic and keeps the dirty bit set
    /// so the next cadence can retry.
    pub fn checkpoint_if_dirty(&self) -> Result<bool, Diagnostic> {
        if !self.checkpoint_dirty.swap(false, Ordering::AcqRel) {
            return Ok(false);
        }
        match self.checkpoint() {
            Ok(()) => Ok(true),
            Err(diagnostic) => {
                self.checkpoint_dirty.store(true, Ordering::Release);
                Err(diagnostic)
            }
        }
    }

    /// Commits the live store and atomically replaces the canonical artifact.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the live snapshot or artifact write fails.
    pub fn save(&self) -> Result<SessionStatus, Diagnostic> {
        let mut session = self.session.lock().map_err(|_| {
            catalogue::PROXY_SESSION_SAVE_FAILED.instantiate(DiagnosticContext::new())
        })?;
        let bytes = self
            .store
            .serialize_session(&mut session, Utc::now())
            .map_err(|mut diagnostic| {
                diagnostic.context.insert(
                    "artifact_path".to_owned(),
                    DiagnosticValue::String(self.artifact_path.display().to_string()),
                );
                diagnostic
            })?;
        atomic_write(&self.artifact_path, &bytes)?;
        remove_recovery_files(&checkpoint_path(&self.artifact_path));
        self.recovered_from_checkpoint
            .store(false, Ordering::Release);
        self.checkpoint_dirty.store(false, Ordering::Release);
        *self.last_checkpoint_at.lock().map_err(|_| {
            catalogue::PROXY_SESSION_SAVE_FAILED.instantiate(DiagnosticContext::new())
        })? = None;
        drop(session);
        self.status()
    }

    /// Closes the in-memory lifecycle after a successful commit-before-exit.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle diagnostic when the session is not active.
    pub fn close(&self) -> Result<(), Diagnostic> {
        self.session
            .lock()
            .map_err(|_| {
                catalogue::SESSION_INVALID_TRANSITION.instantiate(DiagnosticContext::new())
            })?
            .close(Utc::now())
    }

    /// Returns the parent used for sibling session stores.
    #[must_use]
    pub fn store_parent(&self) -> PathBuf {
        self.store
            .root()
            .parent()
            .map_or_else(|| self.store.root().to_path_buf(), Path::to_path_buf)
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Diagnostic> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| save_diagnostic(path, &error.to_string()))?;
    let temporary = recovery_temporary(path);
    let backup = recovery_backup(path);
    let result = (|| {
        let _ = fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        if path.exists() {
            let _ = fs::remove_file(&backup);
            fs::rename(path, &backup).map_err(|error| error.to_string())?;
        }
        if let Err(error) = fs::rename(&temporary, path) {
            if backup.exists() && !path.exists() {
                let _ = fs::rename(&backup, path);
            }
            return Err(error.to_string());
        }
        let _ = fs::remove_file(&backup);
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(save_diagnostic(path, &error));
    }
    Ok(())
}

fn checkpoint_path(artifact_path: &Path) -> PathBuf {
    artifact_path.with_extension("checkpoint.json")
}

fn recovery_temporary(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("data")
    ))
}

fn recovery_backup(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}.bak",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("data")
    ))
}

fn read_recoverable(path: &Path) -> std::io::Result<Vec<u8>> {
    fs::read(path).or_else(|primary| {
        let backup = recovery_backup(path);
        fs::read(backup).map_err(|_| primary)
    })
}

fn read_optional_recoverable(path: &Path) -> Result<Option<Vec<u8>>, Diagnostic> {
    match read_recoverable(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(save_diagnostic(path, &error.to_string())),
    }
}

fn remove_recovery_files(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(recovery_temporary(path));
    let _ = fs::remove_file(recovery_backup(path));
}

fn store_is_empty(store: &TrafficStore) -> Result<bool, Diagnostic> {
    Ok(store.summaries()?.is_empty()
        && store.resend_contexts()?.is_empty()
        && store.fuzzer_jobs()?.is_empty())
}

fn save_diagnostic(path: &Path, error: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "artifact_path".to_owned(),
        DiagnosticValue::String(path.display().to_string()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_owned()),
    );
    catalogue::PROXY_SESSION_SAVE_FAILED.instantiate(context)
}

/// Generates a fresh, process-independent session ID.
///
/// # Errors
///
/// Returns a diagnostic if the generated identity does not satisfy the stable
/// session-ID invariant.
pub fn fresh_session_id() -> Result<SessionId, Diagnostic> {
    let mut bytes = [0_u8; 16];
    if fill(&mut bytes).is_err() {
        let nanos = Utc::now().timestamp_nanos_opt().unwrap_or_default();
        bytes[..8].copy_from_slice(&nanos.to_le_bytes());
    }
    let mut suffix = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut suffix, "{byte:02x}");
    }
    SessionId::new(format!("session:{suffix}"))
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc};

    use apiaxess_api_model::{ApiDocument, ApiSurface, ProvenanceRegistry};
    use apiaxess_session::{
        AllowedNetworkTarget, AnalysisPipelineState, EngagementScope, HostMatch, ScopeDisposition,
        Session, SessionId, TargetIdentifier, TargetIdentity,
    };
    use apiaxess_workbench_store::{FlowCapture, FlowOrigin, TrafficStore};
    use chrono::{Duration, Utc};

    use super::{SessionRuntime, checkpoint_path};

    #[test]
    #[allow(clippy::too_many_lines)]
    fn compact_checkpoint_recovers_after_an_unclean_runtime_drop() {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-checkpoint-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&root).expect("test root");
        let artifact = root.join("session.json");
        let session_id = SessionId::new("session:checkpoint-kill").unwrap();
        let started = Utc::now();
        let mut session = Session::new(
            session_id.clone(),
            EngagementScope {
                declared_at: started,
                target: TargetIdentity {
                    target_type: "android.apk".to_owned(),
                    primary: TargetIdentifier {
                        kind: "sha256".to_owned(),
                        value: "fixture".to_owned(),
                    },
                    aliases: Vec::new(),
                },
                allowed_targets: vec![AllowedNetworkTarget {
                    id: "scope.local".to_owned(),
                    host: HostMatch::Exact {
                        host: "127.0.0.1".to_owned(),
                    },
                    ports: Vec::new(),
                }],
            },
            ApiDocument::new(ApiSurface {
                provenance: ProvenanceRegistry::default(),
                endpoints: Vec::new(),
                protocol_operations: Vec::new(),
                loose_findings: Vec::new(),
                signers: Vec::new(),
            }),
            started,
        );
        session.activate(started).unwrap();
        let store = Arc::new(TrafficStore::open(&root, session_id.as_str()).unwrap());
        let runtime = SessionRuntime::new(session, Arc::clone(&store), artifact.clone());
        runtime.ensure_baseline().unwrap();

        store
            .upsert(&FlowCapture {
                id: 1,
                captured_at: started,
                protocol: "HTTP/1.1".to_owned(),
                method: Some("GET".to_owned()),
                host: Some("127.0.0.1".to_owned()),
                url: Some("http://127.0.0.1/recovered".to_owned()),
                path: Some("/recovered".to_owned()),
                status: Some(200),
                duration_ms: Some(1),
                request_headers: Vec::new(),
                response_headers: Vec::new(),
                request_body: None,
                response_body: None,
                scope: ScopeDisposition::InScope,
                provenance: "test.kill".to_owned(),
                origin: FlowOrigin::Capture,
            })
            .unwrap();
        let mut changed = runtime.session_snapshot().unwrap();
        let checkpoint_time = started + Duration::seconds(1);
        changed
            .set_analysis_pipeline_state(
                AnalysisPipelineState {
                    schema_version: 1,
                    run_id: "pipeline:kill".to_owned(),
                    artifact_path: "fixture.apk".to_owned(),
                    stage: "intake".to_owned(),
                    status: "running".to_owned(),
                    progress_basis_points: 500,
                    dynamic_requested: false,
                    dynamic_ran: false,
                    diagnostics: Vec::new(),
                    updated_at: checkpoint_time,
                },
                checkpoint_time,
            )
            .unwrap();
        runtime.replace_session(changed).unwrap();
        assert!(runtime.checkpoint_if_dirty().unwrap());
        let checkpoint_bytes = fs::read(checkpoint_path(&artifact)).unwrap();
        let checkpoint_text = String::from_utf8(checkpoint_bytes).unwrap();
        assert!(!checkpoint_text.contains("api_document"));
        assert!(!checkpoint_text.contains("workbench_state"));

        // Drop without save/close: this models the durable state left by a kill.
        drop(runtime);
        drop(store);
        let recovered = SessionRuntime::open(&artifact, &root).unwrap();
        assert!(recovered.status().unwrap().recovered_from_checkpoint);
        assert_eq!(recovered.status().unwrap().flow_count, 1);
        assert_eq!(
            recovered
                .session_snapshot()
                .unwrap()
                .analysis_pipeline_state()
                .unwrap()
                .run_id,
            "pipeline:kill"
        );

        drop(recovered);
        fs::remove_dir_all(root).expect("clean test root");
    }
}
