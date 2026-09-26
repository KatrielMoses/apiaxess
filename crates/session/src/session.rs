//! In-memory session aggregate and lifecycle.

use std::collections::BTreeSet;

use apiaxess_api_model::ApiDocument;
use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticValue,
    catalogue::{
        SCOPE_OUTSIDE_DECLARATION, SCOPE_UNDETERMINED, SESSION_API_MODEL_INVALID,
        SESSION_FORMAT_UNSUPPORTED, SESSION_INVALID_TRANSITION, SESSION_JSON_INVALID,
    },
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    ActionRecordInput, AuditRecord, EngagementScope, ScopeDisposition, invariant,
    validate_nonempty, validate_stable_key,
};

/// Stable session identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Constructs a validated session ID.
    ///
    /// # Errors
    ///
    /// Returns a canonical invariant diagnostic for a malformed ID.
    pub fn new(value: impl Into<String>) -> Result<Self, Diagnostic> {
        let value = value.into();
        validate_stable_key("session.id", &value)?;
        Ok(Self(value))
    }

    /// Returns the stable session ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Runtime lifecycle; serialization is an operation, not a hidden service state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLifecycle {
    /// Aggregate exists but feature/workbench actions cannot yet attach.
    Created,
    /// Live session to which the future workbench and feature actions attach.
    Active,
    /// Explicitly finalized terminal session.
    Closed,
}

/// Current format for the compact, crash-recovery session checkpoint.
pub const CURRENT_SESSION_CHECKPOINT_FORMAT_VERSION: u32 = 1;

/// Compact session metadata persisted between full canonical artifact saves.
///
/// The API document and workbench traffic snapshot are intentionally excluded:
/// the former is checkpointed at analysis stage commits, while the latter is
/// already transactionally durable in `SQLite`. This keeps frequent checkpoints
/// bounded even when the evidence document is hundreds of megabytes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCheckpoint {
    /// Checkpoint envelope version, independent from the full session format.
    pub format_version: u32,
    /// Time the checkpoint file was produced.
    pub checkpointed_at: DateTime<Utc>,
    /// Session identity to which the overlay belongs.
    pub session_id: SessionId,
    /// Lifecycle recorded by the live runtime. Checkpoints are active-only.
    pub lifecycle: SessionLifecycle,
    /// Last mutation represented by the compact metadata.
    pub session_updated_at: DateTime<Utc>,
    /// Latest declared engagement scope.
    pub engagement_scope: EngagementScope,
    /// Complete append-only audit metadata at the checkpoint boundary.
    pub audit_trail: Vec<AuditRecord>,
    /// Latest live sandbox attachment metadata, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_handle: Option<SandboxHandle>,
    /// Latest analysis progress metadata, if analysis has started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_pipeline: Option<AnalysisPipelineState>,
}

impl SessionCheckpoint {
    /// Builds a compact checkpoint from an active session.
    #[must_use]
    pub fn from_session(session: &Session, checkpointed_at: DateTime<Utc>) -> Self {
        Self {
            format_version: CURRENT_SESSION_CHECKPOINT_FORMAT_VERSION,
            checkpointed_at,
            session_id: session.id.clone(),
            lifecycle: session.lifecycle,
            session_updated_at: session.updated_at,
            engagement_scope: session.engagement_scope.clone(),
            audit_trail: session.audit_trail.clone(),
            sandbox_handle: session.sandbox_handle.clone(),
            analysis_pipeline: session.analysis_pipeline.clone(),
        }
    }

    /// Serializes a validated compact checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a structured version, invariant, or JSON diagnostic.
    pub fn to_json(&self) -> Result<Vec<u8>, Diagnostic> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| checkpoint_json_diagnostic(&error))
    }

    /// Parses and validates a compact checkpoint without accepting unknown
    /// versions or fields.
    ///
    /// # Errors
    ///
    /// Returns a structured version, invariant, or JSON diagnostic.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Diagnostic> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|error| checkpoint_json_diagnostic(&error))?;
        if let Some(found) = value
            .get("format_version")
            .and_then(serde_json::Value::as_u64)
            && found != u64::from(CURRENT_SESSION_CHECKPOINT_FORMAT_VERSION)
        {
            return Err(checkpoint_version_diagnostic(
                u32::try_from(found).unwrap_or(u32::MAX),
            ));
        }
        let checkpoint: Self =
            serde_json::from_slice(bytes).map_err(|error| checkpoint_json_diagnostic(&error))?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    /// Validates the compact overlay independently of a base artifact.
    ///
    /// # Errors
    ///
    /// Returns a structured version or nested invariant diagnostic.
    pub fn validate(&self) -> Result<(), Diagnostic> {
        if self.format_version != CURRENT_SESSION_CHECKPOINT_FORMAT_VERSION {
            return Err(checkpoint_version_diagnostic(self.format_version));
        }
        validate_stable_key("checkpoint.session_id", self.session_id.as_str())?;
        if self.lifecycle != SessionLifecycle::Active {
            return Err(invariant(
                "checkpoint.lifecycle",
                "incremental checkpoints must represent an active session",
            ));
        }
        if self.checkpointed_at < self.session_updated_at {
            return Err(invariant(
                "checkpoint.checkpointed_at",
                "must not precede the represented session mutation",
            ));
        }
        self.engagement_scope.validate()?;
        if let Some(handle) = &self.sandbox_handle {
            handle.validate()?;
        }
        if let Some(pipeline) = &self.analysis_pipeline {
            pipeline.validate()?;
        }
        Ok(())
    }
}

/// Opaque, losslessly retained slot whose schema will be owned by Phase 2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WorkbenchStateSlot {
    /// Stable schema ID owned by the future workbench crate.
    pub schema_id: String,
    /// Workbench-owned payload format version.
    pub format_version: u32,
    /// Opaque JSON retained without interpretation by the session crate.
    pub payload: serde_json::Value,
}

/// Durable metadata for the active sandbox lease owned by a session.
///
/// Runtime cleanup remains owned by `apiaxess-sandbox`; this value is the
/// serializable attachment point used by later traffic and instrumentation
/// phases after they re-open a session artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxHandle {
    /// Stable session lease identifier.
    pub lease_id: String,
    /// Stable backend identifier.
    pub backend_id: String,
    /// Selected sandbox tier.
    pub tier: String,
    /// Honest isolation description.
    pub isolation: String,
    /// Secured control channel descriptor.
    pub control_channel: String,
    /// Device serial or remote helper identity.
    pub device_serial: String,
}

/// Durable progress and outcome for the product analysis pipeline.
///
/// The session crate intentionally stores stage identifiers as stable strings:
/// the engine owns the executable pipeline while the session owns its durable
/// lifecycle and replayable status.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnalysisPipelineState {
    /// Version of this persisted state shape.
    pub schema_version: u32,
    /// Stable analysis run identifier.
    pub run_id: String,
    /// User-provided artifact path used for the run.
    pub artifact_path: String,
    /// Current or terminal stage identifier.
    pub stage: String,
    /// Current or terminal run status.
    pub status: String,
    /// Progress in basis points, from zero through ten thousand.
    pub progress_basis_points: u16,
    /// Whether dynamic capture was requested.
    pub dynamic_requested: bool,
    /// Whether dynamic facts were actually incorporated.
    pub dynamic_ran: bool,
    /// Diagnostics accumulated by completed stages.
    pub diagnostics: Vec<Diagnostic>,
    /// Last state mutation time.
    pub updated_at: DateTime<Utc>,
}

impl AnalysisPipelineState {
    fn validate(&self) -> Result<(), Diagnostic> {
        if self.schema_version == 0 {
            return Err(invariant(
                "analysis_pipeline.schema_version",
                "must be non-zero",
            ));
        }
        for (path, value) in [
            ("analysis_pipeline.run_id", self.run_id.as_str()),
            ("analysis_pipeline.stage", self.stage.as_str()),
            ("analysis_pipeline.status", self.status.as_str()),
        ] {
            validate_stable_key(path, value)?;
        }
        validate_nonempty("analysis_pipeline.artifact_path", &self.artifact_path)?;
        if self.progress_basis_points > 10_000 {
            return Err(invariant(
                "analysis_pipeline.progress_basis_points",
                "must be between zero and ten thousand",
            ));
        }
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            diagnostic.validate().map_err(|error| {
                invariant(
                    &format!("analysis_pipeline.diagnostics[{index}]"),
                    error.to_string(),
                )
            })?;
        }
        Ok(())
    }
}

impl SandboxHandle {
    fn validate(&self) -> Result<(), Diagnostic> {
        for (path, value) in [
            ("sandbox_handle.lease_id", self.lease_id.as_str()),
            ("sandbox_handle.backend_id", self.backend_id.as_str()),
            ("sandbox_handle.tier", self.tier.as_str()),
            ("sandbox_handle.isolation", self.isolation.as_str()),
            (
                "sandbox_handle.control_channel",
                self.control_channel.as_str(),
            ),
            ("sandbox_handle.device_serial", self.device_serial.as_str()),
        ] {
            validate_stable_key(path, value)?;
        }
        if self.control_channel.contains("adb-over-tcp") || self.control_channel.contains("raw") {
            return Err(invariant(
                "sandbox_handle.control_channel",
                "remote sandbox control must use an authenticated encrypted channel",
            ));
        }
        Ok(())
    }
}

impl WorkbenchStateSlot {
    fn validate(&self) -> Result<(), Diagnostic> {
        validate_stable_key("workbench_state.schema_id", &self.schema_id)?;
        if self.format_version == 0 {
            return Err(invariant(
                "workbench_state.format_version",
                "must be non-zero",
            ));
        }
        Ok(())
    }
}

/// Unit of work shared by engine features and the future workbench.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Session {
    id: SessionId,
    lifecycle: SessionLifecycle,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    closed_at: Option<DateTime<Utc>>,
    engagement_scope: EngagementScope,
    api_document: ApiDocument,
    audit_trail: Vec<AuditRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workbench_state: Option<WorkbenchStateSlot>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_handle: Option<SandboxHandle>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    analysis_pipeline: Option<AnalysisPipelineState>,
}

impl Session {
    /// Creates an inactive session aggregate without starting feature work.
    #[must_use]
    pub fn new(
        id: SessionId,
        engagement_scope: EngagementScope,
        api_document: ApiDocument,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            lifecycle: SessionLifecycle::Created,
            created_at,
            updated_at: created_at,
            closed_at: None,
            engagement_scope,
            api_document,
            audit_trail: Vec::new(),
            workbench_state: None,
            sandbox_handle: None,
            analysis_pipeline: None,
        }
    }

    /// Activates a newly created session.
    ///
    /// # Errors
    ///
    /// Returns a structured lifecycle diagnostic for any other current state.
    pub fn activate(&mut self, at: DateTime<Utc>) -> Result<(), Diagnostic> {
        if self.lifecycle != SessionLifecycle::Created {
            return Err(transition_diagnostic(
                self.lifecycle,
                SessionLifecycle::Active,
            ));
        }
        self.ensure_timestamp("activate", at)?;
        self.lifecycle = SessionLifecycle::Active;
        self.updated_at = at;
        Ok(())
    }

    /// Explicitly finalizes an active session. Closed sessions are terminal.
    ///
    /// # Errors
    ///
    /// Returns a structured lifecycle diagnostic unless the session is active.
    pub fn close(&mut self, at: DateTime<Utc>) -> Result<(), Diagnostic> {
        if self.lifecycle != SessionLifecycle::Active {
            return Err(transition_diagnostic(
                self.lifecycle,
                SessionLifecycle::Closed,
            ));
        }
        if self.sandbox_handle.is_some() {
            return Err(invariant(
                "sandbox_handle",
                "tear down and detach the session sandbox before closing the session",
            ));
        }
        self.ensure_timestamp("close", at)?;
        self.lifecycle = SessionLifecycle::Closed;
        self.updated_at = at;
        self.closed_at = Some(at);
        Ok(())
    }

    /// Records an attempted active-session action and its advisory scope status.
    ///
    /// Outside-scope and undetermined actions are appended and returned
    /// successfully with warnings. This method never enforces authorization.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, timestamp, duplicate-ID, or input diagnostic.
    pub fn record_action(
        &mut self,
        input: ActionRecordInput,
    ) -> Result<crate::ScopeAssessment, Diagnostic> {
        if self.lifecycle != SessionLifecycle::Active {
            return Err(transition_diagnostic(
                self.lifecycle,
                SessionLifecycle::Active,
            ));
        }
        self.ensure_timestamp("record_action", input.occurred_at)?;
        validate_stable_key("audit_trail.new.id", &input.id)?;
        if self.audit_trail.iter().any(|record| record.id == input.id) {
            return Err(invariant(
                "audit_trail.new.id",
                "audit record IDs must be unique within a session",
            ));
        }

        let scope = self.engagement_scope.assess(&input.target);
        let mut diagnostics = input.diagnostics;
        let automatic = match scope.disposition {
            ScopeDisposition::OutsideDeclaredScope => Some(SCOPE_OUTSIDE_DECLARATION),
            ScopeDisposition::Undetermined => Some(SCOPE_UNDETERMINED),
            ScopeDisposition::InScope | ScopeDisposition::NotApplicable => None,
        };
        if let Some(definition) = automatic {
            let mut context = DiagnosticContext::new();
            context.insert(
                "action_id".to_owned(),
                DiagnosticValue::String(input.id.clone()),
            );
            context.insert(
                "scope_disposition".to_owned(),
                DiagnosticValue::String(format!("{:?}", scope.disposition).to_ascii_lowercase()),
            );
            diagnostics.push(definition.instantiate(context));
        }

        let record = AuditRecord {
            id: input.id,
            occurred_at: input.occurred_at,
            actor: input.actor,
            action: input.action,
            target: input.target,
            scope,
            outcome: input.outcome,
            diagnostics,
        };
        record.validate(self.audit_trail.len())?;
        self.updated_at = record.occurred_at;
        let assessment = record.scope.clone();
        self.audit_trail.push(record);
        Ok(assessment)
    }

    /// Replaces the declared engagement scope while the session is active.
    ///
    /// Scope is session data, not a proxy display filter. Existing audit
    /// records retain their original assessment; future actions use the new
    /// declaration.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, timestamp, or scope-invariant diagnostic.
    pub fn update_engagement_scope(
        &mut self,
        scope: EngagementScope,
        at: DateTime<Utc>,
    ) -> Result<(), Diagnostic> {
        if self.lifecycle != SessionLifecycle::Active {
            return Err(transition_diagnostic(
                self.lifecycle,
                SessionLifecycle::Active,
            ));
        }
        self.ensure_timestamp("update_engagement_scope", at)?;
        scope.validate()?;
        self.engagement_scope = scope;
        self.updated_at = at;
        Ok(())
    }

    /// Replaces the opaque future-workbench slot while the session is active.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, timestamp, or slot-invariant diagnostic.
    pub fn set_workbench_state(
        &mut self,
        state: Option<WorkbenchStateSlot>,
        at: DateTime<Utc>,
    ) -> Result<(), Diagnostic> {
        if self.lifecycle != SessionLifecycle::Active {
            return Err(transition_diagnostic(
                self.lifecycle,
                SessionLifecycle::Active,
            ));
        }
        self.ensure_timestamp("set_workbench_state", at)?;
        if let Some(slot) = &state {
            slot.validate()?;
        }
        self.workbench_state = state;
        self.updated_at = at;
        Ok(())
    }

    /// Records the current analysis-pipeline progress in the session.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, timestamp, or pipeline-state invariant diagnostic.
    pub fn set_analysis_pipeline_state(
        &mut self,
        mut state: AnalysisPipelineState,
        at: DateTime<Utc>,
    ) -> Result<(), Diagnostic> {
        if self.lifecycle != SessionLifecycle::Active {
            return Err(transition_diagnostic(
                self.lifecycle,
                SessionLifecycle::Active,
            ));
        }
        self.ensure_timestamp("set_analysis_pipeline_state", at)?;
        state.updated_at = at;
        state.validate()?;
        self.analysis_pipeline = Some(state);
        self.updated_at = at;
        Ok(())
    }

    /// Applies newer compact crash-recovery metadata to this canonical base.
    ///
    /// The evidence-preserving API document and workbench snapshot remain from
    /// the full artifact. `SQLite` holds newer traffic independently.
    ///
    /// # Errors
    ///
    /// Returns a structured diagnostic when identities, lifecycle, ordering,
    /// or any restored nested invariant is inconsistent.
    pub fn apply_checkpoint(&mut self, checkpoint: &SessionCheckpoint) -> Result<(), Diagnostic> {
        checkpoint.validate()?;
        if self.id != checkpoint.session_id {
            return Err(invariant(
                "checkpoint.session_id",
                "must match the canonical session artifact",
            ));
        }
        if self.lifecycle != SessionLifecycle::Active {
            return Err(invariant(
                "session.lifecycle",
                "checkpoint recovery requires an active canonical session",
            ));
        }
        if checkpoint.session_updated_at <= self.updated_at {
            return Ok(());
        }

        self.engagement_scope = checkpoint.engagement_scope.clone();
        self.audit_trail.clone_from(&checkpoint.audit_trail);
        self.sandbox_handle.clone_from(&checkpoint.sandbox_handle);
        self.analysis_pipeline
            .clone_from(&checkpoint.analysis_pipeline);
        self.updated_at = checkpoint.session_updated_at;
        self.validate()
    }

    /// Attaches the durable metadata for a live sandbox lease.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, timestamp, duplicate-lease, or handle-invariant diagnostic.
    pub fn attach_sandbox(
        &mut self,
        handle: SandboxHandle,
        at: DateTime<Utc>,
    ) -> Result<(), Diagnostic> {
        if self.lifecycle != SessionLifecycle::Active {
            return Err(transition_diagnostic(
                self.lifecycle,
                SessionLifecycle::Active,
            ));
        }
        self.ensure_timestamp("attach_sandbox", at)?;
        handle.validate()?;
        if self.sandbox_handle.is_some() {
            return Err(invariant(
                "sandbox_handle",
                "only one sandbox lease may be attached to a session",
            ));
        }
        self.sandbox_handle = Some(handle);
        self.updated_at = at;
        Ok(())
    }

    /// Removes sandbox metadata after the runtime has been torn down.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle or timestamp diagnostic.
    pub fn detach_sandbox(
        &mut self,
        at: DateTime<Utc>,
    ) -> Result<Option<SandboxHandle>, Diagnostic> {
        if self.lifecycle != SessionLifecycle::Active {
            return Err(transition_diagnostic(
                self.lifecycle,
                SessionLifecycle::Active,
            ));
        }
        self.ensure_timestamp("detach_sandbox", at)?;
        let handle = self.sandbox_handle.take();
        self.updated_at = at;
        Ok(handle)
    }

    /// Validates lifecycle, scope, model, audit, and future-slot invariants.
    ///
    /// # Errors
    ///
    /// Returns the first canonical structural or nested-model diagnostic.
    pub fn validate(&self) -> Result<(), Diagnostic> {
        validate_stable_key("session.id", self.id.as_str())?;
        if self.updated_at < self.created_at {
            return Err(invariant(
                "session.updated_at",
                "must not precede created_at",
            ));
        }
        match (self.lifecycle, self.closed_at) {
            (SessionLifecycle::Closed, Some(closed)) if closed == self.updated_at => {}
            (SessionLifecycle::Closed, _) => {
                return Err(invariant(
                    "session.closed_at",
                    "a closed session must have closed_at equal to updated_at",
                ));
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(invariant(
                    "session.closed_at",
                    "only a closed session may carry closed_at",
                ));
            }
        }
        self.engagement_scope.validate()?;
        self.api_document.validate().map_err(|error| {
            let mut context = DiagnosticContext::new();
            context.insert(
                "model_error".to_owned(),
                DiagnosticValue::String(error.to_string()),
            );
            SESSION_API_MODEL_INVALID.instantiate(context)
        })?;
        let mut ids = BTreeSet::new();
        let mut previous = self.created_at;
        for (index, record) in self.audit_trail.iter().enumerate() {
            record.validate(index)?;
            if !ids.insert(&record.id) {
                return Err(invariant(
                    &format!("audit_trail[{index}].id"),
                    "audit record IDs must be unique within a session",
                ));
            }
            if record.occurred_at < previous || record.occurred_at > self.updated_at {
                return Err(invariant(
                    &format!("audit_trail[{index}].occurred_at"),
                    "audit records must be chronological and not later than updated_at",
                ));
            }
            let required_warning = match record.scope.disposition {
                ScopeDisposition::OutsideDeclaredScope => Some(SCOPE_OUTSIDE_DECLARATION.id),
                ScopeDisposition::Undetermined => Some(SCOPE_UNDETERMINED.id),
                ScopeDisposition::InScope | ScopeDisposition::NotApplicable => None,
            };
            if required_warning.is_some_and(|id| {
                !record
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.id.as_ref() == id)
            }) {
                return Err(invariant(
                    &format!("audit_trail[{index}].diagnostics"),
                    "outside-scope and undetermined actions must retain their canonical scope warning",
                ));
            }
            previous = record.occurred_at;
        }
        if let Some(slot) = &self.workbench_state {
            slot.validate()?;
        }
        if let Some(handle) = &self.sandbox_handle {
            handle.validate()?;
        }
        if let Some(state) = &self.analysis_pipeline {
            state.validate()?;
            if state.updated_at < self.created_at || state.updated_at > self.updated_at {
                return Err(invariant(
                    "analysis_pipeline.updated_at",
                    "must fall between session creation and last session mutation",
                ));
            }
        }
        Ok(())
    }

    /// Stable session ID.
    #[must_use]
    pub const fn id(&self) -> &SessionId {
        &self.id
    }

    /// Current runtime lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle
    }

    /// User-declared target and allowed-target set.
    #[must_use]
    pub const fn engagement_scope(&self) -> &EngagementScope {
        &self.engagement_scope
    }

    /// Canonical evidence-preserving API document.
    #[must_use]
    pub const fn api_document(&self) -> &ApiDocument {
        &self.api_document
    }

    /// Mutable API document for future engine orchestration; persistence revalidates it.
    #[must_use]
    pub fn api_document_mut(&mut self) -> &mut ApiDocument {
        &mut self.api_document
    }

    /// Commits a normalized static-pass document while the session is active.
    ///
    /// The document is validated before replacement, and the session mutation
    /// timestamp becomes the commit time so durable round-trips retain the
    /// complete static view and its honesty layer.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, timestamp, or canonical API-model diagnostic.
    pub fn commit_api_document(
        &mut self,
        document: ApiDocument,
        at: DateTime<Utc>,
    ) -> Result<(), Diagnostic> {
        if self.lifecycle != SessionLifecycle::Active {
            return Err(transition_diagnostic(
                self.lifecycle,
                SessionLifecycle::Active,
            ));
        }
        self.ensure_timestamp("commit_api_document", at)?;
        document.validate().map_err(|error| {
            let mut context = DiagnosticContext::new();
            context.insert(
                "model_error".to_owned(),
                DiagnosticValue::String(error.to_string()),
            );
            SESSION_API_MODEL_INVALID.instantiate(context)
        })?;
        self.api_document = document;
        self.updated_at = at;
        Ok(())
    }

    /// Append-only action audit trail.
    #[must_use]
    pub fn audit_trail(&self) -> &[AuditRecord] {
        &self.audit_trail
    }

    /// Opaque Phase 2 workbench state, if attached.
    #[must_use]
    pub const fn workbench_state(&self) -> Option<&WorkbenchStateSlot> {
        self.workbench_state.as_ref()
    }

    /// Metadata for the currently attached sandbox lease, if any.
    #[must_use]
    pub const fn sandbox_handle(&self) -> Option<&SandboxHandle> {
        self.sandbox_handle.as_ref()
    }

    /// Durable analysis-pipeline status, if an analysis run has been started.
    #[must_use]
    pub const fn analysis_pipeline_state(&self) -> Option<&AnalysisPipelineState> {
        self.analysis_pipeline.as_ref()
    }

    /// Last in-memory mutation time.
    #[must_use]
    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    fn ensure_timestamp(&self, operation: &str, at: DateTime<Utc>) -> Result<(), Diagnostic> {
        if at < self.updated_at {
            Err(invariant(
                &format!("session.{operation}.at"),
                "must not precede the last session mutation",
            ))
        } else {
            Ok(())
        }
    }
}

fn checkpoint_version_diagnostic(found: u32) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "format_kind".to_owned(),
        DiagnosticValue::String("session_checkpoint".to_owned()),
    );
    context.insert(
        "found_version".to_owned(),
        DiagnosticValue::Integer(i64::from(found)),
    );
    context.insert(
        "supported_version".to_owned(),
        DiagnosticValue::Integer(i64::from(CURRENT_SESSION_CHECKPOINT_FORMAT_VERSION)),
    );
    let mut diagnostic = SESSION_FORMAT_UNSUPPORTED.instantiate(context);
    diagnostic.why = format!(
        "The session checkpoint is format version {found}; this build reads only version {CURRENT_SESSION_CHECKPOINT_FORMAT_VERSION}."
    )
    .into_boxed_str();
    diagnostic
}

fn checkpoint_json_diagnostic(error: &serde_json::Error) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "format_kind".to_owned(),
        DiagnosticValue::String("session_checkpoint".to_owned()),
    );
    context.insert(
        "json_error".to_owned(),
        DiagnosticValue::String(error.to_string()),
    );
    context.insert(
        "line".to_owned(),
        DiagnosticValue::Integer(i64::try_from(error.line()).unwrap_or(i64::MAX)),
    );
    context.insert(
        "column".to_owned(),
        DiagnosticValue::Integer(i64::try_from(error.column()).unwrap_or(i64::MAX)),
    );
    SESSION_JSON_INVALID.instantiate(context)
}

fn transition_diagnostic(from: SessionLifecycle, to: SessionLifecycle) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "current_state".to_owned(),
        DiagnosticValue::String(format!("{from:?}").to_ascii_lowercase()),
    );
    context.insert(
        "requested_state".to_owned(),
        DiagnosticValue::String(format!("{to:?}").to_ascii_lowercase()),
    );
    SESSION_INVALID_TRANSITION.instantiate(context)
}
