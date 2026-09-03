//! Automated stateless and stateful request attacks.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_external_tools::{
    ExternalToolRunner, ProcessToolRunner, ToolProbeRequest, ToolProcessRequest, ToolRequirement,
    ToolVersion,
};
use apiaxess_session::{
    ActionDescriptor, ActionOutcome, ActionRecordInput, ActionTarget, AuditActor, EngagementScope,
    ScopeDisposition, Session,
};
use apiaxess_workbench_store::{
    IntruderAttackType, IntruderConfig, IntruderJob, IntruderJobState, IntruderPositionLocation,
    IntruderResponseDiff, IntruderResult, IntruderTier, IntruderTokenExtractor, PayloadPosition,
    RepeaterRequest, RepeaterResponse, TrafficStore,
};
use regex::Regex;

use crate::{RepeaterSender, repeater::url_target};

/// Session-scoped intruder job manager.
pub struct IntruderWorkbench {
    store: RwLock<Option<Arc<TrafficStore>>>,
    sender: RwLock<Option<Arc<dyn RepeaterSender>>>,
    scope: RwLock<Option<EngagementScope>>,
    jobs: Mutex<BTreeMap<String, IntruderJob>>,
    controls: Mutex<BTreeMap<String, Arc<JobControl>>>,
    ffuf_proxy: RwLock<Option<std::net::SocketAddr>>,
}

impl std::fmt::Debug for IntruderWorkbench {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IntruderWorkbench")
            .field("job_count", &self.list().len())
            .finish_non_exhaustive()
    }
}

impl Default for IntruderWorkbench {
    fn default() -> Self {
        Self::new()
    }
}

impl IntruderWorkbench {
    /// Creates an empty intruder surface.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: RwLock::new(None),
            sender: RwLock::new(None),
            scope: RwLock::new(None),
            jobs: Mutex::new(BTreeMap::new()),
            controls: Mutex::new(BTreeMap::new()),
            ffuf_proxy: RwLock::new(None),
        }
    }

    /// Attaches and hydrates the durable store.
    ///
    /// # Errors
    ///
    /// Returns the stable persistence diagnostic when saved jobs cannot load.
    pub fn attach_store(&self, store: Arc<TrafficStore>) -> Result<(), Diagnostic> {
        let jobs = store.intruder_jobs()?;
        if let Ok(mut current) = self.store.write() {
            *current = Some(store);
        }
        if let Ok(mut current) = self.jobs.lock() {
            current.clear();
            current.extend(jobs.into_iter().map(|job| (job.id.clone(), job)));
        }
        Ok(())
    }

    /// Attaches the same routed sender used by the repeater.
    pub fn attach_sender(&self, sender: Arc<dyn RepeaterSender>) {
        if let Ok(mut current) = self.sender.write() {
            *current = Some(sender);
        }
    }

    /// Sets scope classification for attack warnings and records.
    pub fn set_engagement_scope(&self, scope: EngagementScope) {
        if let Ok(mut current) = self.scope.write() {
            *current = Some(scope);
        }
    }

    /// Sets the proxy address passed to hidden ffuf jobs.
    pub fn set_ffuf_proxy(&self, address: std::net::SocketAddr) {
        if let Ok(mut current) = self.ffuf_proxy.write() {
            *current = Some(address);
        }
    }

    /// Records one completed intruder result in the active session audit trail.
    ///
    /// The result itself remains in the durable intruder job; this method adds
    /// the canonical session action record when the host application owns the
    /// mutable session aggregate.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the job/result is absent or the session
    /// rejects the append-only audit record.
    pub fn record_result_in_session(
        &self,
        job_id: &str,
        ordinal: u64,
        session: &mut Session,
    ) -> Result<(), Diagnostic> {
        let job = self
            .get(job_id)
            .ok_or_else(|| intruder_config_diagnostic("audit", "job not found"))?;
        let result = job
            .results
            .iter()
            .find(|result| result.ordinal == ordinal)
            .ok_or_else(|| intruder_config_diagnostic("audit", "result not found"))?;
        let outcome = if result.diagnostic.is_some() {
            ActionOutcome::Failed
        } else {
            ActionOutcome::Completed
        };
        session.record_action(ActionRecordInput {
            id: format!("intruder:{job_id}:{}", result.ordinal),
            occurred_at: chrono::Utc::now(),
            actor: AuditActor::User,
            action: ActionDescriptor {
                kind: "workbench.intruder.send".to_owned(),
                summary: format!("Sent intruder result {}", result.ordinal),
            },
            target: ActionTarget::Network {
                host: url_target(&result.request.url)
                    .map_or_else(|| request_host(&result.request.url), |(host, _)| host),
                port: url_target(&result.request.url).and_then(|(_, port)| port),
            },
            outcome,
            diagnostics: result.diagnostic.clone().into_iter().collect(),
        })?;
        Ok(())
    }

    /// Lists jobs ordered by their stable ID.
    #[must_use]
    pub fn list(&self) -> Vec<IntruderJob> {
        self.jobs
            .lock()
            .map(|jobs| jobs.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Reads one job.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<IntruderJob> {
        self.jobs.lock().ok().and_then(|jobs| jobs.get(id).cloned())
    }

    /// Validates and persists a new attack configuration.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration or persistence diagnostic.
    pub fn create(&self, config: IntruderConfig) -> Result<IntruderJob, Diagnostic> {
        validate_config(&config)?;
        // ffuf can only faithfully execute a single URL-position Sniper sweep
        // with one payload set and a status-only match filter (passed via -mc).
        // Anything richer — multiple positions/sets, body/header positions,
        // Clusterbomb/Pitchfork, size/content match rules, or a stateful
        // sequence — must run on the native sender so the configured controls
        // actually take effect rather than being silently dropped.
        let filter = &config.match_filter;
        let ffuf_capable = config.sequence.is_empty()
            && config.auth_preflight.is_none()
            && config.positions.len() == 1
            && config.positions[0].location == IntruderPositionLocation::Url
            && config.payload_sets.len() == 1
            && config.attack_type == IntruderAttackType::Sniper
            && filter.min_size.is_none()
            && filter.max_size.is_none()
            && filter.contains.is_none()
            && filter.regex.is_none();
        let tier = if ffuf_capable {
            IntruderTier::Ffuf
        } else {
            IntruderTier::Native
        };
        let job = IntruderJob {
            id: new_job_id(),
            created_at: chrono::Utc::now(),
            tier,
            state: IntruderJobState::Pending,
            config,
            results: Vec::new(),
            diagnostics: Vec::new(),
        };
        self.persist(&job)?;
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(job.id.clone(), job.clone());
        }
        Ok(job)
    }

    /// Launches a job in the background and returns its running state.
    ///
    /// # Errors
    ///
    /// Returns a configuration, persistence, or lifecycle diagnostic.
    pub fn launch(self: &Arc<Self>, id: &str) -> Result<IntruderJob, Diagnostic> {
        let mut job = self
            .get(id)
            .ok_or_else(|| intruder_config_diagnostic("launch", "job not found"))?;
        if matches!(job.state, IntruderJobState::Running) {
            return Err(intruder_config_diagnostic(
                "launch",
                "job is already running",
            ));
        }
        job.state = IntruderJobState::Running;
        self.persist(&job)?;
        self.replace(job.clone());
        let control = Arc::new(JobControl::default());
        if let Ok(mut controls) = self.controls.lock() {
            controls.insert(id.to_owned(), Arc::clone(&control));
        }
        let manager = Arc::clone(self);
        let job_id = id.to_owned();
        tokio::spawn(async move {
            let result = manager.run_job(&job_id, control).await;
            if let Err(diagnostic) = result {
                manager.append_job_diagnostic(&job_id, diagnostic);
            }
            if let Ok(mut controls) = manager.controls.lock() {
                controls.remove(&job_id);
            }
        });
        Ok(job)
    }

    /// Launches a job and records the launch in the canonical session audit trail.
    ///
    /// # Errors
    ///
    /// Returns a launch or session-audit diagnostic.
    pub fn launch_in_session(
        self: &Arc<Self>,
        id: &str,
        session: &mut Session,
    ) -> Result<IntruderJob, Diagnostic> {
        let job = self.launch(id)?;
        session.record_action(ActionRecordInput {
            id: format!("intruder:{id}:launch"),
            occurred_at: chrono::Utc::now(),
            actor: AuditActor::User,
            action: ActionDescriptor {
                kind: "workbench.intruder.launch".to_owned(),
                summary: format!("Launched intruder job {id}"),
            },
            target: ActionTarget::Network {
                host: url_target(&job.config.base_request.url).map_or_else(
                    || request_host(&job.config.base_request.url),
                    |(host, _)| host,
                ),
                port: url_target(&job.config.base_request.url).and_then(|(_, port)| port),
            },
            outcome: ActionOutcome::Completed,
            diagnostics: Vec::new(),
        })?;
        Ok(job)
    }

    /// Pauses a running job at its next request boundary.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle diagnostic when the job does not exist or run.
    pub fn pause(&self, id: &str) -> Result<IntruderJob, Diagnostic> {
        let job = self
            .get(id)
            .ok_or_else(|| intruder_config_diagnostic("pause", "job not found"))?;
        let control = self.control(id)?;
        control.paused.store(true, Ordering::Release);
        let mut paused = job;
        paused.state = IntruderJobState::Paused;
        self.persist(&paused)?;
        self.replace(paused.clone());
        Ok(paused)
    }

    /// Resumes a paused job.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle diagnostic when no running control exists.
    pub fn resume(&self, id: &str) -> Result<IntruderJob, Diagnostic> {
        let job = self
            .get(id)
            .ok_or_else(|| intruder_config_diagnostic("resume", "job not found"))?;
        let control = self.control(id)?;
        control.paused.store(false, Ordering::Release);
        control.notify.notify_waiters();
        let mut running = job;
        running.state = IntruderJobState::Running;
        self.persist(&running)?;
        self.replace(running.clone());
        Ok(running)
    }

    /// Stops a running job and requests clean cancellation.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle or persistence diagnostic.
    pub fn stop(&self, id: &str) -> Result<IntruderJob, Diagnostic> {
        let job = self
            .get(id)
            .ok_or_else(|| intruder_config_diagnostic("stop", "job not found"))?;
        let control = self.control(id)?;
        control.cancelled.store(true, Ordering::Release);
        control.notify.notify_waiters();
        let mut stopped = job;
        stopped.state = IntruderJobState::Stopped;
        stopped
            .diagnostics
            .push(catalogue::PROXY_INTRUDER_CANCELLED.instantiate(DiagnosticContext::new()));
        self.persist(&stopped)?;
        self.replace(stopped.clone());
        Ok(stopped)
    }

    async fn run_job(&self, id: &str, control: Arc<JobControl>) -> Result<(), Diagnostic> {
        let job = self
            .get(id)
            .ok_or_else(|| intruder_config_diagnostic("run", "job disappeared"))?;
        if job.tier == IntruderTier::Ffuf {
            self.run_ffuf(job, control).await
        } else {
            self.run_native(job, control).await
        }
    }

    async fn run_native(
        &self,
        mut job: IntruderJob,
        control: Arc<JobControl>,
    ) -> Result<(), Diagnostic> {
        let requests = expand_attack(&job.config)?;
        let sender = self.sender.read().ok().and_then(|sender| sender.clone());
        let Some(sender) = sender else {
            return self.finish_failed(
                &job,
                catalogue::PROXY_REPEATER_TRANSPORT_UNAVAILABLE
                    .instantiate(DiagnosticContext::new()),
            );
        };
        // Stateful attacks (auth pre-flight or a token-chain sequence) must run
        // strictly in order; everything else may fan out up to `concurrency`.
        let stateful = !job.config.sequence.is_empty() || job.config.auth_preflight.is_some();
        let concurrency = if stateful {
            1
        } else {
            job.config.concurrency.max(1)
        };
        let rate = job.config.rate_per_second;
        let planned: Vec<(Vec<String>, RepeaterRequest)> =
            requests.into_iter().take(job.config.max_results).collect();
        let mut prior = None;
        let mut index = 0usize;
        while index < planned.len() {
            if control.cancelled.load(Ordering::Acquire) {
                break;
            }
            control.wait_if_paused().await;
            if control.cancelled.load(Ordering::Acquire) {
                break;
            }
            let end = (index + concurrency).min(planned.len());
            let batch = &planned[index..end];
            // Rate limiting paces dispatch; within a stateless batch, sends overlap.
            let responses = self
                .dispatch_batch(&job.config, batch, stateful, rate, &sender)
                .await;
            // Record in ordinal order so diffs and history stay stable.
            self.record_batch(&mut job, batch, responses, &mut prior)?;
            index = end;
        }
        job.state = if control.cancelled.load(Ordering::Acquire) {
            IntruderJobState::Stopped
        } else {
            IntruderJobState::Completed
        };
        self.persist(&job)?;
        self.replace(job);
        Ok(())
    }

    /// Sends one batch of planned requests. A stateful job runs its requests
    /// strictly in order through the token-chain sequence; a stateless batch
    /// fans them out concurrently. Rate limiting paces each dispatch.
    async fn dispatch_batch(
        &self,
        config: &IntruderConfig,
        batch: &[(Vec<String>, RepeaterRequest)],
        stateful: bool,
        rate: u32,
        sender: &Arc<dyn RepeaterSender>,
    ) -> Vec<Result<RepeaterResponse, Diagnostic>> {
        let mut responses = Vec::with_capacity(batch.len());
        if stateful {
            for (_, request) in batch {
                if rate > 0 {
                    tokio::time::sleep(Duration::from_secs_f64(1.0 / f64::from(rate))).await;
                }
                responses.push(self.send_sequence(config, request, &**sender).await);
            }
        } else {
            let mut handles = Vec::with_capacity(batch.len());
            for (_, request) in batch {
                if rate > 0 {
                    tokio::time::sleep(Duration::from_secs_f64(1.0 / f64::from(rate))).await;
                }
                let sender = Arc::clone(sender);
                let request = request.clone();
                handles.push(tokio::spawn(async move { sender.send(request).await }));
            }
            for handle in handles {
                responses.push(
                    handle
                        .await
                        .unwrap_or_else(|error| Err(intruder_task_diagnostic(&error.to_string()))),
                );
            }
        }
        responses
    }

    /// Records one dispatched batch's responses onto the job in ordinal order,
    /// classifying scope, computing the response diff against the prior result,
    /// applying the match filter, and persisting after each result.
    fn record_batch(
        &self,
        job: &mut IntruderJob,
        batch: &[(Vec<String>, RepeaterRequest)],
        responses: Vec<Result<RepeaterResponse, Diagnostic>>,
        prior: &mut Option<RepeaterResponse>,
    ) -> Result<(), Diagnostic> {
        for ((payloads, request), response) in batch.iter().zip(responses) {
            let (response, diagnostic) = match response {
                Ok(response) => (Some(response), None),
                Err(diagnostic) => (None, Some(diagnostic)),
            };
            let scope = self.classify_scope(&request.url);
            let diff = response_diff(prior.as_ref(), response.as_ref());
            let matched = response
                .as_ref()
                .is_some_and(|response| matches_filter(&job.config.match_filter, response));
            let mut diagnostics = Vec::new();
            if scope == ScopeDisposition::OutsideDeclaredScope {
                diagnostics.push(outside_scope(&request.url));
            }
            if let Some(diagnostic) = diagnostic.clone() {
                diagnostics.push(diagnostic.clone());
            }
            let ordinal = job.results.len() + 1;
            job.results.push(IntruderResult {
                ordinal: u64::try_from(ordinal).unwrap_or(u64::MAX),
                payloads: payloads.clone(),
                request: request.clone(),
                response: response.clone(),
                matched,
                filtered: !matched,
                diff,
                scope,
                diagnostic,
            });
            *prior = response;
            job.diagnostics.extend(diagnostics);
            self.persist(job)?;
            self.replace(job.clone());
        }
        Ok(())
    }

    async fn send_sequence(
        &self,
        config: &IntruderConfig,
        first_request: &RepeaterRequest,
        sender: &dyn RepeaterSender,
    ) -> Result<RepeaterResponse, Diagnostic> {
        let mut variables = BTreeMap::new();
        if let Some(preflight) = &config.auth_preflight {
            let response = sender
                .send(inject_request(preflight, &variables))
                .await
                .map_err(|error| sequence_diagnostic("auth_preflight", &error.to_string()))?;
            extract_tokens("auth_preflight", &response, &[], &mut variables)?;
        }
        let mut final_response = None;
        for (index, step) in config.sequence.iter().enumerate() {
            let request = if index == 0 {
                first_request.clone()
            } else {
                step.request.clone()
            };
            let response = sender
                .send(inject_request(&request, &variables))
                .await
                .map_err(|error| sequence_diagnostic(&step.name, &error.to_string()))?;
            extract_tokens(&step.name, &response, &step.extractors, &mut variables)?;
            final_response = Some(response);
        }
        final_response.ok_or_else(|| sequence_diagnostic("sequence", "no sequence response"))
    }

    #[allow(clippy::too_many_lines)]
    async fn run_ffuf(&self, job: IntruderJob, control: Arc<JobControl>) -> Result<(), Diagnostic> {
        let proxy = self
            .ffuf_proxy
            .read()
            .ok()
            .and_then(|proxy| *proxy)
            .ok_or_else(|| {
                catalogue::PROXY_INTRUDER_FFUF_UNAVAILABLE.instantiate(DiagnosticContext::new())
            })?;
        // The bundled ffuf is invoked by absolute path from the install layout;
        // nothing on the host is required. An operator may still point
        // APIAXESS_FFUF at their own binary.
        let launch = crate::bundled::resolve_ffuf();
        if let Some(component) = &launch.bundled_component
            && !component.path.is_file()
        {
            return Err(ffuf_install_missing(component.label, &component.path));
        }
        let runner = ProcessToolRunner;
        let probe = runner
            .probe(&ToolProbeRequest {
                tool_id: "ffuf".to_owned(),
                executable: launch.executable.clone(),
                version_arguments: vec!["-V".to_owned()],
                requirement: ToolRequirement {
                    minimum: ToolVersion {
                        major: 2,
                        minor: 0,
                        patch: 0,
                    },
                },
            })
            .map_err(|error| ffuf_unavailable(&error.to_string()))?;
        let wordlist = std::env::temp_dir().join(format!("apiaxess-{}.wordlist", job.id));
        let output = std::env::temp_dir().join(format!("apiaxess-{}.ffuf.json", job.id));
        let _temporary_files = FfufTempFiles {
            wordlist: wordlist.clone(),
            output: output.clone(),
        };
        let mut values = job
            .config
            .payload_sets
            .first()
            .map(|set| set.values.join("\n"))
            .unwrap_or_default();
        // ffuf's `-ac` auto-calibration consumes the FIRST wordlist entry to learn
        // the soft-404 baseline. On a non-catch-all target that silently drops the
        // first real candidate (and can surface the calibration probe itself as a
        // phantom hit). Prepend a synthetic sacrificial entry so calibration masks
        // it instead of a real path; any result whose payload is not a genuine
        // wordlist entry is filtered out in `append_ffuf_results`.
        if job.config.auto_calibrate {
            let sacrifice = format!("apiaxess-calibration-sacrifice-{}", job.id);
            values = if values.is_empty() {
                sacrifice
            } else {
                format!("{sacrifice}\n{values}")
            };
        }
        fs::write(&wordlist, values)
            .map_err(|error| ffuf_failed("wordlist", &error.to_string()))?;
        let url = ffuf_url(&job.config.base_request, &job.config.positions)?;
        let mut arguments = vec![
            "-u".to_owned(),
            url,
            "-w".to_owned(),
            wordlist.display().to_string(),
            "-of".to_owned(),
            "json".to_owned(),
            "-o".to_owned(),
            output.display().to_string(),
            "-noninteractive".to_owned(),
            "-x".to_owned(),
            format!("http://{proxy}"),
        ];
        // Honor the configured throttle so the run matches its pre-run estimate
        // rather than firing unbounded at ffuf's default thread count.
        if job.config.rate_per_second > 0 {
            arguments.push("-rate".to_owned());
            arguments.push(job.config.rate_per_second.to_string());
        }
        if job.config.concurrency > 1 {
            arguments.push("-t".to_owned());
            arguments.push(job.config.concurrency.to_string());
        }
        // Pass an explicit status matcher when one is configured; otherwise ffuf
        // keeps its default matcher. Size/content rules route to the native
        // tier, so only the status list is meaningful here.
        if !job.config.match_filter.statuses.is_empty() {
            arguments.push("-mc".to_owned());
            arguments.push(
                job.config
                    .match_filter
                    .statuses
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        // Soft-404 / catch-all auto-calibration: ffuf probes random paths, learns
        // the catch-all's response signature, and filters matching hits — so a
        // wildcard/WAF site that answers every path produces no false positives.
        if job.config.auto_calibrate {
            arguments.push("-ac".to_owned());
        }
        let process = runner
            .spawn(&ToolProcessRequest {
                probe,
                arguments,
                working_directory: None,
                environment: launch.environment,
            })
            .map_err(|error| ffuf_failed("process", &error.to_string()))?;
        let started = Instant::now();
        let deadline = started + Duration::from_secs(24 * 60 * 60);
        let mut completed = job;
        let mut seen = 0;
        loop {
            if control.cancelled.load(Ordering::Acquire) {
                process
                    .stop()
                    .map_err(|error| ffuf_failed("stop", &error.to_string()))?;
                completed.state = IntruderJobState::Stopped;
                if completed.diagnostics.iter().all(|diagnostic| {
                    diagnostic.id.as_ref() != catalogue::PROXY_INTRUDER_CANCELLED.id
                }) {
                    completed.diagnostics.push(
                        catalogue::PROXY_INTRUDER_CANCELLED.instantiate(DiagnosticContext::new()),
                    );
                }
                self.persist(&completed)?;
                self.replace(completed);
                return Ok(());
            }
            if let Ok(parsed) = read_ffuf_json(&output) {
                self.append_ffuf_results(&mut completed, &parsed, &mut seen)?;
            }
            if !process.is_running() {
                break;
            }
            if Instant::now() >= deadline {
                process
                    .stop()
                    .map_err(|error| ffuf_failed("timeout", &error.to_string()))?;
                return Err(ffuf_failed("timeout", "ffuf exceeded its 24-hour deadline"));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let parsed =
            read_ffuf_json(&output).map_err(|error| ffuf_failed("json", &error.to_string()))?;
        self.append_ffuf_results(&mut completed, &parsed, &mut seen)?;
        completed.state = IntruderJobState::Completed;
        // Report the actual achieved request rate so the pre-run estimate can be
        // judged honestly against reality (the estimate is latency-bound and
        // often lower than an unrouted ffuf; this closes that gap).
        let candidates = completed
            .config
            .payload_sets
            .first()
            .map_or(0, |set| set.values.len());
        if candidates > 0 {
            let elapsed = started.elapsed().as_secs_f64().max(0.001);
            let actual_rate = f64::from(u32::try_from(candidates).unwrap_or(u32::MAX)) / elapsed;
            completed.diagnostics.push(discovery_rate_diagnostic(
                candidates,
                elapsed,
                actual_rate,
                completed.config.rate_per_second,
            ));
        }
        self.persist(&completed)?;
        self.replace(completed);
        Ok(())
    }

    fn append_ffuf_results(
        &self,
        job: &mut IntruderJob,
        json: &serde_json::Value,
        seen: &mut usize,
    ) -> Result<(), Diagnostic> {
        let Some(results) = json.get("results").and_then(serde_json::Value::as_array) else {
            return Ok(());
        };
        // Under `-ac` we injected a sacrificial wordlist entry and ffuf may also
        // emit its own calibration probe; keep only results whose payload is a
        // genuine caller-supplied wordlist entry so neither leaks into the output.
        let allowed: Option<std::collections::HashSet<&str>> = if job.config.auto_calibrate {
            job.config
                .payload_sets
                .first()
                .map(|set| set.values.iter().map(String::as_str).collect())
        } else {
            None
        };
        let previous_seen = *seen;
        let mut consumed = *seen;
        for (index, entry) in results.iter().enumerate().skip(*seen) {
            consumed = index + 1;
            let payload = ffuf_payload(entry).unwrap_or_default();
            if let Some(allowed) = &allowed
                && !allowed.contains(payload.as_str())
            {
                continue;
            }
            let request = request_with_ffuf_payload(&job.config.base_request, &payload);
            let response = entry
                .get("status")
                .and_then(serde_json::Value::as_u64)
                .and_then(|status| u16::try_from(status).ok())
                .map(|status| RepeaterResponse {
                    status,
                    headers: Vec::new(),
                    body: entry
                        .get("content")
                        .and_then(serde_json::Value::as_str)
                        .map(|body| body.as_bytes().to_vec()),
                    duration_ms: entry
                        .get("duration")
                        .and_then(serde_json::Value::as_u64)
                        .map_or(0, |nanos| nanos / 1_000_000),
                });
            let matched = response
                .as_ref()
                .is_some_and(|response| matches_filter(&job.config.match_filter, response));
            let scope = self.classify_scope(&request.url);
            if scope == ScopeDisposition::OutsideDeclaredScope {
                job.diagnostics.push(outside_scope(&request.url));
            }
            let prior = job
                .results
                .last()
                .and_then(|result| result.response.as_ref());
            job.results.push(IntruderResult {
                ordinal: u64::try_from(job.results.len() + 1).unwrap_or(u64::MAX),
                payloads: vec![payload],
                request,
                diff: response_diff(prior, response.as_ref()),
                response,
                matched,
                filtered: !matched,
                scope,
                diagnostic: None,
            });
            if job.results.len() >= job.config.max_results {
                break;
            }
        }
        *seen = consumed;
        if *seen > previous_seen {
            self.persist(job)?;
            self.replace(job.clone());
        }
        Ok(())
    }

    fn finish_failed(&self, job: &IntruderJob, diagnostic: Diagnostic) -> Result<(), Diagnostic> {
        let mut failed = job.clone();
        failed.state = IntruderJobState::Failed;
        failed.diagnostics.push(diagnostic);
        self.persist(&failed)?;
        self.replace(failed);
        Ok(())
    }

    fn append_job_diagnostic(&self, id: &str, diagnostic: Diagnostic) {
        if let Some(mut job) = self.get(id) {
            job.state = IntruderJobState::Failed;
            job.diagnostics.push(diagnostic);
            if self.persist(&job).is_ok() {
                self.replace(job);
            }
        }
    }

    fn persist(&self, job: &IntruderJob) -> Result<(), Diagnostic> {
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return Err(
                catalogue::PROXY_INTRUDER_PERSISTENCE_FAILED.instantiate(DiagnosticContext::new())
            );
        };
        store.upsert_intruder(job)
    }

    fn replace(&self, job: IntruderJob) {
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(job.id.clone(), job);
        }
    }

    fn control(&self, id: &str) -> Result<Arc<JobControl>, Diagnostic> {
        self.controls
            .lock()
            .ok()
            .and_then(|controls| controls.get(id).cloned())
            .ok_or_else(|| intruder_config_diagnostic("control", "job is not running"))
    }

    fn classify_scope(&self, url: &str) -> ScopeDisposition {
        let Some((host, port)) = url_target(url) else {
            return ScopeDisposition::Undetermined;
        };
        self.scope
            .read()
            .ok()
            .and_then(|scope| {
                scope.as_ref().map(|scope| {
                    scope
                        .assess(&ActionTarget::Network { host, port })
                        .disposition
                })
            })
            .unwrap_or(ScopeDisposition::Undetermined)
    }
}

#[derive(Debug, Default)]
struct JobControl {
    cancelled: AtomicBool,
    paused: AtomicBool,
    notify: tokio::sync::Notify,
}

impl JobControl {
    async fn wait_if_paused(&self) {
        while self.paused.load(Ordering::Acquire) && !self.cancelled.load(Ordering::Acquire) {
            self.notify.notified().await;
        }
    }
}

fn expand_attack(
    config: &IntruderConfig,
) -> Result<Vec<(Vec<String>, RepeaterRequest)>, Diagnostic> {
    let mut results = Vec::new();
    match config.attack_type {
        IntruderAttackType::Sniper => {
            for position in &config.positions {
                let set = config.payload_sets.get(position.set_index).ok_or_else(|| {
                    intruder_config_diagnostic("payload", "position payload set not found")
                })?;
                for value in &set.values {
                    let mut request = config.base_request.clone();
                    apply_position(&mut request, position, value)?;
                    results.push((vec![value.clone()], request));
                }
            }
        }
        IntruderAttackType::Clusterbomb => {
            let indexes = config
                .positions
                .iter()
                .map(|position| position.set_index)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let mut combinations = vec![Vec::<String>::new()];
            for index in indexes.iter().copied() {
                let set = config.payload_sets.get(index).ok_or_else(|| {
                    intruder_config_diagnostic("payload", "position payload set not found")
                })?;
                combinations = combinations
                    .into_iter()
                    .flat_map(|prefix| {
                        set.values.iter().map(move |value| {
                            let mut next = prefix.clone();
                            next.push(value.clone());
                            next
                        })
                    })
                    .collect();
            }
            for values in combinations {
                let values_by_set = indexes
                    .iter()
                    .copied()
                    .zip(values.iter().cloned())
                    .collect::<BTreeMap<_, _>>();
                let mut request = config.base_request.clone();
                let mut applied: Vec<(&PayloadPosition, &str)> = Vec::new();
                for position in &config.positions {
                    let value = values_by_set.get(&position.set_index).ok_or_else(|| {
                        intruder_config_diagnostic("payload", "position payload set not found")
                    })?;
                    applied.push((position, value.as_str()));
                }
                apply_positions(&mut request, &applied)?;
                results.push((values, request));
            }
        }
        IntruderAttackType::Pitchfork => {
            let length = config
                .positions
                .iter()
                .filter_map(|position| {
                    config
                        .payload_sets
                        .get(position.set_index)
                        .map(|set| set.values.len())
                })
                .min()
                .unwrap_or(0);
            for index in 0..length {
                let mut request = config.base_request.clone();
                let mut values = Vec::new();
                for position in &config.positions {
                    values.push(config.payload_sets[position.set_index].values[index].clone());
                }
                let applied: Vec<(&PayloadPosition, &str)> = config
                    .positions
                    .iter()
                    .zip(values.iter())
                    .map(|(position, value)| (position, value.as_str()))
                    .collect();
                apply_positions(&mut request, &applied)?;
                results.push((values, request));
            }
        }
    }
    Ok(results)
}

/// Applies every marked position for one generated request. Positions that
/// share a field (e.g. two markers in the URL) are applied right-to-left, in
/// descending start offset, so substituting an earlier marker with a payload of
/// a different length never shifts the byte offsets of markers that have not
/// been applied yet. Cross-field positions are independent, so a single global
/// descending sort is correct for all of them.
fn apply_positions(
    request: &mut RepeaterRequest,
    positions: &[(&PayloadPosition, &str)],
) -> Result<(), Diagnostic> {
    let mut ordered: Vec<&(&PayloadPosition, &str)> = positions.iter().collect();
    ordered.sort_by(|a, b| b.0.start.cmp(&a.0.start));
    for (position, value) in ordered {
        apply_position(request, position, value)?;
    }
    Ok(())
}

fn apply_position(
    request: &mut RepeaterRequest,
    position: &PayloadPosition,
    value: &str,
) -> Result<(), Diagnostic> {
    match position.location {
        IntruderPositionLocation::Url => {
            replace_range(&mut request.url, position.start, position.end, value)
        }
        IntruderPositionLocation::Body => {
            let body =
                String::from_utf8(request.body.clone().unwrap_or_default()).map_err(|_| {
                    intruder_config_diagnostic("body", "body payload position is not UTF-8")
                })?;
            let mut body = body;
            replace_range(&mut body, position.start, position.end, value)?;
            request.body = Some(body.into_bytes());
            Ok(())
        }
        IntruderPositionLocation::Header => {
            let name = position.header_name.as_deref().ok_or_else(|| {
                intruder_config_diagnostic("header", "header payload position has no header name")
            })?;
            let header = request
                .headers
                .iter_mut()
                .find(|(header, _)| header.eq_ignore_ascii_case(name))
                .ok_or_else(|| {
                    intruder_config_diagnostic(
                        "header",
                        "header payload position names an absent header",
                    )
                })?;
            replace_range(&mut header.1, position.start, position.end, value)
        }
    }
}

fn replace_range(
    value: &mut String,
    start: usize,
    end: usize,
    replacement: &str,
) -> Result<(), Diagnostic> {
    if start > end
        || end > value.len()
        || !value.is_char_boundary(start)
        || !value.is_char_boundary(end)
    {
        return Err(intruder_config_diagnostic(
            "position",
            "payload position is outside the selected field",
        ));
    }
    value.replace_range(start..end, replacement);
    Ok(())
}

fn matches_filter(
    filter: &apiaxess_workbench_store::IntruderMatchFilter,
    response: &RepeaterResponse,
) -> bool {
    let size = response.body.as_ref().map_or(0, |body| body.len() as u64);
    let body = response
        .body
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    (filter.statuses.is_empty() || filter.statuses.contains(&response.status))
        && filter.min_size.is_none_or(|min| size >= min)
        && filter.max_size.is_none_or(|max| size <= max)
        && filter
            .contains
            .as_ref()
            .is_none_or(|needle| body.contains(needle))
        && filter
            .regex
            .as_ref()
            .is_none_or(|pattern| Regex::new(pattern).is_ok_and(|regex| regex.is_match(&body)))
}

fn response_diff(
    previous: Option<&RepeaterResponse>,
    current: Option<&RepeaterResponse>,
) -> IntruderResponseDiff {
    let Some(current) = current else {
        return IntruderResponseDiff::default();
    };
    let Some(previous) = previous else {
        return IntruderResponseDiff {
            status_changed: false,
            size_changed: false,
            size_delta: 0,
            content_changed: false,
        };
    };
    let previous_size =
        i64::try_from(previous.body.as_ref().map_or(0, Vec::len)).unwrap_or(i64::MAX);
    let current_size = i64::try_from(current.body.as_ref().map_or(0, Vec::len)).unwrap_or(i64::MAX);
    IntruderResponseDiff {
        status_changed: previous.status != current.status,
        size_changed: previous_size != current_size,
        size_delta: current_size - previous_size,
        content_changed: previous.body != current.body,
    }
}

fn extract_tokens(
    step: &str,
    response: &RepeaterResponse,
    extractors: &[IntruderTokenExtractor],
    variables: &mut BTreeMap<String, String>,
) -> Result<(), Diagnostic> {
    let body = response
        .body
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default()
        .to_string();
    for extractor in extractors {
        let (variable, value) = match extractor {
            IntruderTokenExtractor::Header { variable, name } => (
                variable,
                response
                    .headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.clone()),
            ),
            IntruderTokenExtractor::Regex { variable, pattern } => (
                variable,
                Regex::new(pattern).ok().and_then(|regex| {
                    regex.captures(&body).and_then(|captures| {
                        captures
                            .get(1)
                            .or_else(|| captures.get(0))
                            .map(|value| value.as_str().to_owned())
                    })
                }),
            ),
            IntruderTokenExtractor::JsonPath { variable, path } => (
                variable,
                serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|mut value| {
                        for segment in path.split('.') {
                            value = value.get(segment)?.clone();
                        }
                        value.as_str().map(str::to_owned)
                    }),
            ),
        };
        let Some(value) = value else {
            return Err(sequence_diagnostic(step, "expected token was not found"));
        };
        variables.insert(variable.clone(), value);
    }
    Ok(())
}

fn inject_request(
    request: &RepeaterRequest,
    variables: &BTreeMap<String, String>,
) -> RepeaterRequest {
    let replace = |value: &str| {
        variables
            .iter()
            .fold(value.to_owned(), |value, (key, token)| {
                value.replace(&format!("{{{{{key}}}}}"), token)
            })
    };
    RepeaterRequest {
        method: replace(&request.method),
        url: replace(&request.url),
        headers: request
            .headers
            .iter()
            .map(|(name, value)| (replace(name), replace(value)))
            .collect(),
        body: request
            .body
            .as_ref()
            .map(|body| replace(&String::from_utf8_lossy(body)).into_bytes()),
    }
}

fn ffuf_url(
    request: &RepeaterRequest,
    positions: &[PayloadPosition],
) -> Result<String, Diagnostic> {
    let url_position = positions
        .iter()
        .find(|position| position.location == IntruderPositionLocation::Url)
        .ok_or_else(|| {
            intruder_config_diagnostic("ffuf", "ffuf requires a URL payload position")
        })?;
    let mut url = request.url.clone();
    replace_range(&mut url, url_position.start, url_position.end, "FUZZ")?;
    Ok(url)
}

fn request_with_ffuf_payload(request: &RepeaterRequest, payload: &str) -> RepeaterRequest {
    let replace = |value: &str| value.replace("FUZZ", payload);
    RepeaterRequest {
        method: request.method.clone(),
        url: replace(&request.url),
        headers: request
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), replace(value)))
            .collect(),
        body: request
            .body
            .as_ref()
            .map(|body| replace(&String::from_utf8_lossy(body)).into_bytes()),
    }
}

fn ffuf_payload(entry: &serde_json::Value) -> Option<String> {
    entry
        .get("input")
        .and_then(serde_json::Value::as_object)
        .and_then(|input| {
            input
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("FUZZ"))
                .and_then(|(_, value)| value.as_str())
                .or_else(|| {
                    input
                        .iter()
                        .find(|(key, _)| !key.eq_ignore_ascii_case("FFUFHASH"))
                        .and_then(|(_, value)| value.as_str())
                })
        })
        .map(str::to_owned)
}

fn request_host(url: &str) -> String {
    url.split_once("://")
        .map_or(url, |(_, remainder)| remainder)
        .split('/')
        .next()
        .unwrap_or("unknown")
        .rsplit('@')
        .next()
        .unwrap_or("unknown")
        .split(':')
        .next()
        .filter(|host| !host.is_empty())
        .unwrap_or("unknown")
        .to_owned()
}

struct FfufTempFiles {
    wordlist: std::path::PathBuf,
    output: std::path::PathBuf,
}

fn read_ffuf_json(path: &std::path::Path) -> Result<serde_json::Value, serde_json::Error> {
    let text = fs::read_to_string(path)
        .map_err(|error| serde_json::Error::io(std::io::Error::other(error.to_string())))?;
    serde_json::from_str(&text)
}

impl Drop for FfufTempFiles {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.wordlist);
        let _ = fs::remove_file(&self.output);
    }
}

fn validate_config(config: &IntruderConfig) -> Result<(), Diagnostic> {
    if config.positions.is_empty()
        || config.payload_sets.is_empty()
        || config.max_results == 0
        || config.concurrency == 0
        || config.base_request.method.is_empty()
        || config.base_request.url.is_empty()
    {
        return Err(intruder_config_diagnostic(
            "config",
            "request, positions, payload sets, concurrency, and max_results are required",
        ));
    }
    for position in &config.positions {
        if config.payload_sets.get(position.set_index).is_none() || position.start > position.end {
            return Err(intruder_config_diagnostic(
                "position",
                "position range or payload set is invalid",
            ));
        }
    }
    Ok(())
}

fn new_job_id() -> String {
    format!(
        "intruder-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    )
}

fn intruder_config_diagnostic(operation: &str, detail: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "operation".to_owned(),
        DiagnosticValue::String(operation.to_owned()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    catalogue::PROXY_INTRUDER_CONFIG_INVALID.instantiate(context)
}

/// Builds the honest observed-rate diagnostic comparing estimate vs. reality.
fn discovery_rate_diagnostic(
    candidates: usize,
    elapsed_seconds: f64,
    actual_rate: f64,
    estimated_rate: u32,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "candidates".to_owned(),
        DiagnosticValue::Integer(i64::try_from(candidates).unwrap_or(i64::MAX)),
    );
    let mut diagnostic = catalogue::WEB_DISCOVERY_RATE_OBSERVED.instantiate(context);
    diagnostic.why = format!(
        "Sent {candidates} probes in {elapsed_seconds:.1}s — actual ~{actual_rate:.1} req/s vs. estimated {estimated_rate} req/s."
    )
    .into();
    diagnostic
}

/// Wraps a rare send-task join failure (a panicked send future) as a stable
/// per-result diagnostic so one bad request cannot abort the whole attack.
fn intruder_task_diagnostic(detail: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    catalogue::PROXY_REPEATER_TRANSPORT_UNAVAILABLE.instantiate(context)
}

fn sequence_diagnostic(step: &str, detail: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert("step".to_owned(), DiagnosticValue::String(step.to_owned()));
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    catalogue::PROXY_INTRUDER_SEQUENCE_FAILED.instantiate(context)
}

fn outside_scope(url: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert("url".to_owned(), DiagnosticValue::String(url.to_owned()));
    catalogue::PROXY_INTRUDER_OUTSIDE_SCOPE.instantiate(context)
}

fn ffuf_unavailable(detail: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    catalogue::PROXY_INTRUDER_FFUF_UNAVAILABLE.instantiate(context)
}

/// A bundled ffuf binary is missing from a correct install. This is an
/// install-integrity failure with a concrete what/why/fix, not a host
/// prerequisite the operator forgot to install.
fn ffuf_install_missing(component: &str, path: &std::path::Path) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "component".to_owned(),
        DiagnosticValue::String(component.to_owned()),
    );
    context.insert(
        "expected_path".to_owned(),
        DiagnosticValue::String(path.display().to_string()),
    );
    let mut diagnostic = catalogue::INSTALL_COMPONENT_MISSING.instantiate(context);
    diagnostic.why = format!("bundled {component} was not found at {}", path.display()).into();
    diagnostic
}

fn ffuf_failed(operation: &str, detail: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "operation".to_owned(),
        DiagnosticValue::String(operation.to_owned()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    catalogue::PROXY_INTRUDER_FFUF_FAILED.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_workbench_store::{IntruderPositionLocation, PayloadSet};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn request() -> RepeaterRequest {
        RepeaterRequest {
            method: "GET".to_owned(),
            url: "https://api.example.test/items?id=FUZZ".to_owned(),
            headers: Vec::new(),
            body: None,
        }
    }

    fn config(attack_type: IntruderAttackType) -> IntruderConfig {
        IntruderConfig {
            base_request: request(),
            positions: vec![PayloadPosition {
                location: IntruderPositionLocation::Url,
                header_name: None,
                start: 34,
                end: 38,
                set_index: 0,
            }],
            payload_sets: vec![PayloadSet {
                name: "values".to_owned(),
                values: vec!["one".to_owned(), "two".to_owned()],
            }],
            attack_type,
            match_filter: apiaxess_workbench_store::IntruderMatchFilter::default(),
            concurrency: 1,
            rate_per_second: 0,
            max_results: 100,
            auth_preflight: None,
            sequence: Vec::new(),
            auto_calibrate: false,
        }
    }

    #[test]
    fn payload_expansion_applies_clusterbomb_values_by_set() {
        let mut attack = config(IntruderAttackType::Clusterbomb);
        attack.positions.push(PayloadPosition {
            location: IntruderPositionLocation::Url,
            header_name: None,
            start: 27,
            end: 31,
            set_index: 1,
        });
        attack.payload_sets.push(PayloadSet {
            name: "second".to_owned(),
            values: vec!["red".to_owned(), "blue".to_owned()],
        });
        let expanded = expand_attack(&attack).expect("expanded");
        assert_eq!(expanded.len(), 4);
        assert_eq!(expanded[0].0, vec!["one", "red"]);
        assert_eq!(expanded[3].0, vec!["two", "blue"]);
    }

    #[test]
    fn ffuf_results_use_the_fuzz_value_not_ffufhash() {
        let entry = serde_json::json!({
            "input": {
                "FFUFHASH": "a783f1",
                "FUZZ": "two"
            }
        });
        assert_eq!(ffuf_payload(&entry).as_deref(), Some("two"));
    }

    #[test]
    fn stateless_and_stateful_jobs_select_the_expected_tier() {
        let path = std::env::temp_dir().join(format!(
            "apiaxess-intruder-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let store = Arc::new(TrafficStore::open(&path, "session:test").expect("store"));
        let manager = IntruderWorkbench::new();
        manager.attach_store(Arc::clone(&store)).expect("attach");
        let stateless = manager
            .create(config(IntruderAttackType::Sniper))
            .expect("create");
        assert_eq!(stateless.tier, IntruderTier::Ffuf);
        let mut stateful_config = config(IntruderAttackType::Sniper);
        stateful_config.auth_preflight = Some(request());
        let stateful = manager.create(stateful_config).expect("create");
        assert_eq!(stateful.tier, IntruderTier::Native);
    }

    fn temp_store() -> Arc<TrafficStore> {
        let path = std::env::temp_dir().join(format!(
            "apiaxess-intruder-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        Arc::new(TrafficStore::open(&path, "session:test").expect("store"))
    }

    #[test]
    fn richer_configs_route_to_native_so_their_controls_take_effect() {
        let manager = IntruderWorkbench::new();
        manager.attach_store(temp_store()).expect("attach");
        // A content match rule cannot be expressed to ffuf faithfully.
        let mut contains = config(IntruderAttackType::Sniper);
        contains.match_filter.contains = Some("token".to_owned());
        assert_eq!(
            manager.create(contains).expect("create").tier,
            IntruderTier::Native
        );
        // Multiple positions/sets (Clusterbomb) exceed ffuf's single-FUZZ model.
        let mut multi = config(IntruderAttackType::Clusterbomb);
        multi.positions.push(PayloadPosition {
            location: IntruderPositionLocation::Url,
            header_name: None,
            start: 27,
            end: 31,
            set_index: 1,
        });
        multi.payload_sets.push(PayloadSet {
            name: "second".to_owned(),
            values: vec!["red".to_owned()],
        });
        assert_eq!(
            manager.create(multi).expect("create").tier,
            IntruderTier::Native
        );
        // A status-only filter still rides the fast ffuf path (passed via -mc).
        let mut status_only = config(IntruderAttackType::Sniper);
        status_only.match_filter.statuses = vec![200, 301];
        assert_eq!(
            manager.create(status_only).expect("create").tier,
            IntruderTier::Ffuf
        );
    }

    #[tokio::test]
    async fn native_attack_runs_every_payload_with_bounded_concurrency() {
        use std::sync::atomic::AtomicUsize;

        struct CountingSender {
            count: Arc<AtomicUsize>,
        }
        impl RepeaterSender for CountingSender {
            fn send(
                &self,
                _request: RepeaterRequest,
            ) -> crate::backend::BackendFuture<Result<RepeaterResponse, Diagnostic>> {
                let count = Arc::clone(&self.count);
                Box::pin(async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(RepeaterResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: Some(b"ok".to_vec()),
                        duration_ms: 1,
                    })
                })
            }
        }

        let manager = Arc::new(IntruderWorkbench::new());
        manager.attach_store(temp_store()).expect("attach");
        let count = Arc::new(AtomicUsize::new(0));
        manager.attach_sender(Arc::new(CountingSender {
            count: Arc::clone(&count),
        }));

        // A content match rule forces the native tier; five payloads, width 3.
        let mut attack = config(IntruderAttackType::Sniper);
        attack.match_filter.contains = Some("ok".to_owned());
        attack.concurrency = 3;
        attack.payload_sets[0].values = (0..5).map(|index| format!("p{index}")).collect();
        let job = manager.create(attack).expect("create");
        assert_eq!(job.tier, IntruderTier::Native);

        let launched = manager.launch(&job.id).expect("launch");
        let mut finished = None;
        for _ in 0..200 {
            let current = manager.get(&launched.id).expect("job present");
            if matches!(current.state, IntruderJobState::Completed) {
                finished = Some(current);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let finished = finished.expect("attack reaches completion");
        assert_eq!(finished.results.len(), 5);
        assert_eq!(count.load(Ordering::SeqCst), 5);
        // Ordinals stay stable and sequential despite concurrent sends.
        for (index, result) in finished.results.iter().enumerate() {
            assert_eq!(result.ordinal, u64::try_from(index + 1).unwrap());
            assert!(result.matched, "body 'ok' satisfies the content filter");
        }
    }
}
