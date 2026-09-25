//! Automated stateless and stateful request attacks.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
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
    DelayPolicy, ExtractLocator, FlowOrigin, FuzzerAttackType, FuzzerConfig, FuzzerJob,
    FuzzerJobState, FuzzerPositionLocation, FuzzerProgress, FuzzerResponseDiff, FuzzerResult,
    FuzzerTier, FuzzerTokenExtractor, GrepConfig, GrepReflectedConfig, PayloadPosition, PayloadSet,
    PayloadSource, RedirectMode, ResendRequest, ResendResponse, TrafficStore,
};
use regex::{Regex, RegexBuilder};

use crate::{
    ResendSender, SendOptions, SendOutcome,
    backend::ORIGIN_MARKER_HEADER,
    payloads::{Cardinality, generate_processed, set_cardinality, validate_set},
    raw_http::{WIRE_HEADERS_MARKER, encode_header_list},
    resend::{url_target, wire_header_list},
};

/// The keyword ffuf substitutes. ffuf replaces its keyword anywhere in the
/// request — URL, headers, body — so it must never occur there by accident:
/// `_` is outside the base64 alphabet of the wire-headers marker, and a
/// template is vanishingly unlikely to contain this literally (unlike `FUZZ`).
const FFUF_KEYWORD: &str = "APIAXESS_FFUF_POINT";

/// One generated attack request paired with the payload values that produced it.
type PlannedRequest = (Vec<String>, ResendRequest);
/// A lazy, fallible stream of planned attack requests.
type AttackPlan = Box<dyn Iterator<Item = Result<PlannedRequest, Diagnostic>> + Send>;

/// Session-scoped fuzzer job manager.
pub struct FuzzerWorkbench {
    store: RwLock<Option<Arc<TrafficStore>>>,
    sender: RwLock<Option<Arc<dyn ResendSender>>>,
    scope: RwLock<Option<EngagementScope>>,
    jobs: Mutex<BTreeMap<String, FuzzerJob>>,
    controls: Mutex<BTreeMap<String, Arc<JobControl>>>,
    ffuf_proxy: RwLock<Option<std::net::SocketAddr>>,
}

impl std::fmt::Debug for FuzzerWorkbench {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FuzzerWorkbench")
            .field("job_count", &self.list().len())
            .finish_non_exhaustive()
    }
}

impl Default for FuzzerWorkbench {
    fn default() -> Self {
        Self::new()
    }
}

impl FuzzerWorkbench {
    /// Creates an empty fuzzer surface.
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
        let jobs = store.fuzzer_jobs()?;
        if let Ok(mut current) = self.store.write() {
            *current = Some(store);
        }
        if let Ok(mut current) = self.jobs.lock() {
            current.clear();
            current.extend(jobs.into_iter().map(|job| (job.id.clone(), job)));
        }
        Ok(())
    }

    /// Attaches the same routed sender used by the resend.
    pub fn attach_sender(&self, sender: Arc<dyn ResendSender>) {
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

    /// Records one completed fuzzer result in the active session audit trail.
    ///
    /// The result itself remains in the durable fuzzer job; this method adds
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
            .ok_or_else(|| fuzzer_config_diagnostic("audit", "job not found"))?;
        let result = job
            .results
            .iter()
            .find(|result| result.ordinal == ordinal)
            .ok_or_else(|| fuzzer_config_diagnostic("audit", "result not found"))?;
        let outcome = if result.diagnostic.is_some() {
            ActionOutcome::Failed
        } else {
            ActionOutcome::Completed
        };
        session.record_action(ActionRecordInput {
            id: format!("fuzzer:{job_id}:{}", result.ordinal),
            occurred_at: chrono::Utc::now(),
            actor: AuditActor::User,
            action: ActionDescriptor {
                kind: "workbench.fuzzer.send".to_owned(),
                summary: format!("Sent fuzzer result {}", result.ordinal),
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
    pub fn list(&self) -> Vec<FuzzerJob> {
        self.jobs
            .lock()
            .map(|jobs| jobs.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Reads one job.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<FuzzerJob> {
        self.jobs.lock().ok().and_then(|jobs| jobs.get(id).cloned())
    }

    /// Removes one job from the queue and the durable store, cancelling it first
    /// if it is currently running.
    ///
    /// # Errors
    ///
    /// Returns a persistence diagnostic when the durable store cannot be written.
    pub fn remove(&self, id: &str) -> Result<(), Diagnostic> {
        if let Ok(controls) = self.controls.lock() {
            if let Some(control) = controls.get(id) {
                control.cancelled.store(true, Ordering::Release);
                control.notify.notify_waiters();
            }
        }
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.remove(id);
        }
        if let Ok(mut controls) = self.controls.lock() {
            controls.remove(id);
        }
        if let Some(store) = self.store.read().ok().and_then(|store| store.clone()) {
            store.remove_fuzzer(id)?;
        }
        Ok(())
    }

    /// Validates and persists a new attack configuration.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration or persistence diagnostic.
    pub fn create(&self, config: FuzzerConfig) -> Result<FuzzerJob, Diagnostic> {
        validate_config(&config)?;
        // ffuf can only faithfully execute a single URL-position Sniper sweep
        // with one payload set and a status-only match filter (passed via -mc).
        // Anything richer — multiple positions/sets, body/header positions,
        // Clusterbomb/Pitchfork, size/content match rules, or a stateful
        // sequence — must run on the native sender so the configured controls
        // actually take effect rather than being silently dropped.
        let filter = &config.match_filter;
        // ffuf can only replay a caller-supplied wordlist verbatim. A generated
        // source (Numbers, Brute forcer, …) or any processing pipeline / URL
        // encoding cannot be expressed to ffuf faithfully, so those route to the
        // native sender where the real payload engine runs.
        let plain_simple_set = config
            .payload_sets
            .first()
            .is_some_and(is_plain_simple_list);
        // Grep (match rules / extracts / reflected) and a Recursive-grep set
        // cannot be expressed to ffuf; they force the native tier.
        let grep = &config.grep;
        let grep_inert =
            grep.match_rules.is_empty() && grep.extract_rules.is_empty() && !grep.reflected.enabled;
        let has_recursive_grep = config
            .payload_sets
            .iter()
            .any(|set| matches!(set.source, PayloadSource::RecursiveGrep { .. }));
        // Attack settings ffuf cannot express faithfully (per-request retries,
        // interval/random delay, scope-aware redirect following, connection-close,
        // or leaving Content-Length un-recomputed) force the native tier. The
        // default settings (no-follow redirects, no retries, fixed rate, recompute
        // Content-Length) are ffuf-compatible.
        let default_attack_settings = matches!(config.delay, DelayPolicy::Fixed { .. })
            && config.retry.max_retries == 0
            && !config.connection_close
            && config.update_content_length
            && config.redirect.mode == RedirectMode::Never
            && !config.redirect.process_cookies;
        // ffuf takes the body as a `-d` string, so only a UTF-8 body can be
        // carried byte-for-byte.
        let body_carriable = config
            .base_request
            .body
            .as_deref()
            .is_none_or(|body| std::str::from_utf8(body).is_ok());
        let ffuf_capable = config.sequence.is_empty()
            && body_carriable
            && config.auth_preflight.is_none()
            && config.positions.len() == 1
            && config.positions[0].location == FuzzerPositionLocation::Url
            && config.payload_sets.len() == 1
            && plain_simple_set
            && config.attack_type == FuzzerAttackType::Sniper
            && grep_inert
            && !has_recursive_grep
            && default_attack_settings
            && filter.min_size.is_none()
            && filter.max_size.is_none()
            && filter.contains.is_none()
            && filter.regex.is_none();
        let tier = if ffuf_capable {
            FuzzerTier::Ffuf
        } else {
            FuzzerTier::Native
        };
        let job = FuzzerJob {
            id: new_job_id(),
            created_at: chrono::Utc::now(),
            tier,
            state: FuzzerJobState::Pending,
            config,
            results: Vec::new(),
            diagnostics: Vec::new(),
            progress: None,
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
    pub fn launch(self: &Arc<Self>, id: &str) -> Result<FuzzerJob, Diagnostic> {
        let mut job = self
            .get(id)
            .ok_or_else(|| fuzzer_config_diagnostic("launch", "job not found"))?;
        if matches!(job.state, FuzzerJobState::Running) {
            return Err(fuzzer_config_diagnostic("launch", "job is already running"));
        }
        job.state = FuzzerJobState::Running;
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
    ) -> Result<FuzzerJob, Diagnostic> {
        let job = self.launch(id)?;
        session.record_action(ActionRecordInput {
            id: format!("fuzzer:{id}:launch"),
            occurred_at: chrono::Utc::now(),
            actor: AuditActor::User,
            action: ActionDescriptor {
                kind: "workbench.fuzzer.launch".to_owned(),
                summary: format!("Launched fuzzer job {id}"),
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
    pub fn pause(&self, id: &str) -> Result<FuzzerJob, Diagnostic> {
        let job = self
            .get(id)
            .ok_or_else(|| fuzzer_config_diagnostic("pause", "job not found"))?;
        let control = self.control(id)?;
        control.paused.store(true, Ordering::Release);
        let mut paused = job;
        paused.state = FuzzerJobState::Paused;
        self.persist(&paused)?;
        self.replace(paused.clone());
        Ok(paused)
    }

    /// Resumes a paused job.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle diagnostic when no running control exists.
    pub fn resume(&self, id: &str) -> Result<FuzzerJob, Diagnostic> {
        let job = self
            .get(id)
            .ok_or_else(|| fuzzer_config_diagnostic("resume", "job not found"))?;
        let control = self.control(id)?;
        control.paused.store(false, Ordering::Release);
        control.notify.notify_waiters();
        let mut running = job;
        running.state = FuzzerJobState::Running;
        self.persist(&running)?;
        self.replace(running.clone());
        Ok(running)
    }

    /// Stops a running job and requests clean cancellation.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle or persistence diagnostic.
    pub fn stop(&self, id: &str) -> Result<FuzzerJob, Diagnostic> {
        let job = self
            .get(id)
            .ok_or_else(|| fuzzer_config_diagnostic("stop", "job not found"))?;
        let control = self.control(id)?;
        control.cancelled.store(true, Ordering::Release);
        control.notify.notify_waiters();
        let mut stopped = job;
        stopped.state = FuzzerJobState::Stopped;
        stopped
            .diagnostics
            .push(catalogue::PROXY_FUZZER_CANCELLED.instantiate(DiagnosticContext::new()));
        self.persist(&stopped)?;
        self.replace(stopped.clone());
        Ok(stopped)
    }

    /// Sets (or clears) a user comment on one result row, then persists. This is
    /// an infrequent user action, so the synchronous persist is off the attack
    /// hot path and does not touch the F-A cadence.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the job or result ordinal is absent, or the
    /// durable store cannot be written.
    pub fn set_result_comment(
        &self,
        id: &str,
        ordinal: u64,
        comment: Option<String>,
    ) -> Result<FuzzerJob, Diagnostic> {
        let mut job = self
            .get(id)
            .ok_or_else(|| fuzzer_config_diagnostic("comment", "job not found"))?;
        let result = job
            .results
            .iter_mut()
            .find(|result| result.ordinal == ordinal)
            .ok_or_else(|| fuzzer_config_diagnostic("comment", "result not found"))?;
        result.comment = comment.filter(|text| !text.is_empty());
        self.persist(&job)?;
        self.replace(job.clone());
        Ok(job)
    }

    async fn run_job(&self, id: &str, control: Arc<JobControl>) -> Result<(), Diagnostic> {
        let job = self
            .get(id)
            .ok_or_else(|| fuzzer_config_diagnostic("run", "job disappeared"))?;
        if job.tier == FuzzerTier::Ffuf {
            self.run_ffuf(job, control).await
        } else if job
            .config
            .payload_sets
            .iter()
            .any(|set| matches!(set.source, PayloadSource::RecursiveGrep { .. }))
        {
            self.run_recursive(job, control).await
        } else {
            self.run_native(job, control).await
        }
    }

    async fn run_native(
        &self,
        mut job: FuzzerJob,
        control: Arc<JobControl>,
    ) -> Result<(), Diagnostic> {
        // Attack expansion is a bounded lazy stream: Numbers/Brute/Cluster spaces
        // can be astronomically large, so requests are generated on demand and we
        // stop pulling once `max_results` is produced — the whole plan is never
        // materialized up front.
        let mut plan = match plan_attack(&job.config) {
            Ok(plan) => plan,
            Err(diagnostic) => return self.finish_failed(&job, diagnostic),
        };
        let sender = self.sender.read().ok().and_then(|sender| sender.clone());
        let Some(sender) = sender else {
            return self.finish_failed(
                &job,
                catalogue::PROXY_RESEND_TRANSPORT_UNAVAILABLE.instantiate(DiagnosticContext::new()),
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
        let delay = job.config.delay;
        let options = self.send_options(&job.config);
        let mut rng = DelayRng::new();
        // Compile grep rules once per run (regexes precompiled), off the hot
        // persist path; a bad grep regex fails the job up front.
        let grep = match GrepContext::compile(&job.config.grep) {
            Ok(grep) => grep,
            Err(diagnostic) => return self.finish_failed(&job, diagnostic),
        };
        let mut prior = None;
        let mut produced = 0usize;
        let mut cadence = PersistCadence::new();
        loop {
            if control.cancelled.load(Ordering::Acquire) {
                break;
            }
            control.wait_if_paused().await;
            if control.cancelled.load(Ordering::Acquire) {
                break;
            }
            // Pull the next bounded batch from the lazy plan, honoring the result
            // cap during expansion rather than generating everything and slicing.
            let mut batch: Vec<PlannedRequest> = Vec::with_capacity(concurrency);
            while batch.len() < concurrency && produced < job.config.max_results {
                match plan.next() {
                    Some(Ok(request)) => {
                        batch.push(request);
                        produced += 1;
                    }
                    Some(Err(diagnostic)) => return self.finish_failed(&job, diagnostic),
                    None => break,
                }
            }
            if batch.is_empty() {
                break;
            }
            // The delay policy paces dispatch; within a stateless batch, sends overlap.
            let outcomes = self
                .dispatch_batch(
                    &job.config,
                    &batch,
                    stateful,
                    delay,
                    &mut rng,
                    &options,
                    &sender,
                )
                .await;
            // Record in ordinal order so diffs and history stay stable.
            self.record_batch(&mut job, &batch, outcomes, &mut prior, &mut cadence, &grep)
                .await?;
        }
        job.state = if control.cancelled.load(Ordering::Acquire) {
            FuzzerJobState::Stopped
        } else {
            FuzzerJobState::Completed
        };
        // Guaranteed final durable persist at the terminal state, regardless of
        // cadence, so the finished job is always fully on disk.
        self.persist_off_runtime(&job).await?;
        self.replace(job);
        Ok(())
    }

    /// Runs a Recursive-grep attack: strictly sequential, each request's payload
    /// fed forward from the first grep-extract value of the previous response.
    /// The seed values prime the queue; the run stops when the extract yields
    /// nothing new or `max_results` is reached. Results (including grep columns)
    /// are recorded through the shared `record_batch` path.
    async fn run_recursive(
        &self,
        mut job: FuzzerJob,
        control: Arc<JobControl>,
    ) -> Result<(), Diagnostic> {
        let sender = self.sender.read().ok().and_then(|sender| sender.clone());
        let Some(sender) = sender else {
            return self.finish_failed(
                &job,
                catalogue::PROXY_RESEND_TRANSPORT_UNAVAILABLE.instantiate(DiagnosticContext::new()),
            );
        };
        let grep = match GrepContext::compile(&job.config.grep) {
            Ok(grep) => grep,
            Err(diagnostic) => return self.finish_failed(&job, diagnostic),
        };
        let seeds = job
            .config
            .payload_sets
            .iter()
            .find_map(|set| match &set.source {
                PayloadSource::RecursiveGrep { seed } => Some(seed.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let mut queue: VecDeque<String> = seeds.into();
        if queue.is_empty() {
            // No seed: one empty-payload request still primes the recursion.
            queue.push_back(String::new());
        }
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut prior = None;
        let mut cadence = PersistCadence::new();
        let delay = job.config.delay;
        let options = self.send_options(&job.config);
        let mut rng = DelayRng::new();
        while job.results.len() < job.config.max_results {
            if control.cancelled.load(Ordering::Acquire) {
                break;
            }
            control.wait_if_paused().await;
            if control.cancelled.load(Ordering::Acquire) {
                break;
            }
            let Some(payload) = queue.pop_front() else {
                break;
            };
            if !seen.insert(payload.clone()) {
                continue;
            }
            let request = match build_recursive_request(&job.config, &payload) {
                Ok(request) => request,
                Err(diagnostic) => return self.finish_failed(&job, diagnostic),
            };
            apply_delay(delay, &mut rng).await;
            let outcome = sender
                .send_with_options(request.clone(), options.clone())
                .await
                .unwrap_or_else(|error| SendOutcome {
                    response: None,
                    diagnostic: Some(error),
                    redirect_chain: Vec::new(),
                    retry_count: 0,
                });
            let batch = vec![(vec![payload], request)];
            self.record_batch(
                &mut job,
                &batch,
                vec![outcome],
                &mut prior,
                &mut cadence,
                &grep,
            )
            .await?;
            // Feed the extracted value forward as the next payload.
            if let Some(next) = job
                .results
                .last()
                .and_then(|result| result.response.as_ref())
                .and_then(|response| grep.recursive_next(response))
                && !seen.contains(&next)
            {
                queue.push_back(next);
            }
        }
        job.state = if control.cancelled.load(Ordering::Acquire) {
            FuzzerJobState::Stopped
        } else {
            FuzzerJobState::Completed
        };
        self.persist_off_runtime(&job).await?;
        self.replace(job);
        Ok(())
    }

    /// Sends one batch of planned requests. A stateful job runs its requests
    /// strictly in order through the token-chain sequence; a stateless batch
    /// fans them out concurrently. Rate limiting paces each dispatch.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_batch(
        &self,
        config: &FuzzerConfig,
        batch: &[(Vec<String>, ResendRequest)],
        stateful: bool,
        delay: DelayPolicy,
        rng: &mut DelayRng,
        options: &SendOptions,
        sender: &Arc<dyn ResendSender>,
    ) -> Vec<SendOutcome> {
        let mut outcomes = Vec::with_capacity(batch.len());
        if stateful {
            // Token-chain sequences run strictly in order; redirect/retry policy
            // is applied to the individual step sends by the sequence path.
            for (_, request) in batch {
                apply_delay(delay, rng).await;
                let result = self.send_sequence(config, request, &**sender).await;
                outcomes.push(plain_outcome(result));
            }
        } else {
            let mut handles = Vec::with_capacity(batch.len());
            for (_, request) in batch {
                apply_delay(delay, rng).await;
                let sender = Arc::clone(sender);
                let request = request.clone();
                let options = options.clone();
                handles.push(tokio::spawn(async move {
                    sender.send_with_options(request, options).await
                }));
            }
            for handle in handles {
                let outcome = match handle.await {
                    Ok(Ok(outcome)) => outcome,
                    Ok(Err(error)) => plain_outcome(Err(error)),
                    Err(error) => plain_outcome(Err(fuzzer_task_diagnostic(&error.to_string()))),
                };
                outcomes.push(outcome);
            }
        }
        outcomes
    }

    /// Records one dispatched batch's responses onto the job in ordinal order,
    /// classifying scope, computing the response diff against the prior result,
    /// applying the match filter, and persisting after each result.
    async fn record_batch(
        &self,
        job: &mut FuzzerJob,
        batch: &[(Vec<String>, ResendRequest)],
        outcomes: Vec<SendOutcome>,
        prior: &mut Option<ResendResponse>,
        cadence: &mut PersistCadence,
        grep: &GrepContext,
    ) -> Result<(), Diagnostic> {
        for ((payloads, request), outcome) in batch.iter().zip(outcomes) {
            let SendOutcome {
                response,
                diagnostic,
                redirect_chain,
                retry_count,
            } = outcome;
            let scope = self.classify_scope(&request.url);
            let diff = response_diff(prior.as_ref(), response.as_ref());
            let matched = response
                .as_ref()
                .is_some_and(|response| matches_filter(&job.config.match_filter, response));
            // Grep is additive: it annotates the result without touching matched.
            let grep_outcome = response.as_ref().map_or_else(
                || grep.empty_outcome(),
                |response| grep.evaluate(response, payloads),
            );
            let timeout = diagnostic.as_ref().is_some_and(is_timeout_diagnostic);
            let mut diagnostics = Vec::new();
            if scope == ScopeDisposition::OutsideDeclaredScope {
                diagnostics.push(outside_scope(&request.url));
            }
            if let Some(diagnostic) = diagnostic.clone() {
                diagnostics.push(diagnostic.clone());
            }
            let ordinal = job.results.len() + 1;
            job.results.push(FuzzerResult {
                ordinal: u64::try_from(ordinal).unwrap_or(u64::MAX),
                payloads: payloads.clone(),
                request: request.clone(),
                response: response.clone(),
                matched,
                filtered: !matched,
                diff,
                scope,
                diagnostic,
                timeout,
                comment: None,
                grep_match_counts: grep_outcome.match_counts,
                grep_extracts: grep_outcome.extracts,
                reflected_count: grep_outcome.reflected,
                redirect_chain,
                retry_count,
            });
            *prior = response;
            // Live polling reflects every result immediately, in place (no full
            // job clone). Durable persistence is throttled below.
            if let Some(pushed) = job.results.last() {
                self.push_live_result(&job.id, pushed, &diagnostics);
            }
            job.diagnostics.extend(diagnostics);
        }
        // Durable checkpoint, off the runtime and gated by cadence, so a long
        // attack neither blocks the async workers nor re-serializes the whole job
        // after every result.
        if cadence.due(batch.len()) {
            self.persist_off_runtime(job).await?;
        }
        Ok(())
    }

    async fn send_sequence(
        &self,
        config: &FuzzerConfig,
        first_request: &ResendRequest,
        sender: &dyn ResendSender,
    ) -> Result<ResendResponse, Diagnostic> {
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
    async fn run_ffuf(&self, job: FuzzerJob, control: Arc<JobControl>) -> Result<(), Diagnostic> {
        let proxy = self
            .ffuf_proxy
            .read()
            .ok()
            .and_then(|proxy| *proxy)
            .ok_or_else(|| {
                catalogue::PROXY_FUZZER_FFUF_UNAVAILABLE.instantiate(DiagnosticContext::new())
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
            .map(|set| simple_values(set).join("\n"))
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
            format!("{}:{FFUF_KEYWORD}", wordlist.display()),
            "-X".to_owned(),
            job.config.base_request.method.clone(),
            "-of".to_owned(),
            "json".to_owned(),
            "-o".to_owned(),
            output.display().to_string(),
            "-noninteractive".to_owned(),
            "-x".to_owned(),
            format!("http://{proxy}"),
            // ffuf runs as an external process and so bypasses the OriginTaggingSender
            // that stamps native fuzz requests. Send the same private origin marker
            // header on every ffuf probe so the proxy tags these flows `Fuzz` and
            // strips the marker before forwarding — keeping ffuf traffic out of the
            // Live list and the fused surface exactly like native fuzz traffic.
            "-H".to_owned(),
            ffuf_origin_header(),
            // ffuf (Go) canonicalizes header names, sorts them, and adds its own
            // User-Agent and Accept-Encoding, so template headers passed as `-H`
            // would not go out as authored. Instead it carries the exact list the
            // native tier sends in the private wire-headers marker; the proxy
            // strips the marker and writes that list upstream byte-for-byte, so
            // both tiers put the same request on the wire — and the inspector's
            // "as sent" view (the same derivation) is true for both.
            "-H".to_owned(),
            ffuf_wire_headers(&job.config.base_request, &job.config.positions),
        ];
        if let Some(body) = job
            .config
            .base_request
            .body
            .as_deref()
            .filter(|body| !body.is_empty())
        {
            // UTF-8 is guaranteed by the tier check.
            arguments.push("-d".to_owned());
            arguments.push(String::from_utf8_lossy(body).into_owned());
        }
        // Honor the configured throttle so the run matches its pre-run estimate
        // rather than firing unbounded at ffuf's default thread count. The ffuf
        // tier only runs a Fixed delay (the tier check enforces this).
        let ffuf_rate = fixed_rate(job.config.delay);
        if ffuf_rate > 0 {
            arguments.push("-rate".to_owned());
            arguments.push(ffuf_rate.to_string());
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
        let mut cadence = PersistCadence::new();
        // ffuf reports only matched hits (at completion), so its result count
        // alone reads "Sent 0" the whole run. Parse the tool's own live progress
        // line from stderr and surface it as attempt-level progress instead (#16b).
        let total_candidates = u64::try_from(
            completed
                .config
                .payload_sets
                .first()
                .map_or(0, |set| simple_values(set).len()),
        )
        .unwrap_or(u64::MAX);
        loop {
            if control.cancelled.load(Ordering::Acquire) {
                process
                    .stop()
                    .map_err(|error| ffuf_failed("stop", &error.to_string()))?;
                completed.state = FuzzerJobState::Stopped;
                if completed.diagnostics.iter().all(|diagnostic| {
                    diagnostic.id.as_ref() != catalogue::PROXY_FUZZER_CANCELLED.id
                }) {
                    completed.diagnostics.push(
                        catalogue::PROXY_FUZZER_CANCELLED.instantiate(DiagnosticContext::new()),
                    );
                }
                self.persist_off_runtime(&completed).await?;
                self.replace(completed);
                return Ok(());
            }
            if let Ok(parsed) = read_ffuf_json(&output) {
                self.append_ffuf_results(&mut completed, &parsed, &mut seen, &mut cadence)
                    .await?;
            }
            if let Some(sent) = parse_ffuf_progress(&process.stderr()) {
                let progress = FuzzerProgress {
                    sent: sent.min(total_candidates),
                    total: total_candidates,
                };
                completed.progress = Some(progress);
                self.set_live_progress(&completed.id, progress);
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
        self.append_ffuf_results(&mut completed, &parsed, &mut seen, &mut cadence)
            .await?;
        completed.state = FuzzerJobState::Completed;
        // A finished sweep sent every candidate; the result set now stands on its
        // own, so progress is cleared rather than left mid-count.
        completed.progress = None;
        // Report the actual achieved request rate so the pre-run estimate can be
        // judged honestly against reality (the estimate is latency-bound and
        // often lower than an unrouted ffuf; this closes that gap).
        let candidates = completed
            .config
            .payload_sets
            .first()
            .map_or(0, |set| simple_values(set).len());
        if candidates > 0 {
            let elapsed = started.elapsed().as_secs_f64().max(0.001);
            let actual_rate = f64::from(u32::try_from(candidates).unwrap_or(u32::MAX)) / elapsed;
            completed.diagnostics.push(rate_observed_diagnostic(
                candidates,
                elapsed,
                actual_rate,
                fixed_rate(completed.config.delay),
                completed.config.auto_calibrate,
            ));
        }
        self.persist_off_runtime(&completed).await?;
        self.replace(completed);
        Ok(())
    }

    async fn append_ffuf_results(
        &self,
        job: &mut FuzzerJob,
        json: &serde_json::Value,
        seen: &mut usize,
        cadence: &mut PersistCadence,
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
                .map(|set| simple_values(set).iter().map(String::as_str).collect())
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
            let request = request_with_ffuf_payload(
                &job.config.base_request,
                &job.config.positions,
                &payload,
            );
            let response = entry
                .get("status")
                .and_then(serde_json::Value::as_u64)
                .and_then(|status| u16::try_from(status).ok())
                .map(|status| {
                    // ffuf does not inline the response body in JSON by default, so
                    // surface its measured response `length` as a Content-Length
                    // header — the honest wire size the GUI's Length column reads —
                    // rather than leaving the row's length blank (F20 parity).
                    let mut headers = Vec::new();
                    if let Some(length) = entry.get("length").and_then(serde_json::Value::as_u64) {
                        headers.push(("content-length".to_owned(), length.to_string()));
                    }
                    ResendResponse {
                        status,
                        headers,
                        body: entry
                            .get("content")
                            .and_then(serde_json::Value::as_str)
                            .map(|body| body.as_bytes().to_vec()),
                        duration_ms: entry
                            .get("duration")
                            .and_then(serde_json::Value::as_u64)
                            .map_or(0, |nanos| nanos / 1_000_000),
                        http_version: None,
                        reason: None,
                    }
                });
            let matched = response
                .as_ref()
                .is_some_and(|response| matches_filter(&job.config.match_filter, response));
            let scope = self.classify_scope(&request.url);
            let mut new_diagnostics = Vec::new();
            if scope == ScopeDisposition::OutsideDeclaredScope {
                new_diagnostics.push(outside_scope(&request.url));
            }
            job.diagnostics.extend(new_diagnostics.iter().cloned());
            let prior = job
                .results
                .last()
                .and_then(|result| result.response.as_ref());
            job.results.push(FuzzerResult {
                ordinal: u64::try_from(job.results.len() + 1).unwrap_or(u64::MAX),
                payloads: vec![payload],
                request,
                diff: response_diff(prior, response.as_ref()),
                response,
                matched,
                filtered: !matched,
                scope,
                diagnostic: None,
                timeout: false,
                comment: None,
                grep_match_counts: Vec::new(),
                grep_extracts: Vec::new(),
                reflected_count: None,
                redirect_chain: Vec::new(),
                retry_count: 0,
            });
            // Mirror the new result into the live job in place (no full clone) so
            // the polling UI advances promptly while durable writes stay throttled.
            if let Some(pushed) = job.results.last() {
                self.push_live_result(&job.id, pushed, &new_diagnostics);
            }
            if job.results.len() >= job.config.max_results {
                break;
            }
        }
        *seen = consumed;
        // Durable checkpoint only when new results landed and the cadence is due;
        // run_ffuf issues a guaranteed final persist at the terminal state.
        if *seen > previous_seen && cadence.due(consumed - previous_seen) {
            self.persist_off_runtime(job).await?;
        }
        Ok(())
    }

    fn finish_failed(&self, job: &FuzzerJob, diagnostic: Diagnostic) -> Result<(), Diagnostic> {
        let mut failed = job.clone();
        failed.state = FuzzerJobState::Failed;
        failed.diagnostics.push(diagnostic);
        self.persist(&failed)?;
        self.replace(failed);
        Ok(())
    }

    fn append_job_diagnostic(&self, id: &str, diagnostic: Diagnostic) {
        if let Some(mut job) = self.get(id) {
            job.state = FuzzerJobState::Failed;
            job.diagnostics.push(diagnostic);
            if self.persist(&job).is_ok() {
                self.replace(job);
            }
        }
    }

    fn persist(&self, job: &FuzzerJob) -> Result<(), Diagnostic> {
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return Err(
                catalogue::PROXY_FUZZER_PERSISTENCE_FAILED.instantiate(DiagnosticContext::new())
            );
        };
        store.upsert_fuzzer(job)
    }

    /// Persists a job durably WITHOUT blocking a runtime worker.
    ///
    /// [`TrafficStore::upsert_fuzzer`] re-serializes the whole job and does a
    /// synchronous `SQLite` write under the store-wide connection mutex. Running
    /// that directly inside the async attack loops (`run_native` / `run_ffuf`)
    /// pins a worker thread for the duration of the write, and with several jobs
    /// persisting after every result the worker pool starves — even a plain
    /// `GET /` then stalls for seconds. Offloading to `spawn_blocking` keeps the
    /// blocking IO off the async workers. Callers gate this behind [`PersistCadence`]
    /// so the full-job serialization cost stays bounded rather than O(n^2).
    async fn persist_off_runtime(&self, job: &FuzzerJob) -> Result<(), Diagnostic> {
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return Err(
                catalogue::PROXY_FUZZER_PERSISTENCE_FAILED.instantiate(DiagnosticContext::new())
            );
        };
        let job = job.clone();
        tokio::task::spawn_blocking(move || store.upsert_fuzzer(&job))
            .await
            .map_err(|error| fuzzer_task_diagnostic(&error.to_string()))?
    }

    fn replace(&self, job: FuzzerJob) {
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(job.id.clone(), job);
        }
    }

    /// Mirrors one freshly-recorded result into the live in-memory job that
    /// `get`/`list` serve to the polling UI, updating it IN PLACE.
    ///
    /// This replaces the former `replace(job.clone())` after every result, which
    /// cloned the entire growing job on each call (O(n^2) churn over a job). Here
    /// only the single new result and any new diagnostics are appended, so live
    /// polling still reflects every result promptly at O(1) amortized cost.
    fn push_live_result(
        &self,
        job_id: &str,
        result: &FuzzerResult,
        new_diagnostics: &[Diagnostic],
    ) {
        if let Ok(mut jobs) = self.jobs.lock()
            && let Some(live) = jobs.get_mut(job_id)
        {
            live.results.push(result.clone());
            live.diagnostics.extend(new_diagnostics.iter().cloned());
        }
    }

    /// Updates a running job's live progress in place, so the polling GUI shows
    /// a truthful "Sent N of M" for a tier (ffuf) whose result rows do not
    /// arrive one-per-attempt.
    fn set_live_progress(&self, job_id: &str, progress: FuzzerProgress) {
        if let Ok(mut jobs) = self.jobs.lock()
            && let Some(live) = jobs.get_mut(job_id)
        {
            live.progress = Some(progress);
        }
    }

    fn control(&self, id: &str) -> Result<Arc<JobControl>, Diagnostic> {
        self.controls
            .lock()
            .ok()
            .and_then(|controls| controls.get(id).cloned())
            .ok_or_else(|| fuzzer_config_diagnostic("control", "job is not running"))
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

    /// Builds the per-send attack settings for a job, capturing the engagement
    /// scope in an in-scope predicate for `RedirectMode::InScope`.
    fn send_options(&self, config: &FuzzerConfig) -> SendOptions {
        let in_scope: Option<crate::ScopePredicate> = self
            .scope
            .read()
            .ok()
            .and_then(|scope| scope.clone())
            .map(|scope| {
                Arc::new(move |host: &str, port: Option<u16>| {
                    scope
                        .assess(&ActionTarget::Network {
                            host: host.to_owned(),
                            port,
                        })
                        .disposition
                        == ScopeDisposition::InScope
                }) as crate::ScopePredicate
            });
        SendOptions {
            redirect: config.redirect,
            retry: config.retry,
            connection_close: config.connection_close,
            update_content_length: config.update_content_length,
            in_scope,
        }
    }
}

/// Wraps a plain send result (no redirect/retry) as a `SendOutcome`.
fn plain_outcome(result: Result<ResendResponse, Diagnostic>) -> SendOutcome {
    match result {
        Ok(response) => SendOutcome {
            response: Some(response),
            diagnostic: None,
            redirect_chain: Vec::new(),
            retry_count: 0,
        },
        Err(diagnostic) => SendOutcome {
            response: None,
            diagnostic: Some(diagnostic),
            redirect_chain: Vec::new(),
            retry_count: 0,
        },
    }
}

/// The sends-per-second of a `Fixed` delay (0 for the interval/random variants),
/// used to pass a `-rate` to ffuf on the fast tier (which only runs Fixed).
fn fixed_rate(delay: DelayPolicy) -> u32 {
    match delay {
        DelayPolicy::Fixed { rate_per_second } => rate_per_second,
        DelayPolicy::Interval { .. } | DelayPolicy::Random { .. } => 0,
    }
}

/// A tiny non-cryptographic RNG for the Random delay variant.
struct DelayRng {
    state: u64,
}

impl DelayRng {
    fn new() -> Self {
        let mut buffer = [0u8; 8];
        let seed = if getrandom::fill(&mut buffer).is_ok() {
            u64::from_le_bytes(buffer)
        } else {
            0
        };
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn in_range(&mut self, min: u64, max: u64) -> u64 {
        if max <= min {
            min
        } else {
            min + self.next_u64() % (max - min + 1)
        }
    }
}

/// The milliseconds to wait before the next dispatch under a delay policy.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn delay_millis(delay: DelayPolicy, rng: &mut DelayRng) -> u64 {
    match delay {
        DelayPolicy::Fixed { rate_per_second } => {
            if rate_per_second == 0 {
                0
            } else {
                (1000.0 / f64::from(rate_per_second)).round() as u64
            }
        }
        DelayPolicy::Interval { ms } => ms,
        DelayPolicy::Random { min_ms, max_ms } => rng.in_range(min_ms, max_ms),
    }
}

/// Sleeps according to the delay policy before the next dispatch.
async fn apply_delay(delay: DelayPolicy, rng: &mut DelayRng) {
    let millis = delay_millis(delay, rng);
    if millis > 0 {
        tokio::time::sleep(Duration::from_millis(millis)).await;
    }
}

/// Persist at least this often by result count, so a fast attack still lands on
/// disk regularly without a durable write after every single result.
const PERSIST_EVERY_RESULTS: usize = 50;
/// Persist at least this often by wall time, so a slow attack (rate-limited or
/// high-latency target) still checkpoints even before it reaches the count.
const PERSIST_EVERY: Duration = Duration::from_millis(500);

/// Throttles durable persistence during an attack loop. The in-memory job is
/// always updated per result (for live polling); only the durable `SQLite` write
/// is gated here, so the full-job serialization cost stays bounded instead of
/// O(n^2). A guaranteed final persist at each terminal state (Completed / Stopped
/// / Failed) is issued by the caller regardless of cadence, so no results are
/// ever lost to the throttle.
struct PersistCadence {
    last: Instant,
    pending: usize,
}

impl PersistCadence {
    fn new() -> Self {
        Self {
            last: Instant::now(),
            pending: 0,
        }
    }

    /// Records `added` new results and reports whether a durable checkpoint is
    /// due, resetting the counters when it is.
    fn due(&mut self, added: usize) -> bool {
        self.pending += added;
        if self.pending >= PERSIST_EVERY_RESULTS || self.last.elapsed() >= PERSIST_EVERY {
            self.pending = 0;
            self.last = Instant::now();
            true
        } else {
            false
        }
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

/// Builds the bounded, lazy attack stream for a configuration. Every source is
/// generated on demand and run through its processing pipeline; the run loop
/// stops pulling at `max_results`, so an astronomically large space (Numbers,
/// Brute forcer, Cluster bomb) is never materialized up front.
fn plan_attack(config: &FuzzerConfig) -> Result<AttackPlan, Diagnostic> {
    match config.attack_type {
        FuzzerAttackType::Sniper => plan_sniper(config),
        FuzzerAttackType::BatteringRam => plan_battering_ram(config),
        FuzzerAttackType::Pitchfork => Ok(Box::new(PitchforkIter::new(config)?)),
        FuzzerAttackType::Clusterbomb => Ok(Box::new(ClusterIter::new(config)?)),
    }
}

/// Sniper: one position at a time, each payload placed while the other positions
/// hold their base value. Positions are chained; each yields its set lazily.
fn plan_sniper(config: &FuzzerConfig) -> Result<AttackPlan, Diagnostic> {
    let mut streams: Vec<AttackPlan> = Vec::with_capacity(config.positions.len());
    for position in &config.positions {
        let set = config
            .payload_sets
            .get(position.set_index)
            .ok_or_else(|| fuzzer_config_diagnostic("payload", "position payload set not found"))?;
        let base = config.base_request.clone();
        let position = position.clone();
        let iter = generate_processed(set)?.map(move |value| {
            let mut request = base.clone();
            apply_position(&mut request, &position, &value)?;
            Ok((vec![value], request))
        });
        streams.push(Box::new(iter));
    }
    Ok(Box::new(streams.into_iter().flatten()))
}

/// Battering ram: one payload set placed into every marked position at once.
fn plan_battering_ram(config: &FuzzerConfig) -> Result<AttackPlan, Diagnostic> {
    let set = config
        .payload_sets
        .first()
        .ok_or_else(|| fuzzer_config_diagnostic("payload", "battering ram needs a payload set"))?;
    let base = config.base_request.clone();
    let positions = config.positions.clone();
    let iter = generate_processed(set)?.map(move |value| {
        let mut request = base.clone();
        let applied: Vec<(&PayloadPosition, &str)> = positions
            .iter()
            .map(|position| (position, value.as_str()))
            .collect();
        apply_positions(&mut request, &applied)?;
        // One payload across all positions, so the result records that value.
        Ok((vec![value], request))
    });
    Ok(Box::new(iter))
}

/// Pitchfork: pair payloads by index across positions, length bounded by the
/// smallest source. Positions are stepped in lockstep, per distinct set.
struct PitchforkIter {
    base: ResendRequest,
    positions: Vec<PayloadPosition>,
    iters: Vec<Box<dyn Iterator<Item = String> + Send>>,
    axis_of_set: BTreeMap<usize, usize>,
    copy: Vec<Option<usize>>,
    done: bool,
}

impl PitchforkIter {
    fn new(config: &FuzzerConfig) -> Result<Self, Diagnostic> {
        let copy: Vec<Option<usize>> = config
            .positions
            .iter()
            .map(|position| position_copy_source(config, position))
            .collect();
        let mut set_order: Vec<usize> = config
            .positions
            .iter()
            .zip(&copy)
            .filter(|(_, is_copy)| is_copy.is_none())
            .map(|(position, _)| position.set_index)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        set_order.sort_unstable();
        let mut iters: Vec<Box<dyn Iterator<Item = String> + Send>> =
            Vec::with_capacity(set_order.len());
        for &index in &set_order {
            let set = config.payload_sets.get(index).ok_or_else(|| {
                fuzzer_config_diagnostic("payload", "position payload set not found")
            })?;
            iters.push(generate_processed(set)?);
        }
        let axis_of_set = set_order
            .iter()
            .enumerate()
            .map(|(axis, &index)| (index, axis))
            .collect();
        let done = set_order.is_empty();
        Ok(Self {
            base: config.base_request.clone(),
            positions: config.positions.clone(),
            iters,
            axis_of_set,
            copy,
            done,
        })
    }
}

impl Iterator for PitchforkIter {
    type Item = Result<PlannedRequest, Diagnostic>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut current = Vec::with_capacity(self.iters.len());
        for iter in &mut self.iters {
            // The shortest source ends the lockstep run.
            if let Some(value) = iter.next() {
                current.push(value);
            } else {
                self.done = true;
                return None;
            }
        }
        let axis_of_set = &self.axis_of_set;
        let values = resolve_position_values(&self.positions, &self.copy, |set_index| {
            axis_of_set
                .get(&set_index)
                .map(|&axis| current[axis].clone())
                .unwrap_or_default()
        });
        Some(build_planned(&self.base, &self.positions, values).inspect_err(|_| self.done = true))
    }
}

/// Cluster bomb: the Cartesian product across positions, streamed as an odometer
/// over regeneratable per-set generators so the product is never built as a Vec.
struct ClusterIter {
    base: ResendRequest,
    positions: Vec<PayloadPosition>,
    sets: Vec<PayloadSet>,
    iters: Vec<Box<dyn Iterator<Item = String> + Send>>,
    current: Vec<String>,
    axis_of_set: BTreeMap<usize, usize>,
    copy: Vec<Option<usize>>,
    started: bool,
    done: bool,
}

impl ClusterIter {
    fn new(config: &FuzzerConfig) -> Result<Self, Diagnostic> {
        let copy: Vec<Option<usize>> = config
            .positions
            .iter()
            .map(|position| position_copy_source(config, position))
            .collect();
        let mut set_order: Vec<usize> = config
            .positions
            .iter()
            .zip(&copy)
            .filter(|(_, is_copy)| is_copy.is_none())
            .map(|(position, _)| position.set_index)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        set_order.sort_unstable();
        let mut sets = Vec::with_capacity(set_order.len());
        let mut iters: Vec<Box<dyn Iterator<Item = String> + Send>> =
            Vec::with_capacity(set_order.len());
        for &index in &set_order {
            let set = config.payload_sets.get(index).ok_or_else(|| {
                fuzzer_config_diagnostic("payload", "position payload set not found")
            })?;
            iters.push(generate_processed(set)?);
            sets.push(set.clone());
        }
        let mut current = Vec::with_capacity(iters.len());
        let mut done = set_order.is_empty();
        for iter in &mut iters {
            if let Some(value) = iter.next() {
                current.push(value);
            } else {
                done = true;
            }
        }
        let axis_of_set = set_order
            .iter()
            .enumerate()
            .map(|(axis, &index)| (index, axis))
            .collect();
        Ok(Self {
            base: config.base_request.clone(),
            positions: config.positions.clone(),
            sets,
            iters,
            current,
            axis_of_set,
            copy,
            started: false,
            done,
        })
    }

    fn emit(&self) -> Result<PlannedRequest, Diagnostic> {
        let current = &self.current;
        let axis_of_set = &self.axis_of_set;
        let values = resolve_position_values(&self.positions, &self.copy, |set_index| {
            axis_of_set
                .get(&set_index)
                .map(|&axis| current[axis].clone())
                .unwrap_or_default()
        });
        build_planned(&self.base, &self.positions, values)
    }
}

impl Iterator for ClusterIter {
    type Item = Result<PlannedRequest, Diagnostic>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if !self.started {
            self.started = true;
            return Some(self.emit().inspect_err(|_| self.done = true));
        }
        // Advance the odometer, last axis fastest; a rolled axis regenerates and
        // carries into the previous one.
        let mut axis = self.iters.len() - 1;
        loop {
            if let Some(value) = self.iters[axis].next() {
                self.current[axis] = value;
                break;
            }
            // This axis rolled over: regenerate it, reset to its first value, and
            // carry into the previous axis.
            self.iters[axis] = regenerate_axis(&self.sets[axis]);
            if let Some(value) = self.iters[axis].next() {
                self.current[axis] = value;
            } else {
                self.done = true;
                return None;
            }
            if axis == 0 {
                self.done = true;
                return None;
            }
            axis -= 1;
        }
        Some(self.emit().inspect_err(|_| self.done = true))
    }
}

/// Restarts one cluster axis. The set already generated once during `new`, so a
/// pipeline recompile cannot newly fail here; an empty iterator is the honest
/// fallback if it somehow did.
fn regenerate_axis(set: &PayloadSet) -> Box<dyn Iterator<Item = String> + Send> {
    generate_processed(set).unwrap_or_else(|_| Box::new(std::iter::empty()))
}

/// Builds one Recursive-grep request by placing the current payload into every
/// marked position (battering-ram semantics — the single recursive value fills
/// each position; the common case is one position).
fn build_recursive_request(
    config: &FuzzerConfig,
    payload: &str,
) -> Result<ResendRequest, Diagnostic> {
    let mut request = config.base_request.clone();
    let applied: Vec<(&PayloadPosition, &str)> = config
        .positions
        .iter()
        .map(|position| (position, payload))
        .collect();
    apply_positions(&mut request, &applied)?;
    Ok(request)
}

/// The `CopyOtherPayload` source position a position is slaved to, if any.
fn position_copy_source(config: &FuzzerConfig, position: &PayloadPosition) -> Option<usize> {
    match config
        .payload_sets
        .get(position.set_index)
        .map(|set| &set.source)
    {
        Some(PayloadSource::CopyOtherPayload { source_position }) => Some(*source_position),
        _ => None,
    }
}

/// Computes each position's payload value: an independent position takes its
/// set's current value; a `CopyOtherPayload` position mirrors the referenced
/// position's value (resolved in a second pass).
fn resolve_position_values(
    positions: &[PayloadPosition],
    copy: &[Option<usize>],
    axis_value: impl Fn(usize) -> String,
) -> Vec<String> {
    let mut values: Vec<String> = positions
        .iter()
        .enumerate()
        .map(|(index, position)| {
            if copy[index].is_some() {
                String::new()
            } else {
                axis_value(position.set_index)
            }
        })
        .collect();
    for index in 0..positions.len() {
        if let Some(source) = copy[index] {
            values[index] = values.get(source).cloned().unwrap_or_default();
        }
    }
    values
}

/// Applies the resolved per-position values to a fresh request clone.
fn build_planned(
    base: &ResendRequest,
    positions: &[PayloadPosition],
    values: Vec<String>,
) -> Result<PlannedRequest, Diagnostic> {
    let mut request = base.clone();
    let applied: Vec<(&PayloadPosition, &str)> = positions
        .iter()
        .zip(&values)
        .map(|(position, value)| (position, value.as_str()))
        .collect();
    apply_positions(&mut request, &applied)?;
    Ok((values, request))
}

/// The pre-skip request count from source cardinalities and attack math, without
/// generating anything. `SkipIfMatchesRegex` cannot be pre-counted, so (as Burp
/// does) this is the pre-skip count; the run reports the actual sent count.
fn expected_request_count(config: &FuzzerConfig) -> Cardinality {
    match config.attack_type {
        FuzzerAttackType::Sniper => {
            let mut total = Cardinality::Exact(0);
            for position in &config.positions {
                if let Some(set) = config.payload_sets.get(position.set_index) {
                    total = total.saturating_add(set_cardinality(set));
                }
            }
            total
        }
        FuzzerAttackType::BatteringRam => config
            .payload_sets
            .first()
            .map_or(Cardinality::Exact(0), set_cardinality),
        FuzzerAttackType::Pitchfork => {
            let mut minimum: Option<Cardinality> = None;
            for position in &config.positions {
                if position_copy_source(config, position).is_some() {
                    continue;
                }
                if let Some(set) = config.payload_sets.get(position.set_index) {
                    let card = set_cardinality(set);
                    minimum = Some(minimum.map_or(card, |current| current.min_with(card)));
                }
            }
            minimum.unwrap_or(Cardinality::Exact(0))
        }
        FuzzerAttackType::Clusterbomb => {
            let mut product = Cardinality::Exact(1);
            let mut axes = BTreeSet::new();
            for position in &config.positions {
                if position_copy_source(config, position).is_some() {
                    continue;
                }
                if axes.insert(position.set_index) {
                    if let Some(set) = config.payload_sets.get(position.set_index) {
                        product = product.saturating_mul(set_cardinality(set));
                    }
                }
            }
            if axes.is_empty() {
                Cardinality::Exact(0)
            } else {
                product
            }
        }
    }
}

/// A pre-run request-count estimate for the count preview: the payload-engine
/// cardinality resolved to a number plus whether that number is exact. An
/// inexact estimate is a saturated lower bound (an enormous or continuous
/// space) that the run bounds at `max_results`.
#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCountPreview {
    /// Estimated number of requests before any `SkipIfMatchesRegex` drops.
    pub count: u64,
    /// Whether `count` is exact (`false` means "at least this many").
    pub exact: bool,
}

/// Computes the pre-run request-count preview for a configuration, honestly,
/// without generating any payloads. This is the single source of truth the GUI
/// preview and the acceptance parity matrix share.
#[must_use]
pub fn preview_request_count(config: &FuzzerConfig) -> RequestCountPreview {
    let cardinality = expected_request_count(config);
    RequestCountPreview {
        count: cardinality.bound(),
        exact: cardinality.is_exact(),
    }
}

/// Whether a set is a plain, caller-supplied wordlist ffuf can replay verbatim:
/// a `SimpleList` with no processing pipeline and no URL encoding.
fn is_plain_simple_list(set: &PayloadSet) -> bool {
    matches!(&set.source, PayloadSource::SimpleList { .. })
        && set.processors.is_empty()
        && set.url_encode_chars.is_none()
}

/// The literal values of a `SimpleList` set, or an empty slice for any generated
/// source (used only on the ffuf path, which is gated to plain simple lists).
fn simple_values(set: &PayloadSet) -> &[String] {
    match &set.source {
        PayloadSource::SimpleList { values } => values,
        _ => &[],
    }
}

/// Applies every marked position for one generated request. Positions that
/// share a field (e.g. two markers in the URL) are applied right-to-left, in
/// descending start offset, so substituting an earlier marker with a payload of
/// a different length never shifts the byte offsets of markers that have not
/// been applied yet. Cross-field positions are independent, so a single global
/// descending sort is correct for all of them.
fn apply_positions(
    request: &mut ResendRequest,
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
    request: &mut ResendRequest,
    position: &PayloadPosition,
    value: &str,
) -> Result<(), Diagnostic> {
    match position.location {
        FuzzerPositionLocation::Url => {
            replace_range(&mut request.url, position.start, position.end, value)
        }
        FuzzerPositionLocation::Body => {
            let body =
                String::from_utf8(request.body.clone().unwrap_or_default()).map_err(|_| {
                    fuzzer_config_diagnostic("body", "body payload position is not UTF-8")
                })?;
            let mut body = body;
            replace_range(&mut body, position.start, position.end, value)?;
            request.body = Some(body.into_bytes());
            Ok(())
        }
        FuzzerPositionLocation::Header => {
            let name = position.header_name.as_deref().ok_or_else(|| {
                fuzzer_config_diagnostic("header", "header payload position has no header name")
            })?;
            let header = request
                .headers
                .iter_mut()
                .find(|(header, _)| header.eq_ignore_ascii_case(name))
                .ok_or_else(|| {
                    fuzzer_config_diagnostic(
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
        return Err(fuzzer_config_diagnostic(
            "position",
            "payload position is outside the selected field",
        ));
    }
    value.replace_range(start..end, replacement);
    Ok(())
}

fn matches_filter(
    filter: &apiaxess_workbench_store::FuzzerMatchFilter,
    response: &ResendResponse,
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
    previous: Option<&ResendResponse>,
    current: Option<&ResendResponse>,
) -> FuzzerResponseDiff {
    let Some(current) = current else {
        return FuzzerResponseDiff::default();
    };
    let Some(previous) = previous else {
        return FuzzerResponseDiff {
            status_changed: false,
            size_changed: false,
            size_delta: 0,
            content_changed: false,
        };
    };
    let previous_size =
        i64::try_from(previous.body.as_ref().map_or(0, Vec::len)).unwrap_or(i64::MAX);
    let current_size = i64::try_from(current.body.as_ref().map_or(0, Vec::len)).unwrap_or(i64::MAX);
    FuzzerResponseDiff {
        status_changed: previous.status != current.status,
        size_changed: previous_size != current_size,
        size_delta: current_size - previous_size,
        content_changed: previous.body != current.body,
    }
}

fn extract_tokens(
    step: &str,
    response: &ResendResponse,
    extractors: &[FuzzerTokenExtractor],
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
            FuzzerTokenExtractor::Header { variable, name } => (
                variable,
                response
                    .headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.clone()),
            ),
            FuzzerTokenExtractor::Regex { variable, pattern } => (
                variable,
                Regex::new(pattern)
                    .ok()
                    .and_then(|regex| regex_capture(&regex, 1, &body)),
            ),
            FuzzerTokenExtractor::JsonPath { variable, path } => (
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

/// Extracts capture `group` from the first regex match, falling back to the
/// whole match when that group is absent. Shared by the stateful sequence
/// extractor and grep-extract so the two never diverge.
fn regex_capture(regex: &Regex, group: usize, text: &str) -> Option<String> {
    regex.captures(text).and_then(|captures| {
        captures
            .get(group)
            .or_else(|| captures.get(0))
            .map(|value| value.as_str().to_owned())
    })
}

/// A precompiled grep configuration: match-rule matchers, extract-rule locators,
/// and reflected settings, all built once per run so a response never triggers a
/// regex recompile.
struct GrepContext {
    matches: Vec<CompiledMatch>,
    extracts: Vec<CompiledExtract>,
    reflected: GrepReflectedConfig,
}

struct CompiledMatch {
    matcher: Matcher,
    exclude_headers: bool,
}

enum Matcher {
    Regex(Regex),
    Literal {
        needle: String,
        case_sensitive: bool,
    },
}

struct CompiledExtract {
    locator: CompiledLocator,
    max_length: usize,
    first_only: bool,
}

enum CompiledLocator {
    Between { start: String, end: String },
    Regex { regex: Regex, group: usize },
    Offset { start: usize, length: usize },
}

/// One result's grep outcome.
struct GrepOutcome {
    match_counts: Vec<u32>,
    extracts: Vec<Option<String>>,
    reflected: Option<u32>,
}

impl GrepContext {
    /// Compiles the grep config once, validating every regex up front.
    #[allow(clippy::similar_names)]
    fn compile(config: &GrepConfig) -> Result<Self, Diagnostic> {
        let mut matches = Vec::with_capacity(config.match_rules.len());
        for rule in &config.match_rules {
            let matcher = if rule.is_regex {
                Matcher::Regex(build_regex(&rule.pattern, rule.case_sensitive)?)
            } else {
                Matcher::Literal {
                    needle: rule.pattern.clone(),
                    case_sensitive: rule.case_sensitive,
                }
            };
            matches.push(CompiledMatch {
                matcher,
                exclude_headers: rule.exclude_headers,
            });
        }
        let mut extracts = Vec::with_capacity(config.extract_rules.len());
        for rule in &config.extract_rules {
            let locator = match &rule.locator {
                ExtractLocator::BetweenDelimiters { start, end } => CompiledLocator::Between {
                    start: start.clone(),
                    end: end.clone(),
                },
                ExtractLocator::Regex { pattern, group } => CompiledLocator::Regex {
                    regex: build_regex(pattern, true)?,
                    group: *group,
                },
                ExtractLocator::Offset { start, length } => CompiledLocator::Offset {
                    start: *start,
                    length: *length,
                },
            };
            extracts.push(CompiledExtract {
                locator,
                max_length: rule.max_length,
                first_only: rule.first_only,
            });
        }
        Ok(Self {
            matches,
            extracts,
            reflected: config.reflected.clone(),
        })
    }

    /// The aligned zero/empty outcome for a result with no response.
    fn empty_outcome(&self) -> GrepOutcome {
        GrepOutcome {
            match_counts: vec![0; self.matches.len()],
            extracts: vec![None; self.extracts.len()],
            reflected: None,
        }
    }

    /// Evaluates all grep rules against one response.
    fn evaluate(&self, response: &ResendResponse, payloads: &[String]) -> GrepOutcome {
        let body = response_body_text(response);
        // Only pay for the headers+body haystack when a rule actually needs it.
        let needs_headers = self.matches.iter().any(|rule| !rule.exclude_headers)
            || (self.reflected.enabled && !self.reflected.exclude_headers);
        let with_headers = if needs_headers {
            response_full_text(response, &body)
        } else {
            String::new()
        };
        let pick = |exclude_headers: bool| -> &str {
            if exclude_headers {
                &body
            } else {
                &with_headers
            }
        };
        let match_counts = self
            .matches
            .iter()
            .map(|rule| match &rule.matcher {
                Matcher::Regex(regex) => {
                    u32::try_from(regex.find_iter(pick(rule.exclude_headers)).count())
                        .unwrap_or(u32::MAX)
                }
                Matcher::Literal {
                    needle,
                    case_sensitive,
                } => count_occurrences(pick(rule.exclude_headers), needle, *case_sensitive),
            })
            .collect();
        let extracts = self
            .extracts
            .iter()
            .map(|rule| extract_value(rule, &body))
            .collect();
        let reflected = if self.reflected.enabled {
            let hay = pick(self.reflected.exclude_headers);
            let mut total = 0u32;
            for payload in payloads {
                total = total.saturating_add(count_occurrences(
                    hay,
                    payload,
                    self.reflected.case_sensitive,
                ));
                if self.reflected.match_pre_url_encoded {
                    let decoded = percent_decode(payload);
                    if decoded != *payload {
                        total = total.saturating_add(count_occurrences(
                            hay,
                            &decoded,
                            self.reflected.case_sensitive,
                        ));
                    }
                }
            }
            Some(total)
        } else {
            None
        };
        GrepOutcome {
            match_counts,
            extracts,
            reflected,
        }
    }

    /// The first extract rule's value from a response — the feed-forward source
    /// for a Recursive-grep payload set.
    fn recursive_next(&self, response: &ResendResponse) -> Option<String> {
        let body = response_body_text(response);
        self.extracts
            .first()
            .and_then(|rule| extract_value(rule, &body))
            .filter(|value| !value.is_empty())
    }
}

fn build_regex(pattern: &str, case_sensitive: bool) -> Result<Regex, Diagnostic> {
    RegexBuilder::new(pattern)
        .case_insensitive(!case_sensitive)
        .build()
        .map_err(|error| fuzzer_config_diagnostic("grep.regex", &error.to_string()))
}

fn response_body_text(response: &ResendResponse) -> String {
    response
        .body
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default()
        .into_owned()
}

fn response_full_text(response: &ResendResponse, body: &str) -> String {
    let mut text = String::new();
    for (name, value) in &response.headers {
        text.push_str(name);
        text.push_str(": ");
        text.push_str(value);
        text.push('\n');
    }
    text.push('\n');
    text.push_str(body);
    text
}

fn count_occurrences(haystack: &str, needle: &str, case_sensitive: bool) -> u32 {
    if needle.is_empty() {
        return 0;
    }
    let count = if case_sensitive {
        haystack.matches(needle).count()
    } else {
        haystack
            .to_lowercase()
            .matches(&needle.to_lowercase())
            .count()
    };
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// Extracts one grep value (body-scoped), honoring first-only vs. all. Each
/// occurrence is capped to `max_length`, then occurrences are joined by newline.
fn extract_value(rule: &CompiledExtract, body: &str) -> Option<String> {
    let items: Vec<String> = match &rule.locator {
        CompiledLocator::Between { start, end } => {
            extract_between(body, start, end, rule.first_only)
        }
        CompiledLocator::Regex { regex, group } => regex
            .captures_iter(body)
            .filter_map(|captures| {
                captures
                    .get(*group)
                    .or_else(|| captures.get(0))
                    .map(|value| value.as_str().to_owned())
            })
            .take(if rule.first_only { 1 } else { usize::MAX })
            .collect(),
        CompiledLocator::Offset { start, length } => {
            let end = start.saturating_add(*length).min(body.len());
            body.get(*start..end)
                .map(str::to_owned)
                .into_iter()
                .collect()
        }
    };
    if items.is_empty() {
        return None;
    }
    Some(
        items
            .into_iter()
            .map(|value| truncate_chars(&value, rule.max_length))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// All texts between delimiters, or just the first when `first_only`.
fn extract_between(body: &str, start: &str, end: &str, first_only: bool) -> Vec<String> {
    let mut found = Vec::new();
    if start.is_empty() {
        return found;
    }
    let mut cursor = 0;
    while let Some(open) = body[cursor..].find(start) {
        let value_start = cursor + open + start.len();
        let Some(close) = body[value_start..].find(end) else {
            break;
        };
        found.push(body[value_start..value_start + close].to_owned());
        if first_only {
            break;
        }
        cursor = value_start + close + end.len().max(1);
    }
    found
}

/// Caps a string to `max_length` characters; `0` means no cap.
fn truncate_chars(value: &str, max_length: usize) -> String {
    if max_length == 0 {
        return value.to_owned();
    }
    value.chars().take(max_length).collect()
}

/// Minimal percent-decoder for reflected pre-URL-encoded matching.
#[allow(clippy::cast_possible_truncation)]
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let high = (bytes[i + 1] as char).to_digit(16);
            let low = (bytes[i + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                out.push((high * 16 + low) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a send diagnostic represents a timeout (tagged by the resend sender).
fn is_timeout_diagnostic(diagnostic: &Diagnostic) -> bool {
    matches!(
        diagnostic.context.get("timeout"),
        Some(DiagnosticValue::Boolean(true))
    )
}

fn inject_request(request: &ResendRequest, variables: &BTreeMap<String, String>) -> ResendRequest {
    let replace = |value: &str| {
        variables
            .iter()
            .fold(value.to_owned(), |value, (key, token)| {
                value.replace(&format!("{{{{{key}}}}}"), token)
            })
    };
    ResendRequest {
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

/// The `-H` value that stamps the Fuzz origin marker on every external ffuf
/// probe. Name and value come from the one shared source of truth (the marker
/// constant and [`FlowOrigin::Fuzz`]) so the ffuf tier tags identically to the
/// `OriginTaggingSender` used by the native tier — never a divergent string.
fn ffuf_origin_header() -> String {
    format!("{ORIGIN_MARKER_HEADER}: {}", FlowOrigin::Fuzz.as_db_str())
}

fn ffuf_url(request: &ResendRequest, positions: &[PayloadPosition]) -> Result<String, Diagnostic> {
    let url_position = positions
        .iter()
        .find(|position| position.location == FuzzerPositionLocation::Url)
        .ok_or_else(|| fuzzer_config_diagnostic("ffuf", "ffuf requires a URL payload position"))?;
    let mut url = request.url.clone();
    replace_range(&mut url, url_position.start, url_position.end, FFUF_KEYWORD)?;
    Ok(url)
}

/// The `-H` value carrying the native tier's exact header list (see
/// [`wire_header_list`]). The list is the same for every probe, because the
/// ffuf tier only fuzzes the URL — except a `Host` derived from a URL whose
/// authority holds the payload: that is left out, and the proxy derives it
/// from the substituted URL ffuf actually requested.
fn ffuf_wire_headers(request: &ResendRequest, positions: &[PayloadPosition]) -> String {
    let mut headers = wire_header_list(request, true);
    let authored_host = request
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"));
    if !authored_host
        && positions
            .iter()
            .any(|position| in_authority(&request.url, position))
    {
        headers.retain(|(name, _)| !name.eq_ignore_ascii_case("host"));
    }
    format!("{WIRE_HEADERS_MARKER}: {}", encode_header_list(&headers))
}

/// Whether a URL position falls inside the URL's authority (`host[:port]`).
fn in_authority(url: &str, position: &PayloadPosition) -> bool {
    let Some(scheme_end) = url.find("://").map(|index| index + 3) else {
        return false;
    };
    let authority_end = url[scheme_end..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |index| scheme_end + index);
    position.start < authority_end && position.end > scheme_end
}

/// Reconstructs the exact request an ffuf probe sent by substituting the payload
/// at the marked position(s) — the same position-based substitution the native
/// sender uses. A plain `.replace("FUZZ", …)` was wrong: the base request holds
/// the template's original span content (e.g. `base`), not the ffuf keyword
/// (that keyword only exists in the URL handed to ffuf via [`ffuf_url`]),
/// so string-replacement left the base template unsubstituted and the "as sent"
/// request was factually false. Falls back to the base request unchanged if the
/// offsets don't apply, rather than fabricating.
fn request_with_ffuf_payload(
    request: &ResendRequest,
    positions: &[PayloadPosition],
    payload: &str,
) -> ResendRequest {
    let mut result = request.clone();
    let applied: Vec<(&PayloadPosition, &str)> = positions
        .iter()
        .map(|position| (position, payload))
        .collect();
    if apply_positions(&mut result, &applied).is_ok() {
        result
    } else {
        request.clone()
    }
}

/// Parses the request count from ffuf's most recent stderr progress line,
/// which looks like `:: Progress: [1234/5000] :: Job [1/1] :: 456 req/sec ...`.
/// Returns the completed count from the last such line, or `None` if none yet.
fn parse_ffuf_progress(stderr: &str) -> Option<u64> {
    stderr
        .rmatch_indices("Progress: [")
        .next()
        .and_then(|(index, marker)| {
            let rest = &stderr[index + marker.len()..];
            let count = rest.split('/').next()?;
            count.trim().parse::<u64>().ok()
        })
}

fn ffuf_payload(entry: &serde_json::Value) -> Option<String> {
    entry
        .get("input")
        .and_then(serde_json::Value::as_object)
        .and_then(|input| {
            input
                .iter()
                .find(|(key, _)| key.as_str() == FFUF_KEYWORD || key.eq_ignore_ascii_case("FUZZ"))
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

fn validate_config(config: &FuzzerConfig) -> Result<(), Diagnostic> {
    if config.positions.is_empty()
        || config.payload_sets.is_empty()
        || config.max_results == 0
        || config.concurrency == 0
        || config.base_request.method.is_empty()
        || config.base_request.url.is_empty()
    {
        return Err(fuzzer_config_diagnostic(
            "config",
            "request, positions, payload sets, concurrency, and max_results are required",
        ));
    }
    for position in &config.positions {
        if config.payload_sets.get(position.set_index).is_none() || position.start > position.end {
            return Err(fuzzer_config_diagnostic(
                "position",
                "position range or payload set is invalid",
            ));
        }
    }
    // Each set must be generable: its processing pipeline compiles, and a
    // generated source's prerequisites (date format, brute alphabet) hold.
    for set in &config.payload_sets {
        validate_set(set)?;
    }
    validate_payload_sources(config)?;
    Ok(())
}

/// Validates source variants whose usability depends on the attack shape rather
/// than the set alone: `RecursiveGrep` (needs a grep extract rule to feed the
/// next payload forward) and `CopyOtherPayload` (only valid in Pitchfork/Cluster
/// bomb, referencing a real, non-copy position other than itself).
fn validate_payload_sources(config: &FuzzerConfig) -> Result<(), Diagnostic> {
    let has_recursive = config
        .payload_sets
        .iter()
        .any(|set| matches!(set.source, PayloadSource::RecursiveGrep { .. }));
    if has_recursive && config.grep.extract_rules.is_empty() {
        // Recursive grep feeds the previous response's first extract value in as
        // the next payload; without an extract rule there is nothing to feed.
        return Err(fuzzer_config_diagnostic(
            "payload.recursive_grep",
            "Recursive grep requires at least one grep extract rule to feed the next payload",
        ));
    }
    for position in &config.positions {
        let Some(PayloadSource::CopyOtherPayload { source_position }) = config
            .payload_sets
            .get(position.set_index)
            .map(|set| &set.source)
        else {
            continue;
        };
        if !matches!(
            config.attack_type,
            FuzzerAttackType::Pitchfork | FuzzerAttackType::Clusterbomb
        ) {
            return Err(fuzzer_config_diagnostic(
                "payload.copy",
                "Copy other payload is only valid in Pitchfork or Cluster bomb",
            ));
        }
        let source = *source_position;
        let this = config
            .positions
            .iter()
            .position(|candidate| std::ptr::eq(candidate, position))
            .unwrap_or(usize::MAX);
        if source == this
            || source >= config.positions.len()
            || position_copy_source(config, &config.positions[source]).is_some()
        {
            return Err(fuzzer_config_diagnostic(
                "payload.copy",
                "Copy other payload must reference a different, non-copy position",
            ));
        }
    }
    Ok(())
}

fn new_job_id() -> String {
    format!(
        "fuzzer-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    )
}

fn fuzzer_config_diagnostic(operation: &str, detail: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "operation".to_owned(),
        DiagnosticValue::String(operation.to_owned()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    catalogue::PROXY_FUZZER_CONFIG_INVALID.instantiate(context)
}

/// Builds the honest observed-rate diagnostic comparing estimate vs. reality.
/// `is_discovery` (directory discovery auto-calibrates) selects the discovery
/// label; an ffuf-tier Fuzz run gets the Fuzz-appropriate id so the Diagnostics
/// dock never calls a Fuzz attack a discovery run.
fn rate_observed_diagnostic(
    candidates: usize,
    elapsed_seconds: f64,
    actual_rate: f64,
    estimated_rate: u32,
    is_discovery: bool,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "candidates".to_owned(),
        DiagnosticValue::Integer(i64::try_from(candidates).unwrap_or(i64::MAX)),
    );
    let definition = if is_discovery {
        catalogue::WEB_DISCOVERY_RATE_OBSERVED
    } else {
        catalogue::PROXY_FUZZER_RATE_OBSERVED
    };
    let unit = if is_discovery { "probes" } else { "requests" };
    let mut diagnostic = definition.instantiate(context);
    diagnostic.why = format!(
        "Sent {candidates} {unit} in {elapsed_seconds:.1}s — actual ~{actual_rate:.1} req/s vs. estimated {estimated_rate} req/s."
    )
    .into();
    diagnostic
}

/// Wraps a rare send-task join failure (a panicked send future) as a stable
/// per-result diagnostic so one bad request cannot abort the whole attack.
fn fuzzer_task_diagnostic(detail: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    catalogue::PROXY_RESEND_TRANSPORT_UNAVAILABLE.instantiate(context)
}

fn sequence_diagnostic(step: &str, detail: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert("step".to_owned(), DiagnosticValue::String(step.to_owned()));
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    catalogue::PROXY_FUZZER_SEQUENCE_FAILED.instantiate(context)
}

fn outside_scope(url: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert("url".to_owned(), DiagnosticValue::String(url.to_owned()));
    catalogue::PROXY_FUZZER_OUTSIDE_SCOPE.instantiate(context)
}

fn ffuf_unavailable(detail: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    catalogue::PROXY_FUZZER_FFUF_UNAVAILABLE.instantiate(context)
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
    catalogue::PROXY_FUZZER_FFUF_FAILED.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_workbench_store::{
        EncodeScheme, ExtractLocator, FuzzerPositionLocation, GrepConfig, GrepExtractRule,
        GrepMatchRule, GrepReflectedConfig, NumberOrder, NumberRadix, PayloadProcessor,
        PayloadSource,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A URL payload position spanning `[start, end)` over set `set_index`.
    fn url_position(start: usize, end: usize, set_index: usize) -> PayloadPosition {
        PayloadPosition {
            location: FuzzerPositionLocation::Url,
            header_name: None,
            start,
            end,
            set_index,
        }
    }

    fn numbers_set(name: &str, from: f64, to: f64) -> PayloadSet {
        PayloadSet {
            name: name.to_owned(),
            source: PayloadSource::Numbers {
                from,
                to,
                step: 1.0,
                order: NumberOrder::Sequential,
                radix: NumberRadix::Dec,
                min_integer_digits: 1,
                max_fraction_digits: 0,
            },
            processors: Vec::new(),
            url_encode_chars: None,
        }
    }

    /// A plain simple-list payload set, the common test shape.
    fn simple_set(name: &str, values: &[&str]) -> PayloadSet {
        PayloadSet {
            name: name.to_owned(),
            source: PayloadSource::SimpleList {
                values: values.iter().map(|value| (*value).to_owned()).collect(),
            },
            processors: Vec::new(),
            url_encode_chars: None,
        }
    }

    fn request() -> ResendRequest {
        ResendRequest {
            method: "GET".to_owned(),
            url: "https://api.example.test/items?id=FUZZ".to_owned(),
            headers: Vec::new(),
            body: None,
        }
    }

    fn config(attack_type: FuzzerAttackType) -> FuzzerConfig {
        FuzzerConfig {
            base_request: request(),
            positions: vec![PayloadPosition {
                location: FuzzerPositionLocation::Url,
                header_name: None,
                start: 34,
                end: 38,
                set_index: 0,
            }],
            payload_sets: vec![simple_set("values", &["one", "two"])],
            attack_type,
            match_filter: apiaxess_workbench_store::FuzzerMatchFilter::default(),
            grep: GrepConfig::default(),
            concurrency: 1,
            delay: DelayPolicy::default(),
            retry: apiaxess_workbench_store::RetryPolicy::default(),
            redirect: apiaxess_workbench_store::RedirectPolicy::default(),
            connection_close: false,
            update_content_length: true,
            max_results: 100,
            auth_preflight: None,
            sequence: Vec::new(),
            auto_calibrate: false,
            internal: false,
        }
    }

    #[test]
    fn payload_expansion_applies_clusterbomb_values_by_set() {
        let mut attack = config(FuzzerAttackType::Clusterbomb);
        attack.positions.push(PayloadPosition {
            location: FuzzerPositionLocation::Url,
            header_name: None,
            start: 27,
            end: 31,
            set_index: 1,
        });
        attack
            .payload_sets
            .push(simple_set("second", &["red", "blue"]));
        let expanded: Vec<PlannedRequest> = plan_attack(&attack)
            .expect("planned")
            .map(|item| item.expect("request"))
            .collect();
        assert_eq!(expanded.len(), 4);
        assert_eq!(expanded[0].0, vec!["one", "red"]);
        assert_eq!(expanded[3].0, vec!["two", "blue"]);
    }

    #[test]
    fn count_preview_matches_the_parity_matrix() {
        // Sniper: 2 positions over one 4-value set -> 8.
        let mut sniper = config(FuzzerAttackType::Sniper);
        sniper.payload_sets = vec![simple_set("s", &["a", "b", "c", "d"])];
        sniper.positions.push(url_position(27, 31, 0));
        let preview = preview_request_count(&sniper);
        assert_eq!(preview.count, 8);
        assert!(preview.exact);

        // Battering ram: one 4-value set -> 4.
        let mut ram = config(FuzzerAttackType::BatteringRam);
        ram.payload_sets = vec![simple_set("s", &["a", "b", "c", "d"])];
        assert_eq!(preview_request_count(&ram).count, 4);

        // Pitchfork: min(3, 5) -> 3.
        let mut pitchfork = config(FuzzerAttackType::Pitchfork);
        pitchfork.payload_sets = vec![
            simple_set("a", &["1", "2", "3"]),
            simple_set("b", &["v", "w", "x", "y", "z"]),
        ];
        pitchfork.positions.push(url_position(27, 31, 1));
        assert_eq!(preview_request_count(&pitchfork).count, 3);

        // Cluster bomb over the same sets: 3 * 5 -> 15.
        let mut cluster = pitchfork.clone();
        cluster.attack_type = FuzzerAttackType::Clusterbomb;
        assert_eq!(preview_request_count(&cluster).count, 15);

        // A generated Numbers source counts exactly without materializing.
        let mut numbers = config(FuzzerAttackType::Sniper);
        numbers.payload_sets = vec![numbers_set("n", 1.0, 100.0)];
        let preview = preview_request_count(&numbers);
        assert_eq!(preview.count, 100);
        assert!(preview.exact);
    }

    #[test]
    fn generated_sources_and_pipelines_route_to_native() {
        let manager = FuzzerWorkbench::new();
        manager.attach_store(temp_store()).expect("attach");
        // A Numbers source cannot be replayed to ffuf verbatim.
        let mut numbers = config(FuzzerAttackType::Sniper);
        numbers.payload_sets = vec![numbers_set("n", 1.0, 5.0)];
        assert_eq!(
            manager.create(numbers).expect("create").tier,
            FuzzerTier::Native
        );
        // A processing pipeline on a plain list also forces native.
        let mut processed = config(FuzzerAttackType::Sniper);
        processed.payload_sets[0].processors =
            vec![PayloadProcessor::AddPrefix { text: "x".into() }];
        assert_eq!(
            manager.create(processed).expect("create").tier,
            FuzzerTier::Native
        );
        // A URL-encode step likewise.
        let mut encoded = config(FuzzerAttackType::Sniper);
        encoded.payload_sets[0].url_encode_chars = Some("&".into());
        assert_eq!(
            manager.create(encoded).expect("create").tier,
            FuzzerTier::Native
        );
        // A plain simple list still rides the fast ffuf path.
        assert_eq!(
            manager
                .create(config(FuzzerAttackType::Sniper))
                .expect("create")
                .tier,
            FuzzerTier::Ffuf
        );
    }

    #[test]
    fn delay_millis_per_variant() {
        let mut rng = DelayRng::new();
        assert_eq!(
            delay_millis(DelayPolicy::Fixed { rate_per_second: 0 }, &mut rng),
            0
        );
        assert_eq!(
            delay_millis(DelayPolicy::Fixed { rate_per_second: 4 }, &mut rng),
            250
        );
        assert_eq!(
            delay_millis(DelayPolicy::Interval { ms: 120 }, &mut rng),
            120
        );
        for _ in 0..200 {
            let ms = delay_millis(
                DelayPolicy::Random {
                    min_ms: 10,
                    max_ms: 20,
                },
                &mut rng,
            );
            assert!((10..=20).contains(&ms), "random delay {ms} out of range");
        }
    }

    #[test]
    fn attack_settings_route_to_native() {
        let manager = FuzzerWorkbench::new();
        manager.attach_store(temp_store()).expect("attach");
        // Interval delay -> native (ffuf can't express it).
        let mut interval = config(FuzzerAttackType::Sniper);
        interval.delay = DelayPolicy::Interval { ms: 50 };
        assert_eq!(
            manager.create(interval).expect("create").tier,
            FuzzerTier::Native
        );
        // Retries -> native.
        let mut retries = config(FuzzerAttackType::Sniper);
        retries.retry = apiaxess_workbench_store::RetryPolicy {
            max_retries: 2,
            pause_ms: 100,
        };
        assert_eq!(
            manager.create(retries).expect("create").tier,
            FuzzerTier::Native
        );
        // Redirect following -> native.
        let mut redirect = config(FuzzerAttackType::Sniper);
        redirect.redirect.mode = apiaxess_workbench_store::RedirectMode::Always;
        assert_eq!(
            manager.create(redirect).expect("create").tier,
            FuzzerTier::Native
        );
        // Connection: close -> native.
        let mut close = config(FuzzerAttackType::Sniper);
        close.connection_close = true;
        assert_eq!(
            manager.create(close).expect("create").tier,
            FuzzerTier::Native
        );
        // All-default (no-follow, no retries, fixed rate, recompute CL) rides ffuf.
        assert_eq!(
            manager
                .create(config(FuzzerAttackType::Sniper))
                .expect("create")
                .tier,
            FuzzerTier::Ffuf
        );
    }

    #[tokio::test]
    async fn redirect_chain_and_retry_count_flow_into_results() {
        // A sender that reports two followed hops and one retry, so we verify the
        // fuzzer records the WS4 outcome fields onto the result row.
        struct OutcomeSender;
        impl ResendSender for OutcomeSender {
            fn send(
                &self,
                _request: ResendRequest,
            ) -> crate::backend::BackendFuture<Result<ResendResponse, Diagnostic>> {
                Box::pin(async move {
                    Ok(ResendResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: Some(b"ok".to_vec()),
                        duration_ms: 1,
                        http_version: None,
                        reason: None,
                    })
                })
            }

            fn send_with_options(
                &self,
                _request: ResendRequest,
                _options: SendOptions,
            ) -> crate::backend::BackendFuture<Result<SendOutcome, Diagnostic>> {
                Box::pin(async move {
                    Ok(SendOutcome {
                        response: Some(ResendResponse {
                            status: 200,
                            headers: Vec::new(),
                            body: Some(b"ok".to_vec()),
                            duration_ms: 1,
                            http_version: None,
                            reason: None,
                        }),
                        diagnostic: None,
                        redirect_chain: vec![apiaxess_workbench_store::RedirectHop {
                            status: 302,
                            location: "https://api.example.test/final".to_owned(),
                        }],
                        retry_count: 1,
                    })
                })
            }
        }

        let manager = Arc::new(FuzzerWorkbench::new());
        manager.attach_store(temp_store()).expect("attach");
        manager.attach_sender(Arc::new(OutcomeSender));
        let mut attack = config(FuzzerAttackType::Sniper);
        // Force native so send_with_options is used.
        attack.redirect.mode = apiaxess_workbench_store::RedirectMode::Always;
        attack.retry = apiaxess_workbench_store::RetryPolicy {
            max_retries: 3,
            pause_ms: 0,
        };
        let job = manager.create(attack).expect("create");
        assert_eq!(job.tier, FuzzerTier::Native);
        manager.launch(&job.id).expect("launch");
        let finished = drive_to_terminal(&manager, &job.id).await;
        assert_eq!(finished.state, FuzzerJobState::Completed);
        assert!(!finished.results.is_empty());
        let first = &finished.results[0];
        assert_eq!(first.retry_count, 1);
        assert_eq!(first.redirect_chain.len(), 1);
        assert_eq!(first.redirect_chain[0].status, 302);
    }

    #[test]
    fn recursive_grep_is_rejected_until_extract_exists() {
        let manager = FuzzerWorkbench::new();
        manager.attach_store(temp_store()).expect("attach");
        let mut attack = config(FuzzerAttackType::Sniper);
        attack.payload_sets = vec![PayloadSet {
            name: "grep".to_owned(),
            source: PayloadSource::RecursiveGrep {
                seed: vec!["a".to_owned()],
            },
            processors: Vec::new(),
            url_encode_chars: None,
        }];
        assert!(
            manager.create(attack).is_err(),
            "recursive grep without an extract rule must validate-reject"
        );
    }

    fn recursive_extract_rule() -> GrepExtractRule {
        GrepExtractRule {
            name: "next".to_owned(),
            locator: ExtractLocator::BetweenDelimiters {
                start: "<next>".to_owned(),
                end: "</next>".to_owned(),
            },
            max_length: 0,
            first_only: true,
        }
    }

    #[test]
    fn grep_evaluate_counts_extracts_and_reflects() {
        let config = GrepConfig {
            match_rules: vec![
                GrepMatchRule {
                    name: "err".to_owned(),
                    pattern: "error".to_owned(),
                    is_regex: false,
                    case_sensitive: false,
                    exclude_headers: true,
                },
                GrepMatchRule {
                    name: "digits".to_owned(),
                    pattern: "[0-9]+".to_owned(),
                    is_regex: true,
                    case_sensitive: true,
                    exclude_headers: true,
                },
            ],
            extract_rules: vec![
                GrepExtractRule {
                    name: "between".to_owned(),
                    locator: ExtractLocator::BetweenDelimiters {
                        start: "<v>".to_owned(),
                        end: "</v>".to_owned(),
                    },
                    max_length: 0,
                    first_only: true,
                },
                GrepExtractRule {
                    name: "re".to_owned(),
                    locator: ExtractLocator::Regex {
                        pattern: "id=([0-9]+)".to_owned(),
                        group: 1,
                    },
                    max_length: 0,
                    first_only: true,
                },
            ],
            reflected: GrepReflectedConfig {
                enabled: true,
                case_sensitive: false,
                exclude_headers: true,
                match_pre_url_encoded: false,
            },
        };
        let grep = GrepContext::compile(&config).expect("compile");
        let response = ResendResponse {
            status: 200,
            headers: vec![("x-error".to_owned(), "ERROR".to_owned())],
            body: Some(b"Error 42 <v>token</v> id=99 alpha".to_vec()),
            duration_ms: 1,
            http_version: None,
            reason: None,
        };
        let outcome = grep.evaluate(&response, &["alpha".to_owned()]);
        // Literal "error", case-insensitive, body-only: the header ERROR is excluded.
        assert_eq!(outcome.match_counts[0], 1);
        // Regex digits, body-only: "42" and "99".
        assert_eq!(outcome.match_counts[1], 2);
        assert_eq!(outcome.extracts[0].as_deref(), Some("token"));
        assert_eq!(outcome.extracts[1].as_deref(), Some("99"));
        assert_eq!(outcome.reflected, Some(1));
    }

    #[test]
    fn grep_extract_respects_max_length_and_all_occurrences() {
        let config = GrepConfig {
            match_rules: Vec::new(),
            extract_rules: vec![GrepExtractRule {
                name: "all".to_owned(),
                locator: ExtractLocator::Regex {
                    pattern: "v=([a-z]+)".to_owned(),
                    group: 1,
                },
                max_length: 3,
                first_only: false,
            }],
            reflected: GrepReflectedConfig::default(),
        };
        let grep = GrepContext::compile(&config).expect("compile");
        let response = ResendResponse {
            status: 200,
            headers: Vec::new(),
            body: Some(b"v=alpha v=bravo".to_vec()),
            duration_ms: 1,
            http_version: None,
            reason: None,
        };
        let outcome = grep.evaluate(&response, &[]);
        // All occurrences joined; each capped to 3 chars.
        assert_eq!(outcome.extracts[0].as_deref(), Some("alp\nbra"));
    }

    #[test]
    fn reflected_matches_pre_url_encoded_form() {
        let config = GrepConfig {
            match_rules: Vec::new(),
            extract_rules: Vec::new(),
            reflected: GrepReflectedConfig {
                enabled: true,
                case_sensitive: true,
                exclude_headers: true,
                match_pre_url_encoded: true,
            },
        };
        let grep = GrepContext::compile(&config).expect("compile");
        let response = ResendResponse {
            status: 200,
            headers: Vec::new(),
            body: Some(b"reflected: <x> here".to_vec()),
            duration_ms: 1,
            http_version: None,
            reason: None,
        };
        // The sent payload was URL-encoded; the response reflects the decoded form.
        let outcome = grep.evaluate(&response, &["%3Cx%3E".to_owned()]);
        assert_eq!(outcome.reflected, Some(1));
    }

    #[test]
    fn grep_and_reflected_route_to_native() {
        let manager = FuzzerWorkbench::new();
        manager.attach_store(temp_store()).expect("attach");
        let mut with_match = config(FuzzerAttackType::Sniper);
        with_match.grep.match_rules = vec![GrepMatchRule {
            name: "e".to_owned(),
            pattern: "e".to_owned(),
            is_regex: false,
            case_sensitive: false,
            exclude_headers: false,
        }];
        assert_eq!(
            manager.create(with_match).expect("create").tier,
            FuzzerTier::Native
        );
        let mut with_reflected = config(FuzzerAttackType::Sniper);
        with_reflected.grep.reflected.enabled = true;
        assert_eq!(
            manager.create(with_reflected).expect("create").tier,
            FuzzerTier::Native
        );
        // A grep-inert config still rides ffuf.
        assert_eq!(
            manager
                .create(config(FuzzerAttackType::Sniper))
                .expect("create")
                .tier,
            FuzzerTier::Ffuf
        );
    }

    #[test]
    fn recursive_grep_with_extract_rule_is_accepted_and_native() {
        let manager = FuzzerWorkbench::new();
        manager.attach_store(temp_store()).expect("attach");
        let mut attack = config(FuzzerAttackType::Sniper);
        attack.payload_sets = vec![PayloadSet {
            name: "r".to_owned(),
            source: PayloadSource::RecursiveGrep {
                seed: vec!["1".to_owned()],
            },
            processors: Vec::new(),
            url_encode_chars: None,
        }];
        attack.grep.extract_rules = vec![recursive_extract_rule()];
        let job = manager.create(attack).expect("create");
        assert_eq!(job.tier, FuzzerTier::Native);
    }

    #[tokio::test]
    async fn recursive_grep_feeds_extracted_value_forward() {
        struct RecursiveSender;
        impl ResendSender for RecursiveSender {
            fn send(
                &self,
                request: ResendRequest,
            ) -> crate::backend::BackendFuture<Result<ResendResponse, Diagnostic>> {
                // The payload is placed at `id=<payload>`; echo the next integer
                // between the delimiters the extract rule looks for.
                let id: u32 = request
                    .url
                    .rsplit("id=")
                    .next()
                    .and_then(|tail| tail.split(|c: char| !c.is_ascii_digit()).next())
                    .and_then(|digits| digits.parse().ok())
                    .unwrap_or(0);
                let body = format!("<next>{}</next>", id + 1);
                Box::pin(async move {
                    Ok(ResendResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: Some(body.into_bytes()),
                        duration_ms: 1,
                        http_version: None,
                        reason: None,
                    })
                })
            }
        }

        let manager = Arc::new(FuzzerWorkbench::new());
        manager.attach_store(temp_store()).expect("attach");
        manager.attach_sender(Arc::new(RecursiveSender));
        let mut attack = config(FuzzerAttackType::Sniper);
        attack.max_results = 5;
        attack.payload_sets = vec![PayloadSet {
            name: "r".to_owned(),
            source: PayloadSource::RecursiveGrep {
                seed: vec!["1".to_owned()],
            },
            processors: Vec::new(),
            url_encode_chars: None,
        }];
        attack.grep.extract_rules = vec![recursive_extract_rule()];
        let job = manager.create(attack).expect("create");
        assert_eq!(job.tier, FuzzerTier::Native);
        manager.launch(&job.id).expect("launch");
        let finished = drive_to_terminal(&manager, &job.id).await;
        assert_eq!(finished.state, FuzzerJobState::Completed);
        assert_eq!(finished.results.len(), 5);
        let payloads: Vec<String> = finished
            .results
            .iter()
            .map(|result| result.payloads[0].clone())
            .collect();
        assert_eq!(payloads, vec!["1", "2", "3", "4", "5"]);
        // Each response's extract populated the grep column and fed the next payload.
        assert_eq!(finished.results[0].grep_extracts[0].as_deref(), Some("2"));
    }

    #[test]
    fn copy_other_payload_rejected_outside_pitchfork_and_cluster() {
        let manager = FuzzerWorkbench::new();
        manager.attach_store(temp_store()).expect("attach");
        let mut sniper = config(FuzzerAttackType::Sniper);
        sniper.payload_sets = vec![
            simple_set("a", &["1"]),
            PayloadSet {
                name: "copy".to_owned(),
                source: PayloadSource::CopyOtherPayload { source_position: 0 },
                processors: Vec::new(),
                url_encode_chars: None,
            },
        ];
        sniper.positions.push(url_position(27, 31, 1));
        assert!(manager.create(sniper).is_err());
    }

    #[test]
    fn copy_other_payload_mirrors_the_referenced_position_in_pitchfork() {
        let mut pitchfork = config(FuzzerAttackType::Pitchfork);
        pitchfork.payload_sets = vec![
            simple_set("a", &["1", "2"]),
            PayloadSet {
                name: "copy".to_owned(),
                source: PayloadSource::CopyOtherPayload { source_position: 0 },
                processors: Vec::new(),
                url_encode_chars: None,
            },
        ];
        pitchfork.positions.push(url_position(27, 31, 1));
        let plan: Vec<PlannedRequest> = plan_attack(&pitchfork)
            .expect("planned")
            .map(|item| item.expect("request"))
            .collect();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].0, vec!["1", "1"]);
        assert_eq!(plan[1].0, vec!["2", "2"]);
    }

    #[tokio::test]
    async fn numbers_source_with_base64_processor_lands_via_native() {
        use std::sync::Mutex;

        struct Capture {
            payloads: Arc<Mutex<Vec<String>>>,
        }
        impl ResendSender for Capture {
            fn send(
                &self,
                request: ResendRequest,
            ) -> crate::backend::BackendFuture<Result<ResendResponse, Diagnostic>> {
                let payloads = Arc::clone(&self.payloads);
                Box::pin(async move {
                    payloads.lock().unwrap().push(request.url);
                    Ok(ResendResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: Some(b"ok".to_vec()),
                        duration_ms: 1,
                        http_version: None,
                        reason: None,
                    })
                })
            }
        }

        let manager = Arc::new(FuzzerWorkbench::new());
        manager.attach_store(temp_store()).expect("attach");
        let payloads = Arc::new(Mutex::new(Vec::new()));
        manager.attach_sender(Arc::new(Capture {
            payloads: Arc::clone(&payloads),
        }));

        // A Numbers source, base64-processed. Padded "01".."03" -> base64.
        let mut attack = config(FuzzerAttackType::Sniper);
        attack.max_results = 100;
        attack.payload_sets = vec![PayloadSet {
            name: "n".to_owned(),
            source: PayloadSource::Numbers {
                from: 1.0,
                to: 3.0,
                step: 1.0,
                order: NumberOrder::Sequential,
                radix: NumberRadix::Dec,
                min_integer_digits: 2,
                max_fraction_digits: 0,
            },
            processors: vec![PayloadProcessor::Encode {
                scheme: EncodeScheme::Base64,
            }],
            url_encode_chars: None,
        }];
        let job = manager.create(attack).expect("create");
        // A generated + processed source cannot ride ffuf.
        assert_eq!(job.tier, FuzzerTier::Native);
        manager.launch(&job.id).expect("launch");
        let finished = drive_to_terminal(&manager, &job.id).await;
        assert_eq!(finished.state, FuzzerJobState::Completed);
        assert_eq!(finished.results.len(), 3);
        let sent = finished
            .results
            .iter()
            .map(|result| result.payloads[0].clone())
            .collect::<Vec<_>>();
        // base64("01") = "MDE=", base64("02") = "MDI=", base64("03") = "MDM=".
        assert_eq!(sent, vec!["MDE=", "MDI=", "MDM="]);
        // The processed payload was actually wired into each sent request URL.
        assert!(
            payloads
                .lock()
                .unwrap()
                .iter()
                .any(|url| url.contains("MDE="))
        );
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

    #[tokio::test]
    async fn ffuf_results_surface_length_as_content_length() {
        // ffuf omits the body but reports `length`; the fuzzer must surface it as
        // a Content-Length header so the GUI's Length column is populated (F20).
        let manager = FuzzerWorkbench::new();
        manager.attach_store(temp_store()).expect("attach");
        let mut job = manager
            .create(config(FuzzerAttackType::Sniper))
            .expect("create");
        let json = serde_json::json!({
            "results": [{ "status": 200, "length": 49, "input": { "FUZZ": "one" } }]
        });
        let mut seen = 0usize;
        let mut cadence = PersistCadence::new();
        manager
            .append_ffuf_results(&mut job, &json, &mut seen, &mut cadence)
            .await
            .expect("append ffuf results");
        assert_eq!(job.results.len(), 1);
        let response = job.results[0].response.as_ref().expect("response present");
        let content_length = response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.clone());
        assert_eq!(content_length.as_deref(), Some("49"));
    }

    #[tokio::test]
    async fn ffuf_result_request_substitutes_the_marked_span_not_literal_fuzz() {
        // Real templates mark the span's original content (here `base`), never the
        // literal `FUZZ` keyword. The stored "as sent" request must show the
        // payload substituted at that span — matching the wire — not the base
        // template. The old `.replace("FUZZ", …)` left this unsubstituted.
        let manager = FuzzerWorkbench::new();
        manager.attach_store(temp_store()).expect("attach");
        let mut job = manager
            .create(config(FuzzerAttackType::Sniper))
            .expect("create");
        job.config.base_request.url = "https://api.example.test/api/users/base/profile".to_owned();
        job.config.positions = vec![PayloadPosition {
            location: FuzzerPositionLocation::Url,
            header_name: None,
            start: 35,
            end: 39,
            set_index: 0,
        }];
        let json = serde_json::json!({
            "results": [{ "status": 200, "length": 110, "input": { "FUZZ": "admin" } }]
        });
        let mut seen = 0usize;
        let mut cadence = PersistCadence::new();
        manager
            .append_ffuf_results(&mut job, &json, &mut seen, &mut cadence)
            .await
            .expect("append ffuf results");
        assert_eq!(job.results.len(), 1);
        assert_eq!(
            job.results[0].request.url,
            "https://api.example.test/api/users/admin/profile"
        );
    }

    #[test]
    fn ffuf_origin_header_matches_the_fuzz_marker_and_parses_back() {
        // The ffuf tier stamps the same marker the OriginTaggingSender uses, and the
        // value must parse back to `Fuzz` exactly as the proxy's strip path does —
        // otherwise ffuf traffic would default to `Capture` and leak into the Live
        // list + fused surface.
        let header = ffuf_origin_header();
        assert_eq!(header, format!("{ORIGIN_MARKER_HEADER}: fuzz"));
        let (name, value) = header.split_once(": ").expect("well-formed header");
        assert!(name.eq_ignore_ascii_case(ORIGIN_MARKER_HEADER));
        assert_eq!(FlowOrigin::from_db_str(value), FlowOrigin::Fuzz);
    }

    #[test]
    fn ffuf_progress_line_is_parsed_for_live_count() {
        // The last progress line wins; a stream with no progress line yet is None.
        let stream = ":: Progress: [10/500] :: Job [1/1] :: 40 req/sec ::\n\
             :: Progress: [123/500] :: Job [1/1] :: 60 req/sec :: Duration: [0:00:02] ::\n";
        assert_eq!(super::parse_ffuf_progress(stream), Some(123));
        assert_eq!(
            super::parse_ffuf_progress("starting up, no progress yet"),
            None
        );
        assert_eq!(super::parse_ffuf_progress(""), None);
    }

    #[test]
    fn ffuf_carries_the_native_wire_header_list() {
        use crate::raw_http::{WIRE_HEADERS_MARKER, decode_header_list};

        let decode = |header: String| {
            let (name, value) = header.split_once(": ").expect("well-formed header");
            assert_eq!(name, WIRE_HEADERS_MARKER);
            decode_header_list(value.as_bytes()).expect("decodable list")
        };
        let pairs = |list: &[(&str, &str)]| {
            list.iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect::<Vec<_>>()
        };
        let path_position = PayloadPosition {
            location: FuzzerPositionLocation::Url,
            header_name: None,
            start: 23,
            end: 27,
            set_index: 0,
        };
        // Exactly what the native tier sends: authored order and case, the
        // private markers dropped, Content-Length recomputed for the body.
        let request = ResendRequest {
            method: "POST".to_owned(),
            url: "http://api.example.test/base".to_owned(),
            headers: pairs(&[
                ("user-agent", "curl/8.12.1"),
                ("accept", "*/*"),
                (ORIGIN_MARKER_HEADER, "fuzz"),
                ("Content-Length", "999"),
            ]),
            body: Some(b"a=1".to_vec()),
        };
        assert_eq!(
            decode(ffuf_wire_headers(&request, &[path_position.clone()])),
            crate::resend::wire_header_list(&request, true)
        );
        assert_eq!(
            decode(ffuf_wire_headers(&request, &[path_position.clone()])),
            pairs(&[
                ("Host", "api.example.test"),
                ("user-agent", "curl/8.12.1"),
                ("accept", "*/*"),
                ("Content-Length", "3"),
            ])
        );
        // A payload in the authority with no authored Host: Host is left for
        // the proxy to derive from the substituted URL ffuf requested.
        let subdomain = ResendRequest {
            method: "GET".to_owned(),
            url: "https://FUZZ.example.test".to_owned(),
            headers: Vec::new(),
            body: None,
        };
        let host_position = PayloadPosition {
            start: 8,
            end: 12,
            ..path_position.clone()
        };
        assert!(decode(ffuf_wire_headers(&subdomain, &[host_position.clone()])).is_empty());
        assert!(in_authority(&subdomain.url, &host_position));
        assert!(!in_authority(&request.url, &path_position));
        // The substitution keyword can never collide with base64 marker text.
        assert!(FFUF_KEYWORD.contains('_'));
    }

    #[test]
    fn rate_diagnostic_labels_fuzz_vs_discovery() {
        // An ffuf-tier Fuzz run must not be labeled a discovery run.
        assert_eq!(
            rate_observed_diagnostic(3, 1.0, 3.0, 0, false).id.as_ref(),
            "proxy.fuzzer-rate-observed"
        );
        assert_eq!(
            rate_observed_diagnostic(3, 1.0, 3.0, 0, true).id.as_ref(),
            "web.discovery-rate-observed"
        );
    }

    #[test]
    fn stateless_and_stateful_jobs_select_the_expected_tier() {
        let path = std::env::temp_dir().join(format!(
            "apiaxess-fuzzer-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let store = Arc::new(TrafficStore::open(&path, "session:test").expect("store"));
        let manager = FuzzerWorkbench::new();
        manager.attach_store(Arc::clone(&store)).expect("attach");
        let stateless = manager
            .create(config(FuzzerAttackType::Sniper))
            .expect("create");
        assert_eq!(stateless.tier, FuzzerTier::Ffuf);
        let mut stateful_config = config(FuzzerAttackType::Sniper);
        stateful_config.auth_preflight = Some(request());
        let stateful = manager.create(stateful_config).expect("create");
        assert_eq!(stateful.tier, FuzzerTier::Native);
    }

    fn temp_store() -> Arc<TrafficStore> {
        let path = std::env::temp_dir().join(format!(
            "apiaxess-fuzzer-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        Arc::new(TrafficStore::open(&path, "session:test").expect("store"))
    }

    #[test]
    fn richer_configs_route_to_native_so_their_controls_take_effect() {
        let manager = FuzzerWorkbench::new();
        manager.attach_store(temp_store()).expect("attach");
        // A content match rule cannot be expressed to ffuf faithfully.
        let mut contains = config(FuzzerAttackType::Sniper);
        contains.match_filter.contains = Some("token".to_owned());
        assert_eq!(
            manager.create(contains).expect("create").tier,
            FuzzerTier::Native
        );
        // Multiple positions/sets (Clusterbomb) exceed ffuf's single-FUZZ model.
        let mut multi = config(FuzzerAttackType::Clusterbomb);
        multi.positions.push(PayloadPosition {
            location: FuzzerPositionLocation::Url,
            header_name: None,
            start: 27,
            end: 31,
            set_index: 1,
        });
        multi.payload_sets.push(simple_set("second", &["red"]));
        assert_eq!(
            manager.create(multi).expect("create").tier,
            FuzzerTier::Native
        );
        // A status-only filter still rides the fast ffuf path (passed via -mc).
        let mut status_only = config(FuzzerAttackType::Sniper);
        status_only.match_filter.statuses = vec![200, 301];
        assert_eq!(
            manager.create(status_only).expect("create").tier,
            FuzzerTier::Ffuf
        );
    }

    #[tokio::test]
    async fn native_attack_runs_every_payload_with_bounded_concurrency() {
        use std::sync::atomic::AtomicUsize;

        struct CountingSender {
            count: Arc<AtomicUsize>,
        }
        impl ResendSender for CountingSender {
            fn send(
                &self,
                _request: ResendRequest,
            ) -> crate::backend::BackendFuture<Result<ResendResponse, Diagnostic>> {
                let count = Arc::clone(&self.count);
                Box::pin(async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(ResendResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: Some(b"ok".to_vec()),
                        duration_ms: 1,
                        http_version: None,
                        reason: None,
                    })
                })
            }
        }

        let manager = Arc::new(FuzzerWorkbench::new());
        manager.attach_store(temp_store()).expect("attach");
        let count = Arc::new(AtomicUsize::new(0));
        manager.attach_sender(Arc::new(CountingSender {
            count: Arc::clone(&count),
        }));

        // A content match rule forces the native tier; five payloads, width 3.
        let mut attack = config(FuzzerAttackType::Sniper);
        attack.match_filter.contains = Some("ok".to_owned());
        attack.concurrency = 3;
        attack.payload_sets[0].source = PayloadSource::SimpleList {
            values: (0..5).map(|index| format!("p{index}")).collect(),
        };
        let job = manager.create(attack).expect("create");
        assert_eq!(job.tier, FuzzerTier::Native);

        let launched = manager.launch(&job.id).expect("launch");
        let mut finished = None;
        for _ in 0..200 {
            let current = manager.get(&launched.id).expect("job present");
            if matches!(current.state, FuzzerJobState::Completed) {
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

    async fn drive_to_terminal(manager: &Arc<FuzzerWorkbench>, id: &str) -> FuzzerJob {
        for _ in 0..400 {
            let current = manager.get(id).expect("job present");
            if matches!(
                current.state,
                FuzzerJobState::Completed | FuzzerJobState::Stopped | FuzzerJobState::Failed
            ) {
                return current;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("job did not reach a terminal state");
    }

    /// A completed native job — persisted through the throttled, off-runtime path
    /// — must be fully on disk: reopening the store and re-hydrating recovers the
    /// terminal state and every result. This guards the cadence throttle against
    /// silently dropping the tail of a job that never hit a mid-run checkpoint.
    #[tokio::test]
    async fn completed_job_survives_a_restart_with_all_results() {
        let path = std::env::temp_dir().join(format!(
            "apiaxess-fuzzer-restart-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let job_id = {
            let store = Arc::new(TrafficStore::open(&path, "session:test").expect("store"));
            let manager = Arc::new(FuzzerWorkbench::new());
            manager.attach_store(store).expect("attach");
            manager.attach_sender(Arc::new(InstantSender));

            let mut attack = config(FuzzerAttackType::Sniper);
            attack.match_filter.contains = Some("x".to_owned());
            attack.max_results = 120;
            attack.payload_sets[0].source = PayloadSource::SimpleList {
                values: (0..120).map(|index| format!("p{index}")).collect(),
            };
            let job = manager.create(attack).expect("create");
            manager.launch(&job.id).expect("launch");
            let finished = drive_to_terminal(&manager, &job.id).await;
            assert_eq!(finished.state, FuzzerJobState::Completed);
            assert_eq!(finished.results.len(), 120);
            job.id
        };

        // Simulate an engine restart: a fresh store + workbench over the same path.
        let reopened = Arc::new(TrafficStore::open(&path, "session:test").expect("reopen"));
        let recovered_manager = Arc::new(FuzzerWorkbench::new());
        recovered_manager.attach_store(reopened).expect("reattach");
        let recovered = recovered_manager.get(&job_id).expect("job recovered");
        assert_eq!(recovered.state, FuzzerJobState::Completed);
        assert_eq!(
            recovered.results.len(),
            120,
            "every result survives a restart despite the throttled persist cadence"
        );
        // Ordinals stay dense and sequential across the persisted set.
        for (index, result) in recovered.results.iter().enumerate() {
            assert_eq!(result.ordinal, u64::try_from(index + 1).unwrap());
        }
    }

    /// A sender that returns instantly — isolates persistence cost from network.
    struct InstantSender;
    impl ResendSender for InstantSender {
        fn send(
            &self,
            _request: ResendRequest,
        ) -> crate::backend::BackendFuture<Result<ResendResponse, Diagnostic>> {
            Box::pin(async move {
                Ok(ResendResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: Some(vec![b'x'; 512]),
                    duration_ms: 1,
                    http_version: None,
                    reason: None,
                })
            })
        }
    }

    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn percentile(sorted_ms: &[f64], pct: f64) -> f64 {
        if sorted_ms.is_empty() {
            return 0.0;
        }
        let rank = (pct / 100.0 * (sorted_ms.len() as f64 - 1.0)).round() as usize;
        sorted_ms[rank.min(sorted_ms.len() - 1)]
    }

    /// Repro/attribution harness for F-A (fuzzer persistence starves the runtime).
    ///
    /// Runs on a deliberately small worker pool so blocking store IO on a worker
    /// is observable. A probe task samples scheduling latency (sleep oversleep)
    /// while N fuzzer jobs each accumulate M results. On the pre-fix code the
    /// probe's p99 spikes into the hundreds of ms / seconds; after routing
    /// persistence off the runtime it stays flat. Ignored by default — this is a
    /// timing measurement, not a CI assertion. Run with:
    ///   cargo test -p apiaxess-workbench-proxy --release -- --ignored --nocapture fuzzer_persistence
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "perf repro; run explicitly with --ignored --nocapture"]
    #[allow(clippy::cast_precision_loss)]
    async fn fuzzer_persistence_runtime_starvation_repro() {
        const JOBS: usize = 24;
        const PAYLOADS: usize = 300;
        const PROBE_INTERVAL_MS: u64 = 5;
        const PROBE_SAMPLES: usize = 400;

        let manager = Arc::new(FuzzerWorkbench::new());
        manager.attach_store(temp_store()).expect("attach");
        manager.attach_sender(Arc::new(InstantSender));

        // Probe task: measure how far each timer wakeup overshoots its deadline.
        // A starved worker pool cannot promptly run the woken timer task, so the
        // oversleep is a direct proxy for "GET / stalls while jobs churn".
        let probe = tokio::spawn(async move {
            let mut oversleep_ms = Vec::with_capacity(PROBE_SAMPLES);
            for _ in 0..PROBE_SAMPLES {
                let start = Instant::now();
                tokio::time::sleep(Duration::from_millis(PROBE_INTERVAL_MS)).await;
                let actual = start.elapsed().as_secs_f64() * 1000.0;
                oversleep_ms.push((actual - PROBE_INTERVAL_MS as f64).max(0.0));
            }
            oversleep_ms
        });

        // Give the probe a head start so its baseline is measured while idle.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let overall = Instant::now();
        for _ in 0..JOBS {
            // A content match rule forces the native tier (the O(n^2) persist path).
            let mut attack = config(FuzzerAttackType::Sniper);
            attack.match_filter.contains = Some("x".to_owned());
            attack.concurrency = 8;
            attack.max_results = PAYLOADS;
            attack.payload_sets[0].source = PayloadSource::SimpleList {
                values: (0..PAYLOADS).map(|index| format!("p{index}")).collect(),
            };
            attack.positions[0].end = 34; // zero-width insert at the FUZZ marker
            let job = manager.create(attack).expect("create");
            manager.launch(&job.id).expect("launch");
        }

        // Wait for every job to reach a terminal state.
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let jobs = manager.list();
            let done = jobs
                .iter()
                .filter(|job| {
                    matches!(
                        job.state,
                        FuzzerJobState::Completed
                            | FuzzerJobState::Stopped
                            | FuzzerJobState::Failed
                    )
                })
                .count();
            if done >= JOBS || Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let wall = overall.elapsed();

        let mut samples = probe.await.expect("probe joined");
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let total_results: usize = manager.list().iter().map(|job| job.results.len()).sum();
        println!(
            "F-A repro: jobs={JOBS} payloads/job={PAYLOADS} results={total_results} wall={:.1}s",
            wall.as_secs_f64()
        );
        println!(
            "F-A repro: probe oversleep ms  p50={:.1}  p95={:.1}  p99={:.1}  max={:.1}",
            percentile(&samples, 50.0),
            percentile(&samples, 95.0),
            percentile(&samples, 99.0),
            samples.last().copied().unwrap_or(0.0),
        );
    }
}
