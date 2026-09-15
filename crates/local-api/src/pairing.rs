//! Device pairing token lifecycle.
//!
//! A device that wants to relay traffic to the workbench must first authenticate
//! a control connection. Because a device is inherently cross-origin, it cannot
//! pass the loopback `Origin` guard the browser UI uses; instead it authenticates
//! by bearer token. This module owns the two-stage token model that makes that
//! secure:
//!
//! 1. The operator mints a **one-time pairing token** on the trusted workbench
//!    (this is what the C5 QR will carry). It is short-lived and single-use.
//! 2. The device presents that pairing token once, in exchange for a longer-lived
//!    **per-session bearer token**. The pairing token is consumed on exchange, so
//!    it can never be replayed.
//! 3. Every subsequent device control/traffic connection authenticates with the
//!    session bearer token, validated against this registry.
//!
//! No token is ever persisted; the registry lives only for the workbench process.
//! A random device on the network cannot mint a pairing token (that path is
//! operator-origin-gated) and cannot forge a 256-bit session token, so it can
//! neither pair nor open the device control channel.

use std::{
    collections::HashMap,
    fmt::Write as _,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use getrandom::fill;

/// A one-time pairing token is valid for this long before it must be re-issued.
const PAIRING_TOKEN_TTL: Duration = Duration::from_secs(5 * 60);

/// A device session bearer token is valid for this long before the device must
/// pair again.
const SESSION_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// A freshly issued token and the wall-clock instant at which it expires.
///
/// The expiry is reported to clients for display only; validation always uses a
/// monotonic clock internally so a wall-clock change cannot extend a token.
#[derive(Debug, Clone)]
pub(crate) struct IssuedToken {
    /// The opaque bearer value the client presents on subsequent requests.
    pub token: String,
    /// Milliseconds since the Unix epoch at which the token expires.
    pub expires_at_ms: u64,
}

/// What a validated pairing token entitles its bearer to (Phase C5). Carries the
/// adb serial the operator armed the token for, so an accept can provision the
/// exact device (via C2's `provision_adb_device`).
#[derive(Debug, Clone)]
pub(crate) struct PairingClaim {
    /// adb serial bound at arm time, if the token was armed for a device.
    pub serial: Option<String>,
}

struct PairingTokenEntry {
    expiry: Instant,
    serial: Option<String>,
}

/// Session-scoped registry of live pairing and device session tokens.
#[derive(Clone, Default)]
pub(crate) struct DevicePairingRegistry {
    inner: Arc<Mutex<PairingState>>,
}

#[derive(Default)]
struct PairingState {
    /// One-time pairing tokens → their expiry + the device serial they were
    /// armed for (`None` for a device that is already provisioned).
    pairing_tokens: HashMap<String, PairingTokenEntry>,
    /// Issued device session bearer tokens → their monotonic expiry instant.
    session_tokens: HashMap<String, Instant>,
}

impl DevicePairingRegistry {
    /// Mints a fresh one-time pairing token, optionally bound to the adb serial
    /// the operator is arming (so accepting it provisions that exact device).
    ///
    /// Returns `None` only if the registry lock is poisoned (fail closed).
    pub fn issue_pairing_token(&self, serial: Option<String>) -> Option<IssuedToken> {
        let token = random_token()?;
        let now = Instant::now();
        let mut state = self.inner.lock().ok()?;
        state.prune(now);
        state.pairing_tokens.insert(
            token.clone(),
            PairingTokenEntry {
                expiry: now + PAIRING_TOKEN_TTL,
                serial,
            },
        );
        Some(IssuedToken {
            token,
            expires_at_ms: wall_clock_expiry_ms(PAIRING_TOKEN_TTL),
        })
    }

    /// Validates and consumes a one-time pairing token, returning what it claims.
    ///
    /// The token is removed on success so it can never be replayed. Consuming is
    /// deliberately separate from issuing a session token (Phase C5): the operator
    /// accept/decline gate sits between them. Returns `None` when the token is
    /// unknown, expired, already used, or the lock is poisoned.
    pub fn consume_pairing_token(&self, pairing_token: &str) -> Option<PairingClaim> {
        let now = Instant::now();
        let mut state = self.inner.lock().ok()?;
        state.prune(now);
        // Remove first: the token is single-use regardless of what follows, and
        // an expired-but-not-yet-pruned entry must not be accepted.
        let entry = state.pairing_tokens.remove(pairing_token)?;
        if entry.expiry <= now {
            return None;
        }
        Some(PairingClaim {
            serial: entry.serial,
        })
    }

    /// Mints a per-session device bearer token. Called only after an operator
    /// accept (Phase C5), so a consumed pairing token alone never yields one.
    ///
    /// Returns `None` only if the CSPRNG or the lock is unavailable (fail closed).
    pub fn issue_session_token(&self) -> Option<IssuedToken> {
        let token = random_token()?;
        let now = Instant::now();
        let mut state = self.inner.lock().ok()?;
        state.prune(now);
        state
            .session_tokens
            .insert(token.clone(), now + SESSION_TOKEN_TTL);
        Some(IssuedToken {
            token,
            expires_at_ms: wall_clock_expiry_ms(SESSION_TOKEN_TTL),
        })
    }

    /// Consumes a pairing token and immediately issues a session token — the
    /// pre-C5 ungated exchange, retained for tests and any ungated callers.
    #[cfg(test)]
    pub fn exchange(&self, pairing_token: &str) -> Option<IssuedToken> {
        self.consume_pairing_token(pairing_token)
            .and_then(|_claim| self.issue_session_token())
    }

    /// Returns whether a device session bearer token is currently valid.
    pub fn validate_session_token(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let now = Instant::now();
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        state.prune(now);
        state
            .session_tokens
            .get(token)
            .is_some_and(|expiry| *expiry > now)
    }
}

impl PairingState {
    /// Drops every expired token so the maps cannot grow without bound.
    fn prune(&mut self, now: Instant) {
        self.pairing_tokens.retain(|_, entry| entry.expiry > now);
        self.session_tokens.retain(|_, expiry| *expiry > now);
    }
}

/// A pending pairing request lives this long awaiting an operator decision.
const PENDING_TTL: Duration = Duration::from_secs(5 * 60);

/// The operator's decision on a device that presented a valid pairing token.
enum PendingStatus {
    /// Awaiting the operator's accept/decline.
    Pending,
    /// Accepted; carries the issued per-session bearer token for the device.
    Accepted(IssuedToken),
    /// Declined by the operator.
    Declined,
}

struct PendingEntry {
    device_name: String,
    serial: Option<String>,
    created_at: Instant,
    status: PendingStatus,
}

/// One device awaiting accept/decline, as the operator UI sees it.
#[derive(Debug, Clone)]
pub(crate) struct PendingSummary {
    pub id: String,
    pub device_name: String,
    pub serial: Option<String>,
    pub requested_ago_ms: u64,
}

/// The device's poll result while it waits for the operator decision.
pub(crate) enum PairingOutcome {
    /// Still awaiting a decision.
    Pending,
    /// Accepted; the device receives this per-session bearer token.
    Accepted(IssuedToken),
    /// The operator declined.
    Declined,
    /// The request is unknown or expired.
    Unknown,
}

/// The accept/decline gate (Phase C5): devices that present a valid pairing token
/// land here as pending requests until a human at the workbench decides. Nothing —
/// no session token, no provisioning — happens without an explicit accept.
#[derive(Clone, Default)]
pub(crate) struct PendingPairingRegistry {
    inner: Arc<Mutex<HashMap<String, PendingEntry>>>,
}

impl PendingPairingRegistry {
    /// Registers a device awaiting the operator's decision; returns the request id
    /// the device polls. Returns `None` on CSPRNG/lock failure (fail closed).
    pub fn register(&self, device_name: String, serial: Option<String>) -> Option<String> {
        let id = random_token()?;
        let mut map = self.inner.lock().ok()?;
        prune_pending(&mut map);
        map.insert(
            id.clone(),
            PendingEntry {
                device_name,
                serial,
                created_at: Instant::now(),
                status: PendingStatus::Pending,
            },
        );
        Some(id)
    }

    /// Requests still awaiting a decision (the operator prompt list).
    pub fn list_pending(&self) -> Vec<PendingSummary> {
        let now = Instant::now();
        let Ok(mut map) = self.inner.lock() else {
            return Vec::new();
        };
        prune_pending(&mut map);
        map.iter()
            .filter(|(_, entry)| matches!(entry.status, PendingStatus::Pending))
            .map(|(id, entry)| PendingSummary {
                id: id.clone(),
                device_name: entry.device_name.clone(),
                serial: entry.serial.clone(),
                requested_ago_ms: u64::try_from(
                    now.saturating_duration_since(entry.created_at).as_millis(),
                )
                .unwrap_or(u64::MAX),
            })
            .collect()
    }

    /// The serial to provision for a pending request, or `None` when the id is
    /// unknown or already decided. Read-only. The inner `Option` distinguishes a
    /// pending request armed for a device (`Some(Some(serial))`) from one armed
    /// without one (`Some(None)`), so all three states are meaningful here.
    #[allow(clippy::option_option)]
    pub fn serial_for_pending(&self, id: &str) -> Option<Option<String>> {
        let map = self.inner.lock().ok()?;
        let entry = map.get(id)?;
        matches!(entry.status, PendingStatus::Pending).then(|| entry.serial.clone())
    }

    /// Records an accept, storing the issued session token for the device to poll.
    /// Returns false if the request is unknown or no longer pending.
    pub fn accept(&self, id: &str, session: IssuedToken) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        match map.get_mut(id) {
            Some(entry) if matches!(entry.status, PendingStatus::Pending) => {
                entry.status = PendingStatus::Accepted(session);
                true
            }
            _ => false,
        }
    }

    /// Records a decline. Returns false if the request is unknown or decided.
    pub fn decline(&self, id: &str) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        match map.get_mut(id) {
            Some(entry) if matches!(entry.status, PendingStatus::Pending) => {
                entry.status = PendingStatus::Declined;
                true
            }
            _ => false,
        }
    }

    /// The device polls this to learn the operator's decision.
    pub fn poll(&self, id: &str) -> PairingOutcome {
        let Ok(mut map) = self.inner.lock() else {
            return PairingOutcome::Unknown;
        };
        prune_pending(&mut map);
        match map.get(id).map(|entry| &entry.status) {
            Some(PendingStatus::Pending) => PairingOutcome::Pending,
            Some(PendingStatus::Accepted(token)) => PairingOutcome::Accepted(token.clone()),
            Some(PendingStatus::Declined) => PairingOutcome::Declined,
            None => PairingOutcome::Unknown,
        }
    }
}

fn prune_pending(map: &mut HashMap<String, PendingEntry>) {
    let now = Instant::now();
    map.retain(|_, entry| now.saturating_duration_since(entry.created_at) < PENDING_TTL);
}

/// Generates a 256-bit random token rendered as lowercase hex.
///
/// Returns `None` only if the platform CSPRNG is unavailable, so callers fail
/// closed rather than mint a predictable token.
fn random_token() -> Option<String> {
    let mut bytes = [0_u8; 32];
    fill(&mut bytes).ok()?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    Some(token)
}

/// Wall-clock expiry in milliseconds since the Unix epoch, for client display.
fn wall_clock_expiry_ms(ttl: Duration) -> u64 {
    let expiry = SystemTime::now() + ttl;
    expiry
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_tokens_are_unique_and_hex() {
        let registry = DevicePairingRegistry::default();
        let first = registry
            .issue_pairing_token(None)
            .expect("first pairing token");
        let second = registry
            .issue_pairing_token(None)
            .expect("second pairing token");
        assert_ne!(first.token, second.token);
        assert_eq!(first.token.len(), 64);
        assert!(first.token.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn exchange_consumes_the_pairing_token_and_issues_a_session_token() {
        let registry = DevicePairingRegistry::default();
        let pairing = registry.issue_pairing_token(None).expect("pairing token");
        let session = registry
            .exchange(&pairing.token)
            .expect("exchange yields a session token");
        assert_ne!(session.token, pairing.token);
        assert!(registry.validate_session_token(&session.token));
        // The pairing token is single-use: a replay must fail.
        assert!(registry.exchange(&pairing.token).is_none());
    }

    #[test]
    fn consume_returns_the_armed_serial_and_gate_splits_issuance() {
        let registry = DevicePairingRegistry::default();
        let pairing = registry
            .issue_pairing_token(Some("SERIAL-XYZ".to_owned()))
            .expect("pairing token");
        // Consuming validates the token and yields its armed serial, but does NOT
        // issue a session token (that is gated behind an operator accept).
        let claim = registry
            .consume_pairing_token(&pairing.token)
            .expect("valid token consumed");
        assert_eq!(claim.serial.as_deref(), Some("SERIAL-XYZ"));
        // Single-use: a second consume fails.
        assert!(registry.consume_pairing_token(&pairing.token).is_none());
        // The session token is minted only by the explicit accept step.
        let session = registry.issue_session_token().expect("session token");
        assert!(registry.validate_session_token(&session.token));
    }

    #[test]
    fn unknown_and_forged_tokens_are_rejected() {
        let registry = DevicePairingRegistry::default();
        assert!(registry.consume_pairing_token("not-a-real-token").is_none());
        assert!(!registry.validate_session_token("not-a-real-token"));
        assert!(!registry.validate_session_token(""));
    }

    #[test]
    fn expired_pairing_tokens_cannot_be_consumed() {
        let registry = DevicePairingRegistry::default();
        let pairing = registry.issue_pairing_token(None).expect("pairing token");
        // Force expiry by rewriting the stored instant into the past.
        {
            let mut state = registry.inner.lock().expect("lock");
            let entry = state
                .pairing_tokens
                .get_mut(&pairing.token)
                .expect("token present");
            entry.expiry = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test clock supports one second in the past");
        }
        assert!(registry.consume_pairing_token(&pairing.token).is_none());
    }

    #[test]
    fn expired_session_tokens_are_rejected() {
        let registry = DevicePairingRegistry::default();
        let session = registry.issue_session_token().expect("session token");
        {
            let mut state = registry.inner.lock().expect("lock");
            let expiry = state
                .session_tokens
                .get_mut(&session.token)
                .expect("token present");
            *expiry = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test clock supports one second in the past");
        }
        assert!(!registry.validate_session_token(&session.token));
    }

    #[test]
    fn pending_gate_accept_flow_yields_the_session_token() {
        let pending = PendingPairingRegistry::default();
        let id = pending
            .register("Pixel 8".to_owned(), Some("SERIAL-XYZ".to_owned()))
            .expect("register pending");
        // The operator sees exactly one pending request with the armed serial.
        let list = pending.list_pending();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].serial.as_deref(), Some("SERIAL-XYZ"));
        assert!(matches!(pending.poll(&id), PairingOutcome::Pending));
        // Accept stores the session token; the device polls it exactly like this.
        assert_eq!(
            pending.serial_for_pending(&id),
            Some(Some("SERIAL-XYZ".to_owned()))
        );
        let session = IssuedToken {
            token: "session".to_owned(),
            expires_at_ms: 0,
        };
        assert!(pending.accept(&id, session));
        match pending.poll(&id) {
            PairingOutcome::Accepted(token) => assert_eq!(token.token, "session"),
            _ => panic!("expected accepted"),
        }
        // Once decided it is no longer offered to the operator.
        assert!(pending.list_pending().is_empty());
        // A second accept is a no-op.
        assert!(!pending.accept(
            &id,
            IssuedToken {
                token: "other".to_owned(),
                expires_at_ms: 0
            }
        ));
    }

    #[test]
    fn pending_gate_decline_and_unknown_are_distinct() {
        let pending = PendingPairingRegistry::default();
        let id = pending
            .register("device".to_owned(), None)
            .expect("register");
        assert!(pending.decline(&id));
        assert!(matches!(pending.poll(&id), PairingOutcome::Declined));
        assert!(matches!(
            pending.poll("never-existed"),
            PairingOutcome::Unknown
        ));
        // A declined request cannot then be accepted.
        assert!(!pending.accept(
            &id,
            IssuedToken {
                token: "x".to_owned(),
                expires_at_ms: 0
            }
        ));
    }
}
