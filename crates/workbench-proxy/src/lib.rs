//! Session-scoped interception proxy and ephemeral certificate authority.
//!
//! The public surface in this crate is intentionally expressed in terms of
//! `ProxyBackend`, flow events, and CA operations. `hudsucker` is an embedded
//! implementation detail of the default backend; later workbench phases must
//! not depend on it directly.

mod backend;
mod bundled;
pub use bundled::resolved_ffuf;
pub mod ca;
pub mod intruder;
pub mod live;
pub mod repeater;
pub mod transparent;
pub mod trust;

pub use apiaxess_workbench_store::{
    RepeaterContext, RepeaterRequest, RepeaterResponse, RepeaterRevision, TrafficStore,
};
pub use backend::{
    BackendHealth, BackendKind, BodyDirection, FlowEvent, FlowObserver, HudsuckerBackend,
    InterceptController, InterceptDecision, NoopObserver, ProxyBackend, ProxyConfig, ProxyCore,
    ProxyHandle, WebSocketDirection,
};
pub use ca::{CaExport, SessionCa};
pub use intruder::IntruderWorkbench;
pub use live::{
    CredentialPrompt, CredentialPromptAnswer, CredentialPromptField, FlowDetail, FlowRecord,
    FlowSummary, LiveWorkbench, LiveUpdate,
};
pub use repeater::{ProxyRepeaterSender, RepeaterSendResult, RepeaterSender, RepeaterWorkbench};
pub use transparent::TransparentFrontend;
pub use trust::{
    BrowserKind, BrowserPlatform, BrowserProfileInstall, BrowserTrustController,
    BrowserTrustStatus, CaStateLog, ClientProfile, SystemCaInstall, SystemStorePurger,
    TrustProvisionReceipt, TrustScope,
};
