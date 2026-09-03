//! Phase 11.4 — linked `frida-core` instrumentation (feature `frida-embedded`).
//!
//! This drives instrumentation through the first-party Rust bindings
//! (`frida-rust`, which links `libfrida-core`) instead of the host Python/Frida
//! CLI. It replaces the CLI spawn/attach/script-load path in
//! [`crate::instrumentation`]: no host Python, no host Frida install. The
//! device-side `frida-server` is still used (it is baked into the owned Android
//! image or pushed as a bundled data file); `frida-core` connects to it over
//! the USB/local transport and drives the session.
//!
//! Build/link: this module is compiled only with the `frida-embedded` feature,
//! which pulls the `frida` crate and links the frida-core devkit. The `frida`
//! crate major tracks the upstream frida release, so it must stay aligned with
//! the pinned devkit and the device-side `frida-server` version — both pinned
//! in `packaging/assets/frida.toml` and fetched by `fetch-frida.ps1`. Because
//! the devkit is only present in a Phase-12 packaging build, this module is not
//! compiled by the default workspace build; when the feature is enabled it must
//! be compiled against the matching frida-rust 0.17.x API.

use std::{
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use frida::{Device, DeviceManager, Frida, ScriptOption, Session, SpawnOptions};

use crate::instrumentation::{InstrumentationMode, InstrumentationRequest};

/// A live, linked frida-core session owning the loaded analysis script.
///
/// frida-rust models the `Frida → DeviceManager → Device → Session → Script`
/// chain with phantom lifetimes over independently reference-counted `GObjects`.
/// The bundle below owns the loaded `Script`; the parent handles that keep it
/// live (the process-global `Frida` context, the `DeviceManager`, `Device`, and
/// `Session`) are held for the process lifetime by the substrate (see
/// [`FridaCoreInstrumentation::run`]), which is why this type carries no
/// lifetime parameter.
pub struct FridaCoreSession {
    /// The loaded analysis script; dropping it unloads the instrumentation.
    _script: frida::Script<'static>,
    /// Target process ID under instrumentation.
    pub pid: u32,
}

/// Send-safe owner for a non-`Send` frida-core session.
///
/// The Frida bindings must stay on the thread that created them. This
/// controller owns that thread and exposes only a stop signal, allowing the
/// normal session-cleanup registry to retain and tear down instrumentation.
pub struct FridaCoreController {
    stop: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl FridaCoreController {
    /// Starts linked instrumentation on its owning thread and waits for the
    /// spawn gate/script-load result.
    pub fn start(request: InstrumentationRequest) -> Result<Self, Diagnostic> {
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (stop_sender, stop_receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("apiaxess-frida-core".to_owned())
            .spawn(move || {
                let instrumentation = FridaCoreInstrumentation::new();
                match instrumentation.run(&request) {
                    Ok(session) => {
                        let _ = ready_sender.send(Ok(()));
                        let _ = stop_receiver.recv();
                        drop(session);
                    }
                    Err(diagnostic) => {
                        let _ = ready_sender.send(Err(diagnostic));
                    }
                }
            })
            .map_err(|error| frida_diagnostic("controller", &error.to_string()))?;
        match ready_receiver.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(())) => Ok(Self {
                stop: Some(stop_sender),
                worker: Some(worker),
            }),
            Ok(Err(diagnostic)) => {
                let _ = worker.join();
                Err(diagnostic)
            }
            Err(error) => {
                let _ = stop_sender.send(());
                let _ = worker.join();
                Err(frida_diagnostic("controller", &error.to_string()))
            }
        }
    }

    /// Stops the owning thread, unloading the script before guest cleanup.
    pub fn teardown(mut self) -> Result<(), Diagnostic> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| frida_diagnostic("controller", "instrumentation thread panicked"))?;
        }
        Ok(())
    }
}

/// Linked frida-core instrumentation substrate.
///
/// Holds the process-global `Frida` context. Feature-trimming (omitting the V8
/// runtime, ICE, and unused bridges while keeping the Android Java/ART bridge
/// the pinning/signing hooks require) is applied through the pinned devkit and
/// the `frida` crate's default-features-off configuration, not at this layer.
pub struct FridaCoreInstrumentation {
    // The frida-core runtime is process-global: `Frida::obtain` is an idempotent
    // no-op after first initialization, and its `Drop` calls `frida_deinit`,
    // which must not run while any session is live. Holding a `&'static Frida`
    // (leaked once at construction) both matches that process-global lifetime and
    // lets `DeviceManager`/`Device`/`Session`/`Script`, whose frida-rust
    // lifetimes are phantom over refcounted handles, resolve to `'static` so a
    // live session can be returned from `run`.
    frida: &'static Frida,
}

impl Default for FridaCoreInstrumentation {
    fn default() -> Self {
        Self::new()
    }
}

impl FridaCoreInstrumentation {
    /// Obtains the process-global frida-core context.
    #[must_use]
    #[allow(unsafe_code)] // The one audited FFI site: frida-core runtime init.
    pub fn new() -> Self {
        // Safety: `Frida::obtain` initializes the process-global frida-core
        // runtime. The handle is leaked so it lives for the process (its `Drop`
        // deinitializes frida-core, which must not happen while sessions run);
        // obtain is idempotent, so a single leaked context is the correct model.
        let frida: &'static Frida = Box::leak(Box::new(unsafe { Frida::obtain() }));
        Self { frida }
    }

    /// Spawns or attaches to the target through the device-side `frida-server`,
    /// loads the analysis script at the earliest possible point, and resumes a
    /// spawn-gated process.
    ///
    /// # Errors
    ///
    /// Returns a structured diagnostic when no device with a running
    /// `frida-server` is reachable, or when spawn/attach/script-load fails.
    pub fn run(&self, request: &InstrumentationRequest) -> Result<FridaCoreSession, Diagnostic> {
        // The manager and device are leaked to `'static` so the `Session`/
        // `Script` produced below (whose frida-rust lifetimes are phantom over
        // independently refcounted GObjects) can outlive this call and be handed
        // back to the caller. This is a bounded, one-time acquisition per
        // instrumentation session; the frida runtime lives until process exit
        // regardless.
        let manager: &'static DeviceManager<'static> =
            Box::leak(Box::new(DeviceManager::obtain(self.frida)));
        // Connect to the device-side frida-server *explicitly* at its forwarded
        // host address (the engine sets up `adb forward tcp:27042` and starts the
        // server before this runs), rather than enumerating USB devices. On Linux
        // an emulator is not a libusb device, so `get_device_by_type(USB)`
        // mis-resolves a phantom (the "arm64 gadget for an x86_64 emulator" tell)
        // and never reaches the deployed root server → "jailed" spawn-gate failure.
        // The explicit remote device is the standard frida approach for emulators
        // and is used uniformly on Windows and Linux. `Device::spawn` needs
        // `&mut self`, so the device is held mutably first.
        let device: &'static mut Device<'static> = Box::leak(Box::new(
            manager
                .get_remote_device(&request.config.device_address)
                .map_err(|error| frida_diagnostic("device", &error.to_string()))?,
        ));

        let (pid, spawn_gated) = match request.mode {
            InstrumentationMode::Spawn => {
                let options = SpawnOptions::default();
                let pid = device
                    .spawn(&request.package_name, &options)
                    .map_err(|error| frida_diagnostic("spawn", &error.to_string()))?;
                (pid, true)
            }
            InstrumentationMode::Attach { pid } => (
                pid.ok_or_else(|| frida_diagnostic("attach", "attach requires a process id"))?,
                false,
            ),
        };

        // Downgrade to a shared `'static` device so `attach` yields a `'static`
        // session (spawn's exclusive borrow is finished).
        let device: &'static Device<'static> = device;
        let session: &'static Session<'static> =
            Box::leak(Box::new(device.attach(pid).map_err(|error| {
                frida_diagnostic("attach", &error.to_string())
            })?));

        let mut option = ScriptOption::default();
        let script = session
            .create_script(&request.script, &mut option)
            .map_err(|error| frida_diagnostic("script-create", &error.to_string()))?;
        script
            .load()
            .map_err(|error| frida_diagnostic("script-load", &error.to_string()))?;

        // Resume the spawn-gated process only after early hooks are installed,
        // so pinning/signing hooks fire before application initialization.
        if spawn_gated {
            device
                .resume(pid)
                .map_err(|error| frida_diagnostic("resume", &error.to_string()))?;
        }

        Ok(FridaCoreSession {
            _script: script,
            pid,
        })
    }
}

fn frida_diagnostic(operation: &str, error: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "operation".to_owned(),
        DiagnosticValue::String(operation.to_owned()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_owned()),
    );
    // Map to the same stable instrumentation diagnostics the CLI path uses; the
    // embedded path is a linked library, so these are device/runtime conditions,
    // never a missing host tool.
    let definition = match operation {
        "device" => catalogue::INSTRUMENTATION_FRIDA_SERVER_HEALTH_FAILED,
        "attach" => catalogue::INSTRUMENTATION_ATTACH_FAILED,
        "script-create" | "script-load" => catalogue::INSTRUMENTATION_SCRIPT_LOAD_FAILED,
        _ => catalogue::INSTRUMENTATION_SPAWN_GATE_FAILED,
    };
    definition.instantiate(context)
}
