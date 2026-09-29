//! Exclusive external-tool discovery and execution boundary.
//!
//! Feature crates depend on the intent-level runner in this crate. They never
//! construct child processes themselves; this keeps process policy, bounded
//! output, and tool provenance in one auditable place.

use std::{
    io::{self, Read},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use process_wrap::std::{ChildWrapper, CommandWrap};
use thiserror::Error;

/// A comparable three-part tool version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ToolVersion {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

impl ToolVersion {
    /// Parses the first `major.minor.patch` sequence found in tool output.
    #[must_use]
    pub fn parse(output: &str) -> Option<Self> {
        let mut numbers = output
            .split(|character: char| !character.is_ascii_digit())
            .filter(|part| !part.is_empty())
            .filter_map(|part| part.parse::<u32>().ok());
        Some(Self {
            major: numbers.next()?,
            minor: numbers.next().unwrap_or(0),
            patch: numbers.next().unwrap_or(0),
        })
    }
}

impl std::fmt::Display for ToolVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A version requirement used during the preflight phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolRequirement {
    /// Minimum supported version, inclusive.
    pub minimum: ToolVersion,
}

/// A bounded tool probe request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolProbeRequest {
    /// Stable `APIaxess` tool ID.
    pub tool_id: String,
    /// Executable name or explicitly configured path.
    pub executable: String,
    /// Arguments used to obtain a version string.
    pub version_arguments: Vec<String>,
    /// Minimum supported version.
    pub requirement: ToolRequirement,
}

/// Evidence collected before a tool is used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolProbe {
    /// Stable `APIaxess` tool ID.
    pub tool_id: String,
    /// Resolved executable used by the probe.
    pub executable: String,
    /// Parsed version.
    pub version: ToolVersion,
    /// Raw bounded version output for reproducibility.
    pub raw_output: String,
}

/// A controlled argument-vector invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolInvocationRequest {
    /// Probe evidence for the executable and version.
    pub probe: ToolProbe,
    /// Argument vector, excluding the executable.
    pub arguments: Vec<String>,
    /// Explicit working directory.
    pub working_directory: Option<std::path::PathBuf>,
    /// Environment variables added to the bounded process.
    pub environment: Vec<(String, String)>,
    /// Maximum time allowed for the process.
    pub timeout: Duration,
}

/// Collected process evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolInvocation {
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Exit code, when the process exited normally.
    pub exit_code: Option<i32>,
    /// Wall-clock duration.
    pub duration: Duration,
}

/// A long-running external-process request. Unlike `ToolInvocationRequest`,
/// this returns control immediately and is explicitly owned by a session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolProcessRequest {
    /// Probe evidence for the executable and version.
    pub probe: ToolProbe,
    /// Argument vector, excluding the executable.
    pub arguments: Vec<String>,
    /// Explicit working directory.
    pub working_directory: Option<std::path::PathBuf>,
    /// Environment variables added to the process.
    pub environment: Vec<(String, String)>,
}

/// A running process owned by a session-scoped feature.
pub struct ToolProcess {
    tool_id: String,
    child: Arc<Mutex<Option<std::process::Child>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
}

/// Opens `path` in the platform file manager (Explorer, Finder, or the
/// desktop's handler via `xdg-open`). Detached on purpose: the window belongs
/// to the operator's desktop, not to any `APIaxess` process group.
///
/// # Errors
///
/// Returns the operating-system error when the file manager cannot start.
pub fn open_in_file_manager(path: &std::path::Path) -> io::Result<()> {
    let opener = if cfg!(windows) {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    Command::new(opener).arg(path).spawn().map(|_| ())
}

/// A feature-owned process command that still crosses the central process
/// boundary. Browser launch uses this port so feature crates do not construct
/// `std::process::Command` directly.
#[derive(Debug)]
pub struct ManagedProcessCommand {
    command: Command,
}

impl ManagedProcessCommand {
    /// Creates a managed command for an explicitly selected executable.
    #[must_use]
    pub fn new(executable: impl AsRef<std::ffi::OsStr>) -> Self {
        Self {
            command: noninteractive_command(executable.as_ref().to_string_lossy().as_ref()),
        }
    }

    /// Adds one argument without invoking a shell.
    pub fn arg(&mut self, argument: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.command.arg(argument);
        self
    }

    /// Adds multiple arguments without invoking a shell.
    pub fn args<I, S>(&mut self, arguments: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.command.args(arguments);
        self
    }

    /// Adds an environment override.
    pub fn env(
        &mut self,
        key: impl AsRef<std::ffi::OsStr>,
        value: impl AsRef<std::ffi::OsStr>,
    ) -> &mut Self {
        self.command.env(key, value);
        self
    }

    /// Starts the process in the platform process boundary.
    ///
    /// # Errors
    ///
    /// Returns an operating-system spawn error when the executable cannot be
    /// started or the process boundary cannot be created.
    pub fn spawn(self) -> io::Result<ManagedProcess> {
        let mut wrapped = CommandWrap::from(self.command);
        #[cfg(windows)]
        {
            // Keep spawned children fully headless. The engine (and, through the
            // engine, java/apktool/jadx/ffuf) are console-subsystem programs; when
            // the windows-subsystem GUI shell — which has no console — spawns them,
            // Windows would otherwise create a visible terminal window. The
            // `CreationFlags` wrapper is the one way to set CREATE_NO_WINDOW that
            // `JobObject` preserves (JobObject overwrites a command's own creation
            // flags, reading only the wrapper's value).
            wrapped.wrap(process_wrap::std::CreationFlags(
                windows::Win32::System::Threading::CREATE_NO_WINDOW,
            ));
            wrapped.wrap(process_wrap::std::JobObject);
        }
        #[cfg(unix)]
        wrapped.wrap(process_wrap::std::ProcessGroup::leader());
        wrapped.spawn().map(|child| ManagedProcess { child })
    }
}

/// A process owned by a feature boundary and safe to terminate as a group.
#[derive(Debug)]
pub struct ManagedProcess {
    child: Box<dyn ChildWrapper>,
}

impl ManagedProcess {
    /// Operating-system process ID.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Checks whether the process has exited.
    ///
    /// # Errors
    ///
    /// Returns the operating-system wait error, if any.
    pub fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    /// Terminates the process group/job and waits for it to exit.
    ///
    /// # Errors
    ///
    /// Returns the operating-system termination or wait error, if any.
    pub fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }
}

impl std::fmt::Debug for ToolProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ToolProcess")
            .field("tool_id", &self.tool_id)
            .field("pid", &self.id())
            .finish_non_exhaustive()
    }
}

impl ToolProcess {
    /// Operating-system process ID, if the process has not exited.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        self.child
            .lock()
            .ok()
            .and_then(|child| child.as_ref().map(std::process::Child::id))
    }

    /// Returns whether the process is still running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.child
            .lock()
            .ok()
            .and_then(|mut child| child.as_mut().map(std::process::Child::try_wait))
            .and_then(Result::ok)
            .is_some_and(|status| status.is_none())
    }

    /// Returns bounded stderr emitted by the process so startup failures can
    /// be diagnosed after the child exits.
    #[must_use]
    pub fn stderr(&self) -> String {
        self.stderr
            .lock()
            .map(|stderr| String::from_utf8_lossy(&stderr).into_owned())
            .unwrap_or_default()
    }

    /// Terminates the process and waits for its operating-system handle.
    ///
    /// # Errors
    ///
    /// Returns a structured tool-boundary failure if the process cannot be
    /// stopped or reaped.
    pub fn stop(&self) -> Result<(), ExternalToolError> {
        let mut slot = self.child.lock().map_err(|_| ExternalToolError::Wait {
            tool_id: self.tool_id.clone(),
            source: io::Error::other("process lock was poisoned"),
        })?;
        let Some(child) = slot.as_mut() else {
            return Ok(());
        };
        let still_running = |child: &mut std::process::Child| {
            child
                .try_wait()
                .map(|status| status.is_none())
                .map_err(|source| ExternalToolError::Wait {
                    tool_id: self.tool_id.clone(),
                    source,
                })
        };
        // Windows first terminates the whole tree so helper grandchildren do
        // not outlive the tool; a tree-kill failure only matters if the child
        // survived it.
        #[cfg(windows)]
        if still_running(child)?
            && let Err(error) = kill_process_tree(child.id(), &self.tool_id)
            && still_running(child)?
        {
            return Err(error);
        }
        // Unix spawns every tool as its own process-group leader, so killing the
        // group reaches grandchildren too. It runs even when the direct child has
        // already exited: a launcher that returned can leave its workers behind.
        #[cfg(unix)]
        kill_process_group(child.id());
        if still_running(child)? {
            child.kill().map_err(|source| ExternalToolError::Kill {
                tool_id: self.tool_id.clone(),
                source,
            })?;
        }
        child.wait().map_err(|source| ExternalToolError::Wait {
            tool_id: self.tool_id.clone(),
            source,
        })?;
        slot.take();
        Ok(())
    }
}

#[cfg(windows)]
fn kill_process_tree(pid: u32, tool_id: &str) -> Result<(), ExternalToolError> {
    let output = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .output()
        .map_err(|source| ExternalToolError::Kill {
            tool_id: tool_id.to_owned(),
            source,
        })?;
    if output.status.success() {
        return Ok(());
    }
    let detail = format!(
        "taskkill exited with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Err(ExternalToolError::Kill {
        tool_id: tool_id.to_owned(),
        source: io::Error::other(detail),
    })
}

/// Sends `SIGKILL` to the process group led by `leader`. An already-empty group
/// (`ESRCH`) is the expected outcome for a tool that left nothing behind.
#[cfg(unix)]
fn kill_process_group(leader: u32) {
    if let Ok(leader) = i32::try_from(leader) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(leader),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
}

impl Drop for ToolProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// The only process-execution port visible to feature crates.
pub trait ExternalToolRunner: Send + Sync {
    /// Probe a tool and verify its minimum version.
    ///
    /// # Errors
    ///
    /// Returns a structured tool-boundary failure when the executable is
    /// missing, the version probe is unusable, or the requirement is unmet.
    fn probe(&self, request: &ToolProbeRequest) -> Result<ToolProbe, ExternalToolError>;

    /// Invoke a previously probed tool.
    ///
    /// # Errors
    ///
    /// Returns a structured tool-boundary failure when the process cannot be
    /// started, collected, or completes after its deadline.
    fn invoke(&self, request: &ToolInvocationRequest) -> Result<ToolInvocation, ExternalToolError>;

    /// Starts a session-owned long-running process.
    ///
    /// The default implementation keeps feature crates honest when a custom
    /// test runner only supports bounded invocations.
    ///
    /// # Errors
    ///
    /// Returns a structured process-boundary error when the runner cannot
    /// start or does not support a long-running process.
    fn spawn(&self, request: &ToolProcessRequest) -> Result<ToolProcess, ExternalToolError> {
        let _ = request;
        Err(ExternalToolError::Unsupported {
            tool_id: "external-tools.runner".to_owned(),
            detail: "this runner does not support long-running processes".to_owned(),
        })
    }
}

/// Production runner backed by native processes.
#[derive(Debug, Default)]
pub struct ProcessToolRunner;

impl ExternalToolRunner for ProcessToolRunner {
    fn probe(&self, request: &ToolProbeRequest) -> Result<ToolProbe, ExternalToolError> {
        let mut command = noninteractive_command(&request.executable);
        command.args(&request.version_arguments);
        let invocation = run_capture(
            &request.tool_id,
            &request.executable,
            &mut command,
            Duration::from_secs(30),
        )?;
        let raw_output = format_output(invocation.stdout.as_bytes(), invocation.stderr.as_bytes());
        if invocation.exit_code != Some(0) {
            return Err(ExternalToolError::Probe {
                tool_id: request.tool_id.clone(),
                detail: format!("version probe exited with {:?}", invocation.exit_code),
                output: bounded(&raw_output),
            });
        }
        let version = ToolVersion::parse(&raw_output).ok_or_else(|| ExternalToolError::Probe {
            tool_id: request.tool_id.clone(),
            detail: "version output did not contain a numeric version".to_owned(),
            output: bounded(&raw_output),
        })?;
        if version < request.requirement.minimum {
            return Err(ExternalToolError::VersionMismatch {
                tool_id: request.tool_id.clone(),
                found: version,
                minimum: request.requirement.minimum,
            });
        }
        Ok(ToolProbe {
            tool_id: request.tool_id.clone(),
            executable: request.executable.clone(),
            version,
            raw_output: bounded(&raw_output),
        })
    }

    fn invoke(&self, request: &ToolInvocationRequest) -> Result<ToolInvocation, ExternalToolError> {
        let mut command = noninteractive_command(&request.probe.executable);
        command.args(&request.arguments);
        if let Some(directory) = &request.working_directory {
            command.current_dir(directory);
        }
        command.envs(request.environment.iter().map(|(key, value)| (key, value)));
        run_capture(
            &request.probe.tool_id,
            &request.probe.executable,
            &mut command,
            request.timeout,
        )
    }

    fn spawn(&self, request: &ToolProcessRequest) -> Result<ToolProcess, ExternalToolError> {
        let mut command = noninteractive_command(&request.probe.executable);
        command.args(&request.arguments);
        if let Some(directory) = &request.working_directory {
            command.current_dir(directory);
        }
        command.envs(request.environment.iter().map(|(key, value)| (key, value)));
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|source| ExternalToolError::Start {
            tool_id: request.probe.tool_id.clone(),
            executable: request.probe.executable.clone(),
            source,
        })?;
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let stderr_pipe = child.stderr.take();
        let stderr_capture = Arc::clone(&stderr);
        if let Some(mut stderr_pipe) = stderr_pipe {
            // Append incrementally rather than once at EOF, so a long-running tool's
            // live progress (e.g. ffuf's periodic `:: Progress:` line) is readable
            // via `stderr()` while it runs — not only after it exits. Still bounded.
            std::thread::spawn(move || {
                let mut buffer = [0_u8; 8 * 1024];
                loop {
                    match stderr_pipe.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if let Ok(mut captured) = stderr_capture.lock() {
                                let room = MAX_CAPTURE_BYTES.saturating_sub(captured.len());
                                if room > 0 {
                                    captured.extend_from_slice(&buffer[..read.min(room)]);
                                }
                            }
                        }
                    }
                }
            });
        }
        Ok(ToolProcess {
            tool_id: request.probe.tool_id.clone(),
            child: Arc::new(Mutex::new(Some(child))),
            stderr,
        })
    }
}

fn noninteractive_command(executable: &str) -> Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        let mut command = Command::new(executable);
        // CREATE_NO_WINDOW (0x0800_0000): the direct tool-runner spawns below use a
        // plain `Command`, so setting the flag here keeps apktool/jadx/java/ffuf
        // from flashing a console window during intake. (The ManagedProcessCommand
        // path re-applies this via a process-wrap wrapper because JobObject would
        // otherwise overwrite a command's own creation flags.)
        command.creation_flags(0x0800_0000);
        if std::path::Path::new(executable)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
            })
        {
            // Some mature Windows tool launchers (including the standard apktool
            // wrapper) inspect this cmd.exe pseudo-variable and pause when they see
            // `/c`. An explicit value keeps orchestration non-interactive without
            // modifying or reimplementing the external tool.
            command.env("CMDCMDLINE", "apiaxess-external-tool");
        }
        command
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        let mut command = Command::new(executable);
        // Each tool leads its own process group, so stopping it (or timing it
        // out) can signal the whole group and not orphan helper grandchildren.
        command.process_group(0);
        command
    }
    #[cfg(not(any(windows, unix)))]
    Command::new(executable)
}

const MAX_CAPTURE_BYTES: usize = 256 * 1024;

fn bounded(value: &str) -> String {
    value.chars().take(MAX_CAPTURE_BYTES).collect()
}

fn format_output(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    if stderr.trim().is_empty() {
        stdout.into_owned()
    } else {
        format!("{stdout}\n{stderr}")
    }
}

fn run_capture(
    tool_id: &str,
    executable: &str,
    command: &mut Command,
    timeout: Duration,
) -> Result<ToolInvocation, ExternalToolError> {
    let started = Instant::now();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|source| ExternalToolError::Start {
        tool_id: tool_id.to_owned(),
        executable: executable.to_owned(),
        source,
    })?;
    let stdout = child.stdout.take().ok_or_else(|| ExternalToolError::Wait {
        tool_id: tool_id.to_owned(),
        source: io::Error::other("stdout pipe was not created"),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| ExternalToolError::Wait {
        tool_id: tool_id.to_owned(),
        source: io::Error::other("stderr pipe was not created"),
    })?;
    let stdout_reader = std::thread::spawn(|| read_limited(stdout));
    let stderr_reader = std::thread::spawn(|| read_limited(stderr));
    let mut next_progress = Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|source| ExternalToolError::Wait {
            tool_id: tool_id.to_owned(),
            source,
        })? {
            break status;
        }
        if started.elapsed() >= timeout {
            // Kill the whole group first: a grandchild still holding the output
            // pipes would otherwise keep the capture threads from finishing.
            #[cfg(unix)]
            kill_process_group(child.id());
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(ExternalToolError::Timeout {
                tool_id: tool_id.to_owned(),
                timeout,
            });
        }
        if started.elapsed() >= next_progress {
            eprintln!(
                "external tool {tool_id} is still running: elapsed={}s deadline={}s",
                started.elapsed().as_secs(),
                timeout.as_secs()
            );
            next_progress = next_progress.saturating_add(Duration::from_secs(30));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| ExternalToolError::Wait {
            tool_id: tool_id.to_owned(),
            source: io::Error::other("stdout capture thread panicked"),
        })?
        .map_err(|source| ExternalToolError::Wait {
            tool_id: tool_id.to_owned(),
            source,
        })?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| ExternalToolError::Wait {
            tool_id: tool_id.to_owned(),
            source: io::Error::other("stderr capture thread panicked"),
        })?
        .map_err(|source| ExternalToolError::Wait {
            tool_id: tool_id.to_owned(),
            source,
        })?;
    Ok(ToolInvocation {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        exit_code: status.code(),
        duration: started.elapsed(),
    })
}

fn read_limited<R: Read>(reader: R) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_CAPTURE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    bytes.truncate(MAX_CAPTURE_BYTES);
    Ok(bytes)
}

/// Failure from probing or invoking an external tool.
#[derive(Debug, Error)]
pub enum ExternalToolError {
    /// Executable could not be started, including a missing executable.
    #[error("could not start `{tool_id}` ({executable}): {source}")]
    Start {
        /// Stable tool ID.
        tool_id: String,
        /// Configured executable.
        executable: String,
        /// OS error.
        source: io::Error,
    },
    /// Version probe failed or returned unusable output.
    #[error("version probe failed for `{tool_id}`: {detail}")]
    Probe {
        /// Stable tool ID.
        tool_id: String,
        /// Failure detail.
        detail: String,
        /// Bounded raw output.
        output: String,
    },
    /// Tool was older than the adapter requirement.
    #[error("`{tool_id}` version {found} is below required {minimum}")]
    VersionMismatch {
        /// Stable tool ID.
        tool_id: String,
        /// Detected version.
        found: ToolVersion,
        /// Minimum version.
        minimum: ToolVersion,
    },
    /// Process status could not be collected.
    #[error("could not collect `{tool_id}` process status: {source}")]
    Wait {
        /// Stable tool ID.
        tool_id: String,
        /// OS error.
        source: io::Error,
    },
    /// Process exceeded its bounded deadline.
    #[error("`{tool_id}` exceeded its {timeout:?} deadline")]
    Timeout {
        /// Stable tool ID.
        tool_id: String,
        /// Configured timeout.
        timeout: Duration,
    },
    /// The selected runner cannot perform the requested process operation.
    #[error("external tool operation is unsupported for `{tool_id}`: {detail}")]
    Unsupported {
        /// Stable tool ID.
        tool_id: String,
        /// Bounded explanation.
        detail: String,
    },
    /// A long-running process could not be terminated.
    #[error("could not terminate `{tool_id}`: {source}")]
    Kill {
        /// Stable tool ID.
        tool_id: String,
        /// OS error.
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::{ToolRequirement, ToolVersion};

    #[test]
    fn parses_versions_embedded_in_tool_output() {
        assert_eq!(
            ToolVersion::parse("jadx version: 1.5.0"),
            Some(ToolVersion {
                major: 1,
                minor: 5,
                patch: 0
            })
        );
        assert!(
            ToolVersion {
                major: 2,
                minor: 0,
                patch: 0
            } >= ToolRequirement {
                minimum: ToolVersion {
                    major: 1,
                    minor: 0,
                    patch: 0
                }
            }
            .minimum
        );
    }

    /// Unix process-group teardown: a tool's grandchildren die with it.
    #[cfg(unix)]
    mod process_group {
        use std::{
            path::PathBuf,
            time::{Duration, Instant},
        };

        use nix::{sys::signal::kill, unistd::Pid};

        use crate::{
            ExternalToolError, ExternalToolRunner, ProcessToolRunner, ToolInvocationRequest,
            ToolProbe, ToolProcessRequest, ToolVersion,
        };

        fn shell_probe() -> ToolProbe {
            ToolProbe {
                tool_id: "sh".to_owned(),
                executable: "/bin/sh".to_owned(),
                version: ToolVersion {
                    major: 0,
                    minor: 0,
                    patch: 0,
                },
                raw_output: String::new(),
            }
        }

        fn pid_file(name: &str) -> PathBuf {
            let path = std::env::temp_dir().join(format!(
                "apiaxess-external-tools-{name}-{}.pid",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            path
        }

        /// A shell that backgrounds a long `sleep` (the grandchild), records
        /// its pid, and waits on it.
        fn launcher_arguments(pid_file: &std::path::Path) -> Vec<String> {
            vec![
                "-c".to_owned(),
                format!("sleep 60 & echo $! > '{}'; wait", pid_file.display()),
            ]
        }

        fn recorded_pid(pid_file: &std::path::Path) -> Pid {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(pid) = std::fs::read_to_string(pid_file)
                    .ok()
                    .and_then(|text| text.trim().parse::<i32>().ok())
                {
                    return Pid::from_raw(pid);
                }
                assert!(
                    Instant::now() < deadline,
                    "launcher never recorded its grandchild pid"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        /// True once `pid` no longer exists (it was killed and reaped by init).
        fn exits_within(pid: Pid, limit: Duration) -> bool {
            let deadline = Instant::now() + limit;
            while Instant::now() < deadline {
                if kill(pid, None).is_err() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        }

        #[test]
        fn stopping_a_tool_also_kills_its_grandchildren() {
            let pid_file = pid_file("stop");
            let process = ProcessToolRunner
                .spawn(&ToolProcessRequest {
                    probe: shell_probe(),
                    arguments: launcher_arguments(&pid_file),
                    working_directory: None,
                    environment: Vec::new(),
                })
                .expect("launcher spawns");
            let grandchild = recorded_pid(&pid_file);
            assert!(kill(grandchild, None).is_ok(), "grandchild is running");

            process.stop().expect("tool stops");

            let reaped = exits_within(grandchild, Duration::from_secs(10));
            if !reaped {
                let _ = kill(grandchild, nix::sys::signal::Signal::SIGKILL);
            }
            let _ = std::fs::remove_file(&pid_file);
            assert!(reaped, "stop() orphaned grandchild {grandchild}");
        }

        #[test]
        fn a_timed_out_invocation_kills_its_grandchildren_and_returns() {
            let pid_file = pid_file("timeout");
            let started = Instant::now();
            let result = ProcessToolRunner.invoke(&ToolInvocationRequest {
                probe: shell_probe(),
                arguments: launcher_arguments(&pid_file),
                working_directory: None,
                environment: Vec::new(),
                timeout: Duration::from_secs(1),
            });
            // The grandchild inherits the output pipes; without the group kill
            // the capture threads would wait for its full 60 s.
            let returned_in = started.elapsed();
            let grandchild = recorded_pid(&pid_file);
            let reaped = exits_within(grandchild, Duration::from_secs(10));
            if !reaped {
                let _ = kill(grandchild, nix::sys::signal::Signal::SIGKILL);
            }
            let _ = std::fs::remove_file(&pid_file);
            assert!(matches!(result, Err(ExternalToolError::Timeout { .. })));
            assert!(
                returned_in < Duration::from_secs(20),
                "timed-out invocation took {returned_in:?}"
            );
            assert!(reaped, "timeout orphaned grandchild {grandchild}");
        }
    }
}
