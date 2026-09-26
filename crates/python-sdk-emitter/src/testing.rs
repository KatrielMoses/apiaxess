//! Test support: runs generated Python so tests prove the SDK executes, not
//! just that its text looks right. Enabled for this crate's tests and, via
//! the `testing` feature, for other crates' tests; never in normal builds.

use std::{collections::BTreeMap, path::Path, time::Duration};

use apiaxess_external_tools::{
    ExternalToolRunner, ProcessToolRunner, ToolInvocationRequest, ToolProbe, ToolProbeRequest,
    ToolRequirement, ToolVersion,
};

/// A minimal stand-in for the `httpx` API the generated SDK uses, installed
/// only when the interpreter has no real `httpx`. It records nothing itself:
/// requests go to the `MockTransport` handler a test supplies.
const HTTPX_STAND_IN: &str = r#""""Minimal httpx stand-in for executing generated SDKs in tests."""
import json as _json


class Auth:
    requires_request_body = False

    def auth_flow(self, request):
        yield request


class Request:
    def __init__(self, method, url, headers=None, content=b""):
        self.method, self.url, self.headers, self.content = method, url, dict(headers or {}), content


class Response:
    def __init__(self, status_code=200, content=b"", headers=None):
        self.status_code, self.content, self.headers = status_code, content, dict(headers or {})

    def json(self):
        return _json.loads(self.content)


class MockTransport:
    def __init__(self, handler):
        self.handler = handler


class Client:
    def __init__(self, base_url="", headers=None, transport=None):
        self.base_url, self.headers, self.transport = str(base_url or ""), dict(headers or {}), transport

    def request(self, method, url, params=None, json=None, auth=None):
        full = url if "://" in url else self.base_url.rstrip("/") + url
        if params:
            full += "?" + "&".join(f"{key}={value}" for key, value in params.items())
        content = b"" if json is None else _json.dumps(json).encode()
        request = Request(method, full, self.headers, content)
        if auth is not None:
            request = next(auth.auth_flow(request))
        return self.transport.handler(request)

    def close(self):
        pass
"#;

/// A Python 3.10+ interpreter, probed through the central process boundary.
fn interpreter() -> Option<ToolProbe> {
    ["python3", "python"].into_iter().find_map(|name| {
        ProcessToolRunner
            .probe(&ToolProbeRequest {
                tool_id: "python".to_owned(),
                executable: name.to_owned(),
                version_arguments: vec!["--version".to_owned()],
                requirement: ToolRequirement {
                    minimum: ToolVersion {
                        major: 3,
                        minor: 10,
                        patch: 0,
                    },
                },
            })
            .ok()
    })
}

/// Runs the interpreter with `arguments` in `root`, `root` importable.
fn run(python: &ToolProbe, root: &Path, arguments: &[&str]) -> Result<(bool, String), String> {
    let invocation = ProcessToolRunner
        .invoke(&ToolInvocationRequest {
            probe: python.clone(),
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            working_directory: Some(root.to_path_buf()),
            environment: vec![
                ("PYTHONPATH".to_owned(), root.display().to_string()),
                ("PYTHONDONTWRITEBYTECODE".to_owned(), "1".to_owned()),
            ],
            timeout: Duration::from_secs(120),
        })
        .map_err(|error| error.to_string())?;
    Ok((
        invocation.exit_code == Some(0),
        format!("{}{}", invocation.stdout, invocation.stderr),
    ))
}

/// Writes `files` under a fresh directory, then runs `script` there with that
/// directory importable. Returns `Ok(None)` when no Python 3.10+ interpreter
/// is installed (skipped), except under CI, where that is a failure.
///
/// # Errors
///
/// Returns the interpreter's output when the script fails.
///
/// # Panics
///
/// Panics when the files cannot be written, or under CI when no interpreter
/// is available.
pub fn run_generated_python(
    files: &BTreeMap<String, String>,
    script: &str,
) -> Result<Option<String>, String> {
    let Some(python) = interpreter() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI must provide Python 3.10+ to execute generated SDKs"
        );
        eprintln!("skipping generated-Python execution: no Python 3.10+ interpreter");
        return Ok(None);
    };
    let root = std::env::temp_dir().join(format!(
        "apiaxess-generated-python-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    for (relative, contents) in files {
        write(&root, relative, contents);
    }
    if !run(&python, &root, &["-c", "import httpx"])?.0 {
        write(&root, "httpx/__init__.py", HTTPX_STAND_IN);
    }
    write(&root, "run_generated.py", script);
    let (success, text) = run(&python, &root, &["run_generated.py"])?;
    let _ = std::fs::remove_dir_all(&root);
    if success { Ok(Some(text)) } else { Err(text) }
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create generated-Python directory");
    }
    std::fs::write(path, contents).expect("write generated-Python file");
}
