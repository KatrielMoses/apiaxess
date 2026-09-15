//! Deterministic typed Python SDK emission from the Phase 5 unified surface.
//!
//! The generated package uses httpx directly and carries recovered signer IR
//! into request middleware. It does not invoke a generic `OpenAPI` generator.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    num::NonZeroU64,
};

use apiaxess_api_model::{
    CanonicalizationOperation, Endpoint, EndpointIdentity, RequirednessAssessment, SchemaShape,
    SchemaSlot, SignerArtifact, SignerKeySource, SignerMode, SignerPrimitive, UnifiedApiSurface,
};
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};

/// Configuration for Python SDK generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonSdkEmitter {
    /// Importable Python package name.
    pub package_name: String,
    /// Distribution name written to pyproject.toml.
    pub distribution_name: String,
    /// Public client class name.
    pub client_class: String,
    /// Dynamic sample threshold used for requiredness.
    pub minimum_dynamic_samples: NonZeroU64,
}

impl Default for PythonSdkEmitter {
    fn default() -> Self {
        Self {
            package_name: "apiaxess_client".to_owned(),
            distribution_name: "apiaxess-recovered-client".to_owned(),
            client_class: "ApiClient".to_owned(),
            minimum_dynamic_samples: NonZeroU64::new(3).expect("non-zero default"),
        }
    }
}

impl PythonSdkEmitter {
    /// Creates an emitter for one importable package.
    #[must_use]
    pub fn new(package_name: impl Into<String>) -> Self {
        let package_name = package_name.into();
        Self {
            distribution_name: package_name.replace('_', "-"),
            package_name,
            ..Self::default()
        }
    }

    /// Generates a complete self-contained Python package in memory.
    ///
    /// # Errors
    ///
    /// Returns diagnostics when the unified surface or package metadata is
    /// invalid.
    // This method intentionally keeps package assembly in emission order.
    #[allow(clippy::too_many_lines)]
    pub fn generate(&self, surface: &UnifiedApiSurface) -> Result<PythonSdk, Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        if let Err(error) = surface.validate() {
            diagnostics.push(diagnostic(
                catalogue::PYTHON_SDK_INVALID_INPUT,
                [
                    ("field", "unified".to_owned()),
                    ("detail", error.to_string()),
                ],
            ));
            return Err(diagnostics);
        }
        if !valid_identifier(&self.package_name)
            || !valid_identifier(&self.client_class)
            || self.distribution_name.trim().is_empty()
        {
            diagnostics.push(diagnostic(
                catalogue::PYTHON_SDK_INVALID_INPUT,
                [
                    ("field", "package_metadata".to_owned()),
                    (
                        "detail",
                        "package and client names must be valid identifiers".to_owned(),
                    ),
                ],
            ));
            return Err(diagnostics);
        }

        let mut endpoints = surface.surface.endpoints.iter().collect::<Vec<_>>();
        endpoints.sort_by(|left, right| left.identity.cmp(&right.identity));
        let mut signers = BTreeMap::<String, (String, SignerArtifact)>::new();
        let mut all_signer_ids = BTreeSet::new();
        let mut deferred_diagnostics = Vec::new();
        let (methods, model_source, model_diagnostics) = {
            let mut model_diagnostics = Vec::new();
            let mut models = ModelBuilder::new(
                surface,
                self.minimum_dynamic_samples,
                &mut model_diagnostics,
            );
            let mut methods = Vec::new();
            for endpoint in endpoints {
                let model_path = endpoint_path(surface, &endpoint.identity);
                let method_name = method_name(&endpoint.identity);
                let mut signer_names = Vec::new();
                for signer in surface.signers_for(&endpoint.identity) {
                    all_signer_ids.insert(signer.signer_id.clone());
                    let class_name = auth_class_name(&signer.signer_id);
                    signer_names.push((signer.signer_id.clone(), class_name.clone()));
                    if signer.signer_mode == SignerMode::Reproducible {
                        signers
                            .entry(signer.signer_id.clone())
                            .or_insert((class_name.clone(), signer.clone()));
                    } else {
                        deferred_diagnostics.push(signer_diagnostic(signer));
                    }
                    signers
                        .entry(signer.signer_id.clone())
                        .or_insert((class_name, signer.clone()));
                }
                if endpoint.authentication.is_none() && signer_names.is_empty() {
                    deferred_diagnostics.push(diagnostic(
                        catalogue::PYTHON_SDK_NO_RECOVERED_AUTH,
                        [
                            ("field", format!("{model_path}.authentication")),
                            (
                                "detail",
                                "no authentication fact or signer binding is attached".to_owned(),
                            ),
                        ],
                    ));
                }
                methods.push(render_method(
                    endpoint,
                    surface,
                    &mut models,
                    &method_name,
                    &model_path,
                    &signer_names,
                    self.minimum_dynamic_samples,
                    &mut deferred_diagnostics,
                ));
            }
            (methods, models.finish(), model_diagnostics)
        };
        diagnostics.extend(model_diagnostics);
        diagnostics.extend(deferred_diagnostics);

        let mut files = BTreeMap::new();
        files.insert(
            "pyproject.toml".to_owned(),
            render_pyproject(self, &signers),
        );
        files.insert(
            format!("{}/__init__.py", self.package_name),
            render_init(self, &signers),
        );
        files.insert(format!("{}/models.py", self.package_name), model_source);
        files.insert(
            format!("{}/auth.py", self.package_name),
            render_auth(&signers, &mut diagnostics),
        );
        files.insert(
            format!("{}/client.py", self.package_name),
            render_client(self, &methods, &signers),
        );
        files.insert(format!("{}/py.typed", self.package_name), String::new());
        files.insert(
            "README.md".to_owned(),
            render_readme(self, surface, &all_signer_ids, &signers),
        );
        Ok(PythonSdk { files, diagnostics })
    }
}

/// Generated package files and non-fatal honesty diagnostics.
#[derive(Clone, Debug, PartialEq)]
pub struct PythonSdk {
    /// Relative path to generated UTF-8 file contents.
    pub files: BTreeMap<String, String>,
    /// Warnings retained for callers.
    pub diagnostics: Vec<Diagnostic>,
}

impl PythonSdk {
    /// Returns a generated file by relative path.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&str> {
        self.files.get(path).map(String::as_str)
    }
}

struct ModelBuilder<'a> {
    surface: &'a UnifiedApiSurface,
    minimum: NonZeroU64,
    definitions: BTreeMap<String, String>,
    names: BTreeMap<String, String>,
    used_names: BTreeSet<String>,
    diagnostics: &'a mut Vec<Diagnostic>,
}

impl<'a> ModelBuilder<'a> {
    fn new(
        surface: &'a UnifiedApiSurface,
        minimum: NonZeroU64,
        diagnostics: &'a mut Vec<Diagnostic>,
    ) -> Self {
        Self {
            surface,
            minimum,
            definitions: BTreeMap::new(),
            names: BTreeMap::new(),
            used_names: BTreeSet::new(),
            diagnostics,
        }
    }

    fn slot_type(&mut self, slot: &SchemaSlot, path: &str, hint: &str) -> String {
        let Some(selected) = slot.shape.selected_candidate() else {
            self.diagnostics.push(diagnostic(
                catalogue::PYTHON_SDK_INVALID_INPUT,
                [
                    ("field", format!("{path}.shape")),
                    ("detail", "selected schema candidate is missing".to_owned()),
                ],
            ));
            return "Any".to_owned();
        };
        let index = slot
            .shape
            .candidates
            .iter()
            .position(|candidate| candidate.id == selected.id)
            .unwrap_or(0);
        self.shape_type(
            &selected.value,
            &format!("{path}.shape.candidates[{index}].value"),
            hint,
        )
    }

    fn shape_type(&mut self, shape: &SchemaShape, path: &str, hint: &str) -> String {
        match shape {
            SchemaShape::Unknown => {
                self.low_confidence(path, "unknown schema shape; emitted Any");
                "Any".to_owned()
            }
            SchemaShape::Null => "None".to_owned(),
            SchemaShape::Boolean => "bool".to_owned(),
            SchemaShape::Integer { .. } => "int".to_owned(),
            SchemaShape::Number { .. } => "float".to_owned(),
            SchemaShape::String { .. } => "str".to_owned(),
            SchemaShape::Array { items } => {
                format!(
                    "list[{}]",
                    self.slot_type(items, &format!("{path}.items"), &format!("{hint}Item"))
                )
            }
            SchemaShape::Object {
                properties,
                openness,
            } => self.object_type(properties, *openness, path, hint),
            SchemaShape::Union { variants } => {
                let types = variants
                    .iter()
                    .enumerate()
                    .map(|(index, variant)| {
                        self.shape_type(
                            variant,
                            &format!("{path}.variants[{index}]"),
                            &format!("{hint}Variant{index}"),
                        )
                    })
                    .collect::<Vec<_>>();
                if types.is_empty() {
                    self.low_confidence(path, "empty union; emitted Any");
                    "Any".to_owned()
                } else {
                    format!("Union[{}]", types.join(", "))
                }
            }
        }
    }

    fn object_type(
        &mut self,
        properties: &[apiaxess_api_model::SchemaProperty],
        openness: apiaxess_api_model::ObjectOpenness,
        path: &str,
        hint: &str,
    ) -> String {
        let name = self.class_name(path, hint);
        if self.definitions.contains_key(&name) {
            return name;
        }
        let mut fields = properties.iter().enumerate().collect::<Vec<_>>();
        fields.sort_by(|left, right| {
            let left_required = matches!(
                left.1.requiredness.assess_requiredness(self.minimum),
                Ok(RequirednessAssessment::Required)
            );
            let right_required = matches!(
                right.1.requiredness.assess_requiredness(self.minimum),
                Ok(RequirednessAssessment::Required)
            );
            right_required
                .cmp(&left_required)
                .then_with(|| left.1.name.as_str().cmp(right.1.name.as_str()))
        });
        let mut field_text = String::new();
        let mut decode_text = String::new();
        for (index, property) in fields {
            let field_name = python_field(property.name.as_str());
            let child_path = format!("{path}.properties[{index}].schema");
            let field_type = self.slot_type(
                &property.schema,
                &child_path,
                &format!("{name}{}", pascal_case(property.name.as_str())),
            );
            let required = matches!(
                property.requiredness.assess_requiredness(self.minimum),
                Ok(RequirednessAssessment::Required)
            );
            let _ = writeln!(
                field_text,
                "    {field_name}: {field_type}{}  # {}",
                if required { "" } else { " | None = None" },
                confidence_text(self.surface, &child_path)
            );
            let input = if required {
                format!("data[{key:?}]", key = property.name.as_str())
            } else {
                format!("data.get({key:?})", key = property.name.as_str())
            };
            let decoded = decode_expression(&input, &property.schema, &field_type);
            let _ = writeln!(
                decode_text,
                "            {field_name}={decoded},  # {}",
                requiredness_text(&property.requiredness, self.minimum)
            );
        }
        let openness_text = match openness {
            apiaxess_api_model::ObjectOpenness::Open => "additional properties may exist",
            apiaxess_api_model::ObjectOpenness::Closed => "closed object",
            apiaxess_api_model::ObjectOpenness::Unknown => "object openness unknown",
        };
        let definition = format!(
            "@dataclass\nclass {name}:\n    \"\"\"Generated model; {confidence}; {openness}.\"\"\"\n{fields}\
\n    @classmethod\n    def from_dict(cls, data: Mapping[str, Any]) -> \"{name}\":\n        return cls(\n{decode}        )\n",
            confidence = confidence_text(self.surface, path),
            openness = openness_text,
            fields = if field_text.is_empty() {
                "    pass\n".to_owned()
            } else {
                field_text
            },
            decode = decode_text,
        );
        self.definitions.insert(name.clone(), definition);
        name
    }

    fn class_name(&mut self, path: &str, hint: &str) -> String {
        if let Some(name) = self.names.get(path) {
            return name.clone();
        }
        let base = format!("{}{}", pascal_case(hint), suffix(path));
        let mut name = base.clone();
        let mut index = 2_u32;
        while !self.used_names.insert(name.clone()) {
            name = format!("{base}{index}");
            index = index.saturating_add(1);
        }
        self.names.insert(path.to_owned(), name.clone());
        name
    }

    fn low_confidence(&mut self, path: &str, detail: &str) {
        let low = self
            .surface
            .confidence
            .facts
            .iter()
            .find(|fact| fact.path == path)
            .is_none_or(|fact| fact.score < 0.6 || fact.merge_counts.true_conflict > 0);
        if low {
            self.diagnostics.push(diagnostic(
                catalogue::PYTHON_SDK_LOW_CONFIDENCE_SCHEMA,
                [("field", path.to_owned()), ("detail", detail.to_owned())],
            ));
        }
    }

    fn finish(self) -> String {
        let mut output = String::from(
            "\"\"\"Typed models generated by APIaxess.\"\"\"\n\n\
             from __future__ import annotations\n\n\
             from collections.abc import Mapping\n\
             from dataclasses import dataclass\n\
             from typing import Any, Union\n\n",
        );
        for definition in self.definitions.values() {
            output.push_str(definition);
            output.push('\n');
        }
        if self.definitions.is_empty() {
            output.push_str("# No structured schemas were recovered.\n");
        }
        output
    }
}

struct Method {
    source: String,
}

// Keeping method rendering linear preserves the generated source ordering.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn render_method(
    endpoint: &Endpoint,
    surface: &UnifiedApiSurface,
    models: &mut ModelBuilder<'_>,
    method_name: &str,
    model_path: &str,
    signers: &[(String, String)],
    minimum: NonZeroU64,
    diagnostics: &mut Vec<Diagnostic>,
) -> Method {
    let placeholders = path_parameter_names(endpoint.identity.path_template.as_str());
    let mut path_params = endpoint
        .path_parameters
        .iter()
        .enumerate()
        .collect::<Vec<_>>();
    path_params.sort_by(|left, right| left.1.name.as_str().cmp(right.1.name.as_str()));
    let mut args = Vec::new();
    let mut path_expr = endpoint.identity.path_template.as_str().to_owned();
    for name in &placeholders {
        let field = python_field(name);
        let field_type = path_params
            .iter()
            .find(|(_, parameter)| parameter.name.as_str() == name)
            .map_or_else(
                || "str".to_owned(),
                |(index, parameter)| {
                    models.slot_type(
                        &parameter.schema,
                        &format!("{model_path}.path_parameters[{index}].schema"),
                        &format!("{method_name}{}", pascal_case(name)),
                    )
                },
            );
        args.push(format!("{field}: {field_type}"));
        path_expr = path_expr.replace(&format!("{{{name}}}"), &format!("{{{field}}}"));
        path_expr = path_expr.replace(&format!(":{name}"), &format!("{{{field}}}"));
    }
    let mut query_entries = Vec::new();
    let mut query_params = endpoint
        .query_parameters
        .iter()
        .enumerate()
        .collect::<Vec<_>>();
    query_params.sort_by(|left, right| left.1.name.as_str().cmp(right.1.name.as_str()));
    for (index, parameter) in query_params {
        let field = python_field(parameter.name.as_str());
        let required = matches!(
            parameter.requiredness.assess_requiredness(minimum),
            Ok(RequirednessAssessment::Required)
        );
        let field_type = models.slot_type(
            &parameter.schema,
            &format!("{model_path}.query_parameters[{index}].schema"),
            &format!("{method_name}{}", pascal_case(parameter.name.as_str())),
        );
        args.push(if required {
            format!("{field}: {field_type}")
        } else {
            format!("{field}: {field_type} | None = None")
        });
        query_entries.push(format!("{key:?}: {field}", key = parameter.name.as_str()));
    }
    let body_type = endpoint.request_body.as_ref().map(|body| {
        models.slot_type(
            body,
            &format!("{model_path}.request_body"),
            &format!("{method_name}Request"),
        )
    });
    if let Some(body_type) = &body_type {
        args.push(format!("body: {body_type} | None = None"));
    }
    let response_type = endpoint.responses.first().map(|response| {
        models.slot_type(
            &response.body,
            &format!("{model_path}.responses[0].body"),
            &format!("{method_name}Response"),
        )
    });
    let return_type = response_type
        .clone()
        .unwrap_or_else(|| "httpx.Response".to_owned());
    let signer_list = signers
        .iter()
        .map(|(id, _)| id.as_str())
        .collect::<Vec<_>>();
    let mut source = String::new();
    let signature = if args.is_empty() {
        "self".to_owned()
    } else {
        format!("self, *, {}", args.join(", "))
    };
    let _ = writeln!(
        source,
        "    def {method_name}({signature}) -> {return_type}:"
    );
    let _ = writeln!(
        source,
        "        \"\"\"{method} {path}\n\n        Coverage: {coverage}\n        Confidence: {confidence}\n        Authentication: {auth}\n        \"\"\"",
        method = endpoint.identity.method,
        path = endpoint.identity.path_template,
        coverage = coverage_text(surface, &endpoint.identity),
        confidence = endpoint_confidence(surface, &endpoint.identity),
        auth = if signers.is_empty() {
            authentication_text(endpoint)
        } else {
            signers
                .iter()
                .map(|(id, class)| format!("{id} via {class}"))
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    let format_args = placeholders
        .iter()
        .map(|name| format!("{field}={field}", field = python_field(name)))
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(source, "        path = {path_expr:?}.format({format_args})");
    if query_entries.is_empty() {
        source.push_str("        params = None\n");
    } else {
        source.push_str("        params = {\n");
        for entry in query_entries {
            let _ = writeln!(source, "            {entry},");
        }
        source.push_str("        }\n        params = {key: value for key, value in params.items() if value is not None}\n");
    }
    let _ = writeln!(
        source,
        "        response = self._request({method:?}, path, params=params, json=_to_json(body) if {has_body} else None, signer_ids={signer_list:?})",
        method = endpoint.identity.method.as_str(),
        has_body = body_type.is_some()
    );
    if let Some(response_type) = response_type {
        let _ = writeln!(
            source,
            "        return _decode_response(response, {response_type})"
        );
    } else {
        source.push_str("        return response\n");
        diagnostics.push(diagnostic(
            catalogue::PYTHON_SDK_LOW_CONFIDENCE_SCHEMA,
            [
                ("field", format!("{model_path}.responses")),
                (
                    "detail",
                    "method returns raw httpx.Response because no response schema was recovered"
                        .to_owned(),
                ),
            ],
        ));
    }
    Method { source }
}

fn render_client(
    emitter: &PythonSdkEmitter,
    methods: &[Method],
    signers: &BTreeMap<String, (String, SignerArtifact)>,
) -> String {
    let mut output = String::from(
        r#""""Typed httpx client generated by APIaxess."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from typing import Any
import httpx
from .auth import CompositeAuth, CredentialProvider
from . import auth as _auth

def _to_json(value: Any) -> Any:
    if value is None: return None
    if is_dataclass(value): return {key: _to_json(item) for key, item in asdict(value).items()}
    if isinstance(value, list): return [_to_json(item) for item in value]
    if isinstance(value, dict): return {key: _to_json(item) for key, item in value.items()}
    return value

def _decode_response(response: httpx.Response, model_type: Any) -> Any:
    if not response.content: return response
    payload = response.json()
    if hasattr(model_type, "from_dict") and isinstance(payload, Mapping): return model_type.from_dict(payload)
    return payload

"#,
    );
    let _ = writeln!(output, "class {}:", emitter.client_class);
    output.push_str(
        "    \"\"\"Generated client; method docstrings expose confidence and auth state.\"\"\"\n\n",
    );
    output.push_str(
        r"    def __init__(self, base_url: str, *, auth: httpx.Auth | None = None, signer_credentials: Mapping[str, CredentialProvider] | None = None, headers: Mapping[str, str] | None = None, http_client: httpx.Client | None = None) -> None:
        self._auth = auth
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(base_url=base_url, headers=headers)
        self._signers: dict[str, httpx.Auth] = {}
        credentials = signer_credentials or {}
",
    );
    for (id, (class_name, signer)) in signers {
        if signer.signer_mode == SignerMode::Reproducible {
            let _ = writeln!(
                output,
                "        if {id:?} in credentials: self._signers[{id:?}] = _auth::{class_name}(credentials[{id:?}])"
            );
        }
    }
    output.push_str(
        r#"
    def close(self) -> None:
        if self._owns_client: self._client.close()

    def __enter__(self): return self
    def __exit__(self, *args: Any) -> None: self.close()

    def _auth_for(self, signer_ids: list[str]) -> httpx.Auth | None:
        configured = [self._signers[item] for item in signer_ids if item in self._signers]
        if configured: return configured[0] if len(configured) == 1 else CompositeAuth(configured)
        if signer_ids and self._auth is None: raise RuntimeError("Supply signer_credentials or auth for this recovered signer")
        return self._auth

    def _request(self, method: str, path: str, *, params: dict[str, Any] | None, json: Any, signer_ids: list[str]) -> httpx.Response:
        return self._client.request(method, path, params=params, json=json, auth=self._auth_for(signer_ids))

"#,
    );
    for method in methods {
        output.push_str(&method.source);
        output.push('\n');
    }
    output.replace("\n+", "\n")
}

// Authentication rendering is kept as one ordered template assembly.
#[allow(clippy::too_many_lines)]
fn render_auth(
    signers: &BTreeMap<String, (String, SignerArtifact)>,
    diagnostics: &mut Vec<Diagnostic>,
) -> String {
    let mut output = String::from(
        r#""""Secret-free httpx authentication generated from signer IR."""

from __future__ import annotations
import base64, hashlib, hmac, os, secrets, time, urllib.parse
from collections.abc import Callable, Iterator, Mapping
from datetime import datetime, timezone
from typing import Any
import httpx
CredentialProvider = Callable[[str], str | bytes] | Mapping[str, str | bytes] | str | bytes

class SignerConfigurationError(RuntimeError): pass

def _credential(provider: CredentialProvider | None, reference: str, env_var: str | None) -> bytes:
    value = provider(reference) if callable(provider) else provider.get(reference) if isinstance(provider, Mapping) else provider
    if value is None and env_var: value = os.environ.get(env_var)
    if value is None: raise SignerConfigurationError(f"Credential {reference!r} was not supplied")
    return value.encode() if isinstance(value, str) else value

def _bytes(value: Any) -> bytes: return value if isinstance(value, bytes) else b"" if value is None else str(value).encode()
def _text(value: Any) -> str: return _bytes(value).decode()
def _field(request: httpx.Request, name: str, timestamp: str, nonce: str) -> Any:
    lower = name.lower()
    if lower == "method": return request.method
    if lower == "path": return request.url.raw_path
    if lower == "query": return request.url.query
    if lower == "body": return request.content or b""
    if lower == "timestamp": return timestamp
    if lower == "nonce": return nonce
    if lower.startswith("header:"): return request.headers.get(name.split(":", 1)[1], "")
    if lower.startswith("query:"): return dict(request.url.params).get(name.split(":", 1)[1], "")
    return request.headers.get(name, "")

def _join(value: Any, delimiter: bytes) -> bytes: return delimiter.join(_bytes(item) for item in value) if isinstance(value, (list, tuple)) else _bytes(value)
def _sort(value: Any) -> Any: return sorted(value) if isinstance(value, (list, tuple)) else urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(_text(value), keep_blank_values=True)), doseq=True)
def _timestamp(format_name: str | None, clock: Callable[[], float]) -> str:
    now = clock()
    if format_name and "millis" in format_name.lower(): return str(int(now * 1000))
    if format_name and ("epoch" in format_name.lower() or "unix" in format_name.lower()): return str(int(now))
    return datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z")
def _nonce(source: Callable[[], str] | None) -> str: return source() if source else secrets.token_urlsafe(16)

class BaseSignerAuth(httpx.Auth):
    requires_request_body = True
    def __init__(self, credential_provider: CredentialProvider | None = None, *, env_var: str | None = None, clock: Callable[[], float] | None = None, nonce_source: Callable[[], str] | None = None) -> None:
        self.credential_provider, self.env_var, self.clock, self.nonce_source = credential_provider, env_var, clock or time.time, nonce_source
    def _encode(self, signature: bytes) -> str:
        if self.encoding in {"base64", "base64standard"}: value = base64.b64encode(signature).decode()
        elif self.encoding in {"base64url", "base64_url"}: value = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        elif self.encoding == "hex": value = signature.hex()
        elif self.encoding in {"raw", "utf8", "utf-8"}: value = signature.decode()
        else: raise SignerConfigurationError(f"Unsupported encoding {self.encoding}")
        return value[:self.truncation] if self.truncation is not None else value
    def _place(self, request: httpx.Request, signature: bytes) -> None:
        value = self.prefix + self._encode(signature) + self.suffix
        if self.wire_location.startswith("header:"): request.headers[self.wire_location.split(":", 1)[1]] = value
        elif self.wire_location.startswith("query:"): request.url = request.url.copy_add_param(self.wire_location.split(":", 1)[1], value)
        else: raise SignerConfigurationError(f"Unsupported wire location {self.wire_location}")
    def auth_flow(self, request: httpx.Request) -> Iterator[httpx.Request]:
        timestamp, nonce = _timestamp(self.timestamp_format, self.clock), _nonce(self.nonce_source)
        credential = _credential(self.credential_provider, self.secret_ref, self.env_var)
        self._active_credential = credential
        canonical = self._canonicalize(request, timestamp, nonce)
        self._place(request, self._sign(canonical, credential))
        yield request

class CompositeAuth(httpx.Auth):
    def __init__(self, auths: list[httpx.Auth]) -> None: self.auths = auths
    def auth_flow(self, request: httpx.Request) -> Iterator[httpx.Request]:
        for auth in self.auths: request = next(auth.auth_flow(request))
        yield request

"#,
    );
    for (id, (class_name, signer)) in signers {
        output.push_str(&render_signer(class_name, signer));
        if signer
            .canonicalization_steps
            .iter()
            .any(|step| matches!(step.operation, CanonicalizationOperation::Template { .. }))
        {
            diagnostics.push(diagnostic(
                catalogue::PYTHON_SDK_SIGNER_REVIEW,
                [
                    ("field", format!("signers[{id}].canonicalization_steps")),
                    (
                        "detail",
                        "template step is emitted as an explicit runtime review failure".to_owned(),
                    ),
                ],
            ));
        }
    }
    output
        .replace(
            "                 canonical = self._canonicalize(request, timestamp, nonce)\n\
",
            "                 credential = _credential(self.credential_provider, self.secret_ref, self.env_var)\n\
                 self._active_credential = credential\n\
                 canonical = self._canonicalize(request, timestamp, nonce)\n\
",
        )
        .replace(
            "                 credential = _credential(self.credential_provider, self.secret_ref, self.env_var)\n\
                 self._place(request, self._sign(canonical, credential))\n\
",
            "                 self._place(request, self._sign(canonical, credential))\n\
",
        )
        .replace(
            "+             return datetime.fromtimestamp(now, timezone.utc).isoformat().replace(\\\"+00:00\\\", \\\"Z\\\")\n",
            "             return datetime.fromtimestamp(now, timezone.utc).isoformat().replace(\\\"+00:00\\\", \\\"Z\\\")\n",
        )
        .replace("\n+", "\n")
}

fn render_signer(class_name: &str, signer: &SignerArtifact) -> String {
    match signer.signer_mode {
        SignerMode::Reproducible => render_reproducible(class_name, signer),
        SignerMode::PartialHypothesis => render_partial(signer),
        SignerMode::DeviceOracle => render_device_oracle(signer),
        SignerMode::ObservedOnly => render_observed(signer),
    }
}

fn render_reproducible(class_name: &str, signer: &SignerArtifact) -> String {
    let secret_ref = match &signer.key_source {
        Some(SignerKeySource::CredentialReference { secret_ref, .. }) => secret_ref.as_str(),
        Some(SignerKeySource::ExternalProvider { provider_ref }) => provider_ref.as_str(),
        _ => "credential://runtime",
    };
    let output = signer.output.as_ref();
    let location = output
        .and_then(|item| item.wire_location.as_deref())
        .map_or("header:X-APIaxess-Signature".to_owned(), |location| {
            normalize_location(location)
        });
    let encoding = output.map_or_else(
        || "hex".to_owned(),
        |item| item.encoding.to_ascii_lowercase(),
    );
    let prefix = output
        .and_then(|item| item.prefix.clone())
        .unwrap_or_default();
    let suffix = output
        .and_then(|item| item.suffix.clone())
        .unwrap_or_default();
    let truncation = output
        .and_then(|item| item.truncation)
        .map_or_else(|| "None".to_owned(), |value| value.to_string());
    let mut text = format!(
        "class {class_name}(BaseSignerAuth):\n    \"\"\"Reproducible signer {id}; confidence {confidence:.3}.\"\"\"\n    secret_ref = {secret_ref:?}\n    wire_location = {location:?}\n    encoding = {encoding:?}\n    prefix = {prefix:?}\n    suffix = {suffix:?}\n    truncation = {truncation}\n    timestamp_format = {timestamp:?}\n\n",
        id = signer.signer_id,
        confidence = signer.confidence,
        timestamp = signer.runtime.timestamp_format
    );
    text.push_str("    def _canonicalize(self, request: httpx.Request, timestamp: str, nonce: str) -> bytes:\n        credential = self._active_credential\n        value: Any = b\"\"\n");
    for (index, step) in signer.canonicalization_steps.iter().enumerate() {
        let _ = writeln!(
            text,
            "        # step {index}: {}",
            python_comment(&step.description)
        );
        text.push_str(&canonicalization_code(&step.operation));
    }
    text.push_str("        return _bytes(value)\n\n");
    text.push_str(&primitive_code(signer.primitive.as_ref()));
    text.push('\n');
    text
}

fn canonicalization_code(operation: &CanonicalizationOperation) -> String {
    match operation {
        CanonicalizationOperation::Field { name } => {
            format!("        value = _field(request, {name:?}, timestamp, nonce)\n")
        }
        CanonicalizationOperation::Uppercase => {
            "        value = _bytes(value).upper()\n".to_owned()
        }
        CanonicalizationOperation::UrlEncode => {
            "        value = urllib.parse.quote(_text(value), safe=\"~\")\n".to_owned()
        }
        CanonicalizationOperation::FormEncode => {
            "        value = urllib.parse.quote_plus(_text(value))\n".to_owned()
        }
        CanonicalizationOperation::Sort => "        value = _sort(value)\n".to_owned(),
        CanonicalizationOperation::Join { delimiter } => {
            format!(
                "        value = _join(value, {})\n",
                python_bytes_literal(delimiter)
            )
        }
        CanonicalizationOperation::Literal { bytes } => {
            format!("        value = {}\n", python_bytes_literal(bytes))
        }
        CanonicalizationOperation::Hash { algorithm } => {
            format!("        value = hashlib.new({algorithm:?}, _bytes(value)).digest()\n")
        }
        CanonicalizationOperation::Hmac { algorithm } => {
            format!("        value = hmac.new(credential, _bytes(value), {algorithm:?}).digest()\n")
        }
        CanonicalizationOperation::Base64 => {
            "        value = base64.b64encode(_bytes(value))\n".to_owned()
        }
        CanonicalizationOperation::Base64Url => {
            "        value = base64.urlsafe_b64encode(_bytes(value)).rstrip(b\"=\")\n".to_owned()
        }
        CanonicalizationOperation::Hex => "        value = _bytes(value).hex()\n".to_owned(),
        CanonicalizationOperation::Template { name } => format!(
            "        raise SignerConfigurationError({name:?} + \" template requires verification\")\n"
        ),
    }
}

fn python_bytes_literal(bytes: &[u8]) -> String {
    format!("bytes({bytes:?})")
}

fn primitive_code(primitive: Option<&SignerPrimitive>) -> String {
    match primitive {
        Some(SignerPrimitive::Hmac { hash }) => format!("    def _sign(self, canonical: bytes, credential: bytes) -> bytes:\n        return hmac.new(credential, canonical, {hash:?}).digest()\n"),
        Some(SignerPrimitive::Digest { algorithm }) => format!("    def _sign(self, canonical: bytes, credential: bytes) -> bytes:\n        del credential\n        return hashlib.new({algorithm:?}, canonical).digest()\n"),
        Some(SignerPrimitive::Rsa { algorithm }) => format!("    def _sign(self, canonical: bytes, credential: bytes) -> bytes:\n        from cryptography.hazmat.primitives import hashes, serialization\n        from cryptography.hazmat.primitives.asymmetric import padding\n        key = serialization.load_pem_private_key(credential, password=None)\n        return key.sign(canonical, padding.PKCS1v15(), getattr(hashes, {algorithm:?})())\n"),
        Some(SignerPrimitive::Ecdsa { algorithm }) => format!("    def _sign(self, canonical: bytes, credential: bytes) -> bytes:\n        from cryptography.hazmat.primitives import hashes, serialization\n        from cryptography.hazmat.primitives.asymmetric import ec\n        key = serialization.load_pem_private_key(credential, password=None)\n        return key.sign(canonical, ec.ECDSA(getattr(hashes, {algorithm:?})()))\n"),
        Some(SignerPrimitive::Unknown { algorithm }) => format!("    def _sign(self, canonical: bytes, credential: bytes) -> bytes:\n        raise SignerConfigurationError(\"unknown primitive: \" + {algorithm:?})\n"),
        None => "    def _sign(self, canonical: bytes, credential: bytes) -> bytes:\n        raise SignerConfigurationError(\"signer primitive was not recovered\")\n".to_owned(),
    }
}

fn render_partial(signer: &SignerArtifact) -> String {
    let mut text = format!(
        "# REVIEW ONLY signer {id}; canonicalization inferred, needs verification.\n# confidence {confidence:.3}; no working httpx.Auth is emitted.\n",
        id = signer.signer_id,
        confidence = signer.confidence
    );
    for alternative in &signer.ranked_alternatives {
        let _ = writeln!(
            text,
            "# hypothesis {} confidence {:.3}; fixtures {}",
            alternative.hypothesis_id,
            alternative.confidence,
            alternative
                .fixtures
                .iter()
                .map(|fixture| fixture.capture_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let _ = write!(
        text,
        "class {}ReviewOnly:\n    \"\"\"Review stub only; not an auth implementation.\"\"\"\n    pass\n\n",
        auth_class_name(&signer.signer_id)
    );
    text
}

fn render_device_oracle(signer: &SignerArtifact) -> String {
    format!(
        "# DEVICE ORACLE signer {}; requires the original instrumented runtime.\n\
         class {}DeviceOracle:\n\
             \"\"\"Callback shape only; key material stays in the original runtime.\"\"\"\n\
             def __init__(self, callback): self.callback = callback\n\
             def sign(self, request: httpx.Request) -> httpx.Request:\n\
                 result = self.callback(request, {:?})\n\
                 if isinstance(result, httpx.Request): return result\n\
                 for name, value in result.items(): request.headers[name] = value\n\
                 return request\n\n",
        signer.signer_id,
        auth_class_name(&signer.signer_id),
        signer.signer_id
    )
}

fn render_observed(signer: &SignerArtifact) -> String {
    format!(
        "# OBSERVED ONLY signer {}; primitive seen, canonicalization not reproduced.\n\
         class {}ObservedOnly:\n\
             \"\"\"Documentation marker only; no working signer is provided.\"\"\"\n\
             primitive = {:?}\n\
             pass\n\n",
        signer.signer_id,
        auth_class_name(&signer.signer_id),
        signer.primitive.as_ref().map(primitive_name)
    )
}

fn render_pyproject(
    emitter: &PythonSdkEmitter,
    signers: &BTreeMap<String, (String, SignerArtifact)>,
) -> String {
    let crypto = signers.values().any(|(_, signer)| {
        matches!(
            signer.primitive,
            Some(SignerPrimitive::Rsa { .. } | SignerPrimitive::Ecdsa { .. })
        )
    });
    let extra = if crypto {
        ", \"cryptography>=42,<50\""
    } else {
        ""
    };
    format!(
        "[build-system]\nrequires = [\"setuptools>=68\"]\nbuild-backend = \"setuptools.build_meta\"\n\n\
         [project]\nname = {name:?}\nversion = \"0.1.0\"\ndescription = \"APIaxess recovered typed httpx client\"\nrequires-python = \">=3.10\"\ndependencies = [\"httpx>=0.27,<1\"{extra}]\n\n\
         [tool.setuptools.packages.find]\ninclude = [{package:?}]\n",
        name = emitter.distribution_name,
        package = emitter.package_name
    )
}

fn render_init(
    emitter: &PythonSdkEmitter,
    signers: &BTreeMap<String, (String, SignerArtifact)>,
) -> String {
    let mut output = format!(
        "\"\"\"APIaxess recovered SDK.\"\"\"\n\nfrom .client import {}\n",
        emitter.client_class
    );
    for (class_name, signer) in signers.values() {
        if signer.signer_mode == SignerMode::Reproducible {
            let _ = writeln!(output, "from .auth import {class_name}");
        }
    }
    output
}

fn render_readme(
    emitter: &PythonSdkEmitter,
    surface: &UnifiedApiSurface,
    signer_ids: &BTreeSet<String>,
    signers: &BTreeMap<String, (String, SignerArtifact)>,
) -> String {
    let mut output = format!(
        "# {}\n\nGenerated by APIaxess.\n\n~~~python\nfrom {} import {}\nclient = {}(\"https://target.example\", signer_credentials={{...}})\n~~~\n\nCredentials are supplied at runtime; no secret is embedded in this package.\n\n## Auth honesty\n\n",
        emitter.distribution_name, emitter.package_name, emitter.client_class, emitter.client_class
    );
    for id in signer_ids {
        if let Some((class_name, signer)) = signers.get(id) {
            if signer.signer_mode == SignerMode::Reproducible {
                let _ = writeln!(
                    output,
                    "- {id}: reproducible {class_name}, confidence {:.3}.",
                    signer.confidence
                );
            } else {
                let _ = writeln!(
                    output,
                    "- {id}: {:?}; inspect auth.py review/device/documentation output.",
                    signer.signer_mode
                );
            }
        } else {
            let _ = writeln!(output, "- {id}: non-reproducible signer; inspect auth.py.");
        }
    }
    if signer_ids.is_empty() {
        output.push_str("- No signer bindings were recovered.\n");
    }
    let _ = writeln!(
        output,
        "\nCoverage: {} confirmed, {} inferred, {} static-only.\n",
        surface.confidence.coverage.confirmed_endpoint_count,
        surface.confidence.coverage.inferred_endpoint_count,
        surface.confidence.coverage.static_only_endpoint_count
    );
    output
}

fn decode_expression(input: &str, slot: &SchemaSlot, type_name: &str) -> String {
    let Some(selected) = slot.shape.selected_candidate() else {
        return input.to_owned();
    };
    match &selected.value {
        SchemaShape::Object { .. } => {
            format!("{type_name}.from_dict({input}) if isinstance({input}, Mapping) else {input}")
        }
        _ => input.to_owned(),
    }
}

fn normalize_location(location: &str) -> String {
    let lower = location.to_ascii_lowercase();
    if lower.starts_with("header:") || lower.starts_with("query:") {
        location.to_owned()
    } else if lower.contains("query") {
        format!("query:{location}")
    } else {
        format!("header:{location}")
    }
}

fn endpoint_path(surface: &UnifiedApiSurface, identity: &EndpointIdentity) -> String {
    surface
        .surface
        .endpoints
        .iter()
        .position(|endpoint| &endpoint.identity == identity)
        .map_or_else(
            || "endpoints[0]".to_owned(),
            |index| format!("endpoints[{index}]"),
        )
}

fn method_name(identity: &EndpointIdentity) -> String {
    format!(
        "{}_{}",
        identity.method.as_str().to_ascii_lowercase(),
        safe_name(identity.path_template.as_str()).trim_matches('_')
    )
}

fn path_parameter_names(path: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else { break };
        names.push(after[..end].to_owned());
        rest = &after[end + 1..];
    }
    for segment in path.split('/') {
        if segment.starts_with(':') || segment.starts_with('*') {
            names.push(segment[1..].to_owned());
        }
    }
    names.sort();
    names.dedup();
    names
}

fn coverage_text(surface: &UnifiedApiSurface, identity: &EndpointIdentity) -> String {
    let fact =
        surface.confidence.facts.iter().find(|fact| {
            fact.endpoint.as_ref() == Some(identity) && fact.path.ends_with(".presence")
        });
    match fact.map(|fact| (fact.static_sample_count > 0, fact.dynamic_sample_count > 0)) {
        Some((true, true)) => "dynamically confirmed".to_owned(),
        Some((false, true)) => "dynamic-only inferred".to_owned(),
        Some((true, false)) => "static-only; runtime confirmation open".to_owned(),
        _ => "unscored".to_owned(),
    }
}

fn endpoint_confidence(surface: &UnifiedApiSurface, identity: &EndpointIdentity) -> String {
    surface
        .confidence
        .facts
        .iter()
        .find(|fact| fact.endpoint.as_ref() == Some(identity) && fact.path.ends_with(".presence"))
        .map_or_else(
            || "unscored".to_owned(),
            |fact| format!("{:.3}", fact.score),
        )
}

fn authentication_text(endpoint: &Endpoint) -> String {
    endpoint.authentication.as_ref().map_or_else(
        || "none recovered; review before authenticated use".to_owned(),
        |fact| {
            fact.selected_candidate().map_or_else(
                || "unresolved authentication fact".to_owned(),
                |candidate| format!("{:?}", candidate.value),
            )
        },
    )
}

fn requiredness_text(
    fact: &apiaxess_api_model::Fact<apiaxess_api_model::RequirednessAssertion>,
    minimum: NonZeroU64,
) -> &'static str {
    match fact.assess_requiredness(minimum) {
        Ok(RequirednessAssessment::Required) => "required",
        Ok(RequirednessAssessment::Optional) => "optional",
        Ok(RequirednessAssessment::Inconclusive) => "inconclusive",
        Err(_) => "invalid",
    }
}

fn confidence_text(surface: &UnifiedApiSurface, path: &str) -> String {
    surface
        .confidence
        .facts
        .iter()
        .find(|fact| fact.path == path)
        .map_or_else(
            || "confidence unscored".to_owned(),
            |fact| format!("confidence {:.3}", fact.score),
        )
}

fn diagnostic<const N: usize>(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    values: [(&str, String); N],
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    for (key, value) in values {
        context.insert(key.to_owned(), DiagnosticValue::String(value));
    }
    definition.instantiate(context)
}

fn signer_diagnostic(signer: &SignerArtifact) -> Diagnostic {
    let definition = match signer.signer_mode {
        SignerMode::DeviceOracle => catalogue::PYTHON_SDK_SIGNER_DEVICE_ORACLE,
        SignerMode::PartialHypothesis | SignerMode::ObservedOnly => {
            catalogue::PYTHON_SDK_SIGNER_REVIEW
        }
        SignerMode::Reproducible => catalogue::PYTHON_SDK_SIGNER_REVIEW,
    };
    diagnostic(
        definition,
        [
            ("field", format!("signers[{}]", signer.signer_id)),
            ("detail", format!("mode {:?}", signer.signer_mode)),
        ],
    )
}

fn auth_class_name(id: &str) -> String {
    format!("{}Auth", pascal_case(&safe_name(id)))
}

fn python_field(value: &str) -> String {
    let mut name = safe_name(value).to_ascii_lowercase();
    if name.is_empty() {
        "value".clone_into(&mut name);
    }
    if matches!(
        name.as_str(),
        "class" | "def" | "from" | "import" | "in" | "is" | "match" | "return" | "self" | "type"
    ) {
        name.push('_');
    }
    name
}

fn pascal_case(value: &str) -> String {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect()
}

fn safe_name(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn suffix(value: &str) -> String {
    let mut hash = 2_166_136_261_u32;
    for byte in value.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    format!("{hash:08x}")
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_ascii_alphabetic()
                || (index > 0 && character.is_ascii_digit())
        })
}

fn python_comment(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

fn primitive_name(primitive: &SignerPrimitive) -> String {
    match primitive {
        SignerPrimitive::Hmac { hash } => format!("hmac:{hash}"),
        SignerPrimitive::Rsa { algorithm } => format!("rsa:{algorithm}"),
        SignerPrimitive::Ecdsa { algorithm } => format!("ecdsa:{algorithm}"),
        SignerPrimitive::Digest { algorithm } => format!("digest:{algorithm}"),
        SignerPrimitive::Unknown { algorithm } => format!("unknown:{algorithm}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_api_model::{SignerScheme, SourceType};

    #[test]
    fn canonicalization_is_emitted_in_order_and_uses_runtime_credentials() {
        let signer = test_signer();
        let text = render_reproducible("TestAuth", &signer);
        assert!(text.contains("credential://key"));
        assert!(text.contains("value = _field(request, \"path\""));
        assert!(text.contains("value = _bytes(value).upper()"));
        assert!(text.contains("hmac.new(credential, canonical, \"sha256\")"));
        assert!(!text.contains("fixtures"));
        assert_eq!(
            canonicalization_code(&CanonicalizationOperation::Literal {
                bytes: vec![0x2f, 0x3f],
            }),
            "        value = bytes([47, 63])\n"
        );
    }

    #[test]
    fn generated_auth_flow_resolves_credentials_before_canonicalization() {
        let signer = test_signer();
        let mut signers = BTreeMap::new();
        signers.insert(signer.signer_id.clone(), ("TestAuth".to_owned(), signer));
        let mut diagnostics = Vec::new();
        let text = render_auth(&signers, &mut diagnostics);
        assert!(text.contains("self._active_credential = credential"));
        assert!(text.contains("credential = self._active_credential"));
        assert!(!text.contains("+             return datetime"));
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn non_reproducible_modes_are_never_working_auth_classes() {
        let mut signer = test_signer();
        signer.signer_mode = SignerMode::PartialHypothesis;
        assert!(render_partial(&signer).contains("ReviewOnly"));
        signer.signer_mode = SignerMode::DeviceOracle;
        assert!(render_device_oracle(&signer).contains("callback"));
        signer.signer_mode = SignerMode::ObservedOnly;
        assert!(render_observed(&signer).contains("Documentation marker only"));
    }

    #[test]
    fn auth_module_emits_each_non_reproducible_mode_honestly() {
        let mut signers = BTreeMap::new();
        for (id, mode) in [
            ("partial", SignerMode::PartialHypothesis),
            ("oracle", SignerMode::DeviceOracle),
            ("observed", SignerMode::ObservedOnly),
        ] {
            let mut signer = test_signer();
            signer.signer_id = format!("signer:{id}");
            signer.signer_mode = mode;
            signers.insert(
                signer.signer_id.clone(),
                (auth_class_name(&signer.signer_id), signer),
            );
        }
        let mut diagnostics = Vec::new();
        let text = render_auth(&signers, &mut diagnostics);
        assert!(text.contains("ReviewOnly"));
        assert!(text.contains("DeviceOracle"));
        assert!(text.contains("ObservedOnly"));
        assert!(!text.contains("class SignerPartial(BaseSignerAuth)"));
    }

    fn test_signer() -> SignerArtifact {
        SignerArtifact {
            schema_version: apiaxess_api_model::SIGNER_IR_SCHEMA_VERSION,
            signer_id: "signer:test".to_owned(),
            scheme: SignerScheme::CustomHmac,
            signer_mode: SignerMode::Reproducible,
            confidence: 0.9,
            coverage: vec![],
            canonicalization_steps: vec![
                apiaxess_api_model::CanonicalizationStep {
                    operation: CanonicalizationOperation::Field {
                        name: "path".to_owned(),
                    },
                    description: "read final path".to_owned(),
                    source_type: SourceType::DynamicCapture,
                },
                apiaxess_api_model::CanonicalizationStep {
                    operation: CanonicalizationOperation::Uppercase,
                    description: "uppercase".to_owned(),
                    source_type: SourceType::DynamicCapture,
                },
            ],
            primitive: Some(SignerPrimitive::Hmac {
                hash: "sha256".to_owned(),
            }),
            key_source: Some(SignerKeySource::CredentialReference {
                secret_ref: "credential://key".to_owned(),
                provider: None,
            }),
            output: Some(apiaxess_api_model::SignerOutput {
                encoding: "hex".to_owned(),
                wire_location: Some("header:X-Signature".to_owned()),
                prefix: None,
                suffix: None,
                truncation: None,
            }),
            runtime: apiaxess_api_model::SignerRuntime::default(),
            fixtures: vec![],
            ranked_alternatives: vec![],
            interface: apiaxess_api_model::SignerInterface::default(),
            reproduction: "pure signer".to_owned(),
            provenance: vec![apiaxess_api_model::SignerProvenance {
                source_type: SourceType::DynamicCapture,
                evidence_ids: vec!["capture:test".to_owned()],
                detail: "fixture".to_owned(),
            }],
        }
    }
}
