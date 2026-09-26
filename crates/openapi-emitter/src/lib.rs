//! Deterministic `OpenAPI` 3.1 emission from the Phase 5 unified surface.
//!
//! This crate builds the publishing document directly. The unified model is
//! richer than `OpenAPI`, so standard tooling gets a useful document while the
//! remaining evidence lives in `x-apiaxess-*` extensions.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
};

use apiaxess_api_model::{
    ApiKeyLocation, AuthenticationScheme, Endpoint, EndpointIdentity, FactConfidence,
    GraphQlOperationType, ObjectOpenness, RequirednessAssessment, ResponseSelector, SchemaShape,
    SchemaSlot, SignerArtifact, SignerBinding, SignerKeySource, SignerMode, SignerPrimitive,
    SignerScheme, SourceType, UnifiedApiSurface, captured_graphql_operations, endpoint_base_url,
    is_transport_header,
};
use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticSeverity, DiagnosticValue, catalogue,
};
use serde_json::{Map, Value, json};

/// `OpenAPI` version emitted by this crate.
pub const OPENAPI_VERSION: &str = "3.1.0";
/// Default sample count required before dynamic requiredness becomes asserted.
pub const DEFAULT_MINIMUM_DYNAMIC_SAMPLES: u64 = 3;
const X_PREFIX: &str = "x-apiaxess-";

/// Configuration for deterministic `OpenAPI` emission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiEmitter {
    /// `OpenAPI` info title.
    pub title: String,
    /// `OpenAPI` info version.
    pub version: String,
    /// Dynamic sample threshold used for sample-gated requiredness.
    pub minimum_dynamic_samples: NonZeroU64,
}

impl Default for OpenApiEmitter {
    fn default() -> Self {
        Self {
            title: "APIaxess recovered API".to_owned(),
            version: "0.1.0".to_owned(),
            minimum_dynamic_samples: NonZeroU64::new(DEFAULT_MINIMUM_DYNAMIC_SAMPLES)
                .expect("the default threshold is non-zero"),
        }
    }
}

impl OpenApiEmitter {
    /// Creates an emitter with explicit `OpenAPI` metadata.
    #[must_use]
    pub fn new(title: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            version: version.into(),
            ..Self::default()
        }
    }

    /// Emits a validated `OpenAPI` document and any non-fatal honesty diagnostics.
    ///
    /// A failed result contains structured diagnostics and never contains a
    /// structurally invalid document.
    ///
    /// # Errors
    ///
    /// Returns diagnostics when the unified surface or emitter metadata is
    /// invalid, or when an endpoint cannot be represented in `OpenAPI`.
    // Keep document assembly linear so emitted fields remain easy to audit.
    #[allow(clippy::too_many_lines)]
    pub fn emit(&self, surface: &UnifiedApiSurface) -> Result<OpenApiEmission, Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        if let Err(error) = surface.validate() {
            diagnostics.push(diagnostic(
                catalogue::OPENAPI_INVALID_INPUT,
                [
                    ("field", "unified".to_owned()),
                    ("detail", error.to_string()),
                ],
            ));
            return Err(diagnostics);
        }
        if self.title.trim().is_empty() || self.version.trim().is_empty() {
            diagnostics.push(diagnostic(
                catalogue::OPENAPI_INVALID_INPUT,
                [
                    ("field", "info".to_owned()),
                    ("detail", "title and version must not be blank".to_owned()),
                ],
            ));
            return Err(diagnostics);
        }

        let mut builder =
            SchemaBuilder::new(surface, self.minimum_dynamic_samples, &mut diagnostics);
        let mut paths = BTreeMap::<String, Value>::new();
        let mut security_schemes = BTreeMap::<String, Value>::new();
        // Operation key -> host and origin of the endpoint that claimed it.
        let mut seen_operations = BTreeMap::<String, (Option<String>, Option<String>)>::new();
        // Every operation is emitted against its own endpoint's origin: the
        // origin most endpoints share is the document's server, and an
        // operation served from any other origin carries its own `servers`.
        let primary_base = surface.primary_base_url();
        let mut seen_operation_ids = BTreeSet::new();
        let endpoint_indices = surface
            .surface
            .endpoints
            .iter()
            .enumerate()
            .map(|(index, endpoint)| (endpoint.identity.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let mut endpoints = surface.surface.endpoints.iter().collect::<Vec<_>>();
        endpoints.sort_by(|left, right| left.identity.cmp(&right.identity));

        for endpoint in endpoints {
            let Some(&original_index) = endpoint_indices.get(&endpoint.identity) else {
                builder.diagnostics.push(diagnostic(
                    catalogue::OPENAPI_INVALID_INPUT,
                    [
                        ("field", "endpoints".to_owned()),
                        (
                            "detail",
                            "endpoint identity index is inconsistent".to_owned(),
                        ),
                    ],
                ));
                continue;
            };
            let model_path = format!("endpoints[{original_index}]");
            let Some(path) = openapi_path(
                endpoint.identity.path_template.as_str(),
                &model_path,
                builder.diagnostics,
            ) else {
                continue;
            };
            let operation_key = format!("{} {path}", endpoint.identity.method.as_str());
            if let Some((claimed_host, claimed_base)) = seen_operations.get(&operation_key) {
                // The same route on another host is a distinct endpoint, but
                // an OpenAPI path item holds one operation per method: record
                // the extra host on the existing operation instead.
                if claimed_host != &endpoint.identity.host {
                    if let Some(Value::Object(operation)) = paths.get_mut(&path).and_then(|item| {
                        item.get_mut(endpoint.identity.method.as_str().to_ascii_lowercase())
                    }) {
                        add_operation_host(
                            operation,
                            claimed_host.as_deref(),
                            claimed_base.as_deref(),
                            endpoint,
                        );
                    }
                    continue;
                }
                builder.diagnostics.push(diagnostic(
                    catalogue::OPENAPI_UNREPRESENTABLE,
                    [("field", model_path.clone()), ("detail", format!("duplicate OpenAPI operation after path normalization: {operation_key}"))],
                ));
                continue;
            }
            seen_operations.insert(
                operation_key,
                (endpoint.identity.host.clone(), endpoint_base_url(endpoint)),
            );
            let path_item = paths
                .entry(path.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            let Value::Object(path_item) = path_item else {
                continue;
            };
            insert_path_extension(path_item, endpoint, surface, &model_path);
            if !is_standard_method(endpoint.identity.method.as_str()) {
                path_item.insert(
                    format!("{X_PREFIX}unsupported-methods"),
                    json!([{"method": endpoint.identity.method.as_str(), "model_path": model_path}]),
                );
                builder.diagnostics.push(diagnostic(
                    catalogue::OPENAPI_UNREPRESENTABLE,
                    [
                        ("field", format!("{model_path}.identity.method")),
                        (
                            "detail",
                            format!(
                                "HTTP method {} is not an OpenAPI operation key",
                                endpoint.identity.method
                            ),
                        ),
                    ],
                ));
                continue;
            }
            let mut operation = emit_operation(
                endpoint,
                surface,
                &model_path,
                &mut builder,
                &mut security_schemes,
            );
            if let (Some(base), Value::Object(fields)) =
                (endpoint_base_url(endpoint), &mut operation)
            {
                if primary_base.as_deref() != Some(base.as_str()) {
                    fields.insert("servers".to_owned(), json!([{"url": base}]));
                }
            }
            let base_operation_id = operation_id(&endpoint.identity);
            let mut unique_operation_id = base_operation_id.clone();
            let mut operation_id_suffix = 2_u32;
            while !seen_operation_ids.insert(unique_operation_id.clone()) {
                unique_operation_id = format!("{base_operation_id}_{operation_id_suffix}");
                operation_id_suffix = operation_id_suffix.saturating_add(1);
            }
            path_item.insert(
                endpoint.identity.method.as_str().to_ascii_lowercase(),
                set_operation_id(operation, unique_operation_id),
            );
        }

        let mut document = Map::new();
        document.insert(
            "openapi".to_owned(),
            Value::String(OPENAPI_VERSION.to_owned()),
        );
        document.insert(
            "info".to_owned(),
            json!({"title": self.title, "version": self.version}),
        );
        document.insert(
            "paths".to_owned(),
            Value::Object(paths.into_iter().collect()),
        );
        // The document server is the primary origin, described by the first
        // endpoint that is served from it.
        let servers = primary_base
            .as_deref()
            .and_then(|primary| {
                surface
                    .surface
                    .endpoints
                    .iter()
                    .position(|endpoint| endpoint_base_url(endpoint).as_deref() == Some(primary))
                    .map(|index| {
                        server_value(
                            primary,
                            &format!("endpoints[{index}].base_url"),
                            surface,
                            builder.diagnostics,
                        )
                    })
            })
            .into_iter()
            .collect::<Vec<_>>();
        if !servers.is_empty() {
            document.insert("servers".to_owned(), Value::Array(servers));
        }
        let emission_diagnostics = builder.diagnostics.clone();
        if emission_diagnostics
            .iter()
            .any(|item| item.severity >= DiagnosticSeverity::Error)
        {
            return Err(emission_diagnostics);
        }
        let mut components = Map::new();
        components.insert(
            "schemas".to_owned(),
            Value::Object(builder.components.into_iter().collect()),
        );
        if !security_schemes.is_empty() {
            components.insert(
                "securitySchemes".to_owned(),
                Value::Object(security_schemes.into_iter().collect()),
            );
        }
        document.insert("components".to_owned(), Value::Object(components));
        add_root_extensions(&mut document, surface, &emission_diagnostics);
        Ok(OpenApiEmission {
            document: Value::Object(document),
            diagnostics: emission_diagnostics,
        })
    }
}

/// Successful `OpenAPI` output together with warnings retained for callers and the root extension.
#[derive(Clone, Debug, PartialEq)]
pub struct OpenApiEmission {
    /// The `OpenAPI` 3.1 JSON document.
    pub document: Value,
    /// Non-fatal diagnostics raised while preserving validity.
    pub diagnostics: Vec<Diagnostic>,
}

// Operation emission stays linear to preserve the document field ordering.
#[allow(clippy::too_many_lines)]
fn emit_operation(
    endpoint: &Endpoint,
    surface: &UnifiedApiSurface,
    model_path: &str,
    builder: &mut SchemaBuilder<'_>,
    security_schemes: &mut BTreeMap<String, Value>,
) -> Value {
    let mut operation = Map::new();
    operation.insert(
        "operationId".to_owned(),
        Value::String(operation_id(&endpoint.identity)),
    );
    operation.insert(
        "summary".to_owned(),
        Value::String(format!(
            "{} {}",
            endpoint.identity.method, endpoint.identity.path_template
        )),
    );
    add_endpoint_extensions(&mut operation, endpoint, surface, model_path);

    let mut parameters = Vec::new();
    let placeholders =
        path_parameter_names(endpoint.identity.path_template.as_str()).unwrap_or_default();
    let mut explicit_path_names = BTreeSet::new();
    let mut path_params = endpoint
        .path_parameters
        .iter()
        .enumerate()
        .collect::<Vec<_>>();
    path_params.sort_by(|left, right| left.1.name.as_str().cmp(right.1.name.as_str()));
    for (parameter_index, parameter) in path_params {
        let name = parameter.name.as_str();
        if !placeholders.iter().any(|placeholder| placeholder == name) {
            builder.diagnostics.push(diagnostic(
                catalogue::OPENAPI_UNREPRESENTABLE,
                [
                    (
                        "field",
                        format!("{model_path}.path_parameters[{parameter_index}]"),
                    ),
                    (
                        "detail",
                        format!("path parameter {name} is not present in the path template"),
                    ),
                ],
            ));
            continue;
        }
        explicit_path_names.insert(name.to_owned());
        parameters.push(emit_parameter(
            "path",
            name,
            true,
            &parameter_schema_path(model_path, "path_parameters", parameter_index, "schema"),
            &parameter.schema,
            Some(&format!(
                "{model_path}.path_parameters[{parameter_index}].presence"
            )),
            Some(&parameter.presence),
            None,
            builder,
        ));
    }
    for name in &placeholders {
        if !explicit_path_names.contains(name) {
            builder.diagnostics.push(diagnostic(
                catalogue::OPENAPI_INCOMPLETE,
                [("field", format!("{model_path}.path_parameters")), ("detail", format!("generated a required string parameter for {name} from the path template"))],
            ));
            let mut parameter = Map::new();
            parameter.insert("name".to_owned(), Value::String(name.clone()));
            parameter.insert("in".to_owned(), Value::String("path".to_owned()));
            parameter.insert("required".to_owned(), Value::Bool(true));
            parameter.insert(
                "schema".to_owned(),
                json!({
                    "type": "string",
                    "x-apiaxess-confidence": {"score": 0.0, "status": "synthetic"},
                    "x-apiaxess-provenance": {"sources": ["path_template"], "evidence": []}
                }),
            );
            parameters.push(Value::Object(parameter));
        }
    }

    let mut query_params = endpoint
        .query_parameters
        .iter()
        .enumerate()
        .collect::<Vec<_>>();
    query_params.sort_by(|left, right| left.1.name.as_str().cmp(right.1.name.as_str()));
    for (parameter_index, parameter) in query_params {
        let schema_path =
            parameter_schema_path(model_path, "query_parameters", parameter_index, "schema");
        let requiredness_path = parameter_schema_path(
            model_path,
            "query_parameters",
            parameter_index,
            "requiredness",
        );
        let required = match parameter
            .requiredness
            .assess_requiredness(builder.minimum_dynamic_samples)
        {
            Ok(RequirednessAssessment::Required) => true,
            Ok(RequirednessAssessment::Optional | RequirednessAssessment::Inconclusive) => false,
            Err(error) => {
                builder.diagnostics.push(diagnostic(
                    catalogue::OPENAPI_INVALID_INPUT,
                    [
                        ("field", requiredness_path.clone()),
                        ("detail", error.to_string()),
                    ],
                ));
                false
            }
        };
        parameters.push(emit_parameter(
            "query",
            parameter.name.as_str(),
            required,
            &schema_path,
            &parameter.schema,
            Some(&format!(
                "{model_path}.query_parameters[{parameter_index}].presence"
            )),
            Some(&parameter.presence),
            Some((&requiredness_path, &parameter.requiredness)),
            builder,
        ));
    }

    let mut headers = endpoint.headers.iter().enumerate().collect::<Vec<_>>();
    headers.sort_by(|left, right| {
        left.1
            .name
            .as_str()
            .to_ascii_lowercase()
            .cmp(&right.1.name.as_str().to_ascii_lowercase())
    });
    for (parameter_index, header) in headers {
        // Transport and browser mechanics are not API parameters, and OpenAPI
        // ignores header parameters named Accept, Content-Type, or
        // Authorization (media types and security schemes carry those).
        let name = header.name.as_str();
        if is_transport_header(name)
            || ["accept", "content-type", "authorization"]
                .iter()
                .any(|ignored| name.eq_ignore_ascii_case(ignored))
        {
            continue;
        }
        parameters.push(emit_parameter(
            "header",
            header.name.as_str(),
            false,
            &parameter_schema_path(model_path, "headers", parameter_index, "schema"),
            &header.schema,
            Some(&format!("{model_path}.headers[{parameter_index}].presence")),
            Some(&header.presence),
            None,
            builder,
        ));
    }
    parameters.sort_by_key(parameter_sort_key);
    operation.insert("parameters".to_owned(), Value::Array(parameters));

    if let Some(body) = &endpoint.request_body {
        let body_path = format!("{model_path}.request_body");
        let reference = builder.schema_ref(body, &body_path);
        let mut media = json!({"schema": reference});
        // A GraphQL endpoint keeps the operations it was seen running, with
        // their documents and variables exactly as captured.
        let graphql = captured_graphql_operations(endpoint);
        if !graphql.is_empty() {
            media["examples"] = Value::Object(
                graphql
                    .iter()
                    .map(|operation| {
                        (
                            operation.name.clone(),
                            json!({
                                "summary": format!("{} {} (as captured)", graphql_type_name(operation.operation_type), operation.name),
                                "value": {
                                    "operationName": operation.name,
                                    "query": operation.query,
                                    "variables": operation.variables
                                }
                            }),
                        )
                    })
                    .collect(),
            );
            operation.insert(
                format!("{X_PREFIX}graphql-operations"),
                Value::Array(
                    graphql
                        .iter()
                        .map(|operation| json!({"type": graphql_type_name(operation.operation_type), "name": operation.name}))
                        .collect(),
                ),
            );
        }
        operation.insert(
            "requestBody".to_owned(),
            json!({
                "required": false,
                "content": {"application/json": media},
                "x-apiaxess-confidence": builder.confidence_extension(&format!("{body_path}.shape")),
                "x-apiaxess-provenance": builder.provenance_extension(&format!("{body_path}.shape")),
                "x-apiaxess-requiredness": "unknown"
            }),
        );
    }

    let mut responses = Map::new();
    let mut response_indices = endpoint.responses.iter().enumerate().collect::<Vec<_>>();
    response_indices.sort_by(|left, right| left.1.selector.cmp(&right.1.selector));
    for (response_index, response) in response_indices {
        let response_path = format!("{model_path}.responses[{response_index}]");
        let body_path = format!("{response_path}.body");
        let key = response_key(response.selector);
        let mut response_value = Map::new();
        let media = response.media_type.as_deref();
        let unknown_body = matches!(
            response
                .body
                .shape
                .selected_candidate()
                .map(|candidate| &candidate.value),
            None | Some(SchemaShape::Unknown)
        );
        response_value.insert(
            "description".to_owned(),
            Value::String(match media {
                Some("text/event-stream") => format!("Recovered response {key}: a Server-Sent Events stream (text/event-stream). Its events are captured per flow, not as one body."),
                Some("text/html") => format!("Recovered response {key}: an HTML document."),
                None if unknown_body => format!("Recovered response {key}; no body or content type was observed."),
                _ => format!("Recovered response {key}"),
            }),
        );
        // A response is emitted with its observed media type; JSON is only
        // assumed for a structured body recorded before media types were.
        if media.is_some() || !unknown_body {
            let mut content = Map::new();
            content.insert(
                media.unwrap_or("application/json").to_owned(),
                json!({"schema": builder.schema_ref(&response.body, &body_path)}),
            );
            response_value.insert("content".to_owned(), Value::Object(content));
        }
        response_value.insert(
            format!("{X_PREFIX}confidence"),
            builder.confidence_extension(&format!("{response_path}.presence")),
        );
        response_value.insert(
            format!("{X_PREFIX}provenance"),
            builder.provenance_extension(&format!("{response_path}.presence")),
        );
        responses.insert(key, Value::Object(response_value));
    }
    if responses.is_empty() {
        builder.diagnostics.push(diagnostic(
            catalogue::OPENAPI_INCOMPLETE,
            [
                ("field", format!("{model_path}.responses")),
                (
                    "detail",
                    "emitted a default response because no response schema was recovered"
                        .to_owned(),
                ),
            ],
        ));
        responses.insert(
            "default".to_owned(),
            json!({
                "description": "Response schema not recovered",
                "x-apiaxess-confidence": {"score": 0.0, "status": "unscored"},
                "x-apiaxess-provenance": {"sources": [], "evidence": []}
            }),
        );
    }
    operation.insert("responses".to_owned(), Value::Object(responses));

    if let Some(authentication_fact) = &endpoint.authentication {
        let auth_path = format!("{model_path}.authentication");
        let Some(authentication) = authentication_fact
            .selected_candidate()
            .map(|candidate| &candidate.value)
        else {
            builder.diagnostics.push(diagnostic(
                catalogue::OPENAPI_INVALID_INPUT,
                [
                    ("field", auth_path.clone()),
                    (
                        "detail",
                        "selected authentication candidate is missing".to_owned(),
                    ),
                ],
            ));
            return Value::Object(operation);
        };
        let mut auth_schemes = Vec::new();
        if let Some((name, mut scheme, clean)) = standard_security_scheme(authentication) {
            if !clean {
                builder.diagnostics.push(diagnostic(
                    catalogue::OPENAPI_AUTH_REVIEW,
                    [("field", auth_path.clone()), ("detail", "OAuth2 flow endpoints were not present; placeholder URLs are marked in the security scheme".to_owned())],
                ));
            }
            if let Value::Object(value) = &mut scheme {
                value.insert(
                    format!("{X_PREFIX}authentication"),
                    serde_json::to_value(authentication).unwrap_or(Value::Null),
                );
                value.insert(
                    format!("{X_PREFIX}confidence"),
                    builder.confidence_extension(&auth_path),
                );
                value.insert(
                    format!("{X_PREFIX}provenance"),
                    builder.provenance_extension(&auth_path),
                );
            }
            security_schemes.insert(name.clone(), scheme);
            let mut security = Map::new();
            security.insert(name, Value::Array(Vec::new()));
            auth_schemes.push(Value::Object(security));
        }
        operation.insert(
            format!("{X_PREFIX}authentication"),
            serde_json::to_value(authentication).unwrap_or(Value::Null),
        );
        if standard_security_scheme(authentication).is_none()
            && matches!(authentication, AuthenticationScheme::OAuth2 { .. })
        {
            builder.diagnostics.push(diagnostic(
                catalogue::OPENAPI_AUTH_REVIEW,
                [
                    ("field", auth_path),
                    (
                        "detail",
                        "OAuth2 flow identifiers did not match a standard OpenAPI flow name"
                            .to_owned(),
                    ),
                ],
            ));
        }
        if !auth_schemes.is_empty() {
            operation.insert("security".to_owned(), Value::Array(auth_schemes));
        }
    }

    let mut signers = surface.signers_for(&endpoint.identity);
    signers.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    if !signers.is_empty() {
        operation.insert(
            format!("{X_PREFIX}signer"),
            Value::Array(
                signers
                    .iter()
                    .map(|signer| signer_extension(signer, &surface.signer_bindings))
                    .collect(),
            ),
        );
    }
    operation.insert(
        format!("{X_PREFIX}fact-paths"),
        Value::Array(
            surface
                .confidence
                .facts
                .iter()
                .filter(|fact| fact.endpoint.as_ref() == Some(&endpoint.identity))
                .map(|fact| Value::String(fact.path.clone()))
                .collect(),
        ),
    );
    Value::Object(operation)
}

// These arguments map directly to the corresponding `OpenAPI` parameter
// fields, so a struct would obscure rather than clarify the emission mapping.
#[allow(clippy::too_many_arguments)]
fn emit_parameter(
    location: &str,
    name: &str,
    required: bool,
    schema_path: &str,
    schema: &SchemaSlot,
    presence_path: Option<&str>,
    presence: Option<&apiaxess_api_model::Fact<apiaxess_api_model::PresenceAssertion>>,
    requiredness: Option<(
        &String,
        &apiaxess_api_model::Fact<apiaxess_api_model::RequirednessAssertion>,
    )>,
    builder: &mut SchemaBuilder<'_>,
) -> Value {
    let mut parameter = Map::new();
    parameter.insert("name".to_owned(), Value::String(name.to_owned()));
    parameter.insert("in".to_owned(), Value::String(location.to_owned()));
    parameter.insert(
        "required".to_owned(),
        Value::Bool(required || location == "path"),
    );
    parameter.insert("schema".to_owned(), builder.schema_ref(schema, schema_path));
    parameter.insert(
        format!("{X_PREFIX}confidence"),
        json!({
            "presence": presence_path.map(|path| builder.confidence_extension(path)).or_else(|| presence.map(|_| json!({"status": "scored"}))).unwrap_or_else(|| json!({"score": 0.0, "status": "synthetic"})),
            "schema": builder.confidence_extension(&format!("{schema_path}.shape")),
            "requiredness": requiredness.map_or_else(|| json!({"score": null, "status": "not-applicable"}), |(path, _)| builder.confidence_extension(path))
        }),
    );
    parameter.insert(
        format!("{X_PREFIX}provenance"),
        builder.provenance_extension(&format!("{schema_path}.shape")),
    );
    if requiredness.is_some() {
        parameter.insert(
            format!("{X_PREFIX}requiredness"),
            Value::String(
                if required {
                    "required"
                } else {
                    "optional_or_inconclusive"
                }
                .to_owned(),
            ),
        );
    }
    Value::Object(parameter)
}

struct SchemaBuilder<'a> {
    surface: &'a UnifiedApiSurface,
    minimum_dynamic_samples: NonZeroU64,
    components: BTreeMap<String, Value>,
    used_names: BTreeSet<String>,
    names: BTreeMap<String, String>,
    diagnostics: &'a mut Vec<Diagnostic>,
}

impl<'a> SchemaBuilder<'a> {
    fn new(
        surface: &'a UnifiedApiSurface,
        minimum_dynamic_samples: NonZeroU64,
        diagnostics: &'a mut Vec<Diagnostic>,
    ) -> Self {
        Self {
            surface,
            minimum_dynamic_samples,
            components: BTreeMap::new(),
            used_names: BTreeSet::new(),
            names: BTreeMap::new(),
            diagnostics,
        }
    }

    fn schema_ref(&mut self, slot: &SchemaSlot, model_path: &str) -> Value {
        let name = self.component_name(model_path);
        if !self.components.contains_key(&name) {
            let value = self.schema_value(slot, model_path);
            self.components.insert(name.clone(), value);
        }
        json!({"$ref": format!("#/components/schemas/{name}"), "x-apiaxess-model-path": model_path})
    }

    fn schema_value(&mut self, slot: &SchemaSlot, model_path: &str) -> Value {
        let Some(selected) = slot.shape.selected_candidate() else {
            self.diagnostics.push(diagnostic(
                catalogue::OPENAPI_INVALID_INPUT,
                [
                    ("field", format!("{model_path}.shape")),
                    ("detail", "selected schema candidate is missing".to_owned()),
                ],
            ));
            return json!({"type": "object", "additionalProperties": true, "x-apiaxess-confidence": {"score": 0.0, "status": "invalid-input"}});
        };
        let selected_index = slot
            .shape
            .candidates
            .iter()
            .position(|candidate| candidate.id == selected.id)
            .unwrap_or(0);
        let shape_path = format!("{model_path}.shape.candidates[{selected_index}].value");
        let mut value = self.shape_value(&selected.value, &shape_path);
        if let Value::Object(object) = &mut value {
            object.insert(
                format!("{X_PREFIX}confidence"),
                self.confidence_extension(&format!("{model_path}.shape")),
            );
            object.insert(
                format!("{X_PREFIX}provenance"),
                self.provenance_extension(&format!("{model_path}.shape")),
            );
            object.insert(
                format!("{X_PREFIX}model-path"),
                Value::String(model_path.to_owned()),
            );
        }
        value
    }

    fn shape_value(&mut self, shape: &SchemaShape, shape_path: &str) -> Value {
        let mut value = match shape {
            SchemaShape::Unknown => json!({}),
            SchemaShape::Null => json!({"type": "null"}),
            SchemaShape::Boolean => json!({"type": "boolean"}),
            SchemaShape::Integer { format } => format_schema("integer", format.as_deref()),
            SchemaShape::Number { format } => format_schema("number", format.as_deref()),
            SchemaShape::String { format } => format_schema("string", format.as_deref()),
            SchemaShape::Array { items } => {
                json!({"type": "array", "items": self.schema_ref(items, &format!("{shape_path}.items"))})
            }
            SchemaShape::Object {
                properties,
                openness,
            } => {
                let mut object = Map::new();
                object.insert("type".to_owned(), Value::String("object".to_owned()));
                let mut property_map = Map::new();
                let mut required = Vec::new();
                for (index, property) in properties.iter().enumerate() {
                    let child_path = format!("{shape_path}.properties[{index}].schema");
                    let requiredness_path =
                        format!("{shape_path}.properties[{index}].requiredness");
                    let mut property_value = self.schema_ref(&property.schema, &child_path);
                    if let Value::Object(property_object) = &mut property_value {
                        property_object.insert(
                            format!("{X_PREFIX}confidence"),
                            self.confidence_extension(&child_path),
                        );
                        property_object.insert(
                            format!("{X_PREFIX}requiredness"),
                            self.requiredness_extension(&requiredness_path, &property.requiredness),
                        );
                    }
                    if matches!(
                        property
                            .requiredness
                            .assess_requiredness(self.minimum_dynamic_samples),
                        Ok(RequirednessAssessment::Required)
                    ) {
                        required.push(property.name.as_str().to_owned());
                    }
                    property_map.insert(property.name.as_str().to_owned(), property_value);
                }
                object.insert("properties".to_owned(), Value::Object(property_map));
                if !required.is_empty() {
                    object.insert(
                        "required".to_owned(),
                        Value::Array(required.into_iter().map(Value::String).collect()),
                    );
                }
                match openness {
                    ObjectOpenness::Open => {
                        object.insert("additionalProperties".to_owned(), Value::Bool(true));
                    }
                    ObjectOpenness::Closed => {
                        object.insert("additionalProperties".to_owned(), Value::Bool(false));
                    }
                    ObjectOpenness::Unknown => {
                        object.insert(
                            format!("{X_PREFIX}object-openness"),
                            Value::String("unknown".to_owned()),
                        );
                    }
                }
                Value::Object(object)
            }
            SchemaShape::Union { variants } => {
                let any_of = variants
                    .iter()
                    .enumerate()
                    .map(|(index, variant)| {
                        let variant_path = format!("{shape_path}.variants[{index}]");
                        let name = self.component_name(&variant_path);
                        if !self.components.contains_key(&name) {
                            let variant_value = self.shape_value(variant, &variant_path);
                            self.components.insert(name.clone(), variant_value);
                        }
                        json!({"$ref": format!("#/components/schemas/{name}"), "x-apiaxess-model-path": variant_path})
                    })
                    .collect::<Vec<_>>();
                json!({"anyOf": any_of})
            }
        };
        if let Value::Object(object) = &mut value {
            object.insert(
                format!("{X_PREFIX}shape-path"),
                Value::String(shape_path.to_owned()),
            );
            object.insert(
                format!("{X_PREFIX}shape-confidence"),
                self.confidence_extension(shape_path),
            );
        }
        value
    }

    fn component_name(&mut self, model_path: &str) -> String {
        if let Some(name) = self.names.get(model_path) {
            return name.clone();
        }
        let base = format!(
            "Schema_{}",
            model_path
                .chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() {
                        character
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        );
        if self.used_names.insert(base.clone()) {
            self.names.insert(model_path.to_owned(), base.clone());
            return base;
        }
        let mut index = 2_u32;
        loop {
            let candidate = format!("{base}_{index}");
            if self.used_names.insert(candidate.clone()) {
                self.names.insert(model_path.to_owned(), candidate.clone());
                return candidate;
            }
            index = index.saturating_add(1);
        }
    }

    fn fact_confidence(&self, path: &str) -> Option<&FactConfidence> {
        self.surface
            .confidence
            .facts
            .iter()
            .find(|fact| fact.path == path)
    }

    fn confidence_extension(&self, path: &str) -> Value {
        self.fact_confidence(path).map_or_else(
            || json!({"score": null, "status": "unscored", "model_path": path}),
            |fact| {
                json!({
                    "score": fact.score,
                    "sample_count": fact.sample_count,
                    "static_sample_count": fact.static_sample_count,
                    "dynamic_sample_count": fact.dynamic_sample_count,
                    "source_agreement": fact.source_agreement,
                    "merge_counts": fact.merge_counts,
                    "merge_case": merge_case(fact),
                    "model_path": fact.path
                })
            },
        )
    }

    fn provenance_extension(&self, path: &str) -> Value {
        self.fact_confidence(path).map_or_else(
            || json!({"sources": [], "evidence": [], "model_path": path}),
            |fact| {
                json!({
                    "sources": fact.sources.iter().map(|source| source_name(*source)).collect::<Vec<_>>(),
                    "evidence": fact.evidence,
                    "model_path": fact.path
                })
            },
        )
    }

    fn requiredness_extension(
        &self,
        path: &str,
        fact: &apiaxess_api_model::Fact<apiaxess_api_model::RequirednessAssertion>,
    ) -> Value {
        json!({
            "assessment": match fact.assess_requiredness(self.minimum_dynamic_samples) {
                Ok(RequirednessAssessment::Required) => "required",
                Ok(RequirednessAssessment::Optional) => "optional",
                Ok(RequirednessAssessment::Inconclusive) => "inconclusive",
                Err(_) => "invalid"
            },
            "confidence": self.confidence_extension(path)
        })
    }
}

fn format_schema(schema_type: &str, format: Option<&str>) -> Value {
    let mut value = Map::new();
    value.insert("type".to_owned(), Value::String(schema_type.to_owned()));
    if let Some(format) = format.filter(|format| !format.trim().is_empty()) {
        value.insert("format".to_owned(), Value::String(format.to_owned()));
    }
    Value::Object(value)
}

fn server_value(
    url: &str,
    model_path: &str,
    surface: &UnifiedApiSurface,
    diagnostics: &mut Vec<Diagnostic>,
) -> Value {
    if url.trim().is_empty() || url.chars().any(char::is_whitespace) {
        diagnostics.push(diagnostic(
            catalogue::OPENAPI_UNREPRESENTABLE,
            [
                ("field", model_path.to_owned()),
                (
                    "detail",
                    "base URL contains whitespace or is empty".to_owned(),
                ),
            ],
        ));
    }
    let mut server = Map::new();
    server.insert("url".to_owned(), Value::String(url.to_owned()));
    let confidence = surface
        .confidence
        .facts
        .iter()
        .find(|fact| fact.path == model_path);
    server.insert(
        format!("{X_PREFIX}confidence"),
        confidence.map_or_else(
            || json!({"score": null, "status": "unscored", "model_path": model_path}),
            |fact| {
                json!({
                    "score": fact.score,
                    "sample_count": fact.sample_count,
                    "merge_counts": fact.merge_counts,
                    "merge_case": merge_case(fact),
                    "model_path": fact.path
                })
            },
        ),
    );
    server.insert(
        format!("{X_PREFIX}provenance"),
        confidence.map_or_else(
            || json!({"sources": [], "evidence": [], "model_path": model_path}),
            |fact| {
                json!({
                    "sources": fact.sources.iter().map(|source| source_name(*source)).collect::<Vec<_>>(),
                    "evidence": fact.evidence,
                    "model_path": fact.path
                })
            },
        ),
    );
    Value::Object(server)
}

fn add_root_extensions(
    document: &mut Map<String, Value>,
    surface: &UnifiedApiSurface,
    diagnostics: &[Diagnostic],
) {
    let tally = surface.evidence_tally();
    document.insert(
        format!("{X_PREFIX}unified-surface-schema-version"),
        json!(surface.schema_version),
    );
    document.insert(
        format!("{X_PREFIX}assembly-run-id"),
        Value::String(surface.assembly_run_id.clone()),
    );
    document.insert(
        format!("{X_PREFIX}assembled-at"),
        Value::String(surface.assembled_at.to_rfc3339()),
    );
    document.insert(
        format!("{X_PREFIX}coverage"),
        json!({
            // Product vocabulary, as the GUI shows it: confirmed = observed in
            // live traffic; inferred = recovered from code only.
            "vocabulary": "confirmed = observed in live traffic; inferred = recovered from code only, not observed",
            "endpoint_count": tally.endpoints,
            "confirmed_endpoint_count": tally.confirmed,
            "also_in_code_endpoint_count": tally.also_in_code,
            "inferred_endpoint_count": tally.inferred,
            // The fusion split behind it: which sources agree on each endpoint.
            "fusion": {
                "static_and_dynamic_endpoint_count": surface.confidence.coverage.confirmed_endpoint_count,
                "dynamic_only_endpoint_count": surface.confidence.coverage.inferred_endpoint_count,
                "static_only_endpoint_count": surface.confidence.coverage.static_only_endpoint_count,
                "dynamic_ground_truth_endpoint_count": surface.confidence.coverage.dynamic_ground_truth_endpoint_count,
                "static_and_dynamic_basis_points": surface.confidence.coverage.confirmed_basis_points,
                "dynamic_only_basis_points": surface.confidence.coverage.inferred_basis_points,
                "static_only_basis_points": surface.confidence.coverage.static_only_basis_points
            },
            "handoff_count": surface.confidence.coverage.handoff_count,
            "resolved_handoff_count": surface.confidence.coverage.resolved_handoff_count,
            "open_handoff_count": surface.confidence.coverage.open_handoff_count,
            "low_confidence_fact_count": surface.confidence.coverage.low_confidence_fact_count,
            "true_conflict_fact_count": surface.confidence.coverage.true_conflict_fact_count,
            "handoffs": surface.confidence.handoffs
        }),
    );
    document.insert(
        format!("{X_PREFIX}provenance"),
        json!({
            "agent_count": surface.surface.provenance.agents.len(),
            "activity_count": surface.surface.provenance.activities.len(),
            "entity_count": surface.surface.provenance.entities.len(),
            "evidence_sidecar": "apiaxess-evidence.json"
        }),
    );
    document.insert(
        format!("{X_PREFIX}facts"),
        json!({
            "count": surface.confidence.facts.len(),
            "evidence_sidecar": "apiaxess-evidence.json"
        }),
    );
    document.insert(
        format!("{X_PREFIX}signers"),
        Value::Array(
            surface
                .surface
                .signers
                .iter()
                .map(|signer| signer_extension(signer, &surface.signer_bindings))
                .collect(),
        ),
    );
    document.insert(
        format!("{X_PREFIX}diagnostics"),
        json!({
            "count": diagnostics.len(),
            "surface_diagnostic_count": surface.diagnostics.len(),
            "evidence_sidecar": "apiaxess-evidence.json"
        }),
    );
    document.insert(
        format!("{X_PREFIX}loose-findings"),
        json!({
            "count": surface.surface.loose_findings.len(),
            "evidence_sidecar": "apiaxess-evidence.json"
        }),
    );
}

fn insert_path_extension(
    path_item: &mut Map<String, Value>,
    endpoint: &Endpoint,
    surface: &UnifiedApiSurface,
    model_path: &str,
) {
    let value = json!({
        "method": endpoint.identity.method.as_str(),
        "path_template": endpoint.identity.path_template.as_str(),
        "model_path": model_path,
        "confidence": endpoint_presence_confidence(surface, &endpoint.identity),
        "coverage": endpoint_coverage(surface, &endpoint.identity)
    });
    let key = format!("{X_PREFIX}endpoint");
    if let Some(Value::Array(endpoints)) = path_item.get_mut(&key) {
        endpoints.push(value);
    } else {
        path_item.insert(key, Value::Array(vec![value]));
    }
}

fn add_endpoint_extensions(
    operation: &mut Map<String, Value>,
    endpoint: &Endpoint,
    surface: &UnifiedApiSurface,
    model_path: &str,
) {
    operation.insert(
        format!("{X_PREFIX}confidence"),
        endpoint_presence_confidence(surface, &endpoint.identity),
    );
    operation.insert(
        format!("{X_PREFIX}provenance"),
        endpoint_presence_provenance(surface, &endpoint.identity),
    );
    operation.insert(
        format!("{X_PREFIX}coverage"),
        endpoint_coverage(surface, &endpoint.identity),
    );
    operation.insert(
        format!("{X_PREFIX}model-path"),
        Value::String(model_path.to_owned()),
    );
}

fn endpoint_presence_confidence(surface: &UnifiedApiSurface, identity: &EndpointIdentity) -> Value {
    surface
        .confidence
        .facts
        .iter()
        .find(|fact| fact.endpoint.as_ref() == Some(identity) && fact.path.ends_with(".presence"))
        .map_or_else(
            || json!({"score": null, "status": "unscored"}),
            |fact| {
                json!({
                    "score": fact.score,
                    "sample_count": fact.sample_count,
                    "merge_counts": fact.merge_counts,
                    "merge_case": merge_case(fact),
                    "model_path": fact.path
                })
            },
        )
}

fn endpoint_presence_provenance(surface: &UnifiedApiSurface, identity: &EndpointIdentity) -> Value {
    surface
        .confidence
        .facts
        .iter()
        .find(|fact| {
            fact.endpoint.as_ref() == Some(identity) && fact.path.ends_with(".presence")
        })
        .map_or_else(
            || json!({"sources": [], "evidence": []}),
            |fact| {
                json!({
                    "sources": fact.sources.iter().map(|source| source_name(*source)).collect::<Vec<_>>(),
                    "evidence": fact.evidence,
                    "model_path": fact.path
                })
            },
        )
}

fn endpoint_coverage(surface: &UnifiedApiSurface, identity: &EndpointIdentity) -> Value {
    let evidence = surface.endpoint_evidence(identity);
    let presence =
        surface.confidence.facts.iter().find(|fact| {
            fact.endpoint.as_ref() == Some(identity) && fact.path.ends_with(".presence")
        });
    let fusion = presence.map_or("unscored", |fact| {
        match (fact.static_sample_count > 0, fact.dynamic_sample_count > 0) {
            (true, true) => "static_and_dynamic",
            (false, true) => "dynamic_only",
            (true, false) => "static_only",
            (false, false) => "unscored",
        }
    });
    json!({
        "status": evidence.label(),
        "confirmed": evidence.observed,
        "also_in_code": evidence.in_code,
        "dynamic_ground_truth": evidence.observed,
        "fusion": fusion
    })
}

fn signer_extension(signer: &SignerArtifact, bindings: &[SignerBinding]) -> Value {
    let binding_targets = bindings
        .iter()
        .filter(|binding| binding.signer_id == signer.signer_id)
        .map(|binding| serde_json::to_value(&binding.target).unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    let key_source = signer.key_source.as_ref().map(|source| match source {
        SignerKeySource::CredentialReference {
            secret_ref,
            provider,
        } => {
            json!({"kind": "credential_reference", "secret_ref": secret_ref, "provider": provider})
        }
        SignerKeySource::DeviceOracle {
            callback_id,
            reason,
        } => json!({"kind": "device_oracle", "callback_id": callback_id, "reason": reason}),
        SignerKeySource::ExternalProvider { provider_ref } => {
            json!({"kind": "external_provider", "provider_ref": provider_ref})
        }
    });
    json!({
        "signer_id": signer.signer_id,
        "scheme": signer_scheme_name(&signer.scheme),
        "signer_mode": signer_mode_name(signer.signer_mode),
        "confidence": signer.confidence,
        "coverage": signer.coverage,
        "canonicalization": signer.canonicalization_steps.iter().map(|step| json!({"operation": canonicalization_name(&step.operation), "description": step.description, "source": source_name(step.source_type)})).collect::<Vec<_>>(),
        "primitive": signer.primitive.as_ref().map(primitive_name),
        "credential_boundary": key_source,
        "output": signer.output,
        "runtime": signer.runtime,
        "interface": signer.interface,
        "reproduction": signer.reproduction,
        "provenance": signer.provenance,
        "targets": binding_targets
    })
}

fn standard_security_scheme(
    authentication: &AuthenticationScheme,
) -> Option<(String, Value, bool)> {
    match authentication {
        AuthenticationScheme::None | AuthenticationScheme::Custom { .. } => None,
        AuthenticationScheme::Basic => Some((
            "basicAuth".to_owned(),
            json!({"type": "http", "scheme": "basic"}),
            true,
        )),
        AuthenticationScheme::Bearer { token_format } => Some((
            "bearerAuth".to_owned(),
            {
                let mut scheme = Map::new();
                scheme.insert("type".to_owned(), Value::String("http".to_owned()));
                scheme.insert("scheme".to_owned(), Value::String("bearer".to_owned()));
                if let Some(format) = token_format {
                    scheme.insert("bearerFormat".to_owned(), Value::String(format.clone()));
                }
                Value::Object(scheme)
            },
            true,
        )),
        AuthenticationScheme::ApiKey { location, name } => Some((
            format!(
                "apiKey_{}_{}",
                match location {
                    ApiKeyLocation::Header => "header",
                    ApiKeyLocation::Query => "query",
                },
                safe_name(name.as_str())
            ),
            json!({
                "type": "apiKey",
                "in": match location { ApiKeyLocation::Header => "header", ApiKeyLocation::Query => "query" },
                "name": name.as_str()
            }),
            true,
        )),
        AuthenticationScheme::OAuth2 { flows } => {
            let mut flow_map = Map::new();
            for flow in flows {
                match flow.to_ascii_lowercase().replace(['-', ' '], "_").as_str() {
                    "authorization_code" | "authorizationcode" => {
                        flow_map.insert(
                            "authorizationCode".to_owned(),
                            json!({"authorizationUrl": "https://example.invalid/oauth/authorize", "tokenUrl": "https://example.invalid/oauth/token", "scopes": {}}),
                        );
                    }
                    "client_credentials" | "clientcredentials" => {
                        flow_map.insert(
                            "clientCredentials".to_owned(),
                            json!({"tokenUrl": "https://example.invalid/oauth/token", "scopes": {}}),
                        );
                    }
                    "password" => {
                        flow_map.insert(
                            "password".to_owned(),
                            json!({"tokenUrl": "https://example.invalid/oauth/token", "scopes": {}}),
                        );
                    }
                    "implicit" => {
                        flow_map.insert(
                            "implicit".to_owned(),
                            json!({"authorizationUrl": "https://example.invalid/oauth/authorize", "scopes": {}}),
                        );
                    }
                    _ => {}
                }
            }
            if flow_map.is_empty() {
                return None;
            }
            let mut scheme = Map::new();
            scheme.insert("type".to_owned(), Value::String("oauth2".to_owned()));
            scheme.insert("flows".to_owned(), Value::Object(flow_map));
            Some(("oauth2Auth".to_owned(), Value::Object(scheme), false))
        }
    }
}

fn openapi_path(path: &str, model_path: &str, diagnostics: &mut Vec<Diagnostic>) -> Option<String> {
    if let Err(detail) = path_parameter_names(path) {
        diagnostics.push(diagnostic(
            catalogue::OPENAPI_UNREPRESENTABLE,
            [
                ("field", format!("{model_path}.identity.path_template")),
                ("detail", detail),
            ],
        ));
        return None;
    }
    Some(
        path.split('/')
            .map(|segment| {
                if let Some(name) = segment.strip_prefix(':') {
                    format!("{{{name}}}")
                } else if let Some(name) = segment.strip_prefix('*') {
                    format!("{{{name}}}")
                } else {
                    segment.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn path_parameter_names(path: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            return Err("path template contains an unmatched opening brace".to_owned());
        };
        let name = &after[..end];
        if name.is_empty()
            || name
                .chars()
                .any(|character| matches!(character, '{' | '}' | '/'))
        {
            return Err(format!("path template contains invalid parameter {name}"));
        }
        if names.iter().any(|existing| existing == name) {
            return Err(format!("path template repeats parameter {name}"));
        }
        names.push(name.to_owned());
        rest = &after[end + 1..];
    }
    for segment in path
        .split('/')
        .filter(|segment| segment.starts_with(':') || segment.starts_with('*'))
    {
        let name = segment[1..].to_owned();
        if name.is_empty()
            || name
                .chars()
                .any(|character| matches!(character, '{' | '}' | ':' | '*'))
        {
            return Err(format!("path template contains invalid parameter {name}"));
        }
        if names.iter().any(|existing| existing == &name) {
            return Err(format!("path template repeats parameter {name}"));
        }
        names.push(name);
    }
    Ok(names)
}

fn response_key(selector: ResponseSelector) -> String {
    match selector {
        ResponseSelector::Exact(status) => status.to_string(),
        ResponseSelector::Class(class) => format!("{class}XX"),
        ResponseSelector::Default => "default".to_owned(),
    }
}

fn parameter_schema_path(base: &str, collection: &str, index: usize, field: &str) -> String {
    format!("{base}.{collection}[{index}].{field}")
}

fn parameter_sort_key(value: &Value) -> String {
    format!(
        "{}:{}",
        value.get("in").and_then(Value::as_str).unwrap_or_default(),
        value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
    )
}

fn set_operation_id(mut operation: Value, operation_id: String) -> Value {
    if let Value::Object(object) = &mut operation {
        object.insert("operationId".to_owned(), Value::String(operation_id));
    }
    operation
}

/// Records one more host serving an already-emitted operation: in the
/// `x-apiaxess-hosts` extension, and as an operation-level server when the
/// endpoint's base URL carries a scheme.
fn add_operation_host(
    operation: &mut Map<String, Value>,
    claimed: Option<&str>,
    claimed_base: Option<&str>,
    endpoint: &Endpoint,
) {
    let hosts = operation
        .entry(format!("{X_PREFIX}hosts"))
        .or_insert_with(|| json!(claimed.into_iter().collect::<Vec<_>>()));
    if let (Value::Array(hosts), Some(host)) = (hosts, endpoint.identity.host.as_deref()) {
        if !hosts.iter().any(|value| value == host) {
            hosts.push(Value::String(host.to_owned()));
        }
    }
    let base = endpoint
        .base_url
        .as_ref()
        .and_then(|fact| fact.selected_candidate())
        .map(|candidate| candidate.value.clone())
        .filter(|value| value.contains("://"));
    if let Some(base) = base {
        // The operation keeps the origin that first claimed it alongside the
        // new one, so neither host is dropped from its servers.
        let servers = operation.entry("servers".to_owned()).or_insert_with(|| {
            Value::Array(
                claimed_base
                    .map(|claimed| json!({"url": claimed}))
                    .into_iter()
                    .collect(),
            )
        });
        if let Value::Array(servers) = servers {
            if !servers.iter().any(|server| server["url"] == base.as_str()) {
                servers.push(json!({"url": base}));
            }
        }
    }
}

fn graphql_type_name(operation_type: GraphQlOperationType) -> &'static str {
    match operation_type {
        GraphQlOperationType::Query => "query",
        GraphQlOperationType::Mutation => "mutation",
        GraphQlOperationType::Subscription => "subscription",
    }
}

fn operation_id(identity: &EndpointIdentity) -> String {
    format!(
        "{}_{}",
        identity.method.as_str().to_ascii_lowercase(),
        safe_name(identity.path_template.as_str())
    )
}

fn safe_name(value: &str) -> String {
    let result = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if result.is_empty() {
        "value".to_owned()
    } else {
        result
    }
}

fn is_standard_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "PUT" | "POST" | "DELETE" | "OPTIONS" | "HEAD" | "PATCH" | "TRACE"
    )
}

fn source_name(source: SourceType) -> &'static str {
    match source {
        SourceType::StaticAnalysis => "static_analysis",
        SourceType::DynamicCapture => "dynamic_capture",
        SourceType::Fusion => "fusion",
    }
}

fn merge_case(fact: &FactConfidence) -> &'static str {
    if fact.merge_counts.true_conflict > 0 {
        "conflict"
    } else if fact.merge_counts.refinement > 0 {
        "refinement"
    } else if fact.merge_counts.gap_fill > 0 {
        "gap_fill"
    } else if fact.merge_counts.agreement > 0 {
        "agreement"
    } else {
        "unclassified"
    }
}

fn signer_mode_name(mode: SignerMode) -> &'static str {
    match mode {
        SignerMode::Reproducible => "reproducible",
        SignerMode::PartialHypothesis => "partial_hypothesis",
        SignerMode::ObservedOnly => "observed_only",
        SignerMode::DeviceOracle => "device_oracle",
    }
}

fn signer_scheme_name(scheme: &SignerScheme) -> String {
    serde_json::to_value(scheme)
        .ok()
        .and_then(|value| value.get("kind").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| "unrecognized".to_owned())
}

fn primitive_name(primitive: &SignerPrimitive) -> Value {
    serde_json::to_value(primitive).unwrap_or(Value::Null)
}

fn canonicalization_name(operation: &apiaxess_api_model::CanonicalizationOperation) -> String {
    serde_json::to_value(operation)
        .ok()
        .and_then(|value| {
            value
                .get("operation")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_api_model::{
        Activity, ActivityId, Agent, AgentId, AgentKind, ApiSurface, CONFIDENCE_SCHEMA_VERSION,
        ConfidenceSummary, CoveragePicture, ProvenanceRegistry, UNIFIED_SURFACE_SCHEMA_VERSION,
    };
    use chrono::Utc;

    #[test]
    fn path_parameter_conversion_is_openapi_shaped() {
        assert_eq!(
            openapi_path("/users/:id", "endpoint", &mut Vec::new()).as_deref(),
            Some("/users/{id}")
        );
        assert!(path_parameter_names("/users/{id").is_err());
    }

    #[test]
    fn standard_auth_mapping_only_uses_valid_scheme_shapes() {
        let (_, bearer, clean) = standard_security_scheme(&AuthenticationScheme::Bearer {
            token_format: Some("JWT".to_owned()),
        })
        .expect("bearer");
        assert!(clean);
        assert_eq!(bearer["type"], "http");
        assert!(
            standard_security_scheme(&AuthenticationScheme::Custom {
                scheme: "x-signature".to_owned(),
            })
            .is_none()
        );
    }

    fn empty_surface() -> UnifiedApiSurface {
        let at = Utc::now();
        let agent = AgentId::new("agent:test").expect("agent");
        let activity = ActivityId::new("activity:confidence").expect("activity");
        let run = apiaxess_api_model::RunId::new("run:confidence").expect("run");
        let provenance = ProvenanceRegistry {
            agents: vec![Agent {
                id: agent.clone(),
                kind: AgentKind::Engine,
                name: "test".to_owned(),
                version: None,
            }],
            activities: vec![Activity {
                id: activity.clone(),
                run_id: run,
                agent,
                source_type: SourceType::Fusion,
                started_at: at,
                ended_at: Some(at),
            }],
            entities: vec![],
        };
        UnifiedApiSurface {
            schema_version: UNIFIED_SURFACE_SCHEMA_VERSION,
            assembly_run_id: "run:assembly".to_owned(),
            assembled_at: at,
            surface: ApiSurface {
                provenance,
                endpoints: vec![],
                protocol_operations: vec![],
                loose_findings: vec![],
                signers: vec![],
            },
            confidence: ConfidenceSummary {
                schema_version: CONFIDENCE_SCHEMA_VERSION,
                run_id: "run:confidence-summary".to_owned(),
                computed_by: activity,
                computed_at: at,
                facts: vec![],
                handoffs: vec![],
                coverage: CoveragePicture::default(),
                diagnostics: vec![],
            },
            endpoints: vec![],
            signer_bindings: vec![],
            diagnostics: vec![],
        }
    }

    #[test]
    fn emission_is_deterministic_and_has_required_openapi_root() {
        let surface = empty_surface();
        let first = OpenApiEmitter::default().emit(&surface).expect("emission");
        let second = OpenApiEmitter::default().emit(&surface).expect("emission");
        assert_eq!(
            serde_json::to_vec(&first.document).expect("json"),
            serde_json::to_vec(&second.document).expect("json")
        );
        assert_eq!(first.document["openapi"], OPENAPI_VERSION);
        assert_eq!(first.document["info"]["title"], "APIaxess recovered API");
        assert!(first.document["paths"].is_object());
        assert!(first.document["x-apiaxess-coverage"].is_object());
    }
}
