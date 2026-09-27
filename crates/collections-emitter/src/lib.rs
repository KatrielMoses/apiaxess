//! Deterministic Postman Collection v2.1 and HAR emission from the unified
//! API surface.
//!
//! Collections are usable request sets. HAR is deliberately limited to
//! request material preserved in signer fixtures; schema facts are never
//! presented as captured traffic.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use apiaxess_api_model::{
    ApiKeyLocation, AuthenticationScheme, CanonicalizationOperation, CapturedGraphQlOperation,
    Endpoint, EndpointIdentity, GraphQlOperationType, RequestEncoding, SchemaShape, SchemaSlot,
    SignerArtifact, SignerFixture, SignerMode, SignerPrimitive, UnifiedApiSurface,
    captured_graphql_operations, endpoint_base_url, is_transport_header,
};
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Map, Value, json};

/// Default collection variable used for an unresolved target base URL.
pub const DEFAULT_BASE_URL: &str = "https://target.example";

/// Configuration for deterministic Postman/HAR emission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionsEmitter {
    /// Collection title.
    pub name: String,
}

impl Default for CollectionsEmitter {
    fn default() -> Self {
        Self {
            name: "APIaxess recovered API".to_owned(),
        }
    }
}

impl CollectionsEmitter {
    /// Creates an emitter with an explicit collection title.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Emits a deterministic Postman Collection v2.1.
    ///
    /// # Errors
    ///
    /// Returns diagnostics when the unified surface is invalid or the
    /// collection name is blank.
    ///
    /// # Panics
    ///
    /// Panics only if the internally constructed JSON document cannot be
    /// serialized, which would indicate a programming error.
    pub fn emit_collection(
        &self,
        surface: &UnifiedApiSurface,
    ) -> Result<PostmanEmission, Vec<Diagnostic>> {
        let mut diagnostics = validate_input(surface)?;
        if self.name.trim().is_empty() {
            diagnostics.push(diagnostic(
                catalogue::COLLECTIONS_INVALID_INPUT,
                [
                    ("field", "name".to_owned()),
                    ("detail", "collection name must not be blank".to_owned()),
                ],
            ));
            return Err(diagnostics);
        }

        let mut variables = BTreeMap::new();
        // Each request is sent to its own endpoint's origin: `baseUrl` is the
        // origin most endpoints share, and every other origin (a third-party
        // host, a second backend) gets its own variable.
        let primary_base = surface.primary_base_url();
        variables.insert(
            "baseUrl".to_owned(),
            json!({
                "key": "baseUrl",
                "value": primary_base.clone().unwrap_or_else(|| DEFAULT_BASE_URL.to_owned()),
                "type": "string",
                "description": "Origin of the primary API (most endpoints). Change it to target another deployment."
            }),
        );
        let mut items = Vec::new();
        let mut diagnosed_signers = BTreeSet::new();
        let mut endpoints = surface.surface.endpoints.iter().collect::<Vec<_>>();
        endpoints.sort_by(|left, right| left.identity.cmp(&right.identity));

        for endpoint in endpoints {
            let identity = &endpoint.identity;
            let signers = surface.signers_for(identity);
            for signer in &signers {
                variables
                    .entry(signer_env_name(signer))
                    .or_insert_with(|| {
                        json!({
                            "key": signer_env_name(signer),
                            "value": "",
                            "type": "string",
                            "description": format!("Runtime credential for signer {}; set in the active Postman environment; intentionally empty here.", signer.signer_id)
                        })
                    });
                if diagnosed_signers.insert(signer.signer_id.clone()) {
                    if let Some(signer_diagnostic) = signer_diagnostic(signer) {
                        diagnostics.push(signer_diagnostic);
                    }
                }
            }
            let base_variable = origin_variable(endpoint, primary_base.as_deref(), &mut variables);
            let requests =
                postman_requests(endpoint, surface, &signers, &base_variable, &mut variables);
            let mut folder = Map::new();
            folder.insert(
                "name".to_owned(),
                Value::String(format!(
                    "{} {}",
                    identity.method.as_str(),
                    identity.path_template.as_str()
                )),
            );
            folder.insert(
                "description".to_owned(),
                Value::String(endpoint_description(surface, identity, &signers)),
            );
            folder.insert("item".to_owned(), Value::Array(requests));
            items.push(Value::Object(folder));
        }

        // gRPC-Web methods, each as the HTTP call it is.
        for grpc in surface.grpc_operations() {
            items.push(grpc_folder(&grpc, primary_base.as_deref(), &mut variables));
        }

        let document = json!({
            "info": {
                "name": self.name,
                "description": format!("Generated by APIaxess. Surface: {}. Confidence and signer honesty are preserved in request descriptions and scripts. Values marked as placeholders were generated from the recovered schema, not captured.", surface.evidence_tally().describe()),
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "variable": variables.into_values().collect::<Vec<_>>(),
            "item": items
        });
        let json_text = serde_json::to_string_pretty(&document)
            .expect("Postman document contains only serializable JSON values");
        Ok(PostmanEmission {
            document,
            json: json_text,
            diagnostics,
        })
    }

    /// Emits HAR 1.2 from request material preserved in signer fixtures.
    ///
    /// # Errors
    ///
    /// Returns diagnostics when the unified surface is invalid.
    ///
    /// # Panics
    ///
    /// Panics only if the internally constructed JSON document cannot be
    /// serialized, which would indicate a programming error.
    pub fn emit_har(&self, surface: &UnifiedApiSurface) -> Result<HarEmission, Vec<Diagnostic>> {
        let mut diagnostics = validate_input(surface)?;
        let mut fixtures = Vec::new();
        for signer in &surface.surface.signers {
            fixtures.extend(signer.fixtures.iter().map(|fixture| (signer, fixture)));
        }
        fixtures.sort_by(|left, right| {
            left.1
                .capture_id
                .cmp(&right.1.capture_id)
                .then_with(|| left.0.signer_id.cmp(&right.0.signer_id))
        });

        let entries = fixtures
            .iter()
            .enumerate()
            .map(|(index, (signer, fixture))| har_entry(surface, index, signer, fixture))
            .collect::<Vec<_>>();
        if entries.is_empty() {
            diagnostics.push(diagnostic(
                catalogue::COLLECTIONS_NO_CAPTURED_TRAFFIC,
                [
                    ("field", "surface.signers[*].fixtures".to_owned()),
                    (
                        "detail",
                        "no preserved signer request fixtures were available".to_owned(),
                    ),
                ],
            ));
        }
        let document = json!({
            "log": {
                "version": "1.2",
                "creator": {"name": "APIaxess", "version": "0.1.0"},
                "entries": entries
            }
        });
        let json_text = serde_json::to_string_pretty(&document)
            .expect("HAR document contains only serializable JSON values");
        Ok(HarEmission {
            document,
            json: json_text,
            diagnostics,
        })
    }

    /// Emits both artifacts from one validated surface.
    ///
    /// # Errors
    ///
    /// Returns diagnostics when the unified surface is invalid.
    pub fn emit(
        &self,
        surface: &UnifiedApiSurface,
    ) -> Result<CollectionsEmission, Vec<Diagnostic>> {
        let collection = self.emit_collection(surface)?;
        let har = self.emit_har(surface).map_err(|mut errors| {
            errors.extend(collection.diagnostics.clone());
            errors
        })?;
        let mut diagnostics = collection.diagnostics.clone();
        diagnostics.extend(har.diagnostics.clone());
        Ok(CollectionsEmission {
            collection,
            har,
            diagnostics,
        })
    }
}

/// Emitted Postman collection document and diagnostics.
#[derive(Clone, Debug, PartialEq)]
pub struct PostmanEmission {
    /// Parsed v2.1 JSON document.
    pub document: Value,
    /// Stable pretty JSON representation.
    pub json: String,
    /// Non-fatal honesty diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Emitted HAR document and diagnostics.
#[derive(Clone, Debug, PartialEq)]
pub struct HarEmission {
    /// Parsed HAR JSON document.
    pub document: Value,
    /// Stable pretty JSON representation.
    pub json: String,
    /// Non-fatal honesty diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Both Phase 6.3 artifacts from one surface.
#[derive(Clone, Debug, PartialEq)]
pub struct CollectionsEmission {
    /// Postman collection.
    pub collection: PostmanEmission,
    /// HAR export.
    pub har: HarEmission,
    /// Combined diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

fn validate_input(surface: &UnifiedApiSurface) -> Result<Vec<Diagnostic>, Vec<Diagnostic>> {
    surface.validate().map(|()| Vec::new()).map_err(|error| {
        vec![diagnostic(
            catalogue::COLLECTIONS_INVALID_INPUT,
            [
                ("field", "unified".to_owned()),
                ("detail", error.to_string()),
            ],
        )]
    })
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

/// A gRPC-Web method as a collection folder. The protobuf message is not
/// reconstructable without the .proto, so the body is a binary file the
/// operator supplies, and the description says so. A method known only from
/// code has no origin to address, so its folder carries no request.
fn grpc_folder(
    grpc: &apiaxess_api_model::ExportableGrpcOperation,
    primary_base: Option<&str>,
    variables: &mut BTreeMap<String, Value>,
) -> Value {
    let mut folder = Map::new();
    folder.insert(
        "name".to_owned(),
        Value::String(format!("gRPC {}/{}", grpc.service, grpc.method)),
    );
    let Some(base) = grpc.base_url.clone() else {
        folder.insert(
            "description".to_owned(),
            Value::String(format!(
                "gRPC method {}/{} — {}. Its origin is unknown (it was never observed being called), so no request is generated.",
                grpc.service,
                grpc.method,
                grpc.evidence.describe()
            )),
        );
        folder.insert("item".to_owned(), Value::Array(Vec::new()));
        return Value::Object(folder);
    };
    let variable = origin_variable_for(Some(base), primary_base, variables);
    let description = format!(
        "gRPC-Web call to {}/{} — {}. The body is one length-prefixed protobuf message; its schema is not recoverable without the service's .proto, so attach the binary message (a captured one works) as the body. The outcome is in the grpc-status trailer.",
        grpc.service,
        grpc.method,
        grpc.evidence.describe()
    );
    folder.insert("description".to_owned(), Value::String(description.clone()));
    let segments: Vec<Value> = [grpc.service.clone(), grpc.method.clone()]
        .into_iter()
        .map(Value::String)
        .collect();
    folder.insert(
        "item".to_owned(),
        json!([{
            "name": format!("{}/{}", grpc.service, grpc.method),
            "request": {
                "method": "POST",
                "description": description,
                "header": [
                    {"key": "content-type", "value": "application/grpc-web+proto"},
                    {"key": "x-grpc-web", "value": "1"}
                ],
                "body": {"mode": "file", "file": {"src": ""}},
                "url": {
                    "raw": format!("{{{{{variable}}}}}{}", grpc.path()),
                    "host": [format!("{{{{{variable}}}}}")],
                    "path": segments
                }
            }
        }]),
    );
    Value::Object(folder)
}

/// The collection variable an endpoint's requests are sent to: `baseUrl` for
/// the primary origin, otherwise a variable of its own origin (added once).
fn origin_variable(
    endpoint: &Endpoint,
    primary_base: Option<&str>,
    variables: &mut BTreeMap<String, Value>,
) -> String {
    origin_variable_for(endpoint_base_url(endpoint), primary_base, variables)
}

/// The collection variable for requests served from `base` (see
/// [`origin_variable`]).
fn origin_variable_for(
    base: Option<String>,
    primary_base: Option<&str>,
    variables: &mut BTreeMap<String, Value>,
) -> String {
    match base {
        Some(base) if primary_base != Some(base.as_str()) => {
            let key = format!(
                "baseUrl_{}",
                safe_name(
                    base.split_once("://")
                        .map_or(base.as_str(), |(_, rest)| rest)
                )
            );
            variables.entry(key.clone()).or_insert_with(|| {
                json!({
                    "key": key,
                    "value": base,
                    "type": "string",
                    "description": format!("Origin of the endpoints served from {base} (not the primary API).")
                })
            });
            key
        }
        _ => "baseUrl".to_owned(),
    }
}

/// The requests for one endpoint: one per GraphQL operation it was seen
/// running (with the captured document), otherwise one request.
fn postman_requests(
    endpoint: &Endpoint,
    surface: &UnifiedApiSurface,
    signers: &[&SignerArtifact],
    base_variable: &str,
    variables: &mut BTreeMap<String, Value>,
) -> Vec<Value> {
    let graphql = captured_graphql_operations(endpoint);
    if graphql.is_empty() {
        return vec![postman_request(
            endpoint,
            surface,
            signers,
            base_variable,
            None,
            variables,
        )];
    }
    graphql
        .iter()
        .map(|operation| {
            postman_request(
                endpoint,
                surface,
                signers,
                base_variable,
                Some(operation),
                variables,
            )
        })
        .collect()
}

// This linear builder keeps the emitted Postman field ordering easy to audit.
#[allow(clippy::too_many_lines)]
fn postman_request(
    endpoint: &Endpoint,
    surface: &UnifiedApiSurface,
    signers: &[&SignerArtifact],
    base_variable: &str,
    graphql: Option<&CapturedGraphQlOperation>,
    variables: &mut BTreeMap<String, Value>,
) -> Value {
    let path = postman_path(endpoint.identity.path_template.as_str());
    let raw = format!("{{{{{base_variable}}}}}{path}");
    let mut url = Map::new();
    url.insert("raw".to_owned(), Value::String(raw));
    url.insert(
        "host".to_owned(),
        json!([format!("{{{{{base_variable}}}}}")]),
    );
    url.insert(
        "path".to_owned(),
        Value::Array(
            path.trim_start_matches('/')
                .split('/')
                .filter(|segment| !segment.is_empty())
                .map(|segment| Value::String(segment.to_owned()))
                .collect(),
        ),
    );
    let mut query = Vec::new();
    let mut query_parameters = endpoint.query_parameters.iter().collect::<Vec<_>>();
    query_parameters.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
    for parameter in query_parameters {
        query.push(json!({
            "key": parameter.name.as_str(),
            "value": "example",
            "description": format!("Placeholder value (not captured); replace before sending. {}", parameter_confidence(surface, endpoint, parameter.name.as_str()))
        }));
    }
    if !query.is_empty() {
        url.insert("query".to_owned(), Value::Array(query));
    }

    let mut headers = Vec::new();
    // Transport and browser mechanics are not parameters a caller supplies
    // (an empty Host or Content-Length variable would break the request);
    // Content-Type is set from the body below and Postman sends its own Accept.
    let mut endpoint_headers = endpoint
        .headers
        .iter()
        .filter(|header| {
            let name = header.name.as_str();
            !is_transport_header(name)
                && !name.eq_ignore_ascii_case("content-type")
                && !name.eq_ignore_ascii_case("accept")
        })
        .collect::<Vec<_>>();
    endpoint_headers.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
    for header in endpoint_headers {
        let value = format!("{{{{{}}}}}", safe_name(header.name.as_str()));
        variables.entry(safe_name(header.name.as_str())).or_insert_with(|| {
            json!({
                "key": safe_name(header.name.as_str()),
                "value": "",
                "type": "string",
                "description": "Request header placeholder; provide a value in the active environment."
            })
        });
        headers.push(json!({
            "key": header.name.as_str(),
            "value": value,
            "type": "text",
            "description": parameter_confidence(surface, endpoint, header.name.as_str())
        }));
    }
    // The body's own media type; Postman writes a multipart boundary itself,
    // and an unobserved media type is not assumed.
    let encoding = RequestEncoding::of(endpoint);
    let content_type = if graphql.is_some() {
        Some("application/json")
    } else {
        match &encoding {
            RequestEncoding::Multipart(_) | RequestEncoding::Unknown => None,
            other => other.media_type(),
        }
    };
    if let Some(content_type) = content_type.filter(|_| endpoint.request_body.is_some()) {
        if !headers.iter().any(|header| {
            header
                .get("key")
                .and_then(Value::as_str)
                .is_some_and(|key| key.eq_ignore_ascii_case("content-type"))
        }) {
            headers.push(json!({"key": "Content-Type", "value": content_type, "type": "text"}));
        }
    }

    let mut request = Map::new();
    request.insert(
        "name".to_owned(),
        Value::String(graphql.map_or_else(
            || {
                format!(
                    "{} {}",
                    endpoint.identity.method.as_str(),
                    endpoint.identity.path_template.as_str()
                )
            },
            |operation| {
                format!(
                    "{} {}",
                    graphql_type_name(operation.operation_type),
                    operation.name
                )
            },
        )),
    );
    let mut description = endpoint_description(surface, &endpoint.identity, signers);
    request.insert(
        "request".to_owned(),
        {
            let mut request_data = Map::new();
            request_data.insert(
                "method".to_owned(),
                Value::String(endpoint.identity.method.as_str().to_owned()),
            );
            request_data.insert("header".to_owned(), Value::Array(headers));
            if let Some(operation) = graphql {
                // The operation as captured: its document and variables.
                request_data.insert("body".to_owned(), json!({
                    "mode": "graphql",
                    "graphql": {
                        "query": operation.query,
                        "variables": serde_json::to_string_pretty(&operation.variables).expect("captured variables are JSON")
                    }
                }));
                let _ = write!(
                    description,
                    "
Body: GraphQL {} {} with its document and variables as captured.",
                    graphql_type_name(operation.operation_type),
                    operation.name
                );
            } else if let Some(slot) = endpoint.request_body.as_ref() {
                let (body, note) = postman_body(slot, &encoding);
                request_data.insert("body".to_owned(), body);
                description.push_str(note);
            }
            request_data.insert("url".to_owned(), Value::Object(url));
            request_data.insert("description".to_owned(), Value::String(description));
            if let Some(auth) = native_auth(
                endpoint
                    .authentication
                    .as_ref()
                    .and_then(|fact| fact.selected_candidate())
                    .map(|candidate| &candidate.value),
            ) {
                request_data.insert("auth".to_owned(), auth);
            }
            Value::Object(request_data)
        },
    );
    let events = signers
        .iter()
        .map(|signer| signer_event(signer))
        .collect::<Vec<_>>();
    if !events.is_empty() {
        request.insert("event".to_owned(), Value::Array(events));
    }
    Value::Object(request)
}

fn endpoint_description(
    surface: &UnifiedApiSurface,
    identity: &EndpointIdentity,
    signers: &[&SignerArtifact],
) -> String {
    let mut lines = vec![
        format!(
            "APIaxess endpoint: {} {}",
            identity.method.as_str(),
            identity.path_template.as_str()
        ),
        format!(
            "Evidence: {}",
            surface.endpoint_evidence(identity).describe()
        ),
        format!(
            "Confidence: {:.3} endpoint-average",
            endpoint_confidence(surface, identity)
        ),
    ];
    if signers.is_empty() {
        lines.push(
            "Authentication: no recovered signer binding; review endpoint auth metadata."
                .to_owned(),
        );
    } else {
        for signer in signers {
            lines.push(format!(
                "Signer {}: {:?}",
                signer.signer_id, signer.signer_mode
            ));
        }
    }
    lines.join("\n")
}

/// A request body in the Postman mode its encoding calls for, with the note
/// that says which values are placeholders.
fn postman_body(slot: &SchemaSlot, encoding: &RequestEncoding) -> (Value, &'static str) {
    const PLACEHOLDERS: &str = "\nBody: placeholder values generated from the recovered schema (strings \"example\", numbers 0, booleans false), not captured data. Replace them before sending.";
    let example = schema_example(slot);
    let fields = || {
        example
            .as_object()
            .map(|object| {
                object
                    .keys()
                    .map(|key| json!({"key": key, "value": "example", "type": "text", "description": "Placeholder value (not captured)."}))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let raw_json = || serde_json::to_string_pretty(&example).expect("example JSON is serializable");
    match encoding {
        RequestEncoding::Json(_) => (
            json!({"mode": "raw", "raw": raw_json(), "options": {"raw": {"language": "json"}}}),
            PLACEHOLDERS,
        ),
        // JSON-shaped text sent as a text media type (beacons): the JSON is
        // kept, but labelled as the text it is sent as, so Postman does not
        // present (or send) it as application/json.
        RequestEncoding::TextJson(_) => (
            json!({"mode": "raw", "raw": raw_json(), "options": {"raw": {"language": "text"}}}),
            PLACEHOLDERS,
        ),
        RequestEncoding::Form(_) => (
            json!({"mode": "urlencoded", "urlencoded": fields()}),
            PLACEHOLDERS,
        ),
        RequestEncoding::Multipart(_) => (
            json!({"mode": "formdata", "formdata": fields()}),
            PLACEHOLDERS,
        ),
        RequestEncoding::Text(_) => (
            json!({"mode": "raw", "raw": "example", "options": {"raw": {"language": "text"}}}),
            "\nBody: placeholder text, not captured data. Replace it before sending.",
        ),
        RequestEncoding::Binary(_) => (
            json!({"mode": "file", "file": {"src": ""}}),
            "\nBody: binary; choose the file to send.",
        ),
        RequestEncoding::Unknown => (
            json!({"mode": "raw", "raw": raw_json()}),
            "\nBody: the request media type was not observed, so no Content-Type is set; the body shows the recovered fields as placeholder values (not captured data).",
        ),
    }
}

fn graphql_type_name(operation_type: GraphQlOperationType) -> &'static str {
    match operation_type {
        GraphQlOperationType::Query => "query",
        GraphQlOperationType::Mutation => "mutation",
        GraphQlOperationType::Subscription => "subscription",
    }
}

// Confidence scores are averaged in the model's f64 output domain; arbitrary
// usize cardinalities cannot be represented exactly by f64.
#[allow(clippy::cast_precision_loss)]
fn endpoint_confidence(surface: &UnifiedApiSurface, identity: &EndpointIdentity) -> f64 {
    let scores = surface
        .confidence
        .facts
        .iter()
        .filter(|fact| fact.endpoint.as_ref() == Some(identity))
        .map(|fact| fact.score)
        .collect::<Vec<_>>();
    if scores.is_empty() {
        0.0
    } else {
        scores.iter().sum::<f64>() / scores.len() as f64
    }
}

fn parameter_confidence(surface: &UnifiedApiSurface, endpoint: &Endpoint, name: &str) -> String {
    let path = surface
        .surface
        .endpoints
        .iter()
        .position(|candidate| candidate.identity == endpoint.identity)
        .map_or_else(
            || format!("endpoint parameter {name}"),
            |index| format!("endpoints[{index}] parameter {name}"),
        );
    surface
        .confidence
        .facts
        .iter()
        .find(|fact| {
            fact.path.contains(&path)
                && fact
                    .path
                    .to_ascii_lowercase()
                    .contains(&name.to_ascii_lowercase())
        })
        .map_or_else(
            || "confidence unscored".to_owned(),
            |fact| format!("confidence {:.3}", fact.score),
        )
}

fn native_auth(authentication: Option<&AuthenticationScheme>) -> Option<Value> {
    match authentication {
        Some(AuthenticationScheme::Basic) => Some(json!({"type": "basic", "basic": [
            {"key": "username", "value": "{{username}}", "type": "string"},
            {"key": "password", "value": "{{password}}", "type": "string"}
        ]})),
        Some(AuthenticationScheme::Bearer { .. }) => Some(json!({"type": "bearer", "bearer": [
            {"key": "token", "value": "{{bearerToken}}", "type": "string"}
        ]})),
        Some(AuthenticationScheme::ApiKey { location, name }) => {
            Some(json!({"type": "apikey", "apikey": [
                {"key": "key", "value": name.as_str(), "type": "string"},
                {"key": "value", "value": format!("{{{{{}}}}}", safe_name(name.as_str())), "type": "string"},
                {"key": "in", "value": match location { ApiKeyLocation::Header => "header", ApiKeyLocation::Query => "query" }, "type": "string"}
            ]}))
        }
        Some(AuthenticationScheme::OAuth2 { .. }) => Some(json!({"type": "oauth2", "oauth2": [
            {"key": "accessToken", "value": "{{oauth2Token}}", "type": "string"},
            {"key": "addTokenTo", "value": "header", "type": "string"}
        ]})),
        Some(AuthenticationScheme::None | AuthenticationScheme::Custom { .. }) | None => None,
    }
}

fn signer_env_name(signer: &SignerArtifact) -> String {
    format!("apiaxess_{}_key", safe_name(&signer.signer_id))
}

fn js_comment(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

fn signer_event(signer: &SignerArtifact) -> Value {
    let script = match signer_script(signer) {
        Ok(lines) => lines,
        Err(review) => review,
    };
    json!({
        "listen": "prerequest",
        "script": {
            "type": "text/javascript",
            "exec": script
        }
    })
}

fn signer_script(signer: &SignerArtifact) -> Result<Vec<String>, Vec<String>> {
    match signer.signer_mode {
        SignerMode::Reproducible => {
            if !matches!(
                signer.primitive,
                Some(SignerPrimitive::Hmac { .. } | SignerPrimitive::Digest { .. })
            ) {
                return Err(review_script(signer, "The Postman sandbox emitter supports HMAC and digest primitives; this reproducible primitive needs an external signer."));
            }
            let mut lines = vec![
                format!("// APIaxess reproducible signer: {}", signer.signer_id),
                format!("// Credential source: pm.environment.get({:?}); no key is embedded.", signer_env_name(signer)),
                "const credential = pm.environment.get(".to_owned() + &format!("{:?}", signer_env_name(signer)) + ");",
                "if (!credential) { throw new Error(\"Set the signer credential in the active Postman environment.\"); }".to_owned(),
                format!(
                    "const timestamp = apiAxessTimestamp({});",
                    js_string_option(signer.runtime.timestamp_format.as_deref())
                ),
                format!(
                    "const nonce = apiAxessNonce({});",
                    js_string_option(signer.runtime.nonce_source.as_deref())
                ),
                "let value = \"\";".to_owned(),
            ];
            for (index, step) in signer.canonicalization_steps.iter().enumerate() {
                lines.push(format!("// step {index}: {}", js_comment(&step.description)));
                lines.extend(js_operation(&step.operation));
            }
            lines.extend([
                primitive_js(signer.primitive.as_ref()),
                output_js(signer),
            ]);
            lines.splice(2..2, helper_js());
            Ok(lines)
        }
        SignerMode::PartialHypothesis => Err(review_script(signer, "Canonicalization inferred, needs verification; this is the ranked best guess only.")),
        SignerMode::DeviceOracle => Err(vec![
            format!("// DEVICE ORACLE signer {}.", signer.signer_id),
            "// Postman cannot access the non-exportable key in the original runtime.".to_owned(),
            format!("// Callback boundary: {:?}.", signer.key_source),
            "// Route signing through the instrumented device/runtime callback; no local signature is attempted.".to_owned(),
        ]),
        SignerMode::ObservedOnly => Err(vec![
            format!("// OBSERVED ONLY signer {}.", signer.signer_id),
            format!("// Primitive observed: {:?}.", signer.primitive),
            "// Primitive was seen, but canonicalization was not reproduced.".to_owned(),
            "// No working signature is emitted.".to_owned(),
        ]),
    }
}

fn review_script(signer: &SignerArtifact, reason: &str) -> Vec<String> {
    let mut lines = vec![
        format!("// REVIEW ONLY signer {}.", signer.signer_id),
        format!("// {reason}"),
        "// This script intentionally does not mutate the request or claim to authenticate it."
            .to_owned(),
    ];
    for alternative in &signer.ranked_alternatives {
        lines.push(format!(
            "// hypothesis {} confidence {:.3}; fixtures: {}",
            alternative.hypothesis_id,
            alternative.confidence,
            alternative
                .fixtures
                .iter()
                .map(|fixture| fixture.capture_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for (index, step) in signer.canonicalization_steps.iter().enumerate() {
        lines.push(format!(
            "// best-guess step {index}: {} ({:?})",
            js_comment(&step.description),
            step.operation
        ));
    }
    if !signer.fixtures.is_empty() {
        lines.push(format!(
            "// fixtures: {}",
            signer
                .fixtures
                .iter()
                .map(|fixture| fixture.capture_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    lines
}

fn signer_diagnostic(signer: &SignerArtifact) -> Option<Diagnostic> {
    let (definition, detail) = match signer.signer_mode {
        SignerMode::DeviceOracle => (
            catalogue::COLLECTIONS_SIGNER_DEVICE_ORACLE,
            "device-oracle signer emitted as documentation; Postman cannot access the original runtime".to_owned(),
        ),
        SignerMode::PartialHypothesis => (
            catalogue::COLLECTIONS_SIGNER_REVIEW,
            "partial signer emitted as a commented review script".to_owned(),
        ),
        SignerMode::ObservedOnly => (
            catalogue::COLLECTIONS_SIGNER_REVIEW,
            "observed-only signer emitted as documentation without working auth".to_owned(),
        ),
        SignerMode::Reproducible
            if !matches!(
                signer.primitive,
                Some(SignerPrimitive::Hmac { .. } | SignerPrimitive::Digest { .. })
            ) => (
                catalogue::COLLECTIONS_SIGNER_REVIEW,
                "reproducible primitive is not available in the Postman sandbox; emitted as review-only".to_owned(),
            ),
        SignerMode::Reproducible => return None,
    };
    Some(diagnostic(
        definition,
        [
            ("field", format!("signers[{}]", signer.signer_id)),
            ("detail", detail),
        ],
    ))
}

fn js_string_option(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| format!("{value:?}"))
}

fn helper_js() -> Vec<String> {
    vec![
        "function apiAxessText(x) { return x === undefined || x === null ? \"\" : String(x); }".to_owned(),
        "function apiAxessBytesToString(bytes) { return String.fromCharCode.apply(null, bytes); }".to_owned(),
        "function apiAxessField(name, timestamp, nonce) {".to_owned(),
        "  const lower = String(name).toLowerCase();".to_owned(),
        "  if (lower === \"method\") return pm.request.method;".to_owned(),
        "  if (lower === \"path\") return pm.request.url.getPath();".to_owned(),
        "  if (lower === \"query\") return pm.request.url.query.toString();".to_owned(),
        "  if (lower === \"body\") return pm.request.body && pm.request.body.raw ? pm.request.body.raw : \"\";".to_owned(),
        "  if (lower === \"timestamp\") return timestamp;".to_owned(),
        "  if (lower === \"nonce\") return nonce;".to_owned(),
        "  if (lower.indexOf(\"header:\") === 0) return pm.request.headers.get(String(name).split(\":\").slice(1).join(\":\")) || \"\";".to_owned(),
        "  if (lower.indexOf(\"query:\") === 0) return pm.request.url.query.get(String(name).split(\":\").slice(1).join(\":\")) || \"\";".to_owned(),
        "  return pm.request.headers.get(name) || \"\";".to_owned(),
        "}".to_owned(),
        "function apiAxessTimestamp(format) { const now = Date.now(); if (!format) return new Date(now).toISOString(); if (String(format).toLowerCase().indexOf(\"millis\") >= 0) return String(now); if (String(format).toLowerCase().indexOf(\"epoch\") >= 0 || String(format).toLowerCase().indexOf(\"unix\") >= 0) return String(Math.floor(now / 1000)); return new Date(now).toISOString(); }".to_owned(),
        "function apiAxessNonce(source) { return source && String(source).toLowerCase().indexOf(\"monotonic\") >= 0 ? String(Date.now()) : pm.variables.replaceIn(\"{{$guid}}\"); }".to_owned(),
    ]
}

fn js_operation(operation: &CanonicalizationOperation) -> Vec<String> {
    match operation {
        CanonicalizationOperation::Field { name } => vec![format!("value = apiAxessField({name:?}, timestamp, nonce);")],
        CanonicalizationOperation::Uppercase => vec!["value = apiAxessText(value).toUpperCase();".to_owned()],
        CanonicalizationOperation::UrlEncode => vec!["value = encodeURIComponent(apiAxessText(value));".to_owned()],
        CanonicalizationOperation::FormEncode => vec!["value = encodeURIComponent(apiAxessText(value)).replace(/%20/g, \"+\");".to_owned()],
        CanonicalizationOperation::Sort => vec![
            "value = apiAxessText(value).split(\"&\").filter(Boolean).sort().join(\"&\");".to_owned()
        ],
        CanonicalizationOperation::Join { delimiter } => vec![format!("value = Array.isArray(value) ? value.join({:?}) : apiAxessText(value);", bytes_text(delimiter))],
        CanonicalizationOperation::Literal { bytes } => vec![format!("value = {:?};", bytes_text(bytes))],
        CanonicalizationOperation::Hash { algorithm } => vec![format!("value = CryptoJS.{}(value).toString(CryptoJS.enc.Hex);", crypto_hash_name(algorithm))],
        CanonicalizationOperation::Hmac { algorithm } => vec![format!("value = CryptoJS.Hmac{}(value, credential).toString(CryptoJS.enc.Hex);", crypto_hash_name(algorithm))],
        CanonicalizationOperation::Base64 => vec!["value = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(apiAxessText(value)));".to_owned()],
        CanonicalizationOperation::Base64Url => vec!["value = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(apiAxessText(value))).replace(/\\+/g, \"-\").replace(/\\//g, \"_\").replace(/=+$/, \"\");".to_owned()],
        CanonicalizationOperation::Hex => vec!["value = CryptoJS.enc.Hex.stringify(CryptoJS.enc.Utf8.parse(apiAxessText(value)));".to_owned()],
        CanonicalizationOperation::Template { name } => vec![format!("throw new Error({name:?} + \" template requires signer review\");")],
    }
}

fn primitive_js(primitive: Option<&SignerPrimitive>) -> String {
    match primitive {
        Some(SignerPrimitive::Hmac { hash }) => format!(
            "let signature = CryptoJS.Hmac{}(value, credential);",
            crypto_hash_name(hash)
        ),
        Some(SignerPrimitive::Digest { algorithm }) => format!(
            "let signature = CryptoJS.{}(value);",
            crypto_hash_name(algorithm)
        ),
        _ => "throw new Error(\"unsupported Postman primitive\");".to_owned(),
    }
}

fn output_js(signer: &SignerArtifact) -> String {
    let output = signer.output.as_ref();
    let encoding = output.map_or_else(
        || "hex".to_owned(),
        |item| item.encoding.to_ascii_lowercase(),
    );
    let prefix = output
        .and_then(|item| item.prefix.as_deref())
        .unwrap_or_default();
    let suffix = output
        .and_then(|item| item.suffix.as_deref())
        .unwrap_or_default();
    let truncation = output.and_then(|item| item.truncation);
    let location = output
        .and_then(|item| item.wire_location.as_deref())
        .map_or_else(
            || "header:X-APIaxess-Signature".to_owned(),
            normalize_location,
        );
    let encoded = match encoding.as_str() {
        "base64" | "base64standard" => "CryptoJS.enc.Base64.stringify(signature)".to_owned(),
        "base64url" | "base64_url" => "CryptoJS.enc.Base64.stringify(signature).replace(/\\+/g, \"-\").replace(/\\//g, \"_\").replace(/=+$/, \"\")".to_owned(),
        _ => "CryptoJS.enc.Hex.stringify(signature)".to_owned(),
    };
    let truncation_js = truncation.map_or_else(String::new, |value| format!(".slice(0, {value})"));
    if let Some(name) = location.strip_prefix("header:") {
        format!(
            "let wireSignature = {prefix:?} + ({encoded}){truncation_js} + {suffix:?}; pm.request.headers.upsert({{key: {name:?}, value: wireSignature}});"
        )
    } else if let Some(name) = location.strip_prefix("query:") {
        format!(
            "let wireSignature = {prefix:?} + ({encoded}){truncation_js} + {suffix:?}; pm.request.url.query.upsert({{key: {name:?}, value: wireSignature}});"
        )
    } else {
        "throw new Error(\"unsupported signer wire location\");".to_owned()
    }
}

fn crypto_hash_name(algorithm: &str) -> String {
    match algorithm.to_ascii_lowercase().replace('-', "").as_str() {
        "sha1" => "SHA1".to_owned(),
        "sha224" => "SHA224".to_owned(),
        "sha384" => "SHA384".to_owned(),
        "sha512" => "SHA512".to_owned(),
        "md5" => "MD5".to_owned(),
        _ => "SHA256".to_owned(),
    }
}

fn bytes_text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| {
        let mut output = String::new();
        for byte in bytes {
            let _ = write!(&mut output, "\\u{byte:04x}");
        }
        output
    })
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

fn postman_path(path: &str) -> String {
    let mut output = path.to_owned();
    let mut cursor = 0;
    while let Some(start) = output[cursor..].find('{') {
        let start = cursor + start;
        let Some(end) = output[start..].find('}') else {
            break;
        };
        let end = start + end;
        let name = output[start + 1..end].to_owned();
        output.replace_range(start..=end, &format!(":{name}"));
        cursor = start + name.len() + 1;
    }
    output
}

fn safe_name(value: &str) -> String {
    let mut output = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    if output.is_empty() {
        "value".clone_into(&mut output);
    }
    output
}

fn schema_example(slot: &SchemaSlot) -> Value {
    let Some(candidate) = slot.shape.selected_candidate() else {
        return Value::Null;
    };
    match &candidate.value {
        SchemaShape::Unknown | SchemaShape::Null => Value::Null,
        SchemaShape::Boolean => Value::Bool(false),
        SchemaShape::Integer { .. } => json!(0),
        SchemaShape::Number { .. } => json!(0.0),
        SchemaShape::String { .. } => Value::String("example".to_owned()),
        SchemaShape::Array { items } => Value::Array(vec![schema_example(items)]),
        SchemaShape::Object { properties, .. } => {
            let mut object = Map::new();
            let mut properties = properties.iter().collect::<Vec<_>>();
            properties.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
            for property in properties {
                object.insert(
                    property.name.as_str().to_owned(),
                    schema_example(&property.schema),
                );
            }
            Value::Object(object)
        }
        SchemaShape::Union { variants } => {
            variants.first().map_or(Value::Null, schema_example_shape)
        }
    }
}

fn schema_example_shape(shape: &SchemaShape) -> Value {
    match shape {
        SchemaShape::Unknown | SchemaShape::Null => Value::Null,
        SchemaShape::Boolean => Value::Bool(false),
        SchemaShape::Integer { .. } => json!(0),
        SchemaShape::Number { .. } => json!(0.0),
        SchemaShape::String { .. } => Value::String("example".to_owned()),
        SchemaShape::Array { items } => Value::Array(vec![schema_example(items)]),
        SchemaShape::Object { properties, .. } => {
            let mut object = Map::new();
            for property in properties {
                object.insert(
                    property.name.as_str().to_owned(),
                    schema_example(&property.schema),
                );
            }
            Value::Object(object)
        }
        SchemaShape::Union { variants } => {
            variants.first().map_or(Value::Null, schema_example_shape)
        }
    }
}

fn har_entry(
    surface: &UnifiedApiSurface,
    index: usize,
    signer: &SignerArtifact,
    fixture: &SignerFixture,
) -> Value {
    let url = fixture_url(
        surface,
        &fixture.request.method,
        &fixture.request.path,
        &fixture.request.query,
    );
    let request_headers = fixture
        .request
        .headers
        .iter()
        .map(|(name, value)| json!({"name": name, "value": value}))
        .collect::<Vec<_>>();
    let request_body = fixture.request.body.as_deref().map(har_content);
    json!({
        "startedDateTime": surface.assembled_at.to_rfc3339(),
        "time": 0,
        "request": {
            "method": fixture.request.method,
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": request_headers,
            "queryString": fixture.request.query.iter().map(|(name, value)| json!({"name": name, "value": value})).collect::<Vec<_>>(),
            "postData": request_body
        },
        "response": {
            "status": 0,
            "statusText": "not captured",
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "content": {"size": 0, "text": ""},
            "_apiaxess_response_observed": false
        },
        "cache": {},
        "timings": {"send": 0, "wait": 0, "receive": 0},
        "_apiaxess_capture_id": fixture.capture_id,
        "_apiaxess_signer_id": signer.signer_id,
        "_apiaxess_entry_index": index
    })
}

fn fixture_url(
    surface: &UnifiedApiSurface,
    method: &str,
    path: &str,
    query: &[(String, String)],
) -> String {
    let base = surface
        .surface
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint
                .identity
                .method
                .as_str()
                .eq_ignore_ascii_case(method)
        })
        .and_then(|endpoint| endpoint.base_url.as_ref())
        .and_then(|fact| fact.selected_candidate())
        .map_or_else(
            || DEFAULT_BASE_URL.to_owned(),
            |candidate| candidate.value.trim_end_matches('/').to_owned(),
        );
    let mut url = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_owned()
    } else {
        format!("{base}/{}", path.trim_start_matches('/'))
    };
    if !query.is_empty() {
        url.push('?');
        url.push_str(
            &query
                .iter()
                .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&"),
        );
    }
    url
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                vec![char::from(byte)]
            } else {
                format!("%{byte:02X}").chars().collect()
            }
        })
        .collect()
}

fn har_content(body: &[u8]) -> Value {
    if let Ok(text) = std::str::from_utf8(body) {
        json!({"size": body.len(), "mimeType": "application/octet-stream", "text": text})
    } else {
        json!({"size": body.len(), "mimeType": "application/octet-stream", "text": BASE64.encode(body), "encoding": "base64"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_api_model::{
        Activity, ActivityId, Agent, AgentId, AgentKind, ApiSurface, CONFIDENCE_SCHEMA_VERSION,
        CanonicalizationOperation, CanonicalizationStep, ConfidenceSummary, CoveragePicture,
        ProvenanceRegistry, SignerKeySource, SignerScheme, SourceType,
        UNIFIED_SURFACE_SCHEMA_VERSION,
    };
    use chrono::Utc;

    #[test]
    fn reproducible_hmac_script_is_ordered_and_secret_free() {
        let signer = test_signer();
        let script = signer_script(&signer).expect("HMAC is supported");
        let text = script.join("\n");
        assert!(text.contains("pm.environment.get"));
        assert!(text.contains("CryptoJS.HmacSHA256"));
        assert!(text.contains("value = apiAxessField(\"path\""));
        assert!(text.contains("value = apiAxessText(value).toUpperCase()"));
        assert!(!text.contains("super-secret"));
    }

    #[test]
    fn non_reproducible_signers_are_comments_only() {
        let mut signer = test_signer();
        signer.signer_mode = SignerMode::PartialHypothesis;
        assert!(signer_script(&signer).is_err());
        signer.signer_mode = SignerMode::DeviceOracle;
        assert!(signer_script(&signer).is_err());
        signer.signer_mode = SignerMode::ObservedOnly;
        assert!(signer_script(&signer).is_err());
    }

    #[test]
    fn empty_surface_emits_deterministic_valid_postman_and_har_documents() {
        let surface = empty_surface();
        let emitter = CollectionsEmitter::default();
        let first = emitter.emit_collection(&surface).expect("collection");
        let second = emitter.emit_collection(&surface).expect("collection");
        assert_eq!(first.json, second.json);
        assert_eq!(
            first.document["info"]["schema"],
            "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        );
        assert!(first.document["item"].as_array().is_some_and(Vec::is_empty));
        let har = emitter.emit_har(&surface).expect("har");
        assert_eq!(har.document["log"]["version"], "1.2");
        assert!(
            har.document["log"]["entries"]
                .as_array()
                .is_some_and(Vec::is_empty)
        );
        assert!(
            har.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "collections.no-captured-traffic")
        );
        let reparsed: Value = serde_json::from_str(&first.json).expect("postman JSON");
        assert_eq!(reparsed, first.document);
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
                source_type: apiaxess_api_model::SourceType::Fusion,
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

    fn test_signer() -> SignerArtifact {
        SignerArtifact {
            schema_version: apiaxess_api_model::SIGNER_IR_SCHEMA_VERSION,
            signer_id: "signer:test".to_owned(),
            scheme: SignerScheme::CustomHmac,
            signer_mode: SignerMode::Reproducible,
            confidence: 0.9,
            coverage: vec![],
            canonicalization_steps: vec![
                CanonicalizationStep {
                    operation: CanonicalizationOperation::Field {
                        name: "path".to_owned(),
                    },
                    description: "read final path".to_owned(),
                    source_type: SourceType::DynamicCapture,
                },
                CanonicalizationStep {
                    operation: CanonicalizationOperation::Uppercase,
                    description: "uppercase".to_owned(),
                    source_type: SourceType::DynamicCapture,
                },
            ],
            primitive: Some(SignerPrimitive::Hmac {
                hash: "sha256".to_owned(),
            }),
            key_source: Some(SignerKeySource::CredentialReference {
                secret_ref: "credential://runtime".to_owned(),
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
            reproduction: "fixture".to_owned(),
            provenance: vec![apiaxess_api_model::SignerProvenance {
                source_type: SourceType::DynamicCapture,
                evidence_ids: vec!["capture:test".to_owned()],
                detail: "fixture".to_owned(),
            }],
        }
    }
}
