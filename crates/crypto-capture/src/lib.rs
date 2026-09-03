//! Phase 4.1: faithful, stateful crypto-primitive capture.

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Current Phase 4.1 record schema.
pub const CRYPTO_CAPTURE_SCHEMA_VERSION: u32 = 1;

/// Primitive family.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Primitive {
    /// Message-authentication operation such as HMAC.
    Mac,
    /// Symmetric encryption or decryption operation.
    Cipher,
    /// One-way message digest operation.
    MessageDigest,
    /// Public-key signing or verification operation.
    Signature,
    /// Native or provider-specific cryptographic operation.
    Native,
    /// Key-derivation operation that produces another key or secret.
    KeyDerivation,
}

/// Key exportability outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyExportability {
    /// The key material was observed in an exportable form.
    Exportable,
    /// The platform retained the key inside a protected provider.
    NonExportable,
    /// Exportability does not apply to this observation.
    NotApplicable,
    /// The capture did not establish whether the key can be exported.
    Unknown,
}

/// Key and Android Keystore metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyCapture {
    /// Algorithm or key family reported by the provider.
    pub algorithm: Option<String>,
    /// Encoding format of the captured key material.
    pub format: Option<String>,
    /// Encoded key bytes when the provider exposed them.
    pub encoded: Option<Vec<u8>>,
    /// Whether the key can cross the provider boundary.
    pub exportability: KeyExportability,
    /// Android Keystore alias associated with the key.
    pub alias: Option<String>,
    /// Provider-specific purpose bit mask for the key.
    pub purposes: Option<i64>,
    /// Provider security classification, such as a hardware-backed tier.
    pub security_level: Option<String>,
    /// Whether the provider reports hardware-backed storage.
    pub hardware_backed: Option<bool>,
}

impl Default for KeyCapture {
    fn default() -> Self {
        Self {
            algorithm: None,
            format: None,
            encoded: None,
            exportability: KeyExportability::NotApplicable,
            alias: None,
            purposes: None,
            security_level: None,
            hardware_backed: None,
        }
    }
}

/// One exact input chunk, with Java offset/length preserved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateChunk {
    /// Update method used by the source API, such as `update` or `doFinal`.
    pub method: String,
    /// Exact bytes supplied by the update call.
    pub bytes: Vec<u8>,
    /// Offset of the source bytes when an input buffer was sliced.
    pub source_offset: Option<usize>,
    /// Length of the source range represented by this chunk.
    pub source_length: Option<usize>,
    /// Whether the source value came from a Java `ByteBuffer`.
    pub byte_buffer: bool,
}

/// Stack evidence at an important lifecycle edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackCapture {
    /// Lifecycle edge at which the stack was captured.
    pub edge: String,
    /// Symbol or address frames retained from the runtime stack.
    pub frames: Vec<String>,
}

/// Post-processing observation associated with primitive output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireObservation {
    /// Bytes observed after the primitive or its wrapper processed the input.
    pub bytes: Vec<u8>,
    /// Encoding used to place the bytes on the request wire.
    pub encoding: Option<String>,
    /// Header, query, body, or other wire location of the observation.
    pub location: Option<String>,
    /// Input bytes associated with this post-processing observation.
    pub input: Option<Vec<u8>>,
}

/// One completed operation ready for later scheme inference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoCaptureRecord {
    /// Schema version used to serialize this record.
    pub schema_version: u32,
    /// Stable operation identifier assigned by the capture boundary.
    pub operation_id: String,
    /// Primitive family involved in the operation.
    pub primitive: Primitive,
    /// Algorithm label reported by the runtime or provider.
    pub algorithm: Option<String>,
    /// Cryptographic provider that handled the operation.
    pub provider: Option<String>,
    /// Key and Keystore metadata associated with the operation.
    pub key: KeyCapture,
    /// Ordered input chunks supplied during the operation.
    pub updates: Vec<UpdateChunk>,
    /// Concatenated message bytes reconstructed from the updates.
    pub accumulated_message: Vec<u8>,
    /// Final output returned by the primitive, when available.
    pub primitive_output: Option<Vec<u8>>,
    /// Per-update outputs returned by APIs that emit intermediate values.
    pub update_outputs: Vec<Vec<u8>>,
    /// Encoded or placed outputs observed at the request boundary.
    pub wire_output: Vec<WireObservation>,
    /// Stack evidence captured at lifecycle edges.
    pub stacks: Vec<StackCapture>,
    /// Runtime thread associated with the operation.
    pub thread_id: Option<u64>,
    /// Request identifier used to correlate the operation with traffic.
    pub request_id: Option<String>,
    /// Flow identifier used to correlate the operation with a network exchange.
    pub flow_id: Option<u64>,
    /// Whether the same primitive object was reused after finalization.
    pub reused_after_finalize: bool,
}

/// Key derivation or Keystore lookup observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyObservation {
    /// Runtime path or API call that produced the observation.
    pub path: String,
    /// Algorithm label associated with the lookup or derivation.
    pub algorithm: Option<String>,
    /// Key and Keystore metadata observed at the path.
    pub key: KeyCapture,
    /// Runtime thread associated with the observation.
    pub thread_id: Option<u64>,
    /// Request identifier used to correlate the observation with traffic.
    pub request_id: Option<String>,
    /// Flow identifier used to correlate the observation with a network exchange.
    pub flow_id: Option<u64>,
}

/// An event emitted by the Frida payload or request adapter.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CaptureEvent {
    /// Begins a new primitive operation and records its initial context.
    OperationStart {
        /// Stable identifier used by subsequent update and finish events.
        operation_id: String,
        /// Primitive family being invoked.
        primitive: Primitive,
        /// Algorithm label reported at operation start.
        algorithm: Option<String>,
        /// Provider handling the operation, when known.
        provider: Option<String>,
        /// Key metadata available at operation start.
        key: KeyCapture,
        /// Runtime thread that initiated the operation.
        thread_id: Option<u64>,
        /// Stack evidence captured at operation start.
        stacks: Vec<StackCapture>,
        /// Request identifier active when the operation started.
        request_id: Option<String>,
    },
    /// Supplies one ordered input chunk to an active operation.
    Update {
        /// Identifier of the active operation receiving the chunk.
        operation_id: String,
        /// Exact bytes and source metadata for this update.
        chunk: UpdateChunk,
        /// Optional stack evidence captured for this update.
        stack: Option<StackCapture>,
    },
    /// Completes an operation and records its final outputs.
    OperationFinish {
        /// Identifier of the operation being completed.
        operation_id: String,
        /// Final primitive output, when the provider returned one.
        output: Option<Vec<u8>>,
        /// Outputs returned by individual update calls.
        update_outputs: Vec<Vec<u8>>,
        /// Optional stack evidence captured at completion.
        stack: Option<StackCapture>,
    },
    /// Records an encoded output observed at the request boundary.
    Wire {
        /// Identifier of the operation that produced the output.
        operation_id: String,
        /// Wire placement and encoding observation.
        observation: WireObservation,
    },
    /// Resets an operation object before it is reused.
    Reset {
        /// Identifier of the operation object being reset.
        operation_id: String,
    },
    /// Associates a thread with the active request and flow context.
    RequestContext {
        /// Request identifier supplied by the traffic boundary.
        request_id: String,
        /// Network flow associated with the request, when known.
        flow_id: Option<u64>,
        /// Runtime thread carrying the request.
        thread_id: Option<u64>,
        /// Whether this context should be used for subsequent events.
        active: bool,
    },
    /// Carries a structured diagnostic emitted by the capture boundary.
    Diagnostic {
        /// Diagnostic describing a capture limitation or event.
        diagnostic: Diagnostic,
    },
    /// Records a Keystore lookup or key-derivation observation.
    KeyObservation {
        /// Runtime path or API call that produced the observation.
        path: String,
        /// Algorithm label associated with the lookup.
        algorithm: Option<String>,
        /// Key metadata observed at the lookup boundary.
        key: KeyCapture,
        /// Runtime thread associated with the observation.
        thread_id: Option<u64>,
    },
    /// Preserves an event type added by a newer producer version.
    #[serde(other)]
    Other,
}

/// Collector errors.
#[derive(Debug, Error)]
pub enum CaptureError {
    /// Event JSON could not be decoded into the capture schema.
    #[error("invalid crypto capture event: {0}")]
    Decode(#[from] serde_json::Error),
    /// An event referred to an operation that is not active or retained.
    #[error("crypto capture event references unknown operation {0}")]
    UnknownOperation(String),
    /// An operation start omitted its required identifier.
    #[error("crypto capture operation ID must not be empty")]
    EmptyOperationId,
}

#[derive(Clone, Debug)]
struct ActiveOperation {
    record: CryptoCaptureRecord,
}

/// Stateful collector preserving update order and request correlation.
#[derive(Clone, Debug, Default)]
pub struct CryptoCaptureCollector {
    active: HashMap<String, ActiveOperation>,
    reused_objects: HashMap<String, bool>,
    thread_context: HashMap<u64, (String, Option<u64>)>,
    completed: Vec<CryptoCaptureRecord>,
    key_observations: Vec<KeyObservation>,
    diagnostics: Vec<Diagnostic>,
}

impl CryptoCaptureCollector {
    /// Applies one event.
    ///
    /// # Errors
    ///
    /// Returns an error when the event is malformed or cannot be correlated
    /// with the collector's active operations.
    // Event handling keeps operation, flow, and key state updates atomic.
    #[allow(clippy::too_many_lines)]
    pub fn apply(&mut self, event: CaptureEvent) -> Result<(), CaptureError> {
        match event {
            CaptureEvent::OperationStart {
                operation_id,
                primitive,
                algorithm,
                provider,
                key,
                thread_id,
                stacks,
                request_id,
            } => {
                if operation_id.is_empty() {
                    return Err(CaptureError::EmptyOperationId);
                }
                let (request_id, flow_id) = self.context_for(thread_id, request_id);
                let reused = self.active.contains_key(&operation_id)
                    || self.reused_objects.remove(&operation_id).unwrap_or(false);
                self.active.insert(
                    operation_id.clone(),
                    ActiveOperation {
                        record: CryptoCaptureRecord {
                            schema_version: CRYPTO_CAPTURE_SCHEMA_VERSION,
                            operation_id,
                            primitive,
                            algorithm,
                            provider,
                            key,
                            updates: Vec::new(),
                            accumulated_message: Vec::new(),
                            primitive_output: None,
                            update_outputs: Vec::new(),
                            wire_output: Vec::new(),
                            stacks,
                            thread_id,
                            request_id,
                            flow_id,
                            reused_after_finalize: reused,
                        },
                    },
                );
            }
            CaptureEvent::Update {
                operation_id,
                chunk,
                stack,
            } => {
                let operation = self
                    .active
                    .get_mut(&operation_id)
                    .ok_or_else(|| CaptureError::UnknownOperation(operation_id.clone()))?;
                operation
                    .record
                    .accumulated_message
                    .extend_from_slice(&chunk.bytes);
                operation.record.updates.push(chunk);
                if let Some(stack) = stack {
                    operation.record.stacks.push(stack);
                }
            }
            CaptureEvent::OperationFinish {
                operation_id,
                output,
                update_outputs,
                stack,
            } => {
                let mut operation = self
                    .active
                    .remove(&operation_id)
                    .ok_or_else(|| CaptureError::UnknownOperation(operation_id.clone()))?;
                operation.record.primitive_output = output;
                operation.record.update_outputs = update_outputs;
                if let Some(stack) = stack {
                    operation.record.stacks.push(stack);
                }
                if let Some(thread_id) = operation.record.thread_id {
                    if let Some((request_id, flow_id)) = self.thread_context.get(&thread_id) {
                        operation.record.request_id = Some(request_id.clone());
                        operation.record.flow_id = *flow_id;
                    }
                }
                self.reused_objects.insert(operation_id, true);
                self.completed.push(operation.record);
            }
            CaptureEvent::Wire {
                operation_id,
                observation,
            } => {
                if let Some(operation) = self.active.get_mut(&operation_id) {
                    operation.record.wire_output.push(observation);
                } else if let Some(record) = self
                    .completed
                    .iter_mut()
                    .rev()
                    .find(|record| record.operation_id == operation_id)
                {
                    record.wire_output.push(observation);
                } else {
                    return Err(CaptureError::UnknownOperation(operation_id));
                }
            }
            CaptureEvent::Reset { operation_id } => {
                if let Some(operation) = self.active.get_mut(&operation_id) {
                    operation.record.reused_after_finalize = true;
                } else {
                    self.reused_objects.insert(operation_id, true);
                }
            }
            CaptureEvent::RequestContext {
                request_id,
                flow_id,
                thread_id,
                active,
            } => {
                if let Some(thread_id) = thread_id {
                    if active {
                        self.thread_context.insert(thread_id, (request_id, flow_id));
                    } else {
                        self.thread_context.remove(&thread_id);
                    }
                }
            }
            CaptureEvent::Diagnostic { diagnostic } => self.diagnostics.push(diagnostic),
            CaptureEvent::KeyObservation {
                path,
                algorithm,
                key,
                thread_id,
            } => {
                let (request_id, flow_id) = self.context_for(thread_id, None);
                self.key_observations.push(KeyObservation {
                    path,
                    algorithm,
                    key,
                    thread_id,
                    request_id,
                    flow_id,
                });
            }
            CaptureEvent::Other => {}
        }
        Ok(())
    }

    /// Decodes and applies one JSON event.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON is invalid or the decoded event cannot
    /// be applied to the collector.
    pub fn apply_json(&mut self, json: &str) -> Result<(), CaptureError> {
        self.apply(serde_json::from_str(json)?)
    }

    /// Completed operations.
    #[must_use]
    pub fn records(&self) -> &[CryptoCaptureRecord] {
        &self.completed
    }

    /// Hook/runtime diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Key derivation, Keystore lookup, and `KeyInfo` observations.
    #[must_use]
    pub fn key_observations(&self) -> &[KeyObservation] {
        &self.key_observations
    }

    /// Drains completed operations.
    pub fn take_records(&mut self) -> Vec<CryptoCaptureRecord> {
        std::mem::take(&mut self.completed)
    }

    fn context_for(
        &self,
        thread_id: Option<u64>,
        request_id: Option<String>,
    ) -> (Option<String>, Option<u64>) {
        request_id.map_or_else(
            || {
                thread_id
                    .and_then(|id| self.thread_context.get(&id).cloned())
                    .map_or((None, None), |(id, flow)| (Some(id), flow))
            },
            |id| (Some(id), None),
        )
    }
}

/// Creates a request correlation event from the stable proxy flow ID.
#[must_use]
pub fn request_context_event(flow_id: u64, thread_id: Option<u64>, active: bool) -> CaptureEvent {
    CaptureEvent::RequestContext {
        request_id: format!("flow:{flow_id}"),
        flow_id: Some(flow_id),
        thread_id,
        active,
    }
}

/// Creates the first-class diagnostic for a valid but non-exportable key.
#[must_use]
pub fn key_non_exportable_diagnostic(
    operation_id: impl Into<String>,
    algorithm: Option<String>,
    alias: Option<String>,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "operation_id".to_owned(),
        DiagnosticValue::String(operation_id.into()),
    );
    if let Some(value) = algorithm {
        context.insert("algorithm".to_owned(), DiagnosticValue::String(value));
    }
    if let Some(value) = alias {
        context.insert("alias".to_owned(), DiagnosticValue::String(value));
    }
    catalogue::CRYPTO_KEY_NON_EXPORTABLE.instantiate(context)
}

/// Frida Java/native payload loaded through the Phase 3 substrate.
pub mod frida_payload {
    use super::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};

    const PAYLOAD: &str = r"
(function () {
  'use strict';
  var states = new Map(), requests = new Map(), nativeAddresses = new Set();
  function sendEvent(event) { try { if (event.kind) event.type=event.kind; send(Object.assign({type:'crypto_capture'}, event)); } catch (_) {} }
  function diagnostic(id, detail) {
    sendEvent({kind:'diagnostic', diagnostic:{schema_version:1,id:id,category:'sandbox',severity:'error',
      what:id,why:'The Phase 4.1 runtime payload reported this condition.',
      fix:'Review the structured evidence and retry on a compatible rooted runtime.',
      context:{detail:{type:'string',value:String(detail || '')}}}});
  }
  function safe(fn, fallback) { try { return fn(); } catch (_) { return fallback; } }
  function tid() { return safe(function () { return Process.getCurrentThreadId(); }, null); }
  function stack(edge) {
    var frames = safe(function () { return Java.use('java.lang.Throwable').$new().getStackTrace()
      .map(function (frame) { return String(frame.toString()); }); }, []);
    return {edge:edge,frames:frames};
  }
  function array(value, offset, length) {
    if (value === null || value === undefined) return null;
    try {
      if (value.$className === 'java.nio.ByteBuffer') {
        var duplicate = value.duplicate(), count = duplicate.remaining(), copied = Java.array('byte', count); duplicate.get(copied);
        return {bytes:Array.prototype.slice.call(copied),source_offset:null,source_length:count,byte_buffer:true};
      }
      var source = Java.array('byte', value), start = Math.max(0, offset || 0);
      var end = length === undefined ? source.length : Math.min(source.length, start + Math.max(0, length));
      return {bytes:Array.prototype.slice.call(source.slice(start,end)),source_offset:start,
        source_length:end-start,byte_buffer:false};
    } catch (error) { diagnostic('crypto.capture-hook-failed', error); return null; }
  }
  function stringBytes(value) {
    try { return Array.prototype.slice.call(Java.use('java.lang.String').$new(String(value)).getBytes()); }
    catch (_) { return []; }
  }
  function keyInfo(key) {
    var result = {algorithm:null,format:null,encoded:null,exportability:'not_applicable',
      alias:null,purposes:null,security_level:null,hardware_backed:null};
    if (!key) return result;
    result.algorithm = safe(function () { return String(key.getAlgorithm()); }, null);
    result.format = safe(function () { return String(key.getFormat()); }, null);
    result.alias = safe(function () { return String(key.getKeystoreAlias()); }, null);
    result.purposes = safe(function () { return Number(key.getPurposes()); }, null);
    result.security_level = safe(function () { return String(key.getSecurityLevel()); }, null);
    result.hardware_backed = safe(function () { return Boolean(key.isInsideSecureHardware()); }, null);
    var encoded = safe(function () { return key.getEncoded(); }, '__threw__');
    if (encoded === '__threw__') result.exportability = 'unknown';
    else if (encoded === null) {
      result.exportability = 'non_exportable';
      sendEvent({kind:'diagnostic',diagnostic:{schema_version:1,id:'crypto.key-non-exportable',
        category:'sandbox',severity:'info',what:'A crypto key is non-exportable.',
        why:'The provider returned no encoded bytes, expected for Keystore or hardware-backed keys.',
        fix:'Retain the operation and use device-oracle mode in later phases.',
        context:{algorithm:{type:'string',value:result.algorithm || 'unknown'}}}});
    } else {
      result.exportability = 'exportable';
      result.encoded = Array.prototype.slice.call(Java.array('byte', encoded));
    }
    return result;
  }
  function keyArg(args) {
    for (var i=0; i<args.length; i++) {
      if (args[i] && safe(function () { return args[i].getEncoded !== undefined; }, false)) return keyInfo(args[i]);
    }
    return keyInfo(null);
  }
  function id(kind, object) { return kind + ':' + safe(function () { return String(object.$h); }, String(object.hashCode())); }
  var lastOperationByThread = new Map();
  function start(kind, object, args, edge) {
    var operationId = id(kind, object), context = requests.get(tid());
    var record = {operation_id:operationId,primitive:kind,algorithm:safe(function () { return String(object.getAlgorithm()); }, null),
      provider:safe(function () { return String(object.getProvider().getName()); }, null),key:keyArg(args || []),
      thread_id:tid(),request_id:context ? context.request_id : null,updates:[],update_outputs:[]};
    states.set(operationId, record);
    lastOperationByThread.set(tid(), operationId);
    sendEvent({kind:'operation_start',operation_id:operationId,primitive:kind,algorithm:record.algorithm,
      provider:record.provider,key:record.key,thread_id:record.thread_id,request_id:record.request_id,
      stacks:[stack(edge)]});
    return record;
  }
  function update(kind, object, args, method) {
    var operationId = id(kind, object), record = states.get(operationId) || start(kind, object, [], 'implicit_init');
    var part = array(args[0], args[1], args[2]); if (!part) return record;
    record.updates.push(part.bytes);
    sendEvent({kind:'update',operation_id:operationId,chunk:{method:method,bytes:part.bytes,
      source_offset:part.source_offset,source_length:part.source_length,byte_buffer:part.byte_buffer},
      stack:record.updates.length === 1 ? stack('first_update') : null});
    return record;
  }
  function resultArray(output, args) {
    if (typeof output === 'number' && args && args.length > 1) return array(args[0], args[1], output);
    return array(output);
  }
  function finish(kind, object, args, output, edge) {
    var operationId = id(kind, object), record = states.get(operationId) || start(kind, object, [], 'implicit_init');
    var part = resultArray(output, args);
    sendEvent({kind:'operation_finish',operation_id:operationId,output:part ? part.bytes : null,
      update_outputs:record.update_outputs || [],stack:stack(edge)});
    states.delete(operationId);
    return output;
  }
  function overloads(K, name, callback) {
    try {
      if (!K[name] || !K[name].overloads) return;
      K[name].overloads.forEach(function (overload) {
        var original = overload.implementation;
        overload.implementation = function () {
          return callback.call(this, original, Array.prototype.slice.call(arguments));
        };
      });
    } catch (error) { diagnostic('crypto.hook-install-failed', name + ': ' + error); }
  }
  function installMac() {
    var K = Java.use('javax.crypto.Mac');
    overloads(K,'init',function (original,args) { var result=original.apply(this,args); start('mac',this,args,'init'); return result; });
    overloads(K,'update',function (original,args) { update('mac',this,args,'update'); return original.apply(this,args); });
    overloads(K,'doFinal',function (original,args) { var result=original.apply(this,args); return finish('mac',this,args,result,'do_final'); });
    overloads(K,'reset',function (original,args) { sendEvent({kind:'reset',operation_id:id('mac',this)}); return original.apply(this,args); });
  }
  function installCipher() {
    var K = Java.use('javax.crypto.Cipher');
    overloads(K,'init',function (original,args) { var result=original.apply(this,args); start('cipher',this,args,'init'); return result; });
    overloads(K,'update',function (original,args) {
      update('cipher',this,args,'update'); var result=original.apply(this,args);
      var record=states.get(id('cipher',this)), part=resultArray(result,args); if (record && part) record.update_outputs.push(part.bytes); return result;
    });
    overloads(K,'doFinal',function (original,args) { var result=original.apply(this,args); return finish('cipher',this,args,result,'do_final'); });
  }
  function installDigest() {
    var K = Java.use('java.security.MessageDigest');
    overloads(K,'update',function (original,args) { update('message_digest',this,args,'update'); return original.apply(this,args); });
    overloads(K,'digest',function (original,args) { var result=original.apply(this,args); return finish('message_digest',this,args,result,'digest'); });
    overloads(K,'reset',function (original,args) { sendEvent({kind:'reset',operation_id:id('message_digest',this)}); return original.apply(this,args); });
  }
  function installSignature() {
    var K = Java.use('java.security.Signature');
    ['initSign','initVerify','init'].forEach(function (name) {
      overloads(K,name,function (original,args) { var result=original.apply(this,args); start('signature',this,args,name); return result; });
    });
    overloads(K,'update',function (original,args) { update('signature',this,args,'update'); return original.apply(this,args); });
    overloads(K,'sign',function (original,args) { var result=original.apply(this,args); return finish('signature',this,args,result,'sign'); });
  }
  function installDerivedKeys() {
    try {
      var S=Java.use('javax.crypto.spec.SecretKeySpec');
      overloads(S,'$init',function (original,args) { var result=original.apply(this,args);
        sendEvent({kind:'key_observation',path:'secret_key_spec',algorithm:args.length > 1 ? String(args[1]) : null,key:keyInfo(this),thread_id:tid()}); return result; });
    } catch (_) {}
    try {
      var F=Java.use('javax.crypto.SecretKeyFactory');
      overloads(F,'generateSecret',function (original,args) { var result=original.apply(this,args);
        sendEvent({kind:'key_observation',path:'secret_key_factory',algorithm:safe(function () { return String(this.getAlgorithm()); },null),key:keyInfo(result),thread_id:tid()}); return result; });
      overloads(F,'getKeySpec',function (original,args) { var result=original.apply(this,args), info=keyInfo(result);
        sendEvent({kind:'key_observation',path:'key_info',algorithm:safe(function () { return String(this.getAlgorithm()); },null),key:info,thread_id:tid()}); return result; });
    } catch (_) {}
    try {
      var KS=Java.use('java.security.KeyStore');
      overloads(KS,'getKey',function (original,args) { var result=original.apply(this,args), info=keyInfo(result);
        info.alias=args[0] ? String(args[0]) : null; sendEvent({kind:'key_observation',path:'keystore_get_key',algorithm:info.algorithm,key:info,thread_id:tid()}); return result; });
    } catch (_) {}
    try {
      var A=Java.use('javax.crypto.KeyAgreement');
      overloads(A,'doPhase',function (original,args) { var result=original.apply(this,args);
        sendEvent({kind:'key_observation',path:'key_agreement',algorithm:safe(function () { return String(this.getAlgorithm()); },null),key:keyInfo(result),thread_id:tid()}); return result; });
      overloads(A,'generateSecret',function (original,args) { var result=original.apply(this,args);
        sendEvent({kind:'key_observation',path:'key_agreement_secret',algorithm:safe(function () { return String(this.getAlgorithm()); },null),key:keyInfo(result),thread_id:tid()}); return result; });
    } catch (_) {}
    try {
      var G=Java.use('javax.crypto.KeyGenerator');
      overloads(G,'generateKey',function (original,args) { var result=original.apply(this,args);
        sendEvent({kind:'key_observation',path:'key_generator',algorithm:safe(function () { return String(this.getAlgorithm()); },null),key:keyInfo(result),thread_id:tid()}); return result; });
    } catch (_) {}
  }
  function installEncoding() {
    try {
      var B=Java.use('android.util.Base64');
      ['encode','encodeToString'].forEach(function (name) { overloads(B,name,function (original,args) {
        var result=original.apply(this,args), part=name === 'encodeToString' ? {bytes:stringBytes(result)} : array(result);
        var flags=args.length > 1 ? Number(args[1]) : 0;
        sendEvent({kind:'wire',operation_id:lastOperationByThread.get(tid()) || 'unknown',
          observation:{bytes:part ? part.bytes : [],encoding:(flags & 8) ? 'base64url' : 'base64',location:name,input:null}});
        return result;
      }); });
    } catch (_) {}
    try {
      var U=Java.use('java.net.URLEncoder');
      overloads(U,'encode',function (original,args) { var result=original.apply(this,args);
        sendEvent({kind:'wire',operation_id:lastOperationByThread.get(tid()) || 'unknown',observation:{bytes:stringBytes(result),
          encoding:'url_encode',location:'URLEncoder',input:null}}); return result; });
    } catch (_) {}
    try {
      var O=Java.use('okio.ByteString');
      ['hex','base64','base64Url'].forEach(function (name) { overloads(O,name,function (original,args) {
        var result=original.apply(this,args);
        sendEvent({kind:'wire',operation_id:lastOperationByThread.get(tid()) || 'unknown',
          observation:{bytes:stringBytes(result),encoding:name,location:'okio.ByteString.' + name,input:null}});
        return result;
      }); });
    } catch (_) {}
  }
  function installWireWrites() {
    try {
      var R=Java.use('okhttp3.Request$Builder');
      ['header','addHeader'].forEach(function (name) { overloads(R,name,function (original,args) {
        var result=original.apply(this,args);
        sendEvent({kind:'wire',operation_id:lastOperationByThread.get(tid()) || 'unknown',
          observation:{bytes:stringBytes(args[1]),encoding:'header',location:name,input:null}});
        return result;
      }); });
    } catch (_) {}
    try {
      var Q=Java.use('okhttp3.HttpUrl$Builder');
      ['addQueryParameter','addEncodedQueryParameter'].forEach(function (name) { overloads(Q,name,function (original,args) {
        var result=original.apply(this,args);
        sendEvent({kind:'wire',operation_id:lastOperationByThread.get(tid()) || 'unknown',
          observation:{bytes:stringBytes(args[1]),encoding:'query',location:name,input:null}});
        return result;
      }); });
    } catch (_) {}
  }
  function scanNative(module) {
    try {
      module.enumerateExports().filter(function (item) { return item.type === 'function' &&
        /(^|_)(HMAC|EVP_|RSA_|ECDSA_)/.test(item.name); }).forEach(function (item) {
        if (nativeAddresses.has(String(item.address))) return; nativeAddresses.add(String(item.address));
        Interceptor.attach(item.address,{onEnter:function (args) {
          this.symbol=item.name; this.module=module.name; this.thread=tid();
          this.input=safe(function () { return Memory.readByteArray(args[0],64); },null);
        },onLeave:function (retval) { sendEvent({kind:'native_call',symbol:this.symbol,module:this.module,
          thread_id:this.thread,output:this.input ? Array.prototype.slice.call(new Uint8Array(this.input)) : null}); }});
      });
    } catch (_) {}
  }
  function installNative() {
    try {
      var N=Java.use('com.android.org.conscrypt.NativeCrypto');
      Object.keys(N).filter(function (name) { return /HMAC|EVP_Digest|EVP_Cipher|DigestSign/.test(name); })
        .forEach(function (name) { overloads(N,name,function (original,args) {
          sendEvent({kind:'native_call',symbol:name,thread_id:tid()}); return original.apply(this,args);
        }); });
    } catch (_) { diagnostic('crypto.native-symbol-unavailable','Conscrypt NativeCrypto JNI boundary unavailable'); }
    try {
      if (Process.attachModuleObserver) Process.attachModuleObserver({onAdded:function (module) { scanNative(module); }});
      Process.enumerateModules().forEach(scanNative);
    } catch (error) { diagnostic('crypto.native-symbol-unavailable',error); }
  }
  function installRequests() {
    try {
      var Builder=Java.use('okhttp3.Request$Builder');
      overloads(Builder,'build',function (original,args) { var result=original.apply(this,args), thread=tid();
        var context={request_id:'okhttp:' + String(result.url()),flow_id:null,thread_id:thread};
        requests.set(thread,context); sendEvent({kind:'request_context',request_id:context.request_id,
          flow_id:null,thread_id:thread,active:true}); return result; });
    } catch (_) {}
  }
  Java.perform(function () {
    try {
      installMac(); installCipher(); installDigest(); installSignature(); installDerivedKeys();
      installEncoding(); installWireWrites(); installNative(); installRequests();
      sendEvent({kind:'ready',capabilities:['java','native','derived_keys','encoding','request_correlation','early_spawn']});
    } catch (error) { diagnostic('crypto.hook-install-failed',error); }
  });
})();
";

    /// Generates a self-contained payload for the target package.
    #[must_use]
    pub fn generate(package_name: &str) -> String {
        PAYLOAD.replace("__PACKAGE__", package_name)
    }

    /// Converts a payload condition into the catalogue diagnostic.
    #[must_use]
    pub fn diagnostic(id: &str, detail: &str) -> Diagnostic {
        let definition = match id {
            "crypto.native-symbol-unavailable" => catalogue::CRYPTO_NATIVE_SYMBOL_UNAVAILABLE,
            "crypto.anti-hooking-detected" => catalogue::CRYPTO_ANTI_HOOKING_DETECTED,
            "crypto.hook-install-failed" => catalogue::CRYPTO_HOOK_INSTALL_FAILED,
            _ => catalogue::CRYPTO_CAPTURE_RUNTIME_FAILED,
        };
        let mut context = DiagnosticContext::new();
        context.insert(
            "detail".to_owned(),
            DiagnosticValue::String(detail.to_owned()),
        );
        definition.instantiate(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_are_accumulated_in_order_and_correlated_to_flow() {
        let mut collector = CryptoCaptureCollector::default();
        collector
            .apply(request_context_event(41, Some(7), true))
            .expect("request");
        collector
            .apply(CaptureEvent::OperationStart {
                operation_id: "mac:1".into(),
                primitive: Primitive::Mac,
                algorithm: Some("HmacSHA256".into()),
                provider: Some("Conscrypt".into()),
                key: KeyCapture {
                    encoded: Some(vec![0, 1, 255]),
                    exportability: KeyExportability::Exportable,
                    ..KeyCapture::default()
                },
                thread_id: Some(7),
                stacks: Vec::new(),
                request_id: None,
            })
            .expect("start");
        for (bytes, offset) in [(vec![1, 2], 2), (vec![3], 5)] {
            collector
                .apply(CaptureEvent::Update {
                    operation_id: "mac:1".into(),
                    chunk: UpdateChunk {
                        method: "update".into(),
                        bytes,
                        source_offset: Some(offset),
                        source_length: Some(1),
                        byte_buffer: false,
                    },
                    stack: None,
                })
                .expect("update");
        }
        collector
            .apply(CaptureEvent::OperationFinish {
                operation_id: "mac:1".into(),
                output: Some(vec![9]),
                update_outputs: Vec::new(),
                stack: None,
            })
            .expect("finish");
        let record = &collector.records()[0];
        assert_eq!(record.accumulated_message, vec![1, 2, 3]);
        assert_eq!(record.flow_id, Some(41));
        assert_eq!(record.request_id.as_deref(), Some("flow:41"));
    }

    #[test]
    fn key_non_exportability_is_an_info_diagnostic() {
        let diagnostic = key_non_exportable_diagnostic(
            "mac:1",
            Some("HmacSHA256".into()),
            Some("signing".into()),
        );
        assert_eq!(diagnostic.id.as_ref(), "crypto.key-non-exportable");
        assert_eq!(
            diagnostic.context.get("alias"),
            Some(&DiagnosticValue::String("signing".into()))
        );
    }

    #[test]
    fn runtime_key_observations_and_unknown_readiness_events_are_safe() {
        let mut collector = CryptoCaptureCollector::default();
        collector
            .apply_json(r#"{"type":"ready","capabilities":["java","native"]}"#)
            .expect("unknown readiness event");
        collector
            .apply_json(r#"{"type":"key_observation","path":"key_info","algorithm":"AES","key":{"algorithm":"AES","format":"RAW","encoded":null,"exportability":"non_exportable","alias":"a","purposes":4,"security_level":"trusted_environment","hardware_backed":true},"thread_id":8}"#)
            .expect("key observation");
        assert_eq!(collector.key_observations().len(), 1);
        assert_eq!(
            collector.key_observations()[0].key.alias.as_deref(),
            Some("a")
        );
    }

    #[test]
    fn payload_contains_java_native_encoding_and_request_paths() {
        let payload = frida_payload::generate("com.example.app");
        for marker in [
            "javax.crypto.Mac",
            "NativeCrypto",
            "attachModuleObserver",
            "ByteBuffer",
            "request_context",
            "Base64",
        ] {
            assert!(payload.contains(marker), "missing payload marker {marker}");
        }
    }
}
