//! Static request-body schema: a body's declared type resolved to its fields.
//!
//! A JSON body built from an object serializes that object's instance
//! fields. This module reads a class's fields from its apktool smali view
//! (the authoritative, un-decompiled declaration): instance fields only, in
//! declaration order, with superclass fields first, honoring the serialized
//! name from Gson/Moshi/kotlinx/Jackson rename annotations and skipping
//! transient/ignored fields. It never adds a field the class does not
//! declare. A type it cannot resolve to a field set is an opaque body.
//!
//! Only classes from the same package root as the code that uses them are
//! resolved, so a library type (a Gson `JsonObject`, an okhttp `RequestBody`)
//! is never mistaken for a DTO and its internals never become body fields.

use std::collections::{BTreeSet, HashMap};

use apiaxess_network_routing::{CorpusDocument, SignatureCorpus, SourceKind};

/// Upper bound on nested DTO resolution, which also bounds cycles.
const MAX_DEPTH: usize = 3;

/// What static analysis knows about a call's request body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StaticBody {
    /// The call sends no body.
    Absent,
    /// The call sends a body whose fields are not statically known.
    Opaque,
    /// The body's resolved field set.
    Fields(Vec<BodyField>),
}

impl StaticBody {
    /// A body whose top-level keys were written literally in one method.
    pub(crate) fn from_keys(keys: &[crate::java_scope::JsonKey]) -> Self {
        if keys.is_empty() {
            return Self::Opaque;
        }
        Self::Fields(crate::java_scope::key_fields(keys))
    }
}

/// One statically resolved body field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BodyField {
    /// Serialized (wire) name.
    pub(crate) name: String,
    pub(crate) shape: BodyShape,
    /// Only primitives are always present; a reference may serialize as
    /// absent (null), and nullability does not survive into dex.
    pub(crate) required: bool,
}

/// A statically resolved field type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BodyShape {
    Unknown,
    String,
    Integer(Option<&'static str>),
    Number(Option<&'static str>),
    Boolean,
    Array(Box<BodyShape>),
    Object(Vec<BodyField>),
}

#[derive(Clone, Debug)]
struct RawField {
    name: String,
    descriptor: String,
    /// Generic element type from the field's `Signature`, for collections.
    element: Option<String>,
}

#[derive(Clone, Debug)]
struct ClassInfo {
    superclass: Option<String>,
    is_interface: bool,
    is_enum: bool,
    fields: Vec<RawField>,
}

/// Lazily-built index of smali classes, for resolving DTO field sets.
pub(crate) struct DtoIndex<'c> {
    corpus: &'c SignatureCorpus,
    smali: Option<HashMap<String, &'c CorpusDocument>>,
    classes: HashMap<String, Option<ClassInfo>>,
}

impl<'c> DtoIndex<'c> {
    pub(crate) fn new(corpus: &'c SignatureCorpus) -> Self {
        Self {
            corpus,
            smali: None,
            classes: HashMap::new(),
        }
    }

    /// The body sent when an instance of `class` is serialized from code in
    /// `anchor` (a dotted class name).
    pub(crate) fn body(&mut self, class: &str, anchor: &str) -> StaticBody {
        let mut visiting = BTreeSet::new();
        match self.fields(class, anchor, 0, &mut visiting) {
            Some(fields) if !fields.is_empty() => StaticBody::Fields(fields),
            _ => StaticBody::Opaque,
        }
    }

    fn fields(
        &mut self,
        class: &str,
        anchor: &str,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> Option<Vec<BodyField>> {
        if depth >= MAX_DEPTH || !same_root(class, anchor) || !visiting.insert(class.to_owned()) {
            return None;
        }
        let info = self.class(class)?;
        if info.is_interface || info.is_enum {
            visiting.remove(class);
            return None;
        }
        let mut fields = match &info.superclass {
            Some(superclass) if superclass != "java.lang.Object" => self
                .fields(superclass, anchor, depth, visiting)
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        for field in &info.fields {
            if fields.iter().any(|existing| existing.name == field.name) {
                continue;
            }
            fields.push(BodyField {
                name: field.name.clone(),
                shape: self.shape(
                    &field.descriptor,
                    field.element.as_deref(),
                    anchor,
                    depth,
                    visiting,
                ),
                required: is_primitive(&field.descriptor),
            });
        }
        visiting.remove(class);
        Some(fields)
    }

    fn shape(
        &mut self,
        descriptor: &str,
        element: Option<&str>,
        anchor: &str,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> BodyShape {
        match descriptor {
            "I" | "S" | "B" | "Ljava/lang/Integer;" | "Ljava/lang/Short;" | "Ljava/lang/Byte;" => {
                BodyShape::Integer(Some("int32"))
            }
            "J" | "Ljava/lang/Long;" => BodyShape::Integer(Some("int64")),
            "F" | "Ljava/lang/Float;" => BodyShape::Number(Some("float")),
            "D" | "Ljava/lang/Double;" => BodyShape::Number(Some("double")),
            "Ljava/math/BigDecimal;" | "Ljava/lang/Number;" => BodyShape::Number(None),
            "Z" | "Ljava/lang/Boolean;" => BodyShape::Boolean,
            "C" | "Ljava/lang/Character;" | "Ljava/lang/String;" | "Ljava/lang/CharSequence;" => {
                BodyShape::String
            }
            _ => {
                if let Some(item) = descriptor.strip_prefix('[') {
                    return BodyShape::Array(Box::new(
                        self.shape(item, None, anchor, depth, visiting),
                    ));
                }
                if is_collection(descriptor) {
                    let item = element.map_or(BodyShape::Unknown, |item| {
                        self.shape(item, None, anchor, depth, visiting)
                    });
                    return BodyShape::Array(Box::new(item));
                }
                let Some(class) = dotted_class(descriptor) else {
                    return BodyShape::Unknown;
                };
                if self.class(&class).is_some_and(|info| info.is_enum) && same_root(&class, anchor)
                {
                    return BodyShape::String;
                }
                match self.fields(&class, anchor, depth + 1, visiting) {
                    Some(fields) if !fields.is_empty() => BodyShape::Object(fields),
                    _ => BodyShape::Unknown,
                }
            }
        }
    }

    fn class(&mut self, class: &str) -> Option<ClassInfo> {
        if !self.classes.contains_key(class) {
            let corpus = self.corpus;
            let index = self.smali.get_or_insert_with(|| {
                corpus
                    .documents()
                    .iter()
                    .filter(|document| document.source_kind == SourceKind::Smali)
                    .filter_map(|document| Some((smali_path_class(&document.path)?, document)))
                    .collect()
            });
            let info = index
                .get(class)
                .copied()
                .and_then(|document| corpus.text_for(document))
                .map(|text| parse_class(&text));
            self.classes.insert(class.to_owned(), info);
        }
        self.classes.get(class).cloned().flatten()
    }
}

/// The dotted class a smali file declares, from its path under a `smali`
/// or `smali_classesN` root (`…/smali_classes2/a/b/C$D.smali` -> `a.b.C.D`).
fn smali_path_class(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let segments = normalized.split('/').collect::<Vec<_>>();
    let root = segments.iter().rposition(|segment| {
        *segment == "smali"
            || segment
                .strip_prefix("smali_classes")
                .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
    })?;
    let relative = segments[root + 1..].join("/");
    let internal = relative.strip_suffix(".smali")?;
    Some(internal.replace(['/', '$'], "."))
}

/// Two classes share a package root when their first two package segments
/// match (the whole package when it is shorter).
fn same_root(class: &str, anchor: &str) -> bool {
    let root = |name: &str| {
        let segments = name.split('.').collect::<Vec<_>>();
        let package = &segments[..segments.len().saturating_sub(1)];
        package[..package.len().min(2)].join(".")
    };
    let root_of_class = root(class);
    !root_of_class.is_empty() && root_of_class == root(anchor)
}

fn is_primitive(descriptor: &str) -> bool {
    matches!(descriptor, "I" | "J" | "S" | "B" | "F" | "D" | "Z" | "C")
}

fn is_collection(descriptor: &str) -> bool {
    matches!(
        descriptor,
        "Ljava/util/List;"
            | "Ljava/util/ArrayList;"
            | "Ljava/util/LinkedList;"
            | "Ljava/util/Set;"
            | "Ljava/util/HashSet;"
            | "Ljava/util/LinkedHashSet;"
            | "Ljava/util/Collection;"
            | "Ljava/lang/Iterable;"
    )
}

fn dotted_class(descriptor: &str) -> Option<String> {
    let internal = descriptor.strip_prefix('L')?.strip_suffix(';')?;
    Some(internal.replace(['/', '$'], "."))
}

/// Annotations whose `value`/`name` is a field's serialized name.
const RENAME_ANNOTATIONS: [&str; 4] = [
    "Lcom/google/gson/annotations/SerializedName;",
    "Lcom/squareup/moshi/Json;",
    "Lkotlinx/serialization/SerialName;",
    "Lcom/fasterxml/jackson/annotation/JsonProperty;",
];

/// Annotations that keep a field out of the serialized body.
const IGNORE_ANNOTATIONS: [&str; 3] = [
    "Lkotlinx/serialization/Transient;",
    "Lcom/squareup/moshi/Transient;",
    "Lcom/fasterxml/jackson/annotation/JsonIgnore;",
];

fn parse_class(text: &str) -> ClassInfo {
    let mut info = ClassInfo {
        superclass: None,
        is_interface: false,
        is_enum: false,
        fields: Vec::new(),
    };
    let mut current: Option<(RawField, bool)> = None;
    let mut annotation: Option<String> = None;
    let mut in_signature = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(".class ") {
            info.is_interface = rest.split_whitespace().any(|word| word == "interface");
        } else if let Some(rest) = line.strip_prefix(".super ") {
            info.superclass = dotted_class(rest.trim());
            info.is_enum = rest.trim() == "Ljava/lang/Enum;";
        } else if let Some(rest) = line.strip_prefix(".field ") {
            push_field(&mut info, current.take());
            current = parse_field_line(rest).map(|field| (field, false));
        } else if line == ".end field" {
            push_field(&mut info, current.take());
        } else if let Some((field, ignored)) = current.as_mut() {
            if let Some(rest) = line.strip_prefix(".annotation ") {
                let name = rest
                    .split_whitespace()
                    .last()
                    .unwrap_or_default()
                    .to_owned();
                if IGNORE_ANNOTATIONS.contains(&name.as_str()) {
                    *ignored = true;
                }
                in_signature = name == "Ldalvik/annotation/Signature;";
                annotation = Some(name);
            } else if line == ".end annotation" {
                annotation = None;
                in_signature = false;
            } else if in_signature {
                // `"Ljava/util/List<", "La/b/Item;", ">;"`: the element type.
                if field.element.is_none() {
                    let value = line.trim_end_matches(',').trim_matches('"');
                    if value.starts_with('L') && value.ends_with(';') && !value.contains('<') {
                        field.element = Some(value.to_owned());
                    }
                }
            } else if let Some(annotation) = &annotation {
                if RENAME_ANNOTATIONS.contains(&annotation.as_str()) {
                    if let Some((key, value)) = line.split_once('=') {
                        let key = key.trim();
                        let value = value.trim().trim_matches('"');
                        if matches!(key, "value" | "name") && !value.is_empty() {
                            value.clone_into(&mut field.name);
                        }
                    }
                }
            }
        } else if line.starts_with(".method ") {
            push_field(&mut info, current.take());
        }
    }
    push_field(&mut info, current);
    info
}

fn push_field(info: &mut ClassInfo, field: Option<(RawField, bool)>) {
    if let Some((field, false)) = field {
        info.fields.push(field);
    }
}

/// Parses `private final transient name:Ljava/lang/String; = "x"`, keeping
/// only serializable instance fields.
fn parse_field_line(rest: &str) -> Option<RawField> {
    let declaration = rest.split(" = ").next()?;
    let mut words = declaration.split_whitespace().collect::<Vec<_>>();
    let last = words.pop()?;
    if words
        .iter()
        .any(|word| matches!(*word, "static" | "transient" | "synthetic"))
    {
        return None;
    }
    let (name, descriptor) = last.split_once(':')?;
    if name.is_empty() || name.contains('$') {
        return None;
    }
    Some(RawField {
        name: name.to_owned(),
        descriptor: descriptor.to_owned(),
        element: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_data_class_resolves_to_its_serialized_instance_fields() {
        let info = parse_class(
            r#".class public final Lcom/example/net/SignUp;
.super Lcom/example/net/Base;

.field public static final Companion:Lcom/example/net/SignUp$Companion;

.field private final email:Ljava/lang/String;

.field private final fullName:Ljava/lang/String;
    .annotation runtime Lcom/google/gson/annotations/SerializedName;
        value = "full_name"
    .end annotation
.end field

.field private final age:I

.field private final transient cache:Ljava/lang/Object;

.field private final token:Ljava/lang/String;
    .annotation runtime Lkotlinx/serialization/Transient;
    .end annotation
.end field

.field private final tags:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.method public constructor <init>()V
    .registers 1
    return-void
.end method
"#,
        );
        let names = info
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["email", "full_name", "age", "tags"]);
        assert_eq!(info.superclass.as_deref(), Some("com.example.net.Base"));
        assert_eq!(
            info.fields[3].element.as_deref(),
            Some("Ljava/lang/String;")
        );
    }

    #[test]
    fn library_types_are_not_resolved_as_dtos() {
        assert!(same_root(
            "com.example.net.dto.SignUp",
            "com.example.api.Service"
        ));
        assert!(!same_root(
            "com.google.gson.JsonObject",
            "com.example.api.Service"
        ));
        assert!(!same_root("okhttp3.RequestBody", "com.example.api.Service"));
    }

    #[test]
    fn smali_paths_map_to_dotted_class_names() {
        assert_eq!(
            smali_path_class("C:/x/apktool/smali_classes4/com/example/net/Api$Body.smali"),
            Some("com.example.net.Api.Body".to_owned())
        );
        assert_eq!(
            smali_path_class("x/smali/a/B.smali"),
            Some("a.B".to_owned())
        );
    }

    #[test]
    fn keys_written_in_one_method_become_the_field_set() {
        assert_eq!(StaticBody::from_keys(&[]), StaticBody::Opaque);
        assert!(matches!(
            StaticBody::from_keys(&[crate::java_scope::JsonKey {
                name: "event".to_owned(),
                shape: BodyShape::String,
                literal: None,
            }]),
            StaticBody::Fields(fields) if fields[0].name == "event" && fields[0].shape == BodyShape::String
        ));
    }
}
