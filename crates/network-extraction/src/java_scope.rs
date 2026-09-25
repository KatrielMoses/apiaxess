//! Method-scoped call-site resolution over jadx-decompiled Java.
//!
//! jadx output has no `.method` markers, so a line/blob scan attributes URL
//! fragments, verbs and bodies at file granularity and glues pieces from
//! unrelated methods together. This module segments a decompiled class into
//! its methods (brace structure, with anonymous-class bodies carved out into
//! their own methods) and evaluates each method's statements in order. A URL,
//! the HTTP verb and the body are bound to the specific `Request.Builder` or
//! `HttpURLConnection` instance they are applied to, so a call site can only
//! ever be composed from values that flow to it inside the same method.
//!
//! Values that cannot be resolved inside the method become named holes
//! (`{orderId}`), never guesses. Constants are followed through the same file
//! and through other decompiled classes named by `package`/`import` (jadx
//! re-substitutes inlined literals as `SomeClass.CONSTANT`).

use std::collections::{BTreeMap, HashMap};

use apiaxess_network_routing::{CorpusDocument, SignatureCorpus, SourceKind};

/// Upper bound on nested constant resolution, which also breaks cycles.
const MAX_CONSTANT_DEPTH: usize = 4;

/// The HTTP stack a resolved call site belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HttpClient {
    OkHttp,
    UrlConnection,
}

/// One HTTP call site resolved inside a single method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCall {
    pub(crate) client: HttpClient,
    pub(crate) method: String,
    pub(crate) base_url: Option<String>,
    pub(crate) path: String,
    pub(crate) query_names: Vec<String>,
    pub(crate) header_names: Vec<String>,
    pub(crate) has_body: bool,
}

/// The outcome for one call site found in a method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CallSite {
    Resolved(ResolvedCall),
    /// A call site whose URL or explicit verb could not be recovered inside
    /// its method.
    Unresolved {
        client: HttpClient,
        method_name: String,
        missing: Missing,
    },
}

/// What kept a call site from resolving.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Missing {
    Url,
    /// The verb was set from a value this method cannot resolve; defaulting
    /// it would be a guess.
    Verb,
}

impl CallSite {
    pub(crate) fn client(&self) -> HttpClient {
        match self {
            Self::Resolved(call) => call.client,
            Self::Unresolved { client, .. } => *client,
        }
    }
}

/// Whether jadx gave up on at least one method of this class, in which case
/// the Java view is not a complete substitute for the smali view.
pub(crate) fn decompilation_incomplete(text: &str) -> bool {
    text.contains("Method not decompiled") || text.contains("Code decompilation failed")
}

/// The fully-qualified name of the top-level class a decompiled Java file
/// declares, from its `package` line and file name.
pub(crate) fn java_class_name(path: &str, text: &str) -> Option<String> {
    let stem = file_stem(path, ".java")?;
    let tokens = lex(text);
    let package = package_of(&tokens);
    Some(if package.is_empty() {
        stem
    } else {
        format!("{package}.{stem}")
    })
}

/// The fully-qualified outer class a smali file declares (inner classes map
/// to the class that encloses them, as jadx emits them in one file).
pub(crate) fn smali_outer_class_name(text: &str) -> Option<String> {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with(".class "))?;
    let descriptor = line.split_whitespace().last()?;
    let internal = descriptor.strip_prefix('L')?.strip_suffix(';')?;
    let outer = internal.split('$').next()?;
    Some(outer.replace('/', "."))
}

/// Segments `text` into method bodies. Returns `None` when the text is not
/// brace-balanced Java, so callers can fall back to another representation.
pub(crate) fn java_method_texts(text: &str) -> Option<Vec<String>> {
    let tokens = lex(text);
    let file = parse_structure(&tokens)?;
    Some(
        file.methods
            .iter()
            .map(|method| render_tokens(&method.tokens))
            .collect(),
    )
}

/// Resolves every HTTP call site in a decompiled Java document, one method at
/// a time.
///
/// `constants` is shared across the documents of one extraction pass so the
/// corpus index and every loaded class are built once.
pub(crate) fn resolve_call_sites(
    document: &CorpusDocument,
    text: &str,
    constants: &mut ConstantIndex<'_>,
) -> Vec<CallSite> {
    let tokens = lex(text);
    let Some(structure) = parse_structure(&tokens) else {
        return Vec::new();
    };
    let context = FileContext::new(&tokens, &structure, file_stem(&document.path, ".java"));
    constants.seed(&context);
    let mut sites = Vec::new();
    for method in &structure.methods {
        let mut evaluator = MethodEvaluator::new(&context, constants);
        for statement in statements(&method.tokens) {
            evaluator.statement(statement);
        }
        sites.extend(evaluator.finish(&method.name));
    }
    sites
}

/// Collects Retrofit service bindings (`retrofit.create(Service.class)`)
/// from a decompiled Java document, each with the base URL of the specific
/// instance that created it.
pub(crate) fn retrofit_bindings(
    document: &CorpusDocument,
    text: &str,
    constants: &mut ConstantIndex<'_>,
) -> Vec<RetrofitBinding> {
    let tokens = lex(text);
    let Some(structure) = parse_structure(&tokens) else {
        return Vec::new();
    };
    let context = FileContext::new(&tokens, &structure, file_stem(&document.path, ".java"));
    constants.seed(&context);
    let mut bindings = Vec::new();
    for method in &structure.methods {
        let mut evaluator = MethodEvaluator::new(&context, constants);
        for statement in statements(&method.tokens) {
            evaluator.statement(statement);
        }
        bindings.append(&mut evaluator.retrofit_bindings);
    }
    bindings
}

/// The fully-qualified (dotted) class a smali file declares, nested classes
/// included (`a/b/Outer$Api` -> `a.b.Outer.Api`).
pub(crate) fn smali_class_name(text: &str) -> Option<String> {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with(".class "))?;
    let descriptor = line.split_whitespace().last()?;
    let internal = descriptor.strip_prefix('L')?.strip_suffix(';')?;
    Some(internal.replace(['/', '$'], "."))
}

// ---------------------------------------------------------------------------
// Lexing

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Num(String),
    Char,
    Sym(&'static str),
}

impl Tok {
    fn is_sym(&self, symbol: &str) -> bool {
        matches!(self, Self::Sym(value) if *value == symbol)
    }

    fn ident(&self) -> Option<&str> {
        match self {
            Self::Ident(value) => Some(value),
            _ => None,
        }
    }
}

const TWO_CHAR_SYMBOLS: [&str; 18] = [
    "->", "::", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=",
    "|=", "^=",
];
const ONE_CHAR_SYMBOLS: &str = "{}()[];,.=+-*/%<>!?:&|^~@";

fn lex(text: &str) -> Vec<Tok> {
    let chars = text.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        let next = chars.get(index + 1).copied();
        if character.is_whitespace() {
            index += 1;
        } else if character == '/' && next == Some('/') {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
        } else if character == '/' && next == Some('*') {
            index += 2;
            while index < chars.len()
                && !(chars[index] == '*' && chars.get(index + 1) == Some(&'/'))
            {
                index += 1;
            }
            index += 2;
        } else if character == '"' {
            if next == Some('"') && chars.get(index + 2) == Some(&'"') {
                // Text block: taken verbatim up to the closing delimiter.
                let start = index + 3;
                let mut end = start;
                while end < chars.len()
                    && !(chars[end] == '"'
                        && chars.get(end + 1) == Some(&'"')
                        && chars.get(end + 2) == Some(&'"'))
                {
                    end += 1;
                }
                tokens.push(Tok::Str(
                    chars[start..end.min(chars.len())].iter().collect(),
                ));
                index = end + 3;
            } else {
                let (value, end) = lex_string(&chars, index + 1);
                tokens.push(Tok::Str(value));
                index = end;
            }
        } else if character == '\'' {
            index += 1;
            while index < chars.len() && chars[index] != '\'' {
                if chars[index] == '\\' {
                    index += 1;
                }
                index += 1;
            }
            index += 1;
            tokens.push(Tok::Char);
        } else if character.is_ascii_digit() {
            let start = index;
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric()
                    || chars[index] == '.'
                    || chars[index] == '_')
            {
                index += 1;
            }
            tokens.push(Tok::Num(chars[start..index].iter().collect()));
        } else if character.is_alphabetic() || character == '_' || character == '$' {
            let start = index;
            while index < chars.len()
                && (chars[index].is_alphanumeric() || chars[index] == '_' || chars[index] == '$')
            {
                index += 1;
            }
            tokens.push(Tok::Ident(chars[start..index].iter().collect()));
        } else {
            let pair = next.map(|next| [character, next].iter().collect::<String>());
            if let Some(symbol) = pair
                .as_deref()
                .and_then(|pair| TWO_CHAR_SYMBOLS.iter().find(|symbol| **symbol == pair))
            {
                tokens.push(Tok::Sym(symbol));
                index += 2;
            } else {
                if let Some(offset) = ONE_CHAR_SYMBOLS.find(character) {
                    tokens.push(Tok::Sym(&ONE_CHAR_SYMBOLS[offset..=offset]));
                }
                index += 1;
            }
        }
    }
    tokens
}

fn lex_string(chars: &[char], mut index: usize) -> (String, usize) {
    let mut value = String::new();
    while index < chars.len() && chars[index] != '"' && chars[index] != '\n' {
        if chars[index] == '\\' && index + 1 < chars.len() {
            index += 1;
            match chars[index] {
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                'b' => value.push('\u{8}'),
                'f' => value.push('\u{c}'),
                'u' => {
                    while chars.get(index) == Some(&'u') {
                        index += 1;
                    }
                    let hex = chars[index..(index + 4).min(chars.len())]
                        .iter()
                        .collect::<String>();
                    if let Some(decoded) =
                        u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                    {
                        value.push(decoded);
                    }
                    index += 3;
                }
                '0'..='7' => {
                    let start = index;
                    while index < chars.len() && index - start < 3 && chars[index].is_digit(8) {
                        index += 1;
                    }
                    let octal = chars[start..index].iter().collect::<String>();
                    if let Some(decoded) =
                        u32::from_str_radix(&octal, 8).ok().and_then(char::from_u32)
                    {
                        value.push(decoded);
                    }
                    index -= 1;
                }
                other => value.push(other),
            }
        } else {
            value.push(chars[index]);
        }
        index += 1;
    }
    (value, index + 1)
}

fn render_tokens(tokens: &[Tok]) -> String {
    let mut out = String::new();
    for token in tokens {
        match token {
            Tok::Ident(value) | Tok::Num(value) => {
                if out
                    .chars()
                    .last()
                    .is_some_and(|last| last.is_alphanumeric() || last == '_' || last == '$')
                {
                    out.push(' ');
                }
                out.push_str(value);
            }
            Tok::Str(value) => {
                out.push('"');
                for character in value.chars() {
                    match character {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        other => out.push(other),
                    }
                }
                out.push('"');
            }
            Tok::Char => out.push_str("' '"),
            Tok::Sym(symbol) => {
                out.push_str(symbol);
                if matches!(*symbol, ";" | "{" | "}") {
                    out.push('\n');
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Structure: brace tree, method bodies, class-level fields

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BraceKind {
    Method,
    Container,
    Block,
}

struct BraceNode {
    open: usize,
    close: usize,
    kind: BraceKind,
    name: String,
    children: Vec<usize>,
}

struct MethodTokens {
    name: String,
    tokens: Vec<Tok>,
}

struct FileStructure {
    methods: Vec<MethodTokens>,
    /// Class-level statements (field declarations) of every class in the file.
    fields: Vec<Vec<Tok>>,
}

const CONTROL_KEYWORDS: [&str; 10] = [
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "synchronized",
    "try",
    "do",
    "else",
    "return",
];

fn parse_structure(tokens: &[Tok]) -> Option<FileStructure> {
    let mut nodes: Vec<BraceNode> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut roots = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.is_sym("{") {
            let (kind, name) = classify_brace(tokens, index);
            nodes.push(BraceNode {
                open: index,
                close: index,
                kind,
                name,
                children: Vec::new(),
            });
            let node = nodes.len() - 1;
            match stack.last() {
                Some(parent) => nodes[*parent].children.push(node),
                None => roots.push(node),
            }
            stack.push(node);
        } else if token.is_sym("}") {
            let node = stack.pop()?;
            nodes[node].close = index;
        }
    }
    if !stack.is_empty() {
        return None;
    }
    let mut structure = FileStructure {
        methods: Vec::new(),
        fields: Vec::new(),
    };
    for node in 0..nodes.len() {
        match nodes[node].kind {
            BraceKind::Method => {
                let mut body = Vec::new();
                collect_body(tokens, &nodes, node, &mut body);
                structure.methods.push(MethodTokens {
                    name: nodes[node].name.clone(),
                    tokens: body,
                });
            }
            BraceKind::Container => {
                structure
                    .fields
                    .extend(container_fields(tokens, &nodes, node));
            }
            BraceKind::Block => {}
        }
    }
    Some(structure)
}

/// Collects a method body's tokens, flattening nested blocks and skipping
/// nested methods and anonymous/local class bodies (they are their own scope).
fn collect_body(tokens: &[Tok], nodes: &[BraceNode], node: usize, out: &mut Vec<Tok>) {
    let mut cursor = nodes[node].open + 1;
    for child in &nodes[node].children {
        let child_node = &nodes[*child];
        out.extend_from_slice(&tokens[cursor..child_node.open]);
        if child_node.kind == BraceKind::Block {
            out.push(Tok::Sym("{"));
            collect_body(tokens, nodes, *child, out);
            out.push(Tok::Sym("}"));
        } else {
            // Keep the statement shape (`x = new Foo() ;`) without the body.
            out.push(Tok::Sym("{"));
            out.push(Tok::Sym("}"));
        }
        cursor = child_node.close + 1;
    }
    out.extend_from_slice(&tokens[cursor..nodes[node].close]);
}

fn container_fields(tokens: &[Tok], nodes: &[BraceNode], node: usize) -> Vec<Vec<Tok>> {
    let mut fields = Vec::new();
    let mut current = Vec::new();
    let mut cursor = nodes[node].open + 1;
    let push_range = |range: &[Tok], current: &mut Vec<Tok>, fields: &mut Vec<Vec<Tok>>| {
        for token in range {
            if token.is_sym(";") {
                fields.push(std::mem::take(current));
            } else {
                current.push(token.clone());
            }
        }
    };
    for child in &nodes[node].children {
        let child_node = &nodes[*child];
        push_range(&tokens[cursor..child_node.open], &mut current, &mut fields);
        match child_node.kind {
            // An anonymous class initializer keeps its statement going.
            BraceKind::Container if current.iter().any(|token| token.is_sym("=")) => {}
            _ => current.clear(),
        }
        cursor = child_node.close + 1;
    }
    push_range(
        &tokens[cursor..nodes[node].close],
        &mut current,
        &mut fields,
    );
    fields
}

fn classify_brace(tokens: &[Tok], open: usize) -> (BraceKind, String) {
    let mut start = open;
    while start > 0 && !matches!(&tokens[start - 1], Tok::Sym(";" | "{" | "}")) {
        start -= 1;
    }
    let mut header = &tokens[start..open];
    if header.iter().enumerate().any(|(index, token)| {
        matches!(
            token.ident(),
            Some("class" | "interface" | "enum" | "record")
        ) && !(index > 0 && header[index - 1].is_sym("."))
    }) {
        return (BraceKind::Container, String::new());
    }
    if header.len() == 1 && header[0].ident() == Some("static") {
        return (BraceKind::Method, "<clinit>".to_owned());
    }
    // Drop a `throws A, b.C` clause.
    let mut depth = 0_i32;
    for (index, token) in header.iter().enumerate() {
        match token {
            Tok::Sym("(") => depth += 1,
            Tok::Sym(")") => depth -= 1,
            Tok::Ident(value) if value == "throws" && depth == 0 => {
                header = &header[..index];
                break;
            }
            _ => {}
        }
    }
    if !header.last().is_some_and(|token| token.is_sym(")")) {
        return (BraceKind::Block, String::new());
    }
    let Some(paren) = matching_open_paren(header, header.len() - 1) else {
        return (BraceKind::Block, String::new());
    };
    if paren == 0 {
        return (BraceKind::Block, String::new());
    }
    let Some(name) = header[paren - 1].ident() else {
        return (BraceKind::Block, String::new());
    };
    if CONTROL_KEYWORDS.contains(&name) {
        return (BraceKind::Block, String::new());
    }
    // `new a.b.Foo(...) {` is an anonymous class body.
    let mut back = paren - 1;
    while back >= 2 && header[back - 1].is_sym(".") && header[back - 2].ident().is_some() {
        back -= 2;
    }
    if back > 0 && header[back - 1].ident() == Some("new") {
        return (BraceKind::Container, String::new());
    }
    if back > 0 && header[back - 1].is_sym(".") {
        return (BraceKind::Block, String::new());
    }
    (BraceKind::Method, name.to_owned())
}

fn matching_open_paren(tokens: &[Tok], close: usize) -> Option<usize> {
    let mut depth = 0_i32;
    for index in (0..=close).rev() {
        if tokens[index].is_sym(")") {
            depth += 1;
        } else if tokens[index].is_sym("(") {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

/// Splits a flattened method body into statements. Braces are statement
/// boundaries too, so statements inside lambda and control blocks are visited
/// in source order.
fn statements(tokens: &[Tok]) -> impl Iterator<Item = &[Tok]> {
    tokens
        .split(|token| matches!(token, Tok::Sym(";" | "{" | "}")))
        .filter(|statement| !statement.is_empty())
}

fn package_of(tokens: &[Tok]) -> String {
    let Some(start) = tokens
        .iter()
        .position(|token| token.ident() == Some("package"))
    else {
        return String::new();
    };
    dotted_until_semicolon(&tokens[start + 1..])
}

fn dotted_until_semicolon(tokens: &[Tok]) -> String {
    let mut out = String::new();
    for token in tokens {
        match token {
            Tok::Ident(value) => out.push_str(value),
            Tok::Sym(".") => out.push('.'),
            Tok::Sym("*") => out.push('*'),
            _ => break,
        }
    }
    out
}

fn file_stem(path: &str, extension: &str) -> Option<String> {
    let name = path.rsplit(['/', '\\']).next()?;
    name.strip_suffix(extension).map(ToOwned::to_owned)
}

// ---------------------------------------------------------------------------
// Expressions

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Str(String),
    Num(String),
    /// A dotted name with no call: `x`, `Foo.BAR`, `this.baseUrl`.
    Name(Vec<String>),
    Call {
        receiver: Option<Box<Expr>>,
        name: String,
        args: Vec<Expr>,
    },
    New {
        ty: Vec<String>,
        args: Vec<Expr>,
    },
    Concat(Vec<Expr>),
    Other,
}

fn split_top_level<'a>(tokens: &'a [Tok], separator: &str) -> Vec<&'a [Tok]> {
    let mut parts = Vec::new();
    let mut depth = 0_i32;
    let mut start = 0;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Tok::Sym("(" | "[") => depth += 1,
            Tok::Sym(")" | "]") => depth -= 1,
            Tok::Sym(symbol) if *symbol == separator && depth == 0 => {
                parts.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&tokens[start..]);
    parts
}

fn has_top_level(tokens: &[Tok], symbols: &[&str]) -> bool {
    let mut depth = 0_i32;
    tokens.iter().any(|token| {
        match token {
            Tok::Sym("(" | "[") => depth += 1,
            Tok::Sym(")" | "]") => depth -= 1,
            _ => {}
        }
        depth == 0 && matches!(token, Tok::Sym(symbol) if symbols.contains(symbol))
    })
}

fn parse_expr(tokens: &[Tok]) -> Expr {
    if tokens.is_empty()
        || has_top_level(
            tokens,
            &["?", "==", "!=", "&&", "||", "->", "::", "=", "-", "*", "/"],
        )
    {
        return Expr::Other;
    }
    let parts = split_top_level(tokens, "+");
    if parts.len() > 1 {
        if parts.iter().any(|part| part.is_empty()) {
            return Expr::Other;
        }
        return Expr::Concat(parts.into_iter().map(parse_expr).collect());
    }
    parse_postfix(tokens)
}

fn parse_args(tokens: &[Tok]) -> Vec<Expr> {
    if tokens.is_empty() {
        return Vec::new();
    }
    split_top_level(tokens, ",")
        .into_iter()
        .map(parse_expr)
        .collect()
}

fn matching_close(tokens: &[Tok], open: usize) -> Option<usize> {
    let mut depth = 0_i32;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        if token.is_sym("(") {
            depth += 1;
        } else if token.is_sym(")") {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

/// Whether `tokens` (the inside of a parenthesis) is a cast type.
fn is_type(tokens: &[Tok]) -> bool {
    !tokens.is_empty()
        && tokens.iter().all(|token| {
            matches!(
                token,
                Tok::Ident(_) | Tok::Sym("." | "<" | ">" | "[" | "]" | ",")
            )
        })
        && tokens[0].ident().is_some()
}

/// Parses `new a.b.Type<...>(args) [{ }]` at the start of `tokens`, returning
/// the expression and the index just past it.
fn parse_new(tokens: &[Tok]) -> Option<(Expr, usize)> {
    let mut ty = Vec::new();
    let mut index = 1;
    while let Some(Tok::Ident(segment)) = tokens.get(index) {
        ty.push(segment.clone());
        index += 1;
        if tokens.get(index).is_some_and(|token| token.is_sym(".")) {
            index += 1;
        } else {
            break;
        }
    }
    // Skip generic arguments.
    if tokens.get(index).is_some_and(|token| token.is_sym("<")) {
        let mut depth = 0_i32;
        while let Some(token) = tokens.get(index) {
            if token.is_sym("<") {
                depth += 1;
            } else if token.is_sym(">") {
                depth -= 1;
            }
            index += 1;
            if depth == 0 {
                break;
            }
        }
    }
    if !tokens.get(index).is_some_and(|token| token.is_sym("(")) {
        return None;
    }
    let close = matching_close(tokens, index)?;
    let args = parse_args(&tokens[index + 1..close]);
    index = close + 1;
    // An anonymous class body left as `{ }` by body collection.
    if tokens.get(index).is_some_and(|token| token.is_sym("{")) {
        index += 2;
    }
    Some((Expr::New { ty, args }, index))
}

fn parse_postfix(tokens: &[Tok]) -> Expr {
    let mut index;
    // Casts and grouping.
    let mut expr = if tokens[0].is_sym("(") {
        let Some(close) = matching_close(tokens, 0) else {
            return Expr::Other;
        };
        if close + 1 == tokens.len() {
            return parse_expr(&tokens[1..close]);
        }
        if is_type(&tokens[1..close]) {
            return parse_postfix(&tokens[close + 1..]);
        }
        index = close + 1;
        parse_expr(&tokens[1..close])
    } else {
        match &tokens[0] {
            Tok::Str(value) => {
                index = 1;
                Expr::Str(value.clone())
            }
            Tok::Num(value) => {
                index = 1;
                Expr::Num(value.clone())
            }
            Tok::Ident(value) if value == "new" => {
                let Some((expr, end)) = parse_new(tokens) else {
                    return Expr::Other;
                };
                index = end;
                expr
            }
            Tok::Ident(value) => {
                index = 1;
                if tokens.get(1).is_some_and(|token| token.is_sym("(")) {
                    let Some(close) = matching_close(tokens, 1) else {
                        return Expr::Other;
                    };
                    index = close + 1;
                    Expr::Call {
                        receiver: None,
                        name: value.clone(),
                        args: parse_args(&tokens[2..close]),
                    }
                } else {
                    Expr::Name(vec![value.clone()])
                }
            }
            _ => return Expr::Other,
        }
    };
    while index < tokens.len() {
        if !tokens[index].is_sym(".") {
            return Expr::Other;
        }
        let Some(Tok::Ident(name)) = tokens.get(index + 1) else {
            return Expr::Other;
        };
        index += 2;
        if tokens.get(index).is_some_and(|token| token.is_sym("(")) {
            let Some(close) = matching_close(tokens, index) else {
                return Expr::Other;
            };
            let args = parse_args(&tokens[index + 1..close]);
            index = close + 1;
            expr = Expr::Call {
                receiver: Some(Box::new(expr)),
                name: name.clone(),
                args,
            };
        } else {
            expr = match expr {
                Expr::Name(mut segments) => {
                    segments.push(name.clone());
                    Expr::Name(segments)
                }
                _ => Expr::Other,
            };
        }
    }
    expr
}

// ---------------------------------------------------------------------------
// File context and constants

struct FileContext {
    package: String,
    class_name: Option<String>,
    /// Simple name -> fully-qualified name.
    imports: HashMap<String, String>,
    wildcard_imports: Vec<String>,
    /// `final` fields with an initializer, by field name.
    constants: HashMap<String, Expr>,
}

impl FileContext {
    fn new(tokens: &[Tok], structure: &FileStructure, stem: Option<String>) -> Self {
        let package = package_of(tokens);
        let mut imports = HashMap::new();
        let mut wildcard_imports = Vec::new();
        for (index, token) in tokens.iter().enumerate() {
            if token.ident() != Some("import") {
                continue;
            }
            if tokens
                .get(index + 1)
                .is_some_and(|token| token.ident() == Some("static"))
            {
                continue;
            }
            let name = dotted_until_semicolon(&tokens[index + 1..]);
            if let Some(prefix) = name.strip_suffix(".*") {
                wildcard_imports.push(prefix.to_owned());
            } else if let Some(simple) = name.rsplit('.').next() {
                imports.insert(simple.to_owned(), name.clone());
            }
        }
        let mut constants = HashMap::new();
        for field in &structure.fields {
            let Some(assign) = field.iter().position(|token| token.is_sym("=")) else {
                continue;
            };
            let modifiers = &field[..assign];
            if !modifiers.iter().any(|token| token.ident() == Some("final")) {
                continue;
            }
            let Some(Tok::Ident(name)) = modifiers.last() else {
                continue;
            };
            constants
                .entry(name.clone())
                .or_insert_with(|| parse_expr(&field[assign + 1..]));
        }
        let class_name = stem.map(|stem| {
            if package.is_empty() {
                stem
            } else {
                format!("{package}.{stem}")
            }
        });
        Self {
            package,
            class_name,
            imports,
            wildcard_imports,
            constants,
        }
    }

    /// Candidate fully-qualified class names for a simple or dotted class
    /// reference written in this file.
    fn class_candidates(&self, segments: &[String]) -> Vec<String> {
        let Some(first) = segments.first() else {
            return Vec::new();
        };
        let rest = segments[1..].join(".");
        let with_rest = |outer: String| {
            if rest.is_empty() {
                outer
            } else {
                format!("{outer}.{rest}")
            }
        };
        let mut candidates = Vec::new();
        if let Some(fq) = self.imports.get(first) {
            candidates.push(with_rest(fq.clone()));
        }
        if !self.package.is_empty() {
            candidates.push(with_rest(format!("{}.{first}", self.package)));
        }
        for prefix in &self.wildcard_imports {
            candidates.push(with_rest(format!("{prefix}.{first}")));
        }
        candidates.push(segments.join("."));
        candidates
    }

    /// Whether a type written as `segments` in this file is the given
    /// fully-qualified type.
    fn type_is(&self, segments: &[String], fq: &str) -> bool {
        let written = segments.join(".");
        written == fq
            || self
                .class_candidates(segments)
                .iter()
                .any(|candidate| candidate == fq)
    }
}

struct LoadedClass {
    context: FileContext,
}

/// Lazily-built lookup of class constants across decompiled documents.
pub(crate) struct ConstantIndex<'c> {
    corpus: &'c SignatureCorpus,
    /// Decompiled documents by file stem, built on first cross-file lookup.
    by_stem: Option<HashMap<String, Vec<&'c CorpusDocument>>>,
    /// Loaded outer classes by fully-qualified name.
    classes: HashMap<String, Option<LoadedClass>>,
    seeded: Option<String>,
}

impl<'c> ConstantIndex<'c> {
    pub(crate) fn new(corpus: &'c SignatureCorpus) -> Self {
        Self {
            corpus,
            by_stem: None,
            classes: HashMap::new(),
            seeded: None,
        }
    }

    fn seed(&mut self, context: &FileContext) {
        self.seeded.clone_from(&context.class_name);
    }

    fn document_for(&mut self, fq: &str) -> Option<&'c CorpusDocument> {
        let corpus = self.corpus;
        let by_stem = self.by_stem.get_or_insert_with(|| {
            let mut map: HashMap<String, Vec<&'c CorpusDocument>> = HashMap::new();
            for document in corpus.documents() {
                if document.source_kind == SourceKind::DecompiledSource {
                    if let Some(stem) = file_stem(&document.path, ".java") {
                        map.entry(stem).or_default().push(document);
                    }
                }
            }
            map
        });
        let stem = fq.rsplit('.').next()?;
        let suffix = format!("{}.java", fq.replace('.', "/"));
        by_stem
            .get(stem)?
            .iter()
            .copied()
            .find(|document| document.path.replace('\\', "/").ends_with(&suffix))
    }

    /// Resolves `Class.FIELD` (or a Kotlin object/companion getter for it)
    /// written in `from`.
    fn lookup(
        &mut self,
        from: &FileContext,
        class: &[String],
        field: &str,
    ) -> Option<(Expr, String)> {
        for candidate in from.class_candidates(class) {
            // Try the named class, then each enclosing class (nested classes
            // are emitted into their outer class's file).
            let mut outer = candidate.as_str();
            loop {
                if self.seeded.as_deref() == Some(outer) {
                    if let Some(expr) = from.constants.get(field) {
                        return Some((expr.clone(), outer.to_owned()));
                    }
                } else if let Some(expr) = self.class_constant(outer, field) {
                    return Some((expr, outer.to_owned()));
                }
                match outer.rfind('.') {
                    Some(dot) => outer = &outer[..dot],
                    None => break,
                }
            }
        }
        None
    }

    fn class_constant(&mut self, fq: &str, field: &str) -> Option<Expr> {
        if !self.classes.contains_key(fq) {
            let loaded = self.document_for(fq).and_then(|document| {
                let text = self.corpus.text_for(document)?;
                let tokens = lex(&text);
                let structure = parse_structure(&tokens)?;
                Some(LoadedClass {
                    context: FileContext::new(
                        &tokens,
                        &structure,
                        file_stem(&document.path, ".java"),
                    ),
                })
            });
            self.classes.insert(fq.to_owned(), loaded);
        }
        self.classes
            .get(fq)
            .and_then(Option::as_ref)
            .and_then(|class| class.context.constants.get(field).cloned())
    }
}

// ---------------------------------------------------------------------------
// Values and evaluation

#[derive(Clone, Debug, PartialEq)]
enum Part {
    Lit(String),
    Hole(String),
}

#[derive(Clone, Debug, Default, PartialEq)]
struct UrlParts {
    scheme: Option<String>,
    host: Option<Vec<Part>>,
    port: Option<String>,
    segments: Vec<Vec<Part>>,
    query_names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
enum Val {
    Str(Vec<Part>),
    HttpUrl(UrlParts),
    ReqBuilder(usize),
    Request(usize),
    JavaUrl(Vec<Part>),
    Conn(usize),
    /// An `okhttp3.Response.Builder`: a response synthesized in-process.
    ResponseBuilder,
    /// A `retrofit2.Retrofit.Builder` with its base URL, when it resolves.
    RetrofitBuilder(Option<String>),
    /// A built `retrofit2.Retrofit` instance with its base URL.
    Retrofit(Option<String>),
    Json,
    Unknown(String),
}

#[derive(Clone, Debug)]
struct Site {
    client: HttpClient,
    url: Option<Val>,
    verb: Verb,
    headers: Vec<String>,
    has_body: bool,
    does_output: bool,
    /// The request only labels a synthesized response and is never sent.
    synthetic: bool,
}

/// The verb bound to a call site.
#[derive(Clone, Debug)]
enum Verb {
    /// No verb call: the stack's default applies.
    Default,
    Known(String),
    /// An explicit verb was set from a value this method cannot resolve.
    Unresolved,
}

impl Site {
    fn new(client: HttpClient) -> Self {
        Self {
            client,
            url: None,
            verb: Verb::Default,
            headers: Vec::new(),
            has_body: false,
            does_output: false,
            synthetic: false,
        }
    }
}

struct MethodEvaluator<'a, 'c> {
    file: &'a FileContext,
    constants: &'a mut ConstantIndex<'c>,
    locals: HashMap<String, Val>,
    sites: Vec<Site>,
    /// `retrofit.create(Service.class)` bindings: service class -> base URL.
    retrofit_bindings: Vec<RetrofitBinding>,
}

/// One Retrofit service interface bound to the instance that created it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetrofitBinding {
    /// Fully-qualified (dotted) service interface name.
    pub(crate) service: String,
    /// The creating instance's base URL; `None` when it does not resolve.
    pub(crate) base_url: Option<String>,
}

const OKHTTP_REQUEST_BUILDER: &str = "okhttp3.Request.Builder";
const OKHTTP_RESPONSE_BUILDER: &str = "okhttp3.Response.Builder";
const RETROFIT_BUILDER: &str = "retrofit2.Retrofit.Builder";
const OKHTTP_HTTP_URL: &str = "okhttp3.HttpUrl";
const OKHTTP_HTTP_URL_BUILDER: &str = "okhttp3.HttpUrl.Builder";
const JAVA_NET_URL: &str = "java.net.URL";

impl<'a, 'c> MethodEvaluator<'a, 'c> {
    fn new(file: &'a FileContext, constants: &'a mut ConstantIndex<'c>) -> Self {
        Self {
            file,
            constants,
            locals: HashMap::new(),
            sites: Vec::new(),
            retrofit_bindings: Vec::new(),
        }
    }

    fn statement(&mut self, tokens: &[Tok]) {
        let tokens = match tokens.first().and_then(Tok::ident) {
            Some("return" | "throw") => &tokens[1..],
            _ => tokens,
        };
        if tokens.is_empty() {
            return;
        }
        let mut depth = 0_i32;
        let mut assign = None;
        for (index, token) in tokens.iter().enumerate() {
            match token {
                Tok::Sym("(" | "[") => depth += 1,
                Tok::Sym(")" | "]") => depth -= 1,
                Tok::Sym("=" | "+=") if depth == 0 => {
                    assign = Some(index);
                    break;
                }
                _ => {}
            }
        }
        let Some(assign) = assign else {
            let expr = parse_expr(tokens);
            self.eval(&expr, 0);
            return;
        };
        let Some(Tok::Ident(name)) = tokens[..assign].last() else {
            return;
        };
        let value = self.eval(&parse_expr(&tokens[assign + 1..]), 0);
        let value = if tokens[assign].is_sym("+=") {
            let previous = self
                .locals
                .get(name)
                .cloned()
                .unwrap_or_else(|| Val::Unknown(name.clone()));
            Val::Str(concat_parts(&[previous, value]))
        } else {
            value
        };
        self.locals.insert(name.clone(), value);
    }

    fn eval(&mut self, expr: &Expr, depth: usize) -> Val {
        match expr {
            Expr::Str(value) | Expr::Num(value) => Val::Str(vec![Part::Lit(value.clone())]),
            Expr::Concat(parts) => {
                let values = parts
                    .iter()
                    .map(|part| self.eval(part, depth))
                    .collect::<Vec<_>>();
                Val::Str(concat_parts(&values))
            }
            Expr::Name(segments) => self.eval_name(segments, depth),
            Expr::New { ty, args } => self.eval_new(ty, args, depth),
            Expr::Call {
                receiver,
                name,
                args,
            } => self.eval_call(receiver.as_deref(), name, args, depth),
            Expr::Other => Val::Unknown("value".to_owned()),
        }
    }

    fn eval_name(&mut self, segments: &[String], depth: usize) -> Val {
        let hint = segments.last().cloned().unwrap_or_default();
        let local = match segments {
            [only] => Some(only),
            [this, field] if this == "this" => Some(field),
            _ => None,
        };
        if let Some(local) = local {
            if let Some(value) = self.locals.get(local) {
                return value.clone();
            }
            if let Some(expr) = self.file.constants.get(local).cloned() {
                return self.eval_constant(&expr, None, depth, &hint);
            }
            return Val::Unknown(hint);
        }
        if self.locals.contains_key(&segments[0]) {
            return Val::Unknown(hint);
        }
        let (class, field) = segments.split_at(segments.len() - 1);
        self.constant(class, &field[0], depth)
            .unwrap_or(Val::Unknown(hint))
    }

    fn constant(&mut self, class: &[String], field: &str, depth: usize) -> Option<Val> {
        if depth >= MAX_CONSTANT_DEPTH {
            return None;
        }
        let (expr, owner) = self.constants.lookup(self.file, class, field)?;
        Some(self.eval_constant(&expr, Some(&owner), depth, field))
    }

    /// Evaluates a class constant in its declaring file's scope.
    fn eval_constant(&mut self, expr: &Expr, owner: Option<&str>, depth: usize, hint: &str) -> Val {
        if depth >= MAX_CONSTANT_DEPTH {
            return Val::Unknown(hint.to_owned());
        }
        // Only plain string composition is followed for constants, plus a
        // Retrofit instance held in a field of this class (evaluated in a
        // scratch scope so a field initializer never adds call sites here).
        if !matches!(
            expr,
            Expr::Str(_) | Expr::Num(_) | Expr::Concat(_) | Expr::Name(_)
        ) {
            if owner.is_none() && matches!(expr, Expr::New { .. } | Expr::Call { .. }) {
                let mut scratch = MethodEvaluator::new(self.file, self.constants);
                return match scratch.eval(expr, depth + 1) {
                    value @ (Val::Retrofit(_) | Val::RetrofitBuilder(_)) => value,
                    _ => Val::Unknown(hint.to_owned()),
                };
            }
            return Val::Unknown(hint.to_owned());
        }
        let foreign = owner.filter(|owner| self.file.class_name.as_deref() != Some(*owner));
        let value = match foreign {
            // A foreign constant's own bare references (`A = B + "/x"`) belong
            // to its declaring class, so qualify them before evaluating.
            Some(owner) => self.eval(&qualify(expr, owner), depth + 1),
            None => self.eval(expr, depth + 1),
        };
        match value {
            Val::Str(parts) => Val::Str(parts),
            _ => Val::Unknown(hint.to_owned()),
        }
    }

    fn eval_new(&mut self, ty: &[String], args: &[Expr], depth: usize) -> Val {
        if self.file.type_is(ty, OKHTTP_REQUEST_BUILDER) {
            self.sites.push(Site::new(HttpClient::OkHttp));
            return Val::ReqBuilder(self.sites.len() - 1);
        }
        if self.file.type_is(ty, RETROFIT_BUILDER) {
            return Val::RetrofitBuilder(None);
        }
        if self.file.type_is(ty, OKHTTP_RESPONSE_BUILDER) {
            return Val::ResponseBuilder;
        }
        if self.file.type_is(ty, OKHTTP_HTTP_URL_BUILDER) {
            return Val::HttpUrl(UrlParts::default());
        }
        if self.file.type_is(ty, JAVA_NET_URL) {
            let values = args
                .iter()
                .map(|arg| self.eval(arg, depth))
                .collect::<Vec<_>>();
            return match values.as_slice() {
                [Val::Str(spec)] => Val::JavaUrl(spec.clone()),
                [Val::JavaUrl(context), Val::Str(spec)] => {
                    Val::JavaUrl(resolve_relative(context, spec))
                }
                [Val::Str(protocol), Val::Str(host), .., Val::Str(file)] => {
                    let mut parts = protocol.clone();
                    parts.push(Part::Lit("://".to_owned()));
                    parts.extend(host.iter().cloned());
                    parts.extend(file.iter().cloned());
                    Val::JavaUrl(parts)
                }
                _ => Val::Unknown("url".to_owned()),
            };
        }
        match ty.last().map(String::as_str) {
            Some("StringBuilder" | "StringBuffer") => match args.first() {
                Some(arg) => match self.eval(arg, depth) {
                    Val::Str(parts) => Val::Str(parts),
                    _ => Val::Str(Vec::new()),
                },
                None => Val::Str(Vec::new()),
            },
            Some("String") => match args.first().map(|arg| self.eval(arg, depth)) {
                Some(Val::Str(parts)) => Val::Str(parts),
                _ => Val::Unknown("value".to_owned()),
            },
            Some("JSONObject") => Val::Json,
            Some(other) => Val::Unknown(lower_first(other)),
            None => Val::Unknown("value".to_owned()),
        }
    }

    fn eval_call(
        &mut self,
        receiver: Option<&Expr>,
        name: &str,
        args: &[Expr],
        depth: usize,
    ) -> Val {
        // Kotlin default-argument bridges: `Type.name$default(receiver, ...)`.
        if let Some(base) = name.strip_suffix("$default") {
            if let (Some(Expr::Name(_)), Some((first, rest))) = (receiver, args.split_first()) {
                return self.eval_call(Some(first), base, rest, depth);
            }
        }
        // Static helpers on a named class.
        if let Some(Expr::Name(segments)) = receiver {
            let is_local = self.locals.contains_key(&segments[0])
                || (segments[0] == "this" && segments.len() == 2);
            if !is_local {
                if let Some(value) = self.eval_static(segments, name, args, depth) {
                    return value;
                }
            }
        }
        let target = match receiver {
            Some(receiver) => self.eval(receiver, depth),
            None => Val::Unknown(getter_hint(name)),
        };
        match target {
            Val::ReqBuilder(site) => self.builder_call(site, name, args, depth),
            Val::Request(site) if name == "newBuilder" => {
                let copy = self.sites[site].clone();
                self.sites.push(copy);
                Val::ReqBuilder(self.sites.len() - 1)
            }
            Val::HttpUrl(url) => self.http_url_call(url, name, args, depth),
            Val::Str(parts) => match name {
                "toString" | "trim" | "intern" => Val::Str(parts),
                "append" | "concat" | "plus" => {
                    let arg = args
                        .first()
                        .map_or(Val::Str(Vec::new()), |arg| self.eval(arg, depth));
                    let joined = Val::Str(concat_parts(&[Val::Str(parts), arg]));
                    self.rebind(receiver, &joined);
                    joined
                }
                _ => Val::Unknown(getter_hint(name)),
            },
            Val::JavaUrl(parts) => match name {
                "openConnection" => {
                    let mut site = Site::new(HttpClient::UrlConnection);
                    site.url = Some(Val::JavaUrl(parts));
                    self.sites.push(site);
                    Val::Conn(self.sites.len() - 1)
                }
                "toString" | "toExternalForm" => Val::Str(parts),
                _ => Val::Unknown(getter_hint(name)),
            },
            Val::Conn(site) => {
                match name {
                    "setRequestMethod" => {
                        let verb = self.literal_arg(args, 0, depth);
                        self.set_verb(site, verb);
                    }
                    "setRequestProperty" | "addRequestProperty" => {
                        if let Some(header) = self.literal_arg(args, 0, depth) {
                            push_unique(&mut self.sites[site].headers, header);
                        }
                    }
                    "setDoOutput" => {
                        if matches!(args.first(), Some(Expr::Name(value)) if value == &["true"]) {
                            self.sites[site].does_output = true;
                        }
                    }
                    "getOutputStream" => {
                        self.sites[site].does_output = true;
                        self.sites[site].has_body = true;
                    }
                    _ => {}
                }
                Val::Unknown(getter_hint(name))
            }
            target @ (Val::RetrofitBuilder(_) | Val::Retrofit(_)) => {
                self.retrofit_call(target, name, args, depth)
            }
            Val::ResponseBuilder => {
                for arg in args {
                    if let Val::Request(site) | Val::ReqBuilder(site) = self.eval(arg, depth) {
                        if name == "request" {
                            self.sites[site].synthetic = true;
                        }
                    }
                }
                Val::ResponseBuilder
            }
            Val::Json => match name {
                "put" | "putOpt" | "accumulate" => Val::Json,
                _ => Val::Unknown("body".to_owned()),
            },
            Val::Request(_) | Val::Unknown(_) => {
                // An opaque call (`execute(new Request.Builder()...)`) still
                // runs its arguments, which may hold the call site itself.
                for arg in args {
                    self.eval(arg, depth);
                }
                Val::Unknown(getter_hint(name))
            }
        }
    }

    fn eval_static(
        &mut self,
        segments: &[String],
        name: &str,
        args: &[Expr],
        depth: usize,
    ) -> Option<Val> {
        let last = segments.last().map(String::as_str);
        // okhttp3.HttpUrl.get/parse (and the Kotlin `toHttpUrl` companion).
        let http_url_owner = self.file.type_is(segments, OKHTTP_HTTP_URL)
            || (matches!(last, Some("INSTANCE" | "Companion"))
                && self
                    .file
                    .type_is(&segments[..segments.len() - 1], OKHTTP_HTTP_URL));
        if http_url_owner && matches!(name, "get" | "parse" | "toHttpUrl" | "toHttpUrlOrNull") {
            return Some(match args.first().map(|arg| self.eval(arg, depth)) {
                Some(Val::Str(parts)) => {
                    parse_http_url(&parts).map_or(Val::Unknown("url".to_owned()), Val::HttpUrl)
                }
                _ => Val::Unknown("url".to_owned()),
            });
        }
        if last == Some("String") && matches!(name, "format") {
            return Some(self.format(args, depth));
        }
        if last == Some("String") && name == "valueOf" {
            return Some(match args.first() {
                Some(Expr::Name(value)) => Val::Unknown(value.last().cloned().unwrap_or_default()),
                Some(arg) => match self.eval(arg, depth) {
                    Val::Str(parts) => Val::Str(parts),
                    _ => Val::Unknown("value".to_owned()),
                },
                None => Val::Unknown("value".to_owned()),
            });
        }
        // Kotlin `object`/companion property getters for a constant.
        if matches!(last, Some("INSTANCE" | "Companion")) && args.is_empty() {
            if let Some(property) = name.strip_prefix("get").filter(|rest| !rest.is_empty()) {
                let class = &segments[..segments.len() - 1];
                for field in property_field_names(property) {
                    if let Some(value) = self.constant(class, &field, depth) {
                        return Some(value);
                    }
                }
            }
        }
        None
    }

    fn builder_call(&mut self, site: usize, name: &str, args: &[Expr], depth: usize) -> Val {
        match name {
            "url" => {
                let value = args
                    .first()
                    .map_or(Val::Unknown("url".to_owned()), |arg| self.eval(arg, depth));
                self.sites[site].url = Some(value);
            }
            "get" | "head" => self.sites[site].verb = Verb::Known(name.to_ascii_uppercase()),
            "post" | "put" | "patch" | "delete" => {
                self.sites[site].verb = Verb::Known(name.to_ascii_uppercase());
                if args
                    .first()
                    .is_some_and(|arg| !matches!(arg, Expr::Name(value) if value == &["null"]))
                {
                    self.sites[site].has_body = true;
                }
            }
            "method" => {
                let verb = self.literal_arg(args, 0, depth);
                self.set_verb(site, verb);
                if args
                    .get(1)
                    .is_some_and(|arg| !matches!(arg, Expr::Name(value) if value == &["null"]))
                {
                    self.sites[site].has_body = true;
                }
            }
            "header" | "addHeader" => {
                if let Some(header) = self.literal_arg(args, 0, depth) {
                    push_unique(&mut self.sites[site].headers, header);
                }
            }
            "build" => return Val::Request(site),
            _ => {}
        }
        Val::ReqBuilder(site)
    }

    fn http_url_call(&mut self, mut url: UrlParts, name: &str, args: &[Expr], depth: usize) -> Val {
        let arg = |this: &mut Self, index: usize| {
            args.get(index)
                .map(|arg| this.eval(arg, depth))
                .map_or_else(|| vec![Part::Hole("value".to_owned())], value_parts)
        };
        match name {
            "scheme" => url.scheme = self.literal_arg(args, 0, depth),
            "host" => url.host = Some(arg(self, 0)),
            "port" => url.port = self.literal_arg(args, 0, depth),
            "addPathSegment" | "addEncodedPathSegment" => url.segments.push(arg(self, 0)),
            "addPathSegments" | "addEncodedPathSegments" => {
                url.segments.extend(split_segments(&arg(self, 0)));
            }
            "encodedPath" => url.segments = split_segments(&arg(self, 0)),
            "addQueryParameter"
            | "addEncodedQueryParameter"
            | "setQueryParameter"
            | "setEncodedQueryParameter" => {
                if let Some(query) = self.literal_arg(args, 0, depth) {
                    push_unique(&mut url.query_names, query);
                }
            }
            "build" | "newBuilder" => {}
            "toString" => return Val::Str(render_http_url(&url)),
            _ => return Val::Unknown(getter_hint(name)),
        }
        Val::HttpUrl(url)
    }

    fn format(&mut self, args: &[Expr], depth: usize) -> Val {
        let values = args
            .iter()
            .map(|arg| (arg.clone(), self.eval(arg, depth)))
            .collect::<Vec<_>>();
        // `String.format(Locale, fmt, ...)` or `String.format(fmt, ...)`.
        let format_index = values
            .iter()
            .position(|(_, value)| matches!(value, Val::Str(parts) if parts.iter().all(|part| matches!(part, Part::Lit(_)))));
        let Some(format_index) = format_index else {
            return Val::Unknown("value".to_owned());
        };
        let Val::Str(parts) = &values[format_index].1 else {
            return Val::Unknown("value".to_owned());
        };
        let pattern = parts
            .iter()
            .map(|part| match part {
                Part::Lit(value) => value.as_str(),
                Part::Hole(_) => "",
            })
            .collect::<String>();
        let mut rest = values[format_index + 1..].iter();
        let mut out = Vec::new();
        let mut literal = String::new();
        let mut chars = pattern.chars().peekable();
        while let Some(character) = chars.next() {
            if character != '%' {
                literal.push(character);
                continue;
            }
            // Skip flags/width/precision up to the conversion character.
            let mut conversion = None;
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() || next == '%' {
                    conversion = Some(next);
                    break;
                }
            }
            match conversion {
                Some('%') => literal.push('%'),
                Some('n') => literal.push('\n'),
                Some(_) => {
                    if !literal.is_empty() {
                        out.push(Part::Lit(std::mem::take(&mut literal)));
                    }
                    match rest.next() {
                        Some((_, value)) => out.extend(value_parts(value.clone())),
                        None => out.push(Part::Hole("value".to_owned())),
                    }
                }
                None => {}
            }
        }
        if !literal.is_empty() {
            out.push(Part::Lit(literal));
        }
        Val::Str(out)
    }

    /// Calls on a Retrofit builder or instance: track the base URL and record
    /// `create(Service.class)` bindings.
    fn retrofit_call(&mut self, target: Val, name: &str, args: &[Expr], depth: usize) -> Val {
        match (target, name) {
            (Val::RetrofitBuilder(_), "baseUrl") => Val::RetrofitBuilder(
                args.first()
                    .and_then(|arg| rendered_literal_url(&self.eval(arg, depth))),
            ),
            (Val::RetrofitBuilder(base), "build") => Val::Retrofit(base),
            (Val::RetrofitBuilder(base), _) => {
                for arg in args {
                    self.eval(arg, depth);
                }
                Val::RetrofitBuilder(base)
            }
            (Val::Retrofit(base), "create") => {
                if let Some(service) = args.first().and_then(|arg| self.class_literal(arg)) {
                    self.retrofit_bindings.push(RetrofitBinding {
                        service,
                        base_url: base,
                    });
                }
                Val::Unknown("service".to_owned())
            }
            (Val::Retrofit(base), "newBuilder") => Val::RetrofitBuilder(base),
            _ => Val::Unknown(getter_hint(name)),
        }
    }

    /// Resolves a `Service.class` literal to the service's dotted name,
    /// preferring a candidate that names a decompiled class in the corpus.
    fn class_literal(&mut self, expr: &Expr) -> Option<String> {
        let Expr::Name(segments) = expr else {
            return None;
        };
        let (class, last) = segments.split_at(segments.len().checked_sub(1)?);
        if last.first().map(String::as_str) != Some("class") || class.is_empty() {
            return None;
        }
        let candidates = self.file.class_candidates(class);
        for candidate in &candidates {
            let mut outer = candidate.as_str();
            loop {
                if self.constants.document_for(outer).is_some() {
                    return Some(candidate.clone());
                }
                match outer.rfind('.') {
                    Some(dot) => outer = &outer[..dot],
                    None => break,
                }
            }
        }
        candidates.into_iter().next()
    }

    fn literal_arg(&mut self, args: &[Expr], index: usize, depth: usize) -> Option<String> {
        let value = self.eval(args.get(index)?, depth);
        match value {
            Val::Str(parts) => literal_text(&parts),
            _ => None,
        }
    }

    /// `sb.append(x)` mutates `sb`; keep the local binding in step.
    fn rebind(&mut self, receiver: Option<&Expr>, value: &Val) {
        let mut receiver = receiver;
        // Walk to the root of a chained `sb.append(a).append(b)`.
        while let Some(Expr::Call {
            receiver: Some(inner),
            name,
            ..
        }) = receiver
        {
            if !matches!(name.as_str(), "append" | "concat") {
                return;
            }
            receiver = Some(inner);
        }
        if let Some(Expr::Name(segments)) = receiver {
            if let [local] = segments.as_slice() {
                if self.locals.contains_key(local) {
                    self.locals.insert(local.clone(), value.clone());
                }
            }
        }
    }

    /// Records an explicit verb; `None` means the argument did not resolve.
    fn set_verb(&mut self, site: usize, verb: Option<String>) {
        self.sites[site].verb = match verb {
            Some(verb) => Verb::Known(verb.to_ascii_uppercase()),
            None => Verb::Unresolved,
        };
    }

    fn finish(self, method_name: &str) -> Vec<CallSite> {
        self.sites
            .into_iter()
            .filter(|site| !site.synthetic)
            .map(|site| {
                let rendered = site.url.as_ref().and_then(render_site_url);
                match rendered {
                    Some(_) if matches!(site.verb, Verb::Unresolved) => CallSite::Unresolved {
                        client: site.client,
                        method_name: method_name.to_owned(),
                        missing: Missing::Verb,
                    },
                    Some((base_url, path, query_names)) => {
                        let method = match &site.verb {
                            Verb::Known(verb) => verb.clone(),
                            // HttpURLConnection turns a GET that writes a
                            // body into a POST.
                            _ if site.client == HttpClient::UrlConnection && site.does_output => {
                                "POST".to_owned()
                            }
                            _ => "GET".to_owned(),
                        };
                        CallSite::Resolved(ResolvedCall {
                            client: site.client,
                            method,
                            base_url,
                            path,
                            query_names,
                            header_names: site.headers,
                            has_body: site.has_body,
                        })
                    }
                    None => CallSite::Unresolved {
                        client: site.client,
                        method_name: method_name.to_owned(),
                        missing: Missing::Url,
                    },
                }
            })
            .collect()
    }
}

/// Rewrites a foreign constant's bare names to be qualified by its owner.
fn qualify(expr: &Expr, owner: &str) -> Expr {
    match expr {
        Expr::Name(segments) if segments.len() == 1 => {
            let mut qualified = owner.split('.').map(ToOwned::to_owned).collect::<Vec<_>>();
            qualified.push(segments[0].clone());
            Expr::Name(qualified)
        }
        Expr::Concat(parts) => {
            Expr::Concat(parts.iter().map(|part| qualify(part, owner)).collect())
        }
        other => other.clone(),
    }
}

fn property_field_names(property: &str) -> Vec<String> {
    let mut names = vec![property.to_owned(), lower_first(property)];
    names.dedup();
    names
}

fn lower_first(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn getter_hint(name: &str) -> String {
    match name
        .strip_prefix("get")
        .filter(|rest| rest.chars().next().is_some_and(char::is_uppercase))
    {
        Some(rest) => lower_first(rest),
        None => "value".to_owned(),
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn value_parts(value: Val) -> Vec<Part> {
    match value {
        Val::Str(parts) => parts,
        Val::Unknown(hint) => vec![Part::Hole(hint)],
        _ => vec![Part::Hole("value".to_owned())],
    }
}

fn concat_parts(values: &[Val]) -> Vec<Part> {
    let mut out: Vec<Part> = Vec::new();
    for value in values {
        for part in value_parts(value.clone()) {
            match (out.last_mut(), part) {
                (Some(Part::Lit(previous)), Part::Lit(next)) => previous.push_str(&next),
                (_, part) => out.push(part),
            }
        }
    }
    out
}

/// A fully-literal URL value (string or `HttpUrl`), rendered.
fn rendered_literal_url(value: &Val) -> Option<String> {
    match value {
        Val::Str(parts) | Val::JavaUrl(parts) => literal_text(parts),
        Val::HttpUrl(url) => literal_text(&render_http_url(url)),
        _ => None,
    }
}

fn literal_text(parts: &[Part]) -> Option<String> {
    let mut out = String::new();
    for part in parts {
        match part {
            Part::Lit(value) => out.push_str(value),
            Part::Hole(_) => return None,
        }
    }
    Some(out)
}

fn split_segments(parts: &[Part]) -> Vec<Vec<Part>> {
    let mut segments = vec![Vec::new()];
    for part in parts {
        match part {
            Part::Lit(value) => {
                for (index, piece) in value.split('/').enumerate() {
                    if index > 0 {
                        segments.push(Vec::new());
                    }
                    if !piece.is_empty() {
                        segments
                            .last_mut()
                            .expect("segments is never empty")
                            .push(Part::Lit(piece.to_owned()));
                    }
                }
            }
            Part::Hole(_) => segments
                .last_mut()
                .expect("segments is never empty")
                .push(part.clone()),
        }
    }
    segments.retain(|segment| !segment.is_empty());
    segments
}

fn parse_http_url(parts: &[Part]) -> Option<UrlParts> {
    let (base, path, query_names) = render_parts_url(parts)?;
    let base = base?;
    let (scheme, host) = base.split_once("://")?;
    let (host, port) = match host.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_owned(), Some(port.to_owned()))
        }
        _ => (host.to_owned(), None),
    };
    Some(UrlParts {
        scheme: Some(scheme.to_owned()),
        host: Some(vec![Part::Lit(host)]),
        port,
        segments: split_segments(&template_to_parts(&path)),
        query_names,
    })
}

/// Turns a rendered `{name}` template back into parts.
fn template_to_parts(template: &str) -> Vec<Part> {
    let mut parts = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        if start > 0 {
            parts.push(Part::Lit(rest[..start].to_owned()));
        }
        parts.push(Part::Hole(rest[start + 1..start + end].to_owned()));
        rest = &rest[start + end + 1..];
    }
    if !rest.is_empty() {
        parts.push(Part::Lit(rest.to_owned()));
    }
    parts
}

fn render_http_url(url: &UrlParts) -> Vec<Part> {
    let mut parts = vec![Part::Lit(format!(
        "{}://",
        url.scheme.clone().unwrap_or_else(|| "https".to_owned())
    ))];
    match &url.host {
        Some(host) => parts.extend(host.iter().cloned()),
        None => parts.push(Part::Hole("host".to_owned())),
    }
    if let Some(port) = &url.port {
        parts.push(Part::Lit(format!(":{port}")));
    }
    for segment in &url.segments {
        parts.push(Part::Lit("/".to_owned()));
        parts.extend(segment.iter().cloned());
    }
    concat_parts(&[Val::Str(parts)])
}

fn resolve_relative(context: &[Part], spec: &[Part]) -> Vec<Part> {
    match spec.first() {
        Some(Part::Lit(value)) if value.contains("://") => spec.to_vec(),
        Some(Part::Lit(value)) if value.starts_with('/') => {
            // Absolute path: keep the context's scheme and authority.
            match render_parts_url(context).and_then(|(base, _, _)| base) {
                Some(base) => {
                    concat_parts(&[Val::Str(vec![Part::Lit(base)]), Val::Str(spec.to_vec())])
                }
                None => spec.to_vec(),
            }
        }
        _ => concat_parts(&[Val::Str(context.to_vec()), Val::Str(spec.to_vec())]),
    }
}

fn render_site_url(value: &Val) -> Option<(Option<String>, String, Vec<String>)> {
    match value {
        Val::Str(parts) | Val::JavaUrl(parts) => render_parts_url(parts),
        Val::HttpUrl(url) => {
            let base = match (&url.scheme, url.host.as_deref().and_then(literal_text)) {
                (Some(scheme), Some(host)) => Some(match &url.port {
                    Some(port) => format!("{scheme}://{host}:{port}"),
                    None => format!("{scheme}://{host}"),
                }),
                _ => None,
            };
            let mut names = HoleNames::default();
            let mut path = String::new();
            for segment in &url.segments {
                path.push('/');
                path.push_str(&names.render(segment));
            }
            if path.is_empty() {
                path.push('/');
            }
            if base.is_none() && path == "/" {
                return None;
            }
            Some((base, path, url.query_names.clone()))
        }
        _ => None,
    }
}

#[derive(Default)]
struct HoleNames {
    used: BTreeMap<String, usize>,
}

impl HoleNames {
    fn name(&mut self, hint: &str) -> String {
        let mut name = hint
            .chars()
            .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect::<String>();
        if name.is_empty() || name.starts_with(|character: char| character.is_ascii_digit()) {
            name = format!("param{name}");
        }
        let count = self.used.entry(name.clone()).or_insert(0);
        *count += 1;
        if *count > 1 {
            format!("{name}{count}")
        } else {
            name
        }
    }

    fn render(&mut self, parts: &[Part]) -> String {
        parts
            .iter()
            .map(|part| match part {
                Part::Lit(value) => value.clone(),
                Part::Hole(hint) => format!("{{{}}}", self.name(hint)),
            })
            .collect()
    }
}

/// Splits a composed URL into (base URL, templated path, query names).
///
/// A leading hole with no literal scheme is treated as an unknown base only
/// when the literal that follows is an absolute path; any other shape is not
/// a URL this method can vouch for.
fn render_parts_url(parts: &[Part]) -> Option<(Option<String>, String, Vec<String>)> {
    let parts = concat_parts(&[Val::Str(parts.to_vec())]);
    let (base, rest): (Option<String>, Vec<Part>) = match parts.first()? {
        Part::Lit(first) if first.starts_with("http://") || first.starts_with("https://") => {
            let scheme_end = first.find("://")? + 3;
            match first[scheme_end..].find(['/', '?', '#']) {
                Some(offset) => {
                    let split = scheme_end + offset;
                    let mut rest = vec![Part::Lit(first[split..].to_owned())];
                    rest.extend(parts[1..].iter().cloned());
                    (Some(first[..split].to_owned()), rest)
                }
                None if parts.len() == 1 => (Some(first.clone()), Vec::new()),
                None => {
                    // A hole inside the authority: the host is not known, but
                    // an absolute path after it still is.
                    let path_start = parts[1..]
                        .iter()
                        .position(|part| matches!(part, Part::Lit(value) if value.contains('/')))?;
                    let Part::Lit(value) = &parts[1 + path_start] else {
                        return None;
                    };
                    let slash = value.find('/')?;
                    let mut rest = vec![Part::Lit(value[slash..].to_owned())];
                    rest.extend(parts[2 + path_start..].iter().cloned());
                    (None, rest)
                }
            }
        }
        Part::Lit(first) if first.starts_with('/') && !first.starts_with("//") => (None, parts),
        Part::Hole(_) => match parts.get(1) {
            Some(Part::Lit(next)) if next.starts_with('/') && !next.starts_with("//") => {
                (None, parts[1..].to_vec())
            }
            _ => return None,
        },
        Part::Lit(_) => return None,
    };
    // Separate the query string and drop any fragment.
    let mut path_parts = Vec::new();
    let mut query_parts = Vec::new();
    let mut in_query = false;
    'outer: for part in rest {
        match part {
            Part::Lit(value) if !in_query => {
                if let Some(index) = value.find(['?', '#']) {
                    if !value[..index].is_empty() {
                        path_parts.push(Part::Lit(value[..index].to_owned()));
                    }
                    if value[index..].starts_with('#') {
                        break 'outer;
                    }
                    in_query = true;
                    query_parts.push(Part::Lit(value[index + 1..].to_owned()));
                } else {
                    path_parts.push(Part::Lit(value));
                }
            }
            part if in_query => query_parts.push(part),
            part => path_parts.push(part),
        }
    }
    let mut names = HoleNames::default();
    let mut path = names.render(&path_parts);
    if path.is_empty() {
        path.push('/');
    }
    if base.is_none() && path == "/" {
        return None;
    }
    let mut query_names = Vec::new();
    let query = query_parts
        .iter()
        .map(|part| match part {
            Part::Lit(value) => value.clone(),
            Part::Hole(_) => "\u{0}".to_owned(),
        })
        .collect::<String>();
    let query = query.split('#').next().unwrap_or_default();
    for pair in query.split('&') {
        let key = pair.split('=').next().unwrap_or_default();
        if !key.is_empty() && !key.contains('\u{0}') {
            push_unique(&mut query_names, key.to_owned());
        }
    }
    Some((base, path, query_names))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(text: &str) -> Vec<CallSite> {
        let tokens = lex(text);
        let structure = parse_structure(&tokens).expect("balanced");
        let context = FileContext::new(&tokens, &structure, Some("Client".to_owned()));
        let corpus = SignatureCorpus::default();
        let mut constants = ConstantIndex::new(&corpus);
        constants.seed(&context);
        let mut sites = Vec::new();
        for method in &structure.methods {
            let mut evaluator = MethodEvaluator::new(&context, &mut constants);
            for statement in statements(&method.tokens) {
                evaluator.statement(statement);
            }
            sites.extend(evaluator.finish(&method.name));
        }
        sites
    }

    fn resolved(sites: &[CallSite]) -> Vec<(String, Option<String>, String)> {
        sites
            .iter()
            .filter_map(|site| match site {
                CallSite::Resolved(call) => Some((
                    call.method.clone(),
                    call.base_url.clone(),
                    call.path.clone(),
                )),
                CallSite::Unresolved { .. } => None,
            })
            .collect()
    }

    #[test]
    fn two_methods_resolve_their_own_url_and_verb() {
        let sites = resolve(
            r#"
package com.example.net;

import okhttp3.Request;

public final class Client {
    private static final String BASE = "https://api.example.test";

    public final int load(String itemId) {
        Request request = new Request.Builder().url(BASE + "/v1/items/" + itemId).get().build();
        return execute(request);
    }

    public final int replace(String body) {
        Request.Builder builder = new Request.Builder().url("https://api.example.test/v1/profile");
        Request request = builder.header("X-Trace", "1").put(RequestBody.create(body, null)).build();
        return execute(request);
    }
}
"#,
        );
        assert_eq!(
            resolved(&sites),
            vec![
                (
                    "GET".to_owned(),
                    Some("https://api.example.test".to_owned()),
                    "/v1/items/{itemId}".to_owned()
                ),
                (
                    "PUT".to_owned(),
                    Some("https://api.example.test".to_owned()),
                    "/v1/profile".to_owned()
                ),
            ]
        );
        let CallSite::Resolved(put) = &sites[1] else {
            panic!("second call site resolves");
        };
        assert_eq!(put.header_names, vec!["X-Trace".to_owned()]);
        assert!(put.has_body);
    }

    #[test]
    fn fragments_never_cross_method_boundaries() {
        // One method sets a URL, a different one builds an HttpUrl with a
        // scheme: the scheme must not be appended to the first URL's path.
        let sites = resolve(
            r#"
import okhttp3.HttpUrl;
import okhttp3.Request;
class Client {
    int a() {
        return execute(new Request.Builder().url("https://h.test/v1/config").get().build());
    }
    int b(String from) {
        HttpUrl url = new HttpUrl.Builder().scheme("https").host("h.test").addPathSegments("v2/reports").addQueryParameter("from", from).build();
        return execute(new Request.Builder().url(url).build());
    }
}
"#,
        );
        assert_eq!(
            resolved(&sites),
            vec![
                (
                    "GET".to_owned(),
                    Some("https://h.test".to_owned()),
                    "/v1/config".to_owned()
                ),
                (
                    "GET".to_owned(),
                    Some("https://h.test".to_owned()),
                    "/v2/reports".to_owned()
                ),
            ]
        );
        let CallSite::Resolved(reports) = &sites[1] else {
            panic!("HttpUrl call site resolves");
        };
        assert_eq!(reports.query_names, vec!["from".to_owned()]);
    }

    #[test]
    fn kotlin_default_bridge_binds_verb_to_its_builder() {
        let sites = resolve(
            r#"
import okhttp3.Request;
class Client {
    int revoke(String tokenId) {
        Request request = Request.Builder.delete$default(new Request.Builder().url("https://h.test/v1/tokens/" + tokenId), null, 1, null).build();
        return execute(request);
    }
}
"#,
        );
        assert_eq!(
            resolved(&sites),
            vec![(
                "DELETE".to_owned(),
                Some("https://h.test".to_owned()),
                "/v1/tokens/{tokenId}".to_owned()
            )]
        );
    }

    #[test]
    fn url_connection_verb_comes_from_its_own_connection() {
        let sites = resolve(
            r#"
import java.net.HttpURLConnection;
import java.net.URL;
class Client {
    int read() throws IOException {
        URLConnection c = new URL("https://h.test/v1/health").openConnection();
        HttpURLConnection connection = (HttpURLConnection) c;
        connection.setRequestMethod("GET");
        return connection.getResponseCode();
    }
    int write() throws IOException {
        URL url = new URL("https://h.test/v1/settings");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        try {
            connection.setRequestMethod("PUT");
            connection.setRequestProperty("Content-Type", "application/json");
            OutputStream out = connection.getOutputStream();
        } finally {
            connection.disconnect();
        }
        return 0;
    }
    int implicitPost() throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL("https://h.test/v1/upload").openConnection();
        connection.setDoOutput(true);
        return connection.getResponseCode();
    }
}
"#,
        );
        assert_eq!(
            resolved(&sites),
            vec![
                (
                    "GET".to_owned(),
                    Some("https://h.test".to_owned()),
                    "/v1/health".to_owned()
                ),
                (
                    "PUT".to_owned(),
                    Some("https://h.test".to_owned()),
                    "/v1/settings".to_owned()
                ),
                (
                    "POST".to_owned(),
                    Some("https://h.test".to_owned()),
                    "/v1/upload".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn string_builder_format_and_query_literals_compose() {
        let sites = resolve(
            r#"
import okhttp3.Request;
class Client {
    int a(String id, int page) {
        StringBuilder sb = new StringBuilder("https://h.test/v1/users/");
        sb.append(id);
        sb.append("/posts?page=");
        sb.append(page);
        return execute(new Request.Builder().url(sb.toString()).build());
    }
    int b(String id) {
        String url = String.format(Locale.US, "https://h.test/v1/carts/%s/lines", id);
        return execute(new Request.Builder().url(url).post(body).build());
    }
}
"#,
        );
        assert_eq!(
            resolved(&sites),
            vec![
                (
                    "GET".to_owned(),
                    Some("https://h.test".to_owned()),
                    "/v1/users/{id}/posts".to_owned()
                ),
                (
                    "POST".to_owned(),
                    Some("https://h.test".to_owned()),
                    "/v1/carts/{id}/lines".to_owned()
                ),
            ]
        );
        let CallSite::Resolved(first) = &sites[0] else {
            panic!("builder call site resolves");
        };
        assert_eq!(first.query_names, vec!["page".to_owned()]);
    }

    #[test]
    fn unresolvable_url_is_reported_not_guessed() {
        let sites = resolve(
            r#"
import okhttp3.Request;
class Client {
    int a(String url) {
        return execute(new Request.Builder().url(url).build());
    }
    int b(Request original) {
        return execute(original.newBuilder().header("A", "b").build());
    }
}
"#,
        );
        assert_eq!(
            sites,
            vec![CallSite::Unresolved {
                client: HttpClient::OkHttp,
                method_name: "a".to_owned(),
                missing: Missing::Url,
            }]
        );
    }

    #[test]
    fn an_unresolvable_explicit_verb_is_reported_not_defaulted() {
        let sites = resolve(
            r#"
import java.net.HttpURLConnection;
import java.net.URL;
class Client {
    int send(String verb) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL("https://h.test/v1/events").openConnection();
        connection.setRequestMethod(verb);
        return connection.getResponseCode();
    }
}
"#,
        );
        assert_eq!(
            sites,
            vec![CallSite::Unresolved {
                client: HttpClient::UrlConnection,
                method_name: "send".to_owned(),
                missing: Missing::Verb,
            }]
        );
    }

    #[test]
    fn a_request_that_only_labels_a_synthesized_response_is_not_a_call() {
        let sites = resolve(
            r#"
import okhttp3.Request;
import okhttp3.Response;
class Client {
    static Response fake(int code) {
        return new Response.Builder().code(code).request(new Request.Builder().url("http://localhost/").build()).build();
    }
}
"#,
        );
        assert!(sites.is_empty());
    }

    #[test]
    fn a_class_named_request_that_is_not_okhttp_is_ignored() {
        let sites = resolve(
            r#"
import com.other.Request;
class Client {
    int a() {
        return execute(new Request.Builder().url("https://h.test/v1/x").build());
    }
}
"#,
        );
        assert!(sites.is_empty());
    }

    fn bindings(text: &str) -> Vec<RetrofitBinding> {
        let tokens = lex(text);
        let structure = parse_structure(&tokens).expect("balanced");
        let context = FileContext::new(&tokens, &structure, Some("Network".to_owned()));
        let corpus = SignatureCorpus::default();
        let mut constants = ConstantIndex::new(&corpus);
        constants.seed(&context);
        let mut out = Vec::new();
        for method in &structure.methods {
            let mut evaluator = MethodEvaluator::new(&context, &mut constants);
            for statement in statements(&method.tokens) {
                evaluator.statement(statement);
            }
            out.append(&mut evaluator.retrofit_bindings);
        }
        out
    }

    #[test]
    fn each_retrofit_service_binds_to_the_instance_that_created_it() {
        let found = bindings(
            r#"
package com.example.net;

import retrofit2.Retrofit;

public final class Network {
    private static final String BASE = "https://api.app.test/";
    private static final Retrofit shared = new Retrofit.Builder().baseUrl("https://cdn.app.test/v2/").build();

    static {
        Object a = new Retrofit.Builder().baseUrl(BASE).client(okHttp).build().create(AccountApi.class);
        Retrofit feeds = new Retrofit.Builder().baseUrl("https://feed.vendor.test/").build();
        Object b = feeds.create(FeedApi.class);
    }

    public final MediaApi media() {
        return (MediaApi) shared.create(MediaApi.class);
    }

    public final OtherApi other(Retrofit injected) {
        return (OtherApi) injected.create(OtherApi.class);
    }
}
"#,
        );
        let base_of = |service: &str| {
            found
                .iter()
                .find(|binding| binding.service == format!("com.example.net.{service}"))
                .map(|binding| binding.base_url.clone())
        };
        assert_eq!(
            base_of("AccountApi"),
            Some(Some("https://api.app.test/".to_owned()))
        );
        assert_eq!(
            base_of("FeedApi"),
            Some(Some("https://feed.vendor.test/".to_owned()))
        );
        assert_eq!(
            base_of("MediaApi"),
            Some(Some("https://cdn.app.test/v2/".to_owned()))
        );
        // An instance from outside the method is not guessed at.
        assert_eq!(base_of("OtherApi"), None);
    }

    #[test]
    fn anonymous_class_methods_are_their_own_scope() {
        let methods = java_method_texts(
            r#"
class Client {
    void outer() {
        String a = "https://h.test/outer";
        Runnable r = new Runnable() {
            public void run() {
                String b = "https://h.test/inner";
            }
        };
    }
}
"#,
        )
        .expect("balanced");
        assert_eq!(methods.len(), 2);
        assert!(methods[0].contains("/outer") && !methods[0].contains("/inner"));
        assert!(methods[1].contains("/inner") && !methods[1].contains("/outer"));
    }

    #[test]
    fn class_names_for_java_and_smali_views_agree() {
        assert_eq!(
            java_class_name(
                "x/jadx/sources/com/example/net/Client.java",
                "package com.example.net;\nclass Client {}"
            ),
            Some("com.example.net.Client".to_owned())
        );
        assert_eq!(
            smali_outer_class_name(".class public final Lcom/example/net/Client$Companion;\n"),
            Some("com.example.net.Client".to_owned())
        );
    }
}
