//! The shared product-copy style law (Lane B enforcement,
//! docs/MAINTAINING.md, "Product-copy rules").
//!
//! One banned-pattern table, applied by every copy-bearing crate's audit
//! test to its production string literals, and re-read by the scripts-lane
//! pytest for README/site. Failures cite the rule set by row so they
//! explain themselves. Deliberate exceptions are granted by a
//! `// copy-allow: <rule-id> <reason>` annotation on the line(s)
//! directly above the string-bearing expression — beside the copy, never a silent
//! pass — and an annotation whose rule never fires is itself a failure
//! (stale allow), so the exception record cannot outlive the exception.
//!
//! Mechanized here: the glow/buzz vocabulary (rows 3/18), importance
//! inflation (row 9), formula phrases (rows 4/7/24/28/29/30), the
//! rhetorical negative-contrast marker (row 1), the narrative-frame
//! ruling (tool-not-story), the em-dash cap, the en-dash range
//! reservation, the retired-middot separator rule, and the arrow ban.
//! Deliberately NOT mechanized (editorial rows, no reliable pattern):
//! padded triples (row 2), hedge clouds (row 8), corporate register
//! (rows 17/19), vague authority (row 23).
//!
//! Vocabulary notes, recorded so the lists don't get "fixed" later:
//! `unlock` stays OFF the glow list (session lock/unlock is a factual
//! capture domain in this product), and `elevated`/`elevation` stay
//! usable (Windows elevation is a factual mechanism) while bare
//! `elevate`/`elevates`/`empower`-class verbs stay banned.

/// Glow/buzz vocabulary (rule rows 3/18). Lowercase; word-boundary
/// matched.
pub const GLOW_VOCABULARY: &[&str] = &[
    "seamless",
    "seamlessly",
    "robust",
    "robustly",
    "nuanced",
    "delve",
    "delves",
    "delving",
    "landscape",
    "ecosystem",
    "elevate",
    "elevates",
    "transform",
    "transforms",
    "transformative",
    "leverage",
    "leverages",
    "leveraging",
    "game-changing",
    "cutting-edge",
    "empower",
    "empowers",
    "empowering",
];

/// Importance inflation (rule row 9). Lowercase; word-boundary matched.
pub const IMPORTANCE_INFLATION: &[&str] = &[
    "crucial",
    "crucially",
    "essential",
    "essentials",
    "pivotal",
    "vital",
    "vitally",
    "comprehensive",
    "comprehensively",
];

/// Formula phrases (rule rows 4/7/24/28/29/30). Lowercase; word-boundary
/// matched at both ends.
pub const FORMULA_PHRASES: &[&str] = &[
    "at its core",
    "worth noting",
    "underscores",
    "let's dive",
    "dive in",
    "dive into",
    "here's the thing",
    "in today's",
    "fast-paced",
    "whether you're",
    "whether you are",
    "by doing",
];

/// Rhetorical negative-contrast markers (rule row 1). The factual
/// scope-contrast shape ("how much and when you type, never which
/// keys") is the recorded exception and contains none of these.
pub const NEGATIVE_CONTRAST_MARKERS: &[&str] =
    &["not just", "isn't just", "is not just", "more than just"];

/// Narrative-frame / anthropomorphism markers (owner ruling 2026-07-12,
/// recorded in docs/MAINTAINING.md: Gilbreth states facts and offers
/// controls; it does not "promise" or narrate itself as an agent).
pub const NARRATIVE_FRAME_MARKERS: &[&str] = &[
    "promise",
    "promises",
    "promised",
    "committed to",
    "we believe",
    "we care",
    "cares about",
    "journey",
    "companion",
];

/// Arrow codepoints banned in copy (rule row 20; owner exception 4
/// covers UI-path arrows in dashboard help text via `copy-allow`).
pub const ARROW_CHARS: &[char] = &['\u{2192}', '\u{2190}', '\u{21D2}', '\u{21D0}', '\u{2194}'];

const EM_DASH: char = '\u{2014}';
const EN_DASH: char = '\u{2013}';
const MIDDOT: char = '\u{00B7}';

/// Where a failure sends the reader: the rule-set row (or decision)
/// behind each rule id.
pub fn rule_row(rule_id: &str) -> &'static str {
    match rule_id {
        "glow-vocabulary" => "docs/MAINTAINING.md, Product-copy rules (glow and buzz vocabulary)",
        "importance-inflation" => "docs/MAINTAINING.md, Product-copy rules (importance inflation)",
        "formula-phrase" => "docs/MAINTAINING.md, Product-copy rules (formula phrases)",
        "negative-contrast" => {
            "docs/MAINTAINING.md, Product-copy rules (rhetorical negative contrast;              factual scope contrasts are the recorded exception)"
        }
        "narrative-frame" => {
            "docs/MAINTAINING.md, Product-copy rules (tool-not-story:              no narrative frames or anthropomorphism in product copy)"
        }
        "em-dash" => {
            "docs/MAINTAINING.md, Product-copy rules (one em dash per string;              per paragraph in prose docs)"
        }
        "en-dash" => "docs/MAINTAINING.md, Product-copy rules (en dash reserved for ranges)",
        "middot-separator" => {
            "docs/MAINTAINING.md, Product-copy rules (the bullet is the separator;              the middot is retired from product copy)"
        }
        "arrow" => {
            "docs/MAINTAINING.md, Product-copy rules (arrows; UI-path arrows              in help text are the recorded exception)"
        }
        _ => "unknown rule id",
    }
}

/// Every rule id the checker can emit (and `copy-allow` can name).
pub const RULE_IDS: &[&str] = &[
    "glow-vocabulary",
    "importance-inflation",
    "formula-phrase",
    "negative-contrast",
    "narrative-frame",
    "em-dash",
    "en-dash",
    "middot-separator",
    "arrow",
];

/// One audited constant (or produced string) that broke a rule, with
/// enough context that the failure explains itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Violation {
    /// The surface being audited (usually a file label).
    pub surface: String,
    /// The constant or produced-string name.
    pub name: String,
    /// 1-based source line of the constant (0 for produced strings).
    pub line: usize,
    pub rule_id: String,
    /// What matched, with a little surrounding context.
    pub detail: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} (line {}): [{}] {} — {}",
            self.surface,
            self.name,
            self.line,
            self.rule_id,
            self.detail,
            rule_row(&self.rule_id)
        )
    }
}

/// A `// copy-allow:` annotation attached to one audited source string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowEntry {
    pub rule_id: String,
    pub reason: String,
    pub line: usize,
}

/// One string-bearing source expression. `name` is its const/static name
/// when there is one, otherwise a line-based label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceConstant {
    pub name: String,
    pub text: String,
    pub line: usize,
    pub allows: Vec<AllowEntry>,
}

fn is_word_char(ch: char) -> bool {
    ch.is_alphanumeric()
}

/// Case-insensitive word-boundary search. Curly apostrophes in the
/// haystack are normalized to straight ones so "whether you’re" still
/// matches the banned "whether you're".
fn find_word(haystack: &str, needle: &str) -> Option<usize> {
    let lower: String = haystack
        .to_lowercase()
        .chars()
        .map(|ch| if ch == '\u{2019}' { '\'' } else { ch })
        .collect();
    let mut from = 0;
    while let Some(offset) = lower[from..].find(needle) {
        let start = from + offset;
        let end = start + needle.len();
        let before_ok = lower[..start]
            .chars()
            .next_back()
            .is_none_or(|ch| !is_word_char(ch));
        let after_ok = lower[end..]
            .chars()
            .next()
            .is_none_or(|ch| !is_word_char(ch));
        if before_ok && after_ok {
            return Some(start);
        }
        from = start + needle.len().max(1);
    }
    None
}

fn context_around(text: &str, index: usize) -> String {
    let start = text
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= index)
        .rev()
        .nth(20)
        .unwrap_or(0);
    let end = text
        .char_indices()
        .map(|(i, _)| i)
        .find(|&i| i >= index + 20 && text.is_char_boundary(i))
        .unwrap_or(text.len());
    let mut snippet: String = text[start..end].replace('\n', "\\n");
    if start > 0 {
        snippet = format!("…{snippet}");
    }
    if end < text.len() {
        snippet = format!("{snippet}…");
    }
    snippet
}

fn vocabulary_hits(text: &str, list: &[&str]) -> Vec<(String, usize)> {
    list.iter()
        .filter_map(|needle| find_word(text, needle).map(|at| (needle.to_string(), at)))
        .collect()
}

/// Audit one string against the whole rule table. `allows` grants rule
/// ids for this string; a granted rule that never fires is reported as
/// stale so the exception record stays true.
pub fn audit_text(
    surface: &str,
    name: &str,
    line: usize,
    text: &str,
    allows: &[AllowEntry],
) -> Vec<Violation> {
    // Phase one: collect every rule hit. `forced` hits ignore allows
    // (the em-dash cap is absolute: a copy-allow grants the one, never
    // more).
    let mut hits: Vec<(&str, String, bool)> = Vec::new();

    for (list, rule) in [
        (GLOW_VOCABULARY, "glow-vocabulary"),
        (IMPORTANCE_INFLATION, "importance-inflation"),
        (FORMULA_PHRASES, "formula-phrase"),
        (NEGATIVE_CONTRAST_MARKERS, "negative-contrast"),
        (NARRATIVE_FRAME_MARKERS, "narrative-frame"),
    ] {
        for (needle, at) in vocabulary_hits(text, list) {
            hits.push((
                rule,
                format!(
                    "banned term \"{needle}\" in \"{}\"",
                    context_around(text, at)
                ),
                false,
            ));
        }
    }

    let em_dashes = text.matches(EM_DASH).count();
    if em_dashes > 0 {
        let at = text.find(EM_DASH).unwrap_or(0);
        hits.push((
            "em-dash",
            format!(
                "em dash in \"{}\" (an em dash needs a copy-allow beside the constant)",
                context_around(text, at)
            ),
            false,
        ));
    }
    if em_dashes > 1 {
        hits.push((
            "em-dash",
            format!("{em_dashes} em dashes in one string; the cap is one and it is not raisable"),
            true,
        ));
    }

    if let Some(at) = text.find(EN_DASH) {
        hits.push((
            "en-dash",
            format!("en dash in \"{}\"", context_around(text, at)),
            false,
        ));
    }
    if let Some(at) = text.find(MIDDOT) {
        hits.push((
            "middot-separator",
            format!("middot in \"{}\"", context_around(text, at)),
            false,
        ));
    }
    if let Some(at) = text.find(|ch| ARROW_CHARS.contains(&ch)) {
        hits.push((
            "arrow",
            format!("arrow in \"{}\"", context_around(text, at)),
            false,
        ));
    }

    // Phase two: apply allows, then audit the allows themselves.
    let allowed = |rule: &str| allows.iter().any(|entry| entry.rule_id == rule);
    let fired: Vec<&str> = hits.iter().map(|(rule, _, _)| *rule).collect();
    let mut violations: Vec<Violation> = hits
        .into_iter()
        .filter(|(rule, _, forced)| *forced || !allowed(rule))
        .map(|(rule, detail, _)| Violation {
            surface: surface.to_string(),
            name: name.to_string(),
            line,
            rule_id: rule.to_string(),
            detail,
        })
        .collect();

    for entry in allows {
        if !RULE_IDS.contains(&entry.rule_id.as_str()) {
            violations.push(Violation {
                surface: surface.to_string(),
                name: name.to_string(),
                line: entry.line,
                rule_id: entry.rule_id.clone(),
                detail: format!(
                    "copy-allow names an unknown rule id \"{}\" (known: {})",
                    entry.rule_id,
                    RULE_IDS.join(", ")
                ),
            });
        } else if !fired.contains(&entry.rule_id.as_str()) {
            violations.push(Violation {
                surface: surface.to_string(),
                name: name.to_string(),
                line: entry.line,
                rule_id: entry.rule_id.clone(),
                detail: "stale copy-allow: the granted rule no longer fires on this string"
                    .to_string(),
            });
        }
    }

    violations
}

#[derive(Clone, Debug)]
enum SourceTokenKind {
    Ident(String),
    Punct(char),
    StringLiteral(String),
    Allow(AllowEntry),
}

#[derive(Clone, Debug)]
struct SourceToken {
    kind: SourceTokenKind,
    line: usize,
}

/// Parse production Rust source into auditable strings. The scan is lexical
/// rather than declaration-shaped: literals in `const` and `static` items,
/// arrays, match arms, function arguments, and other inline expressions all
/// join the audit. `concat!` operands are reconstructed so a phrase cannot be
/// hidden across literal boundaries; `format!`/`format_args!` reconstruct
/// literal positional and named substitutions while leaving dynamic fields as
/// separators. Raw strings are supported.
///
/// Comments, character/byte literals, regex grammar, and inline test modules
/// are code or fixtures rather than rendered copy and are intentionally
/// excluded. `// copy-allow:` attaches to the next audited source string and
/// remains reason-required, rule-specific, and freshness-checked.
pub fn parse_source(source: &str) -> (Vec<SourceConstant>, Vec<Violation>) {
    let (tokens, mut problems) = lex_source(source);
    let regex_tokens = regex_token_mask(&tokens);
    let test_tokens = inline_test_module_mask(&tokens);
    let mut strings = Vec::new();
    let mut pending_allows = Vec::new();
    let mut declaration_name: Option<String> = None;
    let mut index = 0;

    while index < tokens.len() {
        if regex_tokens[index] || test_tokens[index] {
            index += 1;
            continue;
        }

        if let SourceTokenKind::Allow(entry) = &tokens[index].kind {
            pending_allows.push(entry.clone());
            index += 1;
            continue;
        }

        if token_ident(&tokens[index], "const") || token_ident(&tokens[index], "static") {
            declaration_name = tokens[index + 1..]
                .iter()
                .take_while(|token| !token_punct(token, '=') && !token_punct(token, ';'))
                .find_map(|token| match &token.kind {
                    SourceTokenKind::Ident(name) => Some(name.clone()),
                    _ => None,
                });
        }

        if let Some((macro_name, open, close)) = source_macro(&tokens, index) {
            let text = match macro_name {
                "concat" => Some(concat_macro_text(&tokens, open, close)),
                "format" | "format_args" => format_macro_text(&tokens, open, close),
                _ => None,
            };
            if let Some(text) = text {
                strings.push(SourceConstant {
                    name: source_string_name(
                        declaration_name.as_deref(),
                        macro_name,
                        tokens[index].line,
                    ),
                    text,
                    line: tokens[index].line,
                    allows: std::mem::take(&mut pending_allows),
                });
                index = close + 1;
                continue;
            }
        }

        if let SourceTokenKind::StringLiteral(text) = &tokens[index].kind {
            strings.push(SourceConstant {
                name: source_string_name(
                    declaration_name.as_deref(),
                    "inline string",
                    tokens[index].line,
                ),
                text: text.clone(),
                line: tokens[index].line,
                allows: std::mem::take(&mut pending_allows),
            });
        } else if token_punct(&tokens[index], ';') {
            declaration_name = None;
            orphan_allows(&mut pending_allows, &mut problems);
        }
        index += 1;
    }
    orphan_allows(&mut pending_allows, &mut problems);
    (strings, problems)
}

fn source_string_name(declaration: Option<&str>, kind: &str, line: usize) -> String {
    declaration
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{kind}@{line}"))
}

fn orphan_allows(pending: &mut Vec<AllowEntry>, problems: &mut Vec<Violation>) {
    for entry in pending.drain(..) {
        problems.push(Violation {
            surface: String::new(),
            name: "(copy-allow)".to_string(),
            line: entry.line,
            rule_id: entry.rule_id,
            detail: "orphaned copy-allow: no audited source string follows it".to_string(),
        });
    }
}

fn lex_source(source: &str) -> (Vec<SourceToken>, Vec<Violation>) {
    let mut tokens = Vec::new();
    let mut problems = Vec::new();
    let mut index = 0;
    let mut line = 1;

    while index < source.len() {
        let rest = &source[index..];
        if rest.starts_with("//") {
            let end = rest.find('\n').map_or(source.len(), |at| index + at);
            let comment = &source[index + 2..end];
            if let Some(body) = comment.trim_start().strip_prefix("copy-allow:") {
                match parse_allow(body, line) {
                    Ok(entry) => tokens.push(SourceToken {
                        kind: SourceTokenKind::Allow(entry),
                        line,
                    }),
                    Err(problem) => problems.push(problem),
                }
            }
            index = end;
            continue;
        }
        if rest.starts_with("/*") {
            let mut depth = 1;
            index += 2;
            while index < source.len() && depth > 0 {
                let remaining = &source[index..];
                if remaining.starts_with("/*") {
                    depth += 1;
                    index += 2;
                } else if remaining.starts_with("*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    let ch = remaining.chars().next().expect("nonempty remainder");
                    line += usize::from(ch == '\n');
                    index += ch.len_utf8();
                }
            }
            continue;
        }

        let ch = rest.chars().next().expect("nonempty remainder");
        if ch.is_whitespace() {
            line += usize::from(ch == '\n');
            index += ch.len_utf8();
            continue;
        }

        // Byte/C string data and char literals are never rendered Rust copy.
        if rest.starts_with("br\"") || rest.starts_with("br#") {
            if let Some((_, end)) = raw_literal(source, index + 1) {
                line += source[index..end].matches('\n').count();
                index = end;
                continue;
            }
        }
        if rest.starts_with("b\"") || rest.starts_with("c\"") {
            if let Some((_, end)) = quoted_literal(source, index + 1) {
                line += source[index..end].matches('\n').count();
                index = end;
                continue;
            }
        }
        if ch == '\'' {
            if let Some(end) = char_literal_end(source, index) {
                line += source[index..end].matches('\n').count();
                index = end;
                continue;
            }
        }

        if ch == 'r' {
            if let Some((text, end)) = raw_literal(source, index) {
                tokens.push(SourceToken {
                    kind: SourceTokenKind::StringLiteral(text),
                    line,
                });
                line += source[index..end].matches('\n').count();
                index = end;
                continue;
            }
        }
        if ch == '"' {
            if let Some((text, end)) = quoted_literal(source, index) {
                tokens.push(SourceToken {
                    kind: SourceTokenKind::StringLiteral(text),
                    line,
                });
                line += source[index..end].matches('\n').count();
                index = end;
                continue;
            }
        }

        if ch == '_' || ch.is_ascii_alphabetic() {
            let end = source[index..]
                .char_indices()
                .take_while(|(_, next)| *next == '_' || next.is_ascii_alphanumeric())
                .map(|(at, next)| index + at + next.len_utf8())
                .last()
                .unwrap_or(index + ch.len_utf8());
            tokens.push(SourceToken {
                kind: SourceTokenKind::Ident(source[index..end].to_string()),
                line,
            });
            index = end;
            continue;
        }

        if "#!()[]{};,:=.<>".contains(ch) {
            tokens.push(SourceToken {
                kind: SourceTokenKind::Punct(ch),
                line,
            });
        }
        index += ch.len_utf8();
    }
    (tokens, problems)
}

fn parse_allow(body: &str, line: usize) -> Result<AllowEntry, Violation> {
    let body = body.trim();
    let (rule_id, reason) = match body.split_once(char::is_whitespace) {
        Some((id, reason)) => (id.trim(), reason.trim()),
        None => (body, ""),
    };
    if rule_id.is_empty() || reason.is_empty() {
        Err(Violation {
            surface: String::new(),
            name: "(copy-allow)".to_string(),
            line,
            rule_id: rule_id.to_string(),
            detail: "copy-allow needs a rule id and a reason: \
                     `// copy-allow: <rule-id> <reason>`"
                .to_string(),
        })
    } else {
        Ok(AllowEntry {
            rule_id: rule_id.to_string(),
            reason: reason.to_string(),
            line,
        })
    }
}

fn raw_literal(source: &str, start: usize) -> Option<(String, usize)> {
    let after_r = source.get(start + 1..)?;
    let hashes = after_r.chars().take_while(|&ch| ch == '#').count();
    let body_start = start + 1 + hashes;
    if source.get(body_start..body_start + 1)? != "\"" {
        return None;
    }
    let body_start = body_start + 1;
    let closer = format!("\"{}", "#".repeat(hashes));
    let relative_end = source.get(body_start..)?.find(&closer)?;
    let body_end = body_start + relative_end;
    Some((
        source[body_start..body_end].to_string(),
        body_end + closer.len(),
    ))
}

fn quoted_literal(source: &str, start: usize) -> Option<(String, usize)> {
    let body = source.get(start + 1..)?;
    let mut text = String::new();
    let mut chars = body.char_indices().peekable();
    while let Some((offset, ch)) = chars.next() {
        match ch {
            '"' => return Some((text, start + 1 + offset + 1)),
            '\\' => match chars.next()?.1 {
                'n' => text.push('\n'),
                'r' => text.push('\r'),
                't' => text.push('\t'),
                '0' => text.push('\0'),
                '\\' => text.push('\\'),
                '\'' => text.push('\''),
                '"' => text.push('"'),
                'u' => {
                    if chars.next()?.1 != '{' {
                        return None;
                    }
                    let mut hex = String::new();
                    for (_, digit) in chars.by_ref() {
                        if digit == '}' {
                            break;
                        }
                        hex.push(digit);
                    }
                    let value = u32::from_str_radix(&hex, 16).ok()?;
                    text.push(char::from_u32(value)?);
                }
                'x' => {
                    let first = chars.next()?.1;
                    let second = chars.next()?.1;
                    let hex: String = [first, second].iter().collect();
                    text.push(u8::from_str_radix(&hex, 16).ok()? as char);
                }
                '\n' => {
                    while chars
                        .peek()
                        .is_some_and(|(_, next)| *next == ' ' || *next == '\t')
                    {
                        chars.next();
                    }
                }
                '\r' => {
                    // Git may materialize source with CRLF. Rust accepts a
                    // backslash immediately before that pair as the same
                    // string-line continuation as backslash + LF.
                    if chars.next()?.1 != '\n' {
                        return None;
                    }
                    while chars
                        .peek()
                        .is_some_and(|(_, next)| *next == ' ' || *next == '\t')
                    {
                        chars.next();
                    }
                }
                _ => return None,
            },
            _ => text.push(ch),
        }
    }
    None
}

fn char_literal_end(source: &str, start: usize) -> Option<usize> {
    let mut chars = source.get(start + 1..)?.char_indices();
    let (_, first) = chars.next()?;
    match first {
        '\n' | '\r' | '\'' => return None,
        '\\' => match chars.next()?.1 {
            '\n' | '\r' => return None,
            'u' => {
                if chars.next()?.1 != '{' {
                    return None;
                }
                let mut closed = false;
                for (_, ch) in chars.by_ref() {
                    if ch == '}' {
                        closed = true;
                        break;
                    }
                    if ch == '\n' || ch == '\r' {
                        return None;
                    }
                }
                if !closed {
                    return None;
                }
            }
            'x' => {
                chars.next()?;
                chars.next()?;
            }
            _ => {}
        },
        _ => {}
    }

    let (offset, closing) = chars.next()?;
    (closing == '\'').then_some(start + 1 + offset + 1)
}

fn token_ident(token: &SourceToken, expected: &str) -> bool {
    matches!(&token.kind, SourceTokenKind::Ident(name) if name == expected)
}

fn token_punct(token: &SourceToken, expected: char) -> bool {
    matches!(&token.kind, SourceTokenKind::Punct(found) if *found == expected)
}

fn matching_close(tokens: &[SourceToken], open: usize) -> Option<usize> {
    let opener = match &tokens.get(open)?.kind {
        SourceTokenKind::Punct(ch @ ('(' | '[' | '{')) => *ch,
        _ => return None,
    };
    let closer = match opener {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        _ => unreachable!(),
    };
    let mut depth = 0;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        if token_punct(token, opener) {
            depth += 1;
        } else if token_punct(token, closer) {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn source_macro(tokens: &[SourceToken], index: usize) -> Option<(&str, usize, usize)> {
    let SourceTokenKind::Ident(name) = &tokens.get(index)?.kind else {
        return None;
    };
    if !token_punct(tokens.get(index + 1)?, '!') {
        return None;
    }
    let open = index + 2;
    let close = matching_close(tokens, open)?;
    Some((name, open, close))
}

fn concat_macro_text(tokens: &[SourceToken], open: usize, close: usize) -> String {
    tokens[open + 1..close]
        .iter()
        .filter_map(|token| match &token.kind {
            SourceTokenKind::StringLiteral(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .concat()
}

fn format_macro_text(tokens: &[SourceToken], open: usize, close: usize) -> Option<String> {
    let variants = format_macro_variants(tokens, open, close)?;
    Some(join_format_variants(variants))
}

fn format_macro_variants(tokens: &[SourceToken], open: usize, close: usize) -> Option<Vec<String>> {
    let template = tokens[open + 1..close]
        .iter()
        .position(|token| matches!(&token.kind, SourceTokenKind::StringLiteral(_)))?
        + open
        + 1;
    let SourceTokenKind::StringLiteral(template_text) = &tokens[template].kind else {
        unreachable!();
    };
    let arguments = parse_format_arguments(tokens, template + 1, close);
    Some(render_literal_format_variants(template_text, &arguments))
}

#[derive(Debug, Default)]
struct FormatArguments {
    positional: Vec<Vec<String>>,
    named: Vec<(String, Vec<String>)>,
}

const UNKNOWN_FORMAT_FIELD: char = '\u{FFFC}';

fn join_format_variants(variants: Vec<String>) -> String {
    let mut variants = variants.into_iter();
    let mut text = variants.next().unwrap_or_default();
    for variant in variants {
        text.push(UNKNOWN_FORMAT_FIELD);
        text.push_str(&variant);
    }
    text
}

fn parse_format_arguments(
    tokens: &[SourceToken],
    mut start: usize,
    close: usize,
) -> FormatArguments {
    let mut arguments = FormatArguments::default();
    if start < close && token_punct(&tokens[start], ',') {
        start += 1;
    }

    let mut delimiter_depth = 0;
    let mut generic_depth = 0;
    let mut argument_start = start;
    for index in start..close {
        match &tokens[index].kind {
            SourceTokenKind::Punct('(' | '[' | '{') => delimiter_depth += 1,
            SourceTokenKind::Punct(')' | ']' | '}') => delimiter_depth -= 1,
            SourceTokenKind::Punct('<')
                if delimiter_depth == 0
                    && (generic_depth > 0
                        || is_turbofish_open(tokens, index)
                        || is_qualified_path_open(tokens, index, close)) =>
            {
                generic_depth += 1;
            }
            SourceTokenKind::Punct('>') if delimiter_depth == 0 && generic_depth > 0 => {
                generic_depth -= 1;
            }
            SourceTokenKind::Punct(',') if delimiter_depth == 0 && generic_depth == 0 => {
                push_format_argument(&mut arguments, tokens, argument_start, index);
                argument_start = index + 1;
            }
            _ => {}
        }
    }
    push_format_argument(&mut arguments, tokens, argument_start, close);
    arguments
}

fn is_turbofish_open(tokens: &[SourceToken], index: usize) -> bool {
    index >= 2 && token_punct(&tokens[index - 1], ':') && token_punct(&tokens[index - 2], ':')
}

fn is_qualified_path_open(tokens: &[SourceToken], index: usize, close: usize) -> bool {
    let mut depth = 0;
    for cursor in index..close {
        if token_punct(&tokens[cursor], '<') {
            depth += 1;
        } else if token_punct(&tokens[cursor], '>') {
            depth -= 1;
            if depth == 0 {
                return cursor + 2 < close
                    && token_punct(&tokens[cursor + 1], ':')
                    && token_punct(&tokens[cursor + 2], ':');
            }
        }
    }
    false
}

fn push_format_argument(
    arguments: &mut FormatArguments,
    tokens: &[SourceToken],
    start: usize,
    end: usize,
) {
    if start >= end {
        return;
    }
    let (name, value_start) = match (&tokens[start].kind, tokens.get(start + 1)) {
        (SourceTokenKind::Ident(name), Some(equals)) if token_punct(equals, '=') => {
            (Some(name.clone()), start + 2)
        }
        _ => (None, start),
    };
    let candidates = literal_format_argument(tokens, value_start, end);
    if let Some(name) = name {
        arguments.named.push((name, candidates));
    } else {
        arguments.positional.push(candidates);
    }
}

fn literal_format_argument(tokens: &[SourceToken], start: usize, end: usize) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut index = start;
    while index < end {
        if let Some((macro_name, nested_open, nested_close)) = source_macro(tokens, index) {
            if nested_close < end {
                match macro_name {
                    "concat" => {
                        candidates.push(concat_macro_text(tokens, nested_open, nested_close));
                        index = nested_close + 1;
                        continue;
                    }
                    "format" | "format_args" => {
                        if let Some(variants) =
                            format_macro_variants(tokens, nested_open, nested_close)
                        {
                            candidates.extend(variants);
                        }
                        index = nested_close + 1;
                        continue;
                    }
                    _ => {}
                }
            }
        }
        if let SourceTokenKind::StringLiteral(text) = &tokens[index].kind {
            candidates.push(text.clone());
        }
        index += 1;
    }

    // Multiple literals in one expression are retained as candidates (for
    // example, conditional or match arms). Deterministic composition is
    // reconstructed by the explicit `concat!` and nested-format paths above.
    candidates
}

#[derive(Clone, Debug, Default)]
struct FormatAssignment {
    positional: Vec<String>,
    named: Vec<(String, String)>,
}

fn render_literal_format_variants(template: &str, arguments: &FormatArguments) -> Vec<String> {
    let mut assignments = vec![FormatAssignment::default()];
    for candidates in &arguments.positional {
        assignments = extend_format_assignments(assignments, candidates, None);
    }
    for (name, candidates) in &arguments.named {
        assignments = extend_format_assignments(assignments, candidates, Some(name));
    }

    let mut rendered: Vec<String> = assignments
        .iter()
        .map(|assignment| render_literal_format(template, assignment))
        .collect();
    rendered.sort();
    rendered.dedup();
    rendered
}

fn extend_format_assignments(
    assignments: Vec<FormatAssignment>,
    candidates: &[String],
    name: Option<&str>,
) -> Vec<FormatAssignment> {
    let unknown = UNKNOWN_FORMAT_FIELD.to_string();
    let choices: Vec<&String> = if candidates.is_empty() {
        vec![&unknown]
    } else {
        candidates.iter().collect()
    };
    let mut extended = Vec::with_capacity(assignments.len() * choices.len());
    for assignment in assignments {
        for choice in &choices {
            let mut next = assignment.clone();
            if let Some(name) = name {
                next.named.push((name.to_string(), (*choice).clone()));
            } else {
                next.positional.push((*choice).clone());
            }
            extended.push(next);
        }
    }
    extended
}

fn render_literal_format(template: &str, assignment: &FormatAssignment) -> String {
    let mut rendered = String::new();
    let mut chars = template.chars().peekable();
    let mut implicit_index = 0;
    while let Some(ch) = chars.next() {
        match ch {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                rendered.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                rendered.push('}');
            }
            '{' => {
                let mut field = String::new();
                for field_char in chars.by_ref() {
                    if field_char == '}' {
                        break;
                    }
                    field.push(field_char);
                }
                let selector = field.split([':', '!']).next().unwrap_or("").trim();
                let selected = if selector.is_empty() {
                    let index = implicit_index;
                    implicit_index += 1;
                    assignment.positional.get(index)
                } else if let Ok(index) = selector.parse::<usize>() {
                    assignment.positional.get(index)
                } else {
                    assignment
                        .named
                        .iter()
                        .find_map(|(name, value)| (name == selector).then_some(value))
                };
                match selected {
                    Some(argument) => rendered.push_str(argument),
                    None => rendered.push(UNKNOWN_FORMAT_FIELD),
                }
            }
            _ => rendered.push(ch),
        }
    }
    rendered
}

fn regex_token_mask(tokens: &[SourceToken]) -> Vec<bool> {
    let mut mask = vec![false; tokens.len()];
    for index in 0..tokens.len().saturating_sub(4) {
        let regex_type =
            token_ident(&tokens[index], "Regex") || token_ident(&tokens[index], "RegexBuilder");
        if regex_type
            && token_punct(&tokens[index + 1], ':')
            && token_punct(&tokens[index + 2], ':')
            && token_ident(&tokens[index + 3], "new")
            && token_punct(&tokens[index + 4], '(')
        {
            if let Some(close) = matching_close(tokens, index + 4) {
                for skipped in &mut mask[index..=close] {
                    *skipped = true;
                }
            }
        }
    }
    mask
}

fn inline_test_module_mask(tokens: &[SourceToken]) -> Vec<bool> {
    let mut mask = vec![false; tokens.len()];
    let mut index = 0;
    while index + 6 < tokens.len() {
        let cfg_test = token_punct(&tokens[index], '#')
            && token_punct(&tokens[index + 1], '[')
            && token_ident(&tokens[index + 2], "cfg")
            && token_punct(&tokens[index + 3], '(')
            && token_ident(&tokens[index + 4], "test")
            && token_punct(&tokens[index + 5], ')')
            && token_punct(&tokens[index + 6], ']');
        if !cfg_test {
            index += 1;
            continue;
        }

        let mut item = index + 7;
        // Attributes between cfg(test) and the module belong to the same
        // item. Skip each balanced attribute before looking for `mod`.
        while item + 1 < tokens.len()
            && token_punct(&tokens[item], '#')
            && token_punct(&tokens[item + 1], '[')
        {
            let Some(close) = matching_close(tokens, item + 1) else {
                break;
            };
            item = close + 1;
        }
        if item + 2 < tokens.len()
            && token_ident(&tokens[item], "mod")
            && matches!(&tokens[item + 1].kind, SourceTokenKind::Ident(_))
            && token_punct(&tokens[item + 2], '{')
        {
            if let Some(close) = matching_close(tokens, item + 2) {
                for skipped in &mut mask[index..=close] {
                    *skipped = true;
                }
                index = close + 1;
                continue;
            }
        }
        // `#[cfg(test)] mod copy_audit;` is declaration plumbing, not an
        // inline fixture body, so it remains in the production scan.
        index += 7;
    }
    mask
}

/// Parse a source file and audit every production string in it. `surface`
/// labels the file in failures.
pub fn audit_source(surface: &str, source: &str) -> Vec<Violation> {
    let (constants, mut violations) = parse_source(source);
    for problem in &mut violations {
        problem.surface = surface.to_string();
    }
    for constant in &constants {
        violations.extend(audit_text(
            surface,
            &constant.name,
            constant.line,
            &constant.text,
            &constant.allows,
        ));
    }
    violations
}

/// Walk a crate's `src/` tree and audit every `.rs` file in it. The
/// per-crate audit tests call this with `env!("CARGO_MANIFEST_DIR")`,
/// so a new copy-bearing file joins the scan the moment it exists —
/// coverage is the default, and a deliberate exception is a
/// `copy-allow` annotation beside the source string, never absence from a
/// file list. Panics when `src/` is missing or empty so a wrong path
/// can't read as a clean audit.
pub fn audit_crate_src(crate_label: &str, manifest_dir: &str) -> Vec<Violation> {
    let src = std::path::Path::new(manifest_dir).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    assert!(
        !files.is_empty(),
        "no .rs files under {} — wrong manifest dir?",
        src.display()
    );
    files.sort();
    let mut violations = Vec::new();
    for path in files {
        // This module contains the banned-token tables and test fixtures
        // that define the law. It is policy input, never product copy;
        // audit_source's own fixtures exercise it directly instead.
        let relative = path.strip_prefix(manifest_dir).unwrap_or(&path);
        if is_copy_policy_source(crate_label, relative) {
            continue;
        }
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
        let surface = format!("{crate_label}/{}", relative.display());
        violations.extend(audit_source(&surface, &source));
    }
    violations
}

fn is_copy_policy_source(crate_label: &str, relative: &std::path::Path) -> bool {
    crate_label == "gilbreth-core" && relative == std::path::Path::new("src/copy_style.rs")
}

fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

/// Render violations for a test panic message.
pub fn render_report(violations: &[Violation]) -> String {
    violations
        .iter()
        .map(|violation| format!("  - {violation}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Panic with a readable report when any violation exists. The audit
/// tests call this so every crate fails the same way.
pub fn assert_no_violations(violations: &[Violation]) {
    assert!(
        violations.is_empty(),
        "product-copy style violations:\n{}\n(rules: docs/MAINTAINING.md; \
         see its Product-copy rules section)",
        render_report(violations)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_allows() -> Vec<AllowEntry> {
        Vec::new()
    }

    fn allow(rule_id: &str) -> Vec<AllowEntry> {
        vec![AllowEntry {
            rule_id: rule_id.to_string(),
            reason: "test grant".to_string(),
            line: 1,
        }]
    }

    #[test]
    fn clean_copy_passes_every_rule() {
        let text = "Gilbreth records how this machine is used. Nothing leaves this machine.";
        assert!(audit_text("t", "CLEAN", 1, text, &no_allows()).is_empty());
    }

    #[test]
    fn each_vocabulary_family_fires_and_cites_its_row() {
        for (sample, rule) in [
            ("a seamless flow", "glow-vocabulary"),
            ("a crucial step", "importance-inflation"),
            ("at its core, a tool", "formula-phrase"),
            ("not just tracking", "negative-contrast"),
            ("we promise nothing", "narrative-frame"),
        ] {
            let violations = audit_text("t", "S", 1, sample, &no_allows());
            assert_eq!(violations.len(), 1, "{sample}");
            assert_eq!(violations[0].rule_id, rule);
            assert!(!rule_row(rule).is_empty());
        }
    }

    #[test]
    fn word_boundaries_protect_factual_domain_words() {
        // "elevated" (Windows elevation) must not trip "elevate", and
        // "transformed" in a compound is still distinct from "transform".
        for text in [
            "the elevated helper did not start",
            "session unlock rows are recorded",
            "robustness is not claimed here either",
        ] {
            assert!(
                audit_text("t", "S", 1, text, &no_allows()).is_empty(),
                "{text}"
            );
        }
    }

    #[test]
    fn curly_apostrophes_do_not_evade_phrase_bans() {
        let violations = audit_text(
            "t",
            "S",
            1,
            "whether you\u{2019}re new or not",
            &no_allows(),
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id, "formula-phrase");
    }

    #[test]
    fn an_em_dash_needs_an_allow_and_the_cap_is_absolute() {
        let one = "Granted \u{2014} but macOS delivers this at launch.";
        assert_eq!(audit_text("t", "S", 1, one, &no_allows()).len(), 1);
        assert!(audit_text("t", "S", 1, one, &allow("em-dash")).is_empty());

        let two = "stores the action \u{2014} never values \u{2014} and stops.";
        let violations = audit_text("t", "S", 1, two, &allow("em-dash"));
        assert_eq!(violations.len(), 1, "the cap violation survives the allow");
        assert!(violations[0].detail.contains("cap is one"));
    }

    #[test]
    fn en_dash_middot_and_arrow_rules_fire() {
        for (text, rule) in [
            ("9:00\u{2013}17:00", "en-dash"),
            ("all clean \u{00B7} baseline known", "middot-separator"),
            ("tray \u{2192} Privacy", "arrow"),
        ] {
            let violations = audit_text("t", "S", 1, text, &no_allows());
            assert_eq!(violations.len(), 1, "{text}");
            assert_eq!(violations[0].rule_id, rule);
        }
    }

    #[test]
    fn stale_and_unknown_allows_are_reported() {
        let violations = audit_text("t", "S", 1, "plain copy", &allow("em-dash"));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].detail.contains("stale copy-allow"));

        let violations = audit_text("t", "S", 1, "plain copy", &allow("no-such-rule"));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].detail.contains("unknown rule id"));
    }

    #[test]
    fn parser_reads_literals_escapes_and_continuations() {
        let source = r#"
pub const A: &str = "line one\nline two";
const B: &str = "wraps \
                 across lines";
pub(crate) const C: &str = "\u{2013}";
const NOT_COPY: &str = concat!("a", "b");
"#;
        let (constants, problems) = parse_source(source);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(constants.len(), 4);
        assert_eq!(constants[0].text, "line one\nline two");
        assert_eq!(constants[1].text, "wraps across lines");
        assert_eq!(constants[2].text, "\u{2013}");
        assert_eq!(constants[3].text, "ab");
    }

    #[test]
    fn parser_decodes_crlf_string_continuations() {
        let source = "const COPY: &str = \"wraps \\\r\n    across CRLF\";\r\n";
        let (strings, problems) = parse_source(source);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "wraps across CRLF");
    }

    #[test]
    fn scanner_covers_statics_arrays_inline_and_generated_copy() {
        let source = r#"
static HEADLINE: &str = "a crucial step";
const OPTIONS: &[&str] = &["plain", "a seamless flow"];
fn render(count: usize) {
    show("we promise a result");
    let _ = concat!("not ", "just tracking");
    let _ = format!("worth noting: {count}");
    let _ = format!("{promise}");
}
"#;
        let violations = audit_source("t", source);
        let rules: Vec<&str> = violations
            .iter()
            .map(|violation| violation.rule_id.as_str())
            .collect();
        assert!(rules.contains(&"importance-inflation"), "{violations:?}");
        assert!(rules.contains(&"glow-vocabulary"), "{violations:?}");
        assert!(rules.contains(&"narrative-frame"), "{violations:?}");
        assert!(rules.contains(&"negative-contrast"), "{violations:?}");
        assert!(rules.contains(&"formula-phrase"), "{violations:?}");
        assert_eq!(violations.len(), 5, "{violations:?}");
    }

    #[test]
    fn format_scan_covers_the_template_and_literal_arguments() {
        let source = r#"
fn render(count: usize) {
    let _ = format!("worth noting: {count}");
    let _ = format!("{}", "a seamless flow");
    let _ = format!("{}", concat!("not ", "just tracking"));
    let _ = format!("not {}", "just tracking");
    let _ = format!("worth {}", "noting");
    let _ = format!("{} not {}", count, "just tracking");
    let _ = format!("{first} {second}", second = "just tracking", first = "not");
    let _ = format!("{1} {0}", "just tracking", "not");
    let _ = format!("{}", if count == 0 { "a seamless flow" } else { "plain" });
    let _ = format!("{promise}");
}
"#;
        let violations = audit_source("t", source);
        let rules: Vec<&str> = violations
            .iter()
            .map(|violation| violation.rule_id.as_str())
            .collect();
        assert_eq!(violations.len(), 9, "{violations:?}");
        assert!(rules.contains(&"formula-phrase"), "{violations:?}");
        assert!(rules.contains(&"glow-vocabulary"), "{violations:?}");
        assert!(rules.contains(&"negative-contrast"), "{violations:?}");
    }

    #[test]
    fn format_scan_preserves_slots_across_generic_commas() {
        let source = r#"
fn render() {
    let _ = format!(
        "{} not {}",
        std::collections::HashMap::<String, String>::new().len(),
        "just tracking",
    );
    let _ = format!(
        "{} not {}",
        <Outer<String, Inner<u8, u16>> as Value>::get(),
        "just tracking",
    );
}
"#;
        let violations = audit_source("t", source);
        assert_eq!(violations.len(), 2, "{violations:?}");
        assert!(
            violations
                .iter()
                .all(|violation| violation.rule_id == "negative-contrast"),
            "{violations:?}"
        );
    }

    #[test]
    fn format_scan_combines_literal_candidates_across_slots() {
        let source = r#"
fn render(flag: bool) {
    let _ = format!(
        "{} {}",
        if flag { "not" } else { "plain" },
        if flag { "just tracking" } else { "plain" },
    );
}
"#;
        let violations = audit_source("t", source);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].rule_id, "negative-contrast");
    }

    #[test]
    fn format_scan_keeps_same_slot_alternatives_distinct() {
        let source = r#"
fn render(flag: bool) {
    let _ = format!("{}", if flag { "not " } else { "just tracking" });
    let _ = format!("{0}{0}", if flag { "not " } else { "just tracking" });
    let _ = format!(
        "{value}{value}",
        value = if flag { "not " } else { "just tracking" },
    );
}
"#;
        assert!(audit_source("t", source).is_empty());
    }

    #[test]
    fn rust_labels_and_lifetimes_do_not_hide_source_strings() {
        let source = r#"
fn render<'a>(value: &'a str) { 'retry: loop { show("not just tracking"); if value.is_empty() { break 'retry; } } }
"#;
        let violations = audit_source("t", source);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].rule_id, "negative-contrast");
    }

    #[test]
    fn scanner_excludes_comments_chars_bytes_regex_and_test_fixtures() {
        let source = r###"
// "a crucial step" and an em dash — are commentary.
/* "a seamless flow" /* nested "we promise" */ is commentary too. */
const CH: char = '—';
const BYTES: &[u8] = b"not just bytes";
const RAW_BYTES: &[u8] = br#"worth noting"#;
fn compile() {
    let _ = Regex::new(concat!(r"[-–—]", "we promise")).unwrap();
    let _ = RegexBuilder::new(r#"not just regex"#).build();
    show(r#"plain raw copy"#);
    show("plain copy");
}
#[cfg(test)]
mod tests {
    const FIXTURE: &str = "a seamless flow";
}
"###;
        assert!(audit_source("t", source).is_empty());
    }

    #[test]
    fn scanner_resumes_after_an_inline_test_module() {
        let source = r#"
pub const BEFORE: &str = "plain";
#[cfg(test)]
mod tests {
    const FIXTURE: &str = "a seamless flow";
}
pub const AFTER: &str = "still · scanned";
"#;
        let violations = audit_source("t", source);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].rule_id, "middot-separator");
        assert_eq!(violations[0].name, "AFTER");
    }

    #[test]
    fn allows_inside_inline_test_modules_are_ignored_with_the_fixtures() {
        let source = r#"
#[cfg(test)]
mod tests {
    // copy-allow: invented-rule fixture-only grant
    const FIXTURE: &str = "a seamless flow";
}
pub const AFTER: &str = "plain";
"#;
        assert!(audit_source("t", source).is_empty());
    }

    #[test]
    fn source_allows_apply_to_inline_and_generated_copy_and_stay_strict() {
        let source = r#"
// copy-allow: arrow path notation in this help text
show("Tray → Privacy");
// copy-allow: negative-contrast recorded factual construction
let built = concat!("not ", "just tracking");
// copy-allow: em-dash no hit remains
show("plain copy");
// copy-allow: invented-rule no such law
show("plain copy");
"#;
        let violations = audit_source("t", source);
        assert_eq!(violations.len(), 2, "{violations:?}");
        assert!(violations
            .iter()
            .any(|violation| violation.detail.contains("stale copy-allow")));
        assert!(violations
            .iter()
            .any(|violation| violation.detail.contains("unknown rule id")));
    }

    #[test]
    fn allows_attach_to_the_next_source_string_and_orphans_fail() {
        let source = "\
// copy-allow: en-dash the range separator itself\n\
pub const RANGE: &str = \"\\u{2013}\";\n\
\n\
// copy-allow: em-dash floating with no constant\n\
fn unrelated() {}\n";
        let (constants, problems) = parse_source(source);
        assert_eq!(constants.len(), 1);
        assert_eq!(constants[0].allows.len(), 1);
        assert_eq!(constants[0].allows[0].rule_id, "en-dash");
        assert_eq!(problems.len(), 1);
        assert!(problems[0].detail.contains("orphaned"));
        assert!(audit_source("t", source)
            .iter()
            .all(|violation| violation.detail.contains("orphaned")));
    }

    #[test]
    fn audit_source_skips_inline_test_modules() {
        let source = "\
pub const REAL: &str = \"plain\";\n\
#[cfg(test)]\n\
mod tests {\n\
    const FIXTURE: &str = \"two \u{2014} dashes \u{2014} here\";\n\
}\n";
        assert!(audit_source("t", source).is_empty());
    }

    #[test]
    fn crate_src_walk_finds_and_audits_this_crate() {
        // The walker's own crate is its fixture: it must find src files
        // (the empty-walk panic guards wrong paths) and this crate's
        // constants must pass the law it defines.
        let violations = audit_crate_src("gilbreth-core", env!("CARGO_MANIFEST_DIR"));
        assert_no_violations(&violations);
    }

    #[test]
    fn crate_walk_excludes_only_the_shared_policy_definition() {
        assert!(is_copy_policy_source(
            "gilbreth-core",
            std::path::Path::new("src/copy_style.rs")
        ));
        assert!(!is_copy_policy_source(
            "gilbreth-core",
            std::path::Path::new("src/other.rs")
        ));
        assert!(!is_copy_policy_source(
            "gilbreth-app",
            std::path::Path::new("src/copy_style.rs")
        ));
    }

    #[test]
    fn a_test_module_declaration_does_not_stop_the_scan() {
        // `#[cfg(test)] mod copy_audit;` is plumbing; constants after it
        // are still product copy and must be scanned.
        let source = "\
#[cfg(test)]\n\
mod copy_audit;\n\
pub const AFTER: &str = \"still \u{00B7} scanned\";\n";
        let violations = audit_source("t", source);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id, "middot-separator");
    }

    #[test]
    fn a_reasonless_allow_is_rejected() {
        let source = "// copy-allow: em-dash\npub const X: &str = \"a \u{2014} b\";\n";
        let violations = audit_source("t", source);
        assert!(
            violations
                .iter()
                .any(|violation| violation.detail.contains("needs a rule id and a reason")),
            "{violations:?}"
        );
        // And the constant itself still fails: the malformed allow
        // granted nothing.
        assert!(violations
            .iter()
            .any(|violation| violation.rule_id == "em-dash"));
    }
}
