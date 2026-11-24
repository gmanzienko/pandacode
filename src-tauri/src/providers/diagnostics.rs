//! Keep the cause of a failed startup visible after noisy runtime warnings.

use unicode_segmentation::UnicodeSegmentation;

/// ECMA-48 escape parser state: which part of a control sequence the next char belongs to.
#[derive(Clone, Copy)]
enum Esc {
    None,
    /// After ESC.
    Start,
    /// ESC followed by intermediate bytes (`ESC ( B`).
    Intermediate,
    /// Control Sequence Introducer: parameters until a final byte.
    Csi,
    /// Operating System Command: until BEL or ST.
    Osc,
    /// ESC inside an OSC: `\` completes the ST.
    OscEsc,
    /// DCS, SOS, PM or APC string: until ST.
    StringTerm,
    /// ESC inside such a string.
    StringEsc,
}

/// Removes escape sequences and other control characters, keeping line breaks and tabs.
/// A sequence never swallows a newline or the text after its final byte.
fn step_escape(state: &mut Esc, ch: char, mut emit: impl FnMut(char)) {
    *state = match (*state, ch) {
        (_, '\u{18}' | '\u{1a}') => Esc::None,
        (Esc::None, '\u{1b}') => Esc::Start,
        (_, '\u{90}' | '\u{98}' | '\u{9e}' | '\u{9f}') => Esc::StringTerm,
        (_, '\u{9b}') => Esc::Csi,
        (_, '\u{9d}') => Esc::Osc,
        (Esc::None, ch) => {
            if !ch.is_control() || matches!(ch, '\n' | '\r' | '\t') {
                emit(ch);
            } else if matches!(ch, '\u{b}' | '\u{c}' | '\u{85}') { emit(' '); }
            Esc::None
        }
        // Every unfinished sequence ends at a line break, which is kept.
        (_, ch @ ('\n' | '\r')) => {
            emit(ch);
            Esc::None
        }
        // ESC always starts a new sequence, abandoning an unfinished one.
        (Esc::Start | Esc::Intermediate, '\u{1b}') => Esc::Start,
        (Esc::Start, '[') => Esc::Csi,
        (Esc::Start, ']') => Esc::Osc,
        (Esc::Start, 'P' | 'X' | '^' | '_') => Esc::StringTerm,
        (Esc::Start | Esc::Intermediate, '\u{20}'..='\u{2f}') => Esc::Intermediate,
        // A two-char escape (`ESC 7`, `ESC =`) or an intermediate's final byte.
        (Esc::Start | Esc::Intermediate, _) => Esc::None,
        (Esc::Csi, '\u{40}'..='\u{7e}') => Esc::None,
        (Esc::Csi, '\u{20}'..='\u{3f}') => Esc::Csi,
        (Esc::Csi, '\u{1b}') => Esc::Start,
        // Not part of a CSI: the sequence is aborted and the char is ordinary text.
        (Esc::Csi, ch) => {
            if !ch.is_control() || ch == '\t' {
                emit(ch);
            } else if matches!(ch, '\u{b}' | '\u{c}' | '\u{85}') { emit(' '); }
            Esc::None
        }
        (Esc::Osc, '\u{07}' | '\u{9c}') | (Esc::StringTerm, '\u{9c}') => Esc::None,
        (Esc::Osc, '\u{1b}') => Esc::OscEsc,
        (Esc::StringTerm, '\u{1b}') => Esc::StringEsc,
        (Esc::Osc | Esc::StringTerm, _) => *state,
        // `ESC \` is the string terminator; any other char after the ESC begins
        // a new sequence, exactly as it would after a lone ESC.
        (Esc::OscEsc | Esc::StringEsc, '\\') => Esc::None,
        (Esc::OscEsc | Esc::StringEsc, '\u{1b}') => Esc::Start,
        (Esc::OscEsc | Esc::StringEsc, '[') => Esc::Csi,
        (Esc::OscEsc | Esc::StringEsc, ']') => Esc::Osc,
        (Esc::OscEsc | Esc::StringEsc, 'P' | 'X' | '^' | '_') => Esc::StringTerm,
        (Esc::OscEsc | Esc::StringEsc, '\u{20}'..='\u{2f}') => Esc::Intermediate,
        (Esc::OscEsc | Esc::StringEsc, _) => Esc::None,
    };
}

fn strip_escapes(text: &str) -> String {
    let mut clean = String::with_capacity(text.len());
    let mut state = Esc::None;
    for ch in text.chars() { step_escape(&mut state, ch, |ch| clean.push(ch)); }
    clean
}

/// Credential field names; a line naming one beside `=` or `:` is dropped whole.
/// `cookie` covers `set-cookie`, `authorization` `proxy-authorization`, `api-key` `x-api-key`.
const CREDENTIAL_FIELDS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "accesstoken",
    "access-token",
    "refresh_token",
    "refreshtoken",
    "refresh-token",
    "client_secret",
    "clientsecret",
    "client-secret",
    "auth_token",
    "authtoken",
    "auth-token",
    "id_token",
    "idtoken",
    "id-token",
    "session_token",
    "sessiontoken",
    "session-token",
    "api_secret", "apisecret", "api-secret",
    "bearer_token", "bearertoken", "bearer-token",
    "private_key", "privatekey", "private-key",
    "secret_key", "secretkey", "secret-key",
    "signing_key", "signingkey", "signing-key",
    "access_key", "accesskey", "access-key",
    "passwd", "passphrase",
    "password",
    "authorization",
    "cookie",
];

/// Decode known JSON/JS escapes while preserving unknown or incomplete sequences.
fn decode_common_escapes(text: &str) -> String {
    let hex = |start: usize, count: usize| {
        let raw = text.get(start..start.checked_add(count)?)?;
        if raw.bytes().all(|b| b.is_ascii_hexdigit()) { u32::from_str_radix(raw, 16).ok() } else { None }
    };
    let bytes = text.as_bytes();
    let mut decoded = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            let simple = match bytes.get(index + 1) {
                Some(b'\\') => Some('\\'), Some(b'/') => Some('/'),
                Some(b'"') => Some('"'), Some(b'\'') => Some('\''),
                Some(b'n') => Some('\n'), Some(b'r') => Some('\r'), Some(b't') => Some('\t'),
                Some(b'b') => Some('\u{8}'), Some(b'f') => Some('\u{c}'),
                _ => None,
            };
            if let Some(ch) = simple {
                decoded.push(ch);
                index += 2;
                continue;
            }
            if bytes.get(index + 1) == Some(&b'u') && bytes.get(index + 2) == Some(&b'{') {
                let start = index + 3;
                let count = bytes[start..].iter().take_while(|b| b.is_ascii_hexdigit()).take(7).count();
                if (1..=6).contains(&count) && bytes.get(start + count) == Some(&b'}') {
                    if let Some(code) = hex(start, count) {
                        decoded.push(char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER));
                        index = start + count + 1;
                        continue;
                    }
                }
            }
            let digits = match bytes.get(index + 1) { Some(b'u') => 4, Some(b'x') => 2, _ => 0 };
            if digits > 0 {
                if let Some(mut code) = hex(index + 2, digits) {
                    let mut consumed = digits + 2;
                    if (0xd800..=0xdbff).contains(&code) && text.get(index + 6..index + 8) == Some(r"\u") {
                        if let Some(low) = hex(index + 8, 4).filter(|low| (0xdc00..=0xdfff).contains(low)) {
                            code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
                            consumed = 12;
                        }
                    }
                    decoded.push(char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER));
                    index += consumed;
                    continue;
                }
            }
        }
        let ch = text[index..].chars().next().unwrap();
        decoded.push(ch);
        index += ch.len_utf8();
    }
    decoded
}

fn canonical_for_check(text: &str) -> String {
    if !text.contains('\\') && !text.bytes().any(|b| (b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t')) || b == 0x7f || b >= 0x80) {
        return text.to_owned();
    }
    let mut canonical = text.to_owned();
    for _ in 0..3 {
        let next = strip_escapes(&decode_common_escapes(&canonical));
        if next == canonical { break; }
        canonical = next;
    }
    canonical
}

fn is_credential_key(key: &str) -> bool {
    let canon = canonical_for_check(key);
    let trimmed = canon.trim().trim_matches(|ch: char| matches!(ch, '\\' | '"' | '\''));
    if trimmed.is_empty() || trimmed.contains(char::is_whitespace) { return false; }
    let lower = trimmed.to_ascii_lowercase();
    let token_suffix = lower.strip_suffix("token").filter(|before|
        before.ends_with(['_', '-', '.'])
            || trimmed.strip_suffix("Token").is_some_and(|prefix| prefix.chars().next_back().is_some_and(|ch| ch.is_ascii_lowercase())));
    let key_suffix = lower.strip_suffix("key").filter(|before|
        before.ends_with(['_', '-', '.'])
            || trimmed.strip_suffix("Key").is_some_and(|prefix| prefix.chars().next_back().is_some_and(|ch| ch.is_ascii_lowercase())));
    let non_secret_key = key_suffix.is_some_and(|before| {
        let prefix = before.trim_end_matches(['_', '-', '.']);
        ["public", "pub", "ssh_pub", "primary", "foreign", "sort", "partition", "shard", "cache", "cache_entry",
            "lookup", "search", "map", "hash", "object", "json", "item", "row", "node", "react", "element", "group",
            "index", "hot", "shortcut", "hotkey", "arrow", "enter", "escape", "tab", "shift", "ctrl", "alt", "meta",
            "modifier", "press", "pressed", "down", "up", "board", "composite", "unique", "surrogate", "natural",
            "candidate", "parent", "child", "join", "merge", "group_by", "order_by", "locale", "i18n", "translation",
            "message", "metric", "label", "tag", "field", "column", "property", "prop", "attr", "attribute", "config",
            "setting", "option", "pref", "preference", "storage", "local_storage", "session_storage", "state", "route",
            "query", "param", "header", "env", "var", "name", "type", "id", "format", "event", "code", "char", "virtual",
            "scan", "dead", "repeat", "lock", "num", "caps", "scroll", "fn", "function", "media", "volume", "home",
            "end", "page", "insert", "delete", "backspace", "space"].iter().any(|excluded| {
                let Some(start) = prefix.strip_suffix(excluded).map(str::len) else { return false; };
                start == 0 || matches!(prefix.as_bytes()[start - 1], b'_' | b'-' | b'.')
                    || (trimmed.as_bytes()[start - 1].is_ascii_lowercase() && trimmed.as_bytes()[start].is_ascii_uppercase())
            })
    });
    if non_secret_key && !CREDENTIAL_FIELDS.iter().any(|field| lower.contains(field)) { return false; }
    // Ignore incidental fields inside a non-secret suffix (invalid_token contains id_token).
    let non_secret_start = token_suffix.and_then(|before| {
        let prefix = before.trim_end_matches(['_', '-', '.']);
        ["max", "min", "input", "output", "prompt", "completion", "context", "total", "cached",
            "reasoning", "thinking", "page", "nextpage", "prevpage", "previouspage", "continuation",
            "cursor", "sync", "cancel", "cancellation", "design", "eof", "syntax", "unexpected",
            "invalid", "parse", "lex", "next", "prev", "last", "first", "start", "end", "current"]
            .iter().filter_map(|excluded| {
                let start = prefix.strip_suffix(*excluded)?.len();
                (start == 0 || matches!(prefix.as_bytes()[start - 1], b'_' | b'-' | b'.')
                    || (trimmed.as_bytes()[start - 1].is_ascii_lowercase()
                        && trimmed.as_bytes()[start].is_ascii_uppercase())).then_some(start)
            }).next()
    });
    if non_secret_start.is_some_and(|start| !CREDENTIAL_FIELDS.iter().any(|field| lower[..start].contains(field))) {
        return false;
    }
    CREDENTIAL_FIELDS.iter().any(|field| lower.contains(field))
        || matches!(lower.as_str(), "token" | "secret" | "secrets" | "credential" | "credentials" | "pwd" | "bearer")
        || ["secret", "secrets", "pwd"].iter().any(|suffix| lower.strip_suffix(suffix).is_some_and(|before| before.ends_with(['_', '-', '.'])))
        || lower.contains("_secret_") || lower.contains("-secret-")
        || trimmed.strip_suffix("Secret").is_some_and(|before| before.chars().next_back().is_some_and(|ch| ch.is_ascii_lowercase()))
        || token_suffix.is_some() || key_suffix.is_some()

}

fn has_credential_key_assignment(text: &str) -> bool {
    // Use the same bounded key lexer for complete text and overflowed lines.
    let mut scanner = OverflowLine::new(OmitNext::None);
    scanner.push_str(text);
    if scanner.in_bare_token { scanner.flush_token(); }
    scanner.ever_marker
}

fn has_pem_private_key_marker(text: &str, kind: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let prefix = format!("-----{} ", kind.to_ascii_lowercase());
    lower.match_indices(&prefix).any(|(start, _)| {
        lower[start + prefix.len()..].split_once("-----")
            .is_some_and(|(label, _)| !label.contains(['\r', '\n']) && label.contains("private key"))
    })
}

fn has_bearer_value(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.contains("bearer\n") || lower.contains("bearer\r")
        || lower.split('\r').any(|part| part.trim_matches(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | '\\')) == "bearer")
    { return true; }
    for (start, _) in lower.match_indices("bearer") {
        if lower[..start].chars().next_back().is_some_and(|ch| ch.is_ascii_alphanumeric())
            || !lower[start + 6..].chars().next().is_some_and(char::is_whitespace) { continue; }
        let mut words = text[start + 6..].split_whitespace();
        let raw = words.next().unwrap_or("");
        let trim = |ch: char| matches!(ch, '.' | ',' | ';' | ':' | '!' | '?' | ')' | '\'' | '"');
        let first = raw.trim_end_matches(trim).to_ascii_lowercase();
        let second = words.next().unwrap_or("").trim_end_matches(trim).to_ascii_lowercase();
        if !raw.contains([':', '=']) && matches!(first.as_str(), "token" | "tokens" | "auth" | "authentication" | "authorization" | "header" | "headers" | "scheme" | "prefix" | "credential" | "credentials")
            && (second.is_empty() || matches!(second.as_str(), "is" | "was" | "are" | "were" | "not" | "missing" | "required" | "expected" | "invalid" | "expired" | "empty" | "absent" | "needed" | "must" | "cannot" | "failed" | "from" | "in" | "for" | "or" | "and" | "to" | "with" | "without" | "found" | "provided" | "configured" | "supplied" | "set" | "present" | "unspecified" | "unknown" | "denied" | "rejected"))
            && words.all(|word| {
                let word = word.trim_end_matches(trim);
                !word.is_empty() && word.len() <= 16 && word.bytes().all(|byte| byte.is_ascii_lowercase())
            })
        { continue; }
        return true;
    }
    false
}

fn contains_credential_marker(text: &str, assigns: bool) -> bool {
    has_pem_private_key_marker(text, "begin") || has_bearer_value(text)
        || (assigns && has_credential_key_assignment(text))
}

fn is_secret_free_status_line(raw: &str, canonical: &str) -> bool {
    if raw.contains(['\\', '=', '\r']) || canonical.contains(['=', '@', '{', '"', '\r']) || canonical.contains("://")
        || has_pem_private_key_marker(canonical, "begin") || has_bearer_value(canonical)
    { return false; }
    for (colon, _) in canonical.match_indices(':') {
        let before = canonical[..colon].trim_end();
        let word = before.rsplit(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '_' | '-' | '.')).next().unwrap_or("");
        if !is_credential_key(word) { continue; }
        if before.contains('\'') { return false; }
        for (start, _) in before.match_indices('[') {
            let rest = &before[start + 1..];
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 || rest.as_bytes().get(digits) != Some(&b']') { return false; }
        }
        let rest = canonical[colon + 1..].trim().trim_end_matches(['.', '!', ';', ')']);
        if rest.contains([':', '=', '[']) { return false; }
        let rest = rest.to_ascii_lowercase().split_ascii_whitespace().collect::<Vec<_>>().join(" ");
        return matches!(rest.as_str(), "required" | "missing" | "not found" | "not set" | "not configured" | "not provided" | "not specified" | "not supplied" | "none" | "none configured" | "none found" | "empty" | "blank" | "unset" | "is required" | "is missing" | "is empty" | "is not set" | "is not configured" | "must be set" | "cannot be empty" | "must not be empty" | "missing or invalid" | "invalid or missing" | "required but missing" | "needed" | "expected" | "can't be blank" | "can't be empty" | "cannot be blank" | "must not be blank" | "is blank" | "header too large" | "header is too large" | "too large" | "too long" | "too short")
            && redact_inline_secrets(canonical) == canonical;
    }
    false
}

const MAX_BLOCK_DEPTH: usize = 4096;

#[derive(Default)]
enum OmitNext {
    #[default]
    None,
    Value { key_indent: Option<usize> },
    /// Unclosed credential quotes deliberately remain fail-closed.
    Quoted(char, bool),
    YamlBlock { key_indent: usize },
    Pem,
    /// Unclosed quotes remain fail-closed so truncated multiline secrets cannot leak.
    Block { stack: Vec<char>, overflowed: bool, quote: Option<char>, quote_triple: bool },
}

fn is_yaml_block_header(text: &str) -> bool {
    let header = text.split('#').next().unwrap_or("").trim();
    let mut tokens = header.split_whitespace().peekable();
    while let Some(token) = tokens.next() {
        if tokens.peek().is_some() {
            if !token.starts_with(['!', '&']) { return false; }
            continue;
        }
        if !token.starts_with(['|', '>']) { return false; }
        let mut chomp = false;
        let mut digit = false;
        for ch in token[1..].chars() {
            match ch {
                '-' | '+' if !chomp => chomp = true,
                '1'..='9' if !digit => digit = true,
                _ => return false,
            }
        }
        return true;
    }
    false
}

fn is_yaml_sibling_key_line(raw: &str, key_indent: usize) -> bool {
    let indent = raw.chars().take_while(|ch| ch.is_whitespace()).count();
    if indent > key_indent { return false; }
    let rest = raw.trim_start();
    if !rest.as_bytes().first().is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_') { return false; }
    let end = rest.bytes().take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')).count();
    rest[end..].starts_with(':') && rest[end + 1..].starts_with([' ', '\t'])
}

fn ends_with_assign(text: &str) -> bool {
    text.trim_end_matches(|ch: char| ch.is_whitespace() || ch == '\\').ends_with([':', '='])
}

fn ends_with_bearer_token(text: &str) -> bool {
    let lower = text.trim_end_matches(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | '\\')).to_ascii_lowercase();
    lower.strip_suffix("bearer").is_some_and(|before| before.chars().next_back().is_none_or(|ch| !ch.is_ascii_alphanumeric()))
}

/// Tracks an entire line with bounded tokens, tail and bracket storage, even when its bytes are discarded.
pub(super) struct OverflowLine {
    esc: Esc,
    started_value: bool,
    started_value_indent: Option<usize>,
    indent_locked: bool,
    started_block: bool,
    started_quoted: bool,
    in_quoted_scalar: bool,
    started_pem: bool,
    in_pem: bool,
    open_url: OpenUrlTracker,
    allow_nested: bool,
    nested: Option<Box<OverflowLine>>,
    rescanning_escape: bool,
    awaiting_value_block: bool,
    cred_stack: Vec<char>,
    cred_closer_counts: [usize; 3],
    block_overflowed: bool,
    quote: Option<char>,
    quote_escaped: bool,
    quote_triple: bool,
    quote_run: u8,
    quote_nonempty: bool,
    empty_quote: Option<char>,
    prev_outside_quote: Option<char>,
    token: String,
    token_was_credential: bool,
    in_bare_token: bool,
    bare_esc_remaining: u8,
    bare_esc_braces: bool,
    pending_cred_key: bool,
    pending_allows_colon: bool,
    prev_token_was_bare_word: bool,
    after_cred_assign: bool,
    saw_new_marker: bool,
    ever_marker: bool,
    any_non_ws: bool,
    any_non_closing: bool,
    tail: std::collections::VecDeque<char>,
    pem_tail: String,
    line_indent: usize,
    in_yaml_indent: Option<usize>,
    yaml_inherited: bool,
    after_assign_tail: String,
    after_assign_comment: bool,
    after_assign_overflow: bool,
}

impl OverflowLine {
    fn new(state: OmitNext) -> Self {
        let in_yaml_indent = match &state { OmitNext::YamlBlock { key_indent } => Some(*key_indent), _ => None };
        let started_value = matches!(state, OmitNext::Value { .. });
        let started_value_indent = match &state { OmitNext::Value { key_indent } => *key_indent, _ => None };
        let started_block = matches!(state, OmitNext::Block { .. });
        let started_quoted = matches!(state, OmitNext::Quoted(..));
        let started_pem = matches!(state, OmitNext::Pem);
        let quote_triple = matches!(state, OmitNext::Quoted(_, true) | OmitNext::Block { quote_triple: true, .. });
        let quote_nonempty = started_quoted || matches!(state, OmitNext::Block { quote: Some(_), .. });
        let (cred_stack, block_overflowed, quote) = match state {
            OmitNext::Block { stack, overflowed, quote, .. } => (stack, overflowed, quote),
            OmitNext::Quoted(quote, _) => (Vec::new(), false, Some(quote)),
            _ => (Vec::new(), false, None),
        };
        let mut cred_closer_counts = [0; 3];
        for &closer in &cred_stack { cred_closer_counts[Self::closer_index(closer)] += 1; }
        Self {
            esc: Esc::None, started_value, started_value_indent, indent_locked: false, started_block, started_quoted, in_quoted_scalar: started_quoted, awaiting_value_block: started_value,
            started_pem, in_pem: started_pem, open_url: OpenUrlTracker::new(), allow_nested: true, nested: None, rescanning_escape: false,
            cred_stack, cred_closer_counts, block_overflowed, quote, quote_escaped: false, quote_triple, quote_run: 0, quote_nonempty, empty_quote: None, prev_outside_quote: None,
            token: String::new(), token_was_credential: false, in_bare_token: false,
            bare_esc_remaining: 0, bare_esc_braces: false, pending_cred_key: false,
            pending_allows_colon: false, prev_token_was_bare_word: false,
            after_cred_assign: false, saw_new_marker: false, ever_marker: false,
            any_non_ws: false, any_non_closing: false, tail: std::collections::VecDeque::new(), pem_tail: String::new(),
            line_indent: 0, in_yaml_indent, yaml_inherited: false, after_assign_tail: String::new(), after_assign_comment: false, after_assign_overflow: false,
        }
    }

    pub(super) fn in_open_url_authority(&self) -> bool {
        self.open_url.keeps_cr()
    }

    fn in_block(&self) -> bool { self.block_overflowed || !self.cred_stack.is_empty() }

    fn closer_index(ch: char) -> usize { match ch { '}' => 0, ']' => 1, _ => 2 } }

    fn push_bracket(&mut self, closer: char) {
        if self.cred_stack.len() == MAX_BLOCK_DEPTH { self.block_overflowed = true; }
        else { self.cred_stack.push(closer); self.cred_closer_counts[Self::closer_index(closer)] += 1; }
    }

    fn push_token(&mut self, ch: char) {
        self.token.push(ch);
        if self.token.len() > 256 {
            let lower = canonical_for_check(&self.token).to_ascii_lowercase();
            self.token_was_credential |= CREDENTIAL_FIELDS.iter().any(|field| lower.contains(field));
            let mut start = self.token.len() - 128;
            while !self.token.is_char_boundary(start) { start += 1; }
            self.token.drain(..start);
        }
    }

    fn mark_assignment(&mut self) {
        self.after_assign_tail.clear();
        self.after_assign_comment = false;
        self.after_assign_overflow = false;
        self.after_cred_assign = true;
        self.pending_cred_key = false;
        self.pending_allows_colon = false;
        self.saw_new_marker = true;
        self.ever_marker = true;
        self.prev_token_was_bare_word = false;
    }

    fn flush_token(&mut self) {
        if self.in_bare_token && self.token != "\\" && !self.rescanning_escape && self.token.contains('\\') {
            let canon = canonical_for_check(&self.token);
            if canon != self.token {
                self.token.clear();
                self.token_was_credential = false;
                self.in_bare_token = false;
                self.bare_esc_remaining = 0;
                self.bare_esc_braces = false;
                self.rescanning_escape = true;
                for ch in canon.chars() { self.scan_char(ch); }
                if self.in_bare_token { self.flush_token(); }
                self.rescanning_escape = false;
                return;
            }
        }
        if !self.after_cred_assign && !(self.in_bare_token && self.token == "\\") {
            let canon = canonical_for_check(&self.token);
            let bare_allows_colon = !self.prev_token_was_bare_word;
            let is_eq = canon.trim_end_matches(|ch: char| ch.is_whitespace() || ch == '\\').ends_with('=');
            let key_part = canon.trim_end_matches(|ch: char| ch.is_whitespace() || matches!(ch, ':' | '=' | '\\'));
            if self.in_bare_token && ends_with_assign(&canon)
                && ((key_part.is_empty() && self.pending_cred_key && (is_eq || self.pending_allows_colon))
                    || (!key_part.is_empty() && (is_eq || bare_allows_colon)
                        && (self.token_was_credential || is_credential_key(key_part))))
            {
                self.mark_assignment();
            } else {
                self.pending_cred_key = self.token_was_credential || is_credential_key(&canon);
                self.pending_allows_colon = !self.in_bare_token || bare_allows_colon;
                self.prev_token_was_bare_word = self.in_bare_token && self.token != "-";
            }
        }
        self.token.clear();
        self.token_was_credential = false;
        self.in_bare_token = false;
        self.bare_esc_remaining = 0;
        self.bare_esc_braces = false;
    }

    fn end_value(&mut self) {
        self.after_assign_tail.clear();
        self.after_assign_comment = false;
        self.after_assign_overflow = false;
        self.tail.clear();
        self.pem_tail.clear();
        self.quote_nonempty = false;
        self.quote_triple = false;
        self.quote_run = 0;
        self.empty_quote = None;
        self.pending_cred_key = false;
        self.pending_allows_colon = false;
        self.after_cred_assign = false;
        self.saw_new_marker = false;
        self.in_bare_token = false;
        self.token.clear();
        self.token_was_credential = false;
        self.awaiting_value_block = false;
        self.prev_token_was_bare_word = false;
    }

    fn bare_char(&mut self, ch: char) -> bool {
        if self.bare_esc_braces {
            if ch.is_ascii_hexdigit() || ch == '}' {
                self.push_token(ch);
                if ch == '}' { self.bare_esc_braces = false; }
                return true;
            }
            self.bare_esc_braces = false;
        }
        if self.bare_esc_remaining == u8::MAX {
            if matches!(ch, ':' | '=' | '{' | '[' | '}' | ']' | ',' | ';' | '"' | '\'' | ' ' | '\t') {
                self.bare_esc_remaining = 0;
                return false;
            }
            self.push_token(ch);
            self.bare_esc_remaining = match ch { 'u' => 254, 'x' => 2, _ => 0 };
            return true;
        }
        if self.bare_esc_remaining == 254 {
            self.bare_esc_remaining = 0;
            if ch == '{' { self.push_token(ch); self.bare_esc_braces = true; return true; }
            if ch.is_ascii_hexdigit() { self.push_token(ch); self.bare_esc_remaining = 3; return true; }
        } else if self.bare_esc_remaining > 0 {
            if ch.is_ascii_hexdigit() {
                self.push_token(ch);
                self.bare_esc_remaining -= 1;
                return true;
            }
            self.bare_esc_remaining = 0;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '\\') {
            self.push_token(ch);
            if ch == '\\' { self.bare_esc_remaining = u8::MAX; }
            return true;
        }
        false
    }

    fn opens_single_quote(&self) -> bool {
        if self.prev_outside_quote.is_none_or(|prev| !prev.is_ascii_alphanumeric()) { return true; }
        let mut prefix = [0u8; 3];
        let mut length = 0;
        let skip = usize::from(self.tail.back() == Some(&'\''));
        for ch in self.tail.iter().rev().skip(skip) {
            if !ch.is_ascii_alphanumeric() && *ch != '_' { break; }
            if length == prefix.len() { return false; }
            prefix[length] = ch.to_ascii_lowercase() as u8;
            length += 1;
        }
        prefix[..length].reverse();
        matches!(&prefix[..length], b"b" | b"r" | b"f" | b"u" | b"br" | b"rb" | b"fr" | b"rf")
    }

    fn update_pem_state(&mut self) {
        if !self.pem_tail.contains('\\')
            && !self.pem_tail.contains("-----") { return; }
        let raw = &self.pem_tail;
        let canonical = canonical_for_check(raw);
        if self.in_pem && (has_pem_private_key_marker(&raw, "end") || has_pem_private_key_marker(&canonical, "end")) {
            self.in_pem = false;
            self.tail.clear();
            self.pem_tail.clear();
            if self.quote.is_none() && !self.in_block() && !self.in_quoted_scalar { self.end_value(); }
        } else if !self.in_pem && (has_pem_private_key_marker(&raw, "begin") || has_pem_private_key_marker(&canonical, "begin")) {
            self.in_pem = true;
            self.saw_new_marker = true;
            self.ever_marker = true;
        }
    }

    fn closes_quote(&mut self, ch: char) -> bool {
        if self.quote_escaped { self.quote_escaped = false; self.quote_run = 0; }
        else if ch == '\\' { self.quote_escaped = true; self.quote_run = 0; }
        else if self.quote == Some(ch) {
            if !self.quote_triple { return true; }
            self.quote_run += 1;
            return self.quote_run == 3;
        } else { self.quote_run = 0; }
        false
    }

    fn scan_char(&mut self, ch: char) {
        if ch == '\r' { self.line_indent = 0; self.indent_locked = false; }
        if !self.indent_locked {
            if ch.is_whitespace() { if ch != '\r' { self.line_indent += 1; } }
            else {
                self.indent_locked = true;
                if let Some(key_indent) = self.in_yaml_indent {
                    if self.line_indent <= key_indent { self.in_yaml_indent = None; self.yaml_inherited = false; }
                    else { self.yaml_inherited = true; }
                }
            }
        }
        if !ch.is_whitespace() {
            self.any_non_ws = true;
            if self.quote.is_some() || !matches!(ch, '}' | ']' | ')' | ',') { self.any_non_closing = true; }
        }
        if self.yaml_inherited { return; }
        if (self.after_cred_assign || self.awaiting_value_block) && !self.in_block() && self.quote.is_none() {
            if ch == '#' { self.after_assign_comment = true; }
            else if !self.after_assign_comment {
                if ch.is_whitespace() {
                    if !self.after_assign_tail.is_empty() && !self.after_assign_tail.ends_with(' ') { self.after_assign_tail.push(' '); }
                } else if self.after_assign_tail.len() < 128 { self.after_assign_tail.push(ch); }
                else { self.after_assign_overflow = true; }
            }
        }
        if self.tail.len() == 128 { self.tail.pop_front(); }
        self.tail.push_back(ch);
        self.pem_tail.push(ch);
        if self.pem_tail.len() >= 256 {
            if self.pem_tail.contains('\\') { self.pem_tail = canonical_for_check(&self.pem_tail); }
            if self.pem_tail.len() > 160 {
                let start = self.pem_tail.char_indices().rev().nth(127).map_or(0, |(i, _)| i);
                self.pem_tail.drain(..start);
            }
        }
        self.open_url.push(ch);
        if matches!(ch, '-' | '"' | '\'' | '}' | ']') || (matches!(ch, 'd' | 'D') && self.tail.iter().rev().nth(1) == Some(&'2')) { self.update_pem_state(); }
        if self.in_quoted_scalar {
            if self.closes_quote(ch) {
                self.quote = None;
                self.in_quoted_scalar = false;
                self.end_value();
                self.prev_outside_quote = Some(ch);
            }
            return;
        }
        if self.in_block() {
            if let Some(q) = self.empty_quote.take() {
                if ch == q {
                    self.quote = Some(q);
                    self.quote_triple = true;
                    self.quote_run = 0;
                    self.quote_escaped = false;
                    self.quote_nonempty = false;
                    return;
                }
            }
            if let Some(close) = self.quote {
                let was_empty = !self.quote_nonempty && !self.quote_triple;
                if self.closes_quote(ch) {
                    self.quote = None;
                    self.empty_quote = was_empty.then_some(close);
                    self.quote_triple = false;
                    self.quote_run = 0;
                    self.quote_escaped = false;
                    self.quote_nonempty = false;
                    self.prev_outside_quote = Some(ch);
                    self.prev_token_was_bare_word = false;
                } else { self.quote_nonempty = true; }
            } else {
                match ch {
                    '"' | '\x60' => self.quote = Some(ch),
                    '\'' if self.opens_single_quote() => self.quote = Some(ch),
                    '{' => self.push_bracket('}'),
                    '[' => self.push_bracket(']'),
                    '(' => self.push_bracket(')'),
                    '}' | ']' | ')' => {
                        if self.cred_stack.last() == Some(&ch) {
                            self.cred_stack.pop();
                            self.cred_closer_counts[Self::closer_index(ch)] -= 1;
                        } else if !self.block_overflowed && self.cred_closer_counts[Self::closer_index(ch)] > 0 {
                            if let Some(pos) = self.cred_stack.iter().rposition(|&closer| closer == ch) {
                                for closer in self.cred_stack.drain(pos + 1..) {
                                    self.cred_closer_counts[Self::closer_index(closer)] -= 1;
                                }
                            }
                        }
                        if !self.in_block() { self.end_value(); }
                    }
                    _ => {}
                }
                if self.quote.is_some() {
                    self.quote_triple = false;
                    self.quote_run = 0;
                    self.quote_escaped = false;
                    self.quote_nonempty = false;
                }
                self.prev_outside_quote = Some(ch);
            }
            return;
        }
        if self.in_pem && self.quote.is_none() { return; }
        if let Some(q) = self.empty_quote.take() {
            if ch == q {
                self.quote = Some(q);
                self.quote_nonempty = false;
                self.quote_triple = true;
                self.quote_run = 0;
                self.token.clear();
                self.token_was_credential = false;
                return;
            }
        }
        // A single quote can wrap an entire JSON or env payload, rather than a scalar key.
        if self.quote == Some('\'') && !self.after_cred_assign && !self.awaiting_value_block
            && !self.quote_escaped && matches!(ch, '{' | '[' | '"' | ':' | '=' | ',' | ';')
            // Keep URL userinfo in the URL redactor rather than treating it as an embedded payload.
            && !has_open_url_authority(&self.tail.iter().collect::<String>())
        {
            let canon = canonical_for_check(&self.token);
            self.pending_cred_key = self.token_was_credential || match ch {
                '=' => canon.split_whitespace().next_back().is_some_and(is_credential_key),
                ':' => is_credential_key(&canon),
                _ => false,
            };
            self.pending_allows_colon = ch == ':' && !canon.trim().contains(char::is_whitespace);
            if matches!(ch, '{' | '[') && ends_with_assign(&canon) {
                let is_eq = canon.trim_end_matches(|ch: char| ch.is_whitespace() || ch == '\\').ends_with('=');
                let key_part = canon.trim_end_matches(|ch: char| ch.is_whitespace() || matches!(ch, ':' | '=' | '\\'));
                if self.token_was_credential
                    || (is_eq && key_part.split_whitespace().next_back().is_some_and(is_credential_key))
                    || (!is_eq && is_credential_key(key_part))
                {
                    self.mark_assignment();
                }
            }
            self.token.clear();
            self.token_was_credential = false;
            self.quote = None;
            self.prev_token_was_bare_word = false;
        }
        if let Some(close) = self.quote {
            if close == '"' && self.allow_nested && !self.after_cred_assign && !self.awaiting_value_block {
                if self.nested.is_none() && !self.quote_escaped && matches!(ch, '\\' | '{' | '[' | ':' | '=' | '-') {
                    let mut nested = Self::new(OmitNext::None);
                    nested.allow_nested = false;
                    nested.push_str(&canonical_for_check(&self.token));
                    self.nested = Some(Box::new(nested));
                }
                if let Some(nested) = &mut self.nested {
                    if self.quote_escaped {
                        match ch {
                            '"' | '\\' | '/' | '\'' => nested.scan_char(ch),
                            'n' => nested.scan_char('\n'),
                            'r' => nested.scan_char('\r'),
                            't' => nested.scan_char('\t'),
                            _ => { nested.scan_char('\\'); nested.scan_char(ch); }
                        }
                    } else if ch != '\\' && ch != close { nested.scan_char(ch); }
                    self.ever_marker |= nested.ever_marker;
                }
            }
            let empty = self.token.is_empty() && !self.quote_triple && (self.after_cred_assign || self.awaiting_value_block);
            if self.closes_quote(ch) {
                self.nested = None;
                self.flush_token();
                self.quote = None;
                self.quote_nonempty = false;
                self.empty_quote = empty.then_some(close);
                self.quote_triple = false;
                self.quote_run = 0;
                self.prev_outside_quote = Some(ch);
                self.prev_token_was_bare_word = false;
            } else { self.push_token(ch); }
            return;
        }
        if self.in_bare_token {
            if self.bare_char(ch) { self.prev_outside_quote = Some(ch); return; }
            self.flush_token();
            if self.quote.is_some() || self.in_block() || self.in_quoted_scalar || self.in_pem {
                self.scan_char(ch);
                return;
            }
        }
        let opens_quote = ch == '"' || (ch == '\'' && self.opens_single_quote())
            || (ch == '\x60' && (self.after_cred_assign || self.awaiting_value_block));
        if opens_quote {
            self.quote = Some(ch);
            self.quote_nonempty = false;
            self.quote_triple = false;
            self.quote_run = 0;
            self.prev_token_was_bare_word = false;
            self.quote_escaped = false;
            self.token.clear();
            self.token_was_credential = false;
        } else if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '\\') {
            self.in_bare_token = true;
            self.bare_char(ch);
        } else if !ch.is_whitespace() {
            match ch {
                ':' | '=' => {
                    if self.pending_cred_key && (ch == '=' || self.pending_allows_colon) {
                        self.mark_assignment();
                    } else {
                        self.pending_cred_key = false;
                        self.pending_allows_colon = false;
                    }
                }
                '{' | '[' | '(' if self.after_cred_assign || self.awaiting_value_block => {
                    self.push_bracket(match ch { '{' => '}', '[' => ']', _ => ')' });
                    self.awaiting_value_block = false;
                    self.pending_cred_key = false;
                }
                ',' | ';' | '}' | ']' => {
                    self.pending_cred_key = false;
                    self.after_cred_assign = false;
                    if matches!(ch, ',' | ';') { self.awaiting_value_block = false; }
                }
                _ => self.pending_cred_key = false,
            }
            self.prev_token_was_bare_word = false;
            if !self.pending_cred_key { self.pending_allows_colon = false; }
        }
        if matches!(ch, '\r' | '\n') { self.prev_token_was_bare_word = false; }
        self.prev_outside_quote = Some(ch);
    }

    pub(super) fn push_str(&mut self, chunk: &str) {
        for ch in chunk.chars() {
            let mut esc = self.esc;
            step_escape(&mut esc, ch, |ch| self.scan_char(ch));
            self.esc = esc;
        }
    }

    fn finish(mut self, allow_trailing_bearer: bool) -> OmitNext {
        if self.in_bare_token { self.flush_token(); }
        self.update_pem_state();
        if self.quote == Some('"') {
            if let Some(nested) = self.nested.take() {
                let inner = nested.finish(allow_trailing_bearer);
                if !matches!(inner, OmitNext::None) { return inner; }
            }
        }
        let tail_raw: String = self.tail.iter().collect();
        let tail_canon = canonical_for_check(&tail_raw);
        let bare_bearer = [&tail_raw, &tail_canon].iter().any(|tail| {
            tail.rsplit('\r').next().unwrap_or(tail)
                .trim_matches(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | '\\'))
                .eq_ignore_ascii_case("bearer")
        });
        if let Some(key_indent) = self.in_yaml_indent {
            return OmitNext::YamlBlock { key_indent };
        }
        if self.in_quoted_scalar {
            OmitNext::Quoted(self.quote.unwrap(), self.quote_triple)
        } else if self.in_block() {
            OmitNext::Block { stack: self.cred_stack, overflowed: self.block_overflowed, quote: self.quote, quote_triple: self.quote_triple }
        } else if self.quote.is_some() && (self.after_cred_assign || self.awaiting_value_block) {
            OmitNext::Quoted(self.quote.unwrap(), self.quote_triple)
        } else if self.in_pem {
            OmitNext::Pem
        } else if (self.after_cred_assign || self.awaiting_value_block) && !self.after_assign_overflow && is_yaml_block_header(&self.after_assign_tail) {
            OmitNext::YamlBlock { key_indent: self.started_value_indent.unwrap_or(self.line_indent) }
        } else if (self.after_cred_assign || self.awaiting_value_block) && !self.after_assign_overflow
            && !self.after_assign_tail.trim().is_empty()
            && self.after_assign_tail.split_whitespace().all(|token| token.starts_with(['!', '&']))
        {
            OmitNext::Value { key_indent: Some(self.started_value_indent.unwrap_or(self.line_indent)) }
        } else if (self.after_cred_assign || self.awaiting_value_block) && self.after_assign_comment
            && self.after_assign_tail.trim().is_empty() && !self.after_assign_overflow
        {
            OmitNext::Value { key_indent: Some(self.started_value_indent.unwrap_or(self.line_indent)) }
        } else if self.started_value && !self.any_non_ws {
            OmitNext::Value { key_indent: self.started_value_indent }
        } else if self.started_value && !self.any_non_closing {
            OmitNext::None
        } else if (self.after_cred_assign || self.pending_cred_key || self.started_value) && (ends_with_assign(&tail_raw) || ends_with_assign(&tail_canon)) {
            OmitNext::Value { key_indent: Some(self.started_value_indent.unwrap_or(self.line_indent)) }
        } else if (self.saw_new_marker || self.started_value || bare_bearer || allow_trailing_bearer) && (ends_with_bearer_token(&tail_raw) || ends_with_bearer_token(&tail_canon)) {
            OmitNext::Value { key_indent: None }
        } else {
            OmitNext::None
        }
    }
}

pub(super) struct Cleaner { omit_next: OmitNext }

impl Cleaner {
    pub(super) fn new() -> Self { Self { omit_next: OmitNext::None } }

    pub(super) fn begin_overflow(&mut self) -> OverflowLine { OverflowLine::new(std::mem::take(&mut self.omit_next)) }

    pub(super) fn finish_overflow(&mut self, line: OverflowLine) -> &'static str {
        let sensitive = line.yaml_inherited || line.ever_marker || line.started_pem || line.in_pem || line.started_quoted
            || (line.started_block && (line.in_block() || line.any_non_closing))
            || (line.started_value && line.any_non_closing);
        self.omit_next = line.finish(true);
        if sensitive { OMITTED } else { OVERSIZED_OMITTED }
    }

    pub(super) fn clean_line(&mut self, line: &str) -> String {
        let raw = strip_escapes(line);
        if matches!(self.omit_next, OmitNext::Value { key_indent: Some(k) } if is_yaml_sibling_key_line(&raw, k)) {
            self.omit_next = OmitNext::None;
        }
        let canonical = canonical_for_check(&raw);
        let mut scanner = self.begin_overflow();
        scanner.push_str(&raw);
        let inherited = scanner.yaml_inherited || (scanner.started_block && (scanner.in_block() || scanner.any_non_closing))
            || (scanner.started_value && scanner.any_non_closing) || scanner.started_quoted || scanner.started_pem;
        let assigns = raw.contains(':') || raw.contains('=');
        let marked = |value: &str| contains_credential_marker(value, assigns || value.contains(':') || value.contains('='));
        let mut sensitive = scanner.ever_marker || has_bearer_value(&raw) || has_pem_private_key_marker(&raw, "begin")
            || (canonical != raw && marked(&canonical))
            || (raw.contains(['{', '[']) && json_containers(&raw).any(|(start, end)| json_literals(&raw[start..end]).any(|literal| literal.map_or(true, |(_, _, decoded)| marked(&canonical_for_check(&decoded))))))
            || (raw.contains('"') && standalone_literals(&raw).any(|(_, _, decoded, _)| marked(&canonical_for_check(&decoded))));
        let status = !inherited && sensitive && is_secret_free_status_line(&raw, &canonical);
        if status { sensitive = false; }
        let sanitized = if sensitive || inherited { OMITTED.to_owned() } else { redact_inline_secrets(&redact_url_credentials(&raw)) };
        if !status && sanitized != OMITTED && sanitized != raw {
            let canon_san = canonical_for_check(&sanitized);
            if canon_san != canonical { sensitive |= marked(&canon_san); }
        }
        if !status && !sensitive && !inherited && sanitized.contains('\\') {
            let canon_san = canonical_for_check(&sanitized);
            sensitive |= marked(&canon_san) || redact_inline_secrets(&canon_san) != canon_san;
        }
        self.omit_next = scanner.finish(sensitive);
        if sensitive { OMITTED.to_owned() } else { sanitized.replace('\r', "\n") }
    }
}

/// Bounded URL continuity for streams with many carriage returns.
pub(super) struct OpenUrlTracker {
    esc: Esc,
    tail: std::collections::VecDeque<char>,
    open: bool,
    slashes: usize,
    saw_colon: bool,
}

impl OpenUrlTracker {
    pub(super) fn new() -> Self { Self { esc: Esc::None, tail: std::collections::VecDeque::new(), open: false, slashes: 0, saw_colon: false } }
    pub(super) fn clear(&mut self) { self.tail.clear(); self.open = false; self.slashes = 0; self.saw_colon = false; self.esc = Esc::None; }
    pub(super) fn is_open(&self) -> bool { self.open }
    pub(super) fn keeps_cr(&self) -> bool { self.open || self.saw_colon }
    pub(super) fn push_raw(&mut self, ch: char) {
        let mut esc = self.esc;
        step_escape(&mut esc, ch, |ch| self.push(ch));
        self.esc = esc;
    }
    pub(super) fn push(&mut self, ch: char) {
        if self.tail.len() == 24 { self.tail.pop_front(); }
        self.tail.push_back(ch);
        match ch {
            ch if ch.is_whitespace() && ch != '\r' => { self.open = false; self.saw_colon = false; self.slashes = 0; }
            '?' | '#' => { self.open = false; self.slashes = 0; }
            ':' if self.open => { self.saw_colon = true; self.slashes = 0; }
            '/' => {
                let tail: String = self.tail.iter().collect();
                let canonical = canonical_for_check(&tail);
                if canonical.ends_with("://") { self.open = true; }
                else if self.slashes % 2 == 0 { self.open = false; }
                self.slashes = 0;
            }
            '\\' => self.slashes += 1,
            _ => {
                self.slashes = 0;
                if !self.open && matches!(ch, 'f' | 'F' | '}') {
                    let raw: String = self.tail.iter().collect();
                    let canonical = canonical_for_check(&raw);
                    self.open = has_open_url_authority(&canonical);
                    // Retain decoded partial schemes so successive unicode escapes fit the bounded tail.
                    if canonical != raw { self.tail = canonical.chars().collect(); }
                }
            }
        }
    }
}

fn diagnostic_lines(text: &str) -> impl Iterator<Item = &str> {
    let mut plain_lines = (!text.contains('\r')).then(|| text.split_terminator('\n'));
    let mut chars = text.char_indices().peekable();
    let mut start = 0;
    let mut tracker = OpenUrlTracker::new();
    std::iter::from_fn(move || {
        if let Some(lines) = &mut plain_lines { return lines.next(); }
        while let Some((i, ch)) = chars.next() {
            if ch == '\n' || (ch == '\r' && (chars.peek().is_some_and(|(_, ch)| *ch == '\n') || !tracker.keeps_cr())) {
                let line = &text[start..i];
                start = if ch == '\r' && chars.peek().is_some_and(|(_, ch)| *ch == '\n') { chars.next().unwrap().0 + 1 } else { i + 1 };
                tracker.clear();
                return Some(line);
            }
            tracker.push_raw(ch);
        }
        if start < text.len() {
            let line = &text[start..];
            start = text.len();
            Some(line)
        } else { None }
    })
}

pub(super) fn clean(text: &str) -> String {
    let raw = strip_escapes(text);
    let mut cleaner = Cleaner::new();
    diagnostic_lines(&raw).map(|line| cleaner.clean_line(line)).collect::<Vec<_>>().join("\n")
}

const BOUNDED_LINE_LIMIT: usize = 64 * 1024;
const RETAINED_EDGE: usize = 16 * 1024;

/// External RPC frames can be huge; keep the headline and final cause, never a partial raw line.
pub(super) fn clean_bounded(text: &str) -> String {
    let mut cleaner = Cleaner::new();
    let mut head = Vec::new();
    let mut head_bytes = 0;
    let mut head_closed = false;
    let mut tail = std::collections::VecDeque::<String>::new();
    let mut tail_bytes = 0;
    let mut truncated = false;
    let mut previous_marker = None;
    for raw in diagnostic_lines(text) {
        let offset = raw.as_ptr() as usize - text.as_ptr() as usize;
        let skip = text.len() > 256 * 1024 && offset >= RETAINED_EDGE
            && offset + raw.len() < text.len().saturating_sub(RETAINED_EDGE);
        let mut line = if raw.len() > BOUNDED_LINE_LIMIT || skip {
            let mut scanner = cleaner.begin_overflow();
            scanner.push_str(raw);
            let marker = cleaner.finish_overflow(scanner);
            if skip { truncated = true; head_closed = true; continue; }
            if marker == OVERSIZED_OMITTED { "[Line over 64 KB omitted]".to_owned() } else { marker.to_owned() }
        } else { cleaner.clean_line(raw) };
        let marker = match line.as_str() {
            OMITTED => Some(OMITTED),
            "[Line over 64 KB omitted]" => Some("[Line over 64 KB omitted]"),
            _ => None,
        };
        if marker.is_some() && marker == previous_marker { continue; }
        previous_marker = marker;
        if !head_closed && head_bytes + line.len() + usize::from(!head.is_empty()) <= RETAINED_EDGE {
            head_bytes += line.len() + usize::from(!head.is_empty());
            head.push(line);
            continue;
        }
        head_closed = true;
        if head.is_empty() && line.len() > RETAINED_EDGE {
            let prefix = truncate_bytes_grapheme_safe(&line, RETAINED_EDGE);
            let end = prefix.len() - '…'.len_utf8();
            head.push(prefix);
            line.drain(..end);
        }
        if line.len() > RETAINED_EDGE {
            line = suffix_bytes_grapheme_safe(&line, RETAINED_EDGE);
            truncated = true;
        }
        tail_bytes += line.len();
        tail.push_back(line);
        while tail_bytes + tail.len().saturating_sub(1) > RETAINED_EDGE {
            tail_bytes -= tail.pop_front().unwrap().len();
            truncated = true;
        }
    }
    if truncated { head.push("[Output truncated]".to_owned()); }
    head.extend(tail);
    head.join("\n")
}

const OMITTED: &str = "[Credential detail omitted]";
const OVERSIZED_OMITTED: &str = "[Line over 16 KB omitted]";

fn quoted_end(text: &str, start: usize) -> (usize, bool) {
    let bytes = text.as_bytes();
    let mut end = start + 1;
    while end < bytes.len() {
        match bytes[end] {
            b'\\' => end = (end + 2).min(bytes.len()),
            b'"' => return (end + 1, true),
            _ => end += 1,
        }
    }
    (end, false)
}

fn unescaped_authority_terminator(text: &str) -> Option<usize> {
    let mut slashes = 0;
    for (i, ch) in text.char_indices() {
        if (ch.is_whitespace() && ch != '\r') || matches!(ch, '?' | '#') || (ch == '/' && slashes % 2 == 0) { return Some(i); }
        slashes = if ch == '\\' { slashes + 1 } else { 0 };
    }
    None
}

/// Locate literal or escaped colon/slash units without decoding the surrounding password.
fn raw_scheme_separators(text: &str) -> Vec<(usize, usize)> {
    fn unit(text: &str, start: usize, wanted: u32) -> Option<usize> {
        let bytes = text.as_bytes();
        if u32::from(*bytes.get(start)?) == wanted { return Some(start + 1); }
        if bytes[start] != b'\\' { return None; }
        let kind = bytes.get(start + 1)?.to_ascii_lowercase();
        if kind == b'/' && wanted == 0x2f { return Some(start + 2); }
        let (hex, end) = match kind {
            b'x' => (text.get(start + 2..start + 4)?, start + 4),
            b'u' if bytes.get(start + 2) == Some(&b'{') => {
                let rest = &text[start + 3..];
                let length = rest.bytes().take(7).position(|b| b == b'}')?;
                if !(1..=6).contains(&length) { return None; }
                (&rest[..length], start + 4 + length)
            }
            b'u' => (text.get(start + 2..start + 6)?, start + 6),
            _ => return None,
        };
        (hex.bytes().all(|b| b.is_ascii_hexdigit()) && u32::from_str_radix(hex, 16) == Ok(wanted)).then_some(end)
    }
    let mut found = Vec::new();
    let mut index = 0;
    while index < text.len() {
        if matches!(text.as_bytes()[index], b':' | b'\\') {
            if let Some(after) = unit(text, index, 0x3a).and_then(|next| unit(text, next, 0x2f)).and_then(|next| unit(text, next, 0x2f)) {
                found.push((index, after));
                index = after;
                continue;
            }
        }
        index += text[index..].chars().next().unwrap().len_utf8();
    }
    found
}

fn active_authority(line: &str, index: usize) -> Option<(String, usize)> {
    let ws_start = line[..index].rfind(|ch: char| ch.is_whitespace() && ch != '\r').map_or(0, |i| i + line[i..].chars().next().unwrap().len_utf8());
    let prefix = &line[ws_start..index];
    if !prefix.contains(':') && !prefix.contains('\\') { return None; }
    let raw = raw_scheme_separators(prefix).into_iter().next_back();
    if let Some((sep, after)) = raw {
        if unescaped_authority_terminator(&prefix[after..]).is_none() { return Some((prefix.to_owned(), sep)); }
    }
    if !prefix.contains('\\') { return None; }
    let canonical = canonical_for_check(prefix);
    let sep = canonical.rfind("://")?;
    if canonical[sep + 3..].contains(|ch: char| (ch.is_whitespace() && ch != '\r') || matches!(ch, '/' | '?' | '#')) { return None; }
    Some((canonical, sep))
}

fn host_port_prefix(text: &str) -> &str {
    let mut cap = text.len().min(264);
    while !text.is_char_boundary(cap) { cap -= 1; }
    let mut ipv6 = text.starts_with('[');
    for (i, ch) in text[..cap].char_indices() {
        if ch == ']' && ipv6 { ipv6 = false; continue; }
        if ch.is_whitespace() || matches!(ch, '/' | '?' | '#' | ',' | ';' | '"' | '\'' | ')' | '}' | ']' | '>' | '@') {
            return &text[..i];
        }
    }
    &text[..cap]
}

fn has_bare_proxy_at(text: &str) -> bool {
    let scan = |text: &str| text.match_indices('@').any(|(at, _)| {
        let after = host_port_prefix(&text[at + 1..]);
        let host_port = if after.starts_with('[') {
            after.find("]:").and_then(|end| after[1..end].parse::<std::net::Ipv6Addr>().ok().map(|_| &after[end + 2..]))
        } else { after.split_once(':').filter(|(host, _)| strict_host(host)).map(|(_, port)| port) };
        let Some(port) = host_port else { return false; };
        let digits = port.bytes().take_while(u8::is_ascii_digit).count();
        (1..=5).contains(&digits) && port[digits..].chars().next().is_none_or(|ch| ch.is_whitespace() || matches!(ch, '/' | '?' | '#' | ',' | ';' | '"' | '\'' | '>' | ')' | ']' | '}' | '.' | ':' | '!'))
    });
    scan(text) || (text.contains('\\') && scan(&canonical_for_check(text)))
}

fn has_escaped_at(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains(r"\u0040") || lower.contains(r"\x40") || lower.match_indices(r"\u{").any(|(start, _)| {
        let rest = &lower[start + 3..];
        let Some(end) = rest.bytes().take(7).position(|b| b == b'}') else { return false; };
        (1..=6).contains(&end) && rest[..end].bytes().all(|b| b.is_ascii_hexdigit())
            && u32::from_str_radix(&rest[..end], 16) == Ok(0x40)
    })
}

pub(super) fn has_open_url_authority(text: &str) -> bool {
    active_authority(text, text.len()).is_some()
}

/// Incremental raw authority boundaries, with opener inspection only when a scheme opens.
struct AuthorityTracker {
    open_url: OpenUrlTracker,
    unquoted: bool,
    ws_start: usize,
    pos: usize,
}

impl AuthorityTracker {
    fn new() -> Self { Self { open_url: OpenUrlTracker::new(), unquoted: false, ws_start: 0, pos: 0 } }
    fn reset(&mut self, pos: usize) { self.open_url.clear(); self.unquoted = false; self.ws_start = pos; self.pos = pos; }
    fn is_open(&self) -> bool { self.open_url.is_open() }
    fn is_unquoted(&self) -> bool { self.is_open() && self.unquoted }
    fn advance_to(&mut self, line: &str, target: usize) {
        for (i, ch) in line[self.pos..target].char_indices() {
            let end = self.pos + i + ch.len_utf8();
            if ch.is_whitespace() && ch != '\r' { self.ws_start = end; }
            let was_open = self.is_open();
            self.open_url.push(ch);
            if !was_open && self.is_open() {
                let mut start = self.ws_start.max(end.saturating_sub(48));
                while !line.is_char_boundary(start) { start += 1; }
                let prefix = canonical_for_check(&line[start..end]);
                let opener = prefix.rfind("://").and_then(|sep| {
                    prefix[..sep].trim_end_matches(|ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')).chars().next_back()
                });
                self.unquoted = !matches!(opener, Some('\'' | '"' | '<'));
            } else if !self.is_open() { self.unquoted = false; }
        }
        self.pos = target;
    }
}

#[derive(Clone, Copy)]
enum JsonExpect { ArrayStart, Value, Comma, ObjectStart, Key, Colon, ObjectValue, ObjectComma }

struct JsonFrame { node: usize, close: u8, expect: JsonExpect, valid: bool, depth: usize }

impl JsonFrame {
    fn value(&mut self, string: bool) {
        self.expect = match self.expect {
            JsonExpect::ArrayStart | JsonExpect::Value => JsonExpect::Comma,
            JsonExpect::ObjectValue => JsonExpect::ObjectComma,
            JsonExpect::ObjectStart | JsonExpect::Key if string => JsonExpect::Colon,
            other => { self.valid = false; other }
        };
    }
}

fn valid_json_string(raw: &str) -> bool {
    if !raw.ends_with('"') || raw.len() < 2 { return false; }
    let bytes = raw.as_bytes();
    let mut i = 1;
    while i + 1 < bytes.len() {
        if bytes[i] < 0x20 { return false; }
        if bytes[i] != b'\\' { i += 1; continue; }
        i += 1;
        match bytes.get(i).copied() {
            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => i += 1,
            Some(b'u') => {
                let Some(hex) = raw.get(i + 1..i + 5) else { return false; };
                if !hex.bytes().all(|b| b.is_ascii_hexdigit()) { return false; }
                let code = u16::from_str_radix(hex, 16).unwrap();
                i += 5;
                if (0xd800..=0xdbff).contains(&code) {
                    if !raw[i..].starts_with(r"\u") { return false; }
                    let Some(low) = raw.get(i + 2..i + 6).and_then(|hex| u16::from_str_radix(hex, 16).ok()) else { return false; };
                    if !(0xdc00..=0xdfff).contains(&low) { return false; }
                    i += 6;
                } else if (0xdc00..=0xdfff).contains(&code) { return false; }
            }
            _ => return false,
        }
    }
    i == bytes.len() - 1
}

fn valid_json_atom(text: &str) -> bool {
    if matches!(text, "true" | "false" | "null") { return true; }
    let bytes = text.as_bytes();
    let mut i = usize::from(bytes.first() == Some(&b'-'));
    if bytes.get(i) == Some(&b'0') { i += 1; }
    else {
        if !bytes.get(i).is_some_and(|b| matches!(b, b'1'..=b'9')) { return false; }
        while bytes.get(i).is_some_and(u8::is_ascii_digit) { i += 1; }
    }
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        let first = i;
        while bytes.get(i).is_some_and(u8::is_ascii_digit) { i += 1; }
        if first == i { return false; }
    }
    if bytes.get(i).is_some_and(|b| matches!(b, b'e' | b'E')) {
        i += 1;
        if bytes.get(i).is_some_and(|b| matches!(b, b'+' | b'-')) { i += 1; }
        let first = i;
        while bytes.get(i).is_some_and(u8::is_ascii_digit) { i += 1; }
        if first == i { return false; }
    }
    i == bytes.len()
}

/// Grammar validity propagates once per frame; failed outer wrappers never cause rescans.
fn json_containers(line: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = line.as_bytes();
    let mut tracker = AuthorityTracker::new();
    let mut frames = Vec::<JsonFrame>::new();
    let mut nodes = Vec::<(usize, usize, bool, bool)>::new();
    let mut i = 0;
    while i < bytes.len() {
        tracker.advance_to(line, i);
        let byte = bytes[i];
        if byte == b'"' && (!frames.is_empty() || !tracker.is_unquoted()) {
            let (end, closed) = quoted_end(line, i);
            if let Some(frame) = frames.last_mut() {
                frame.value(true);
                frame.valid &= closed && valid_json_string(&line[i..end]);
                tracker.reset(end);
            }
            i = end;
            continue;
        }
        if matches!(byte, b'{' | b'[') && !tracker.is_open() {
            let eligible = i == 0 || line[..i].chars().next_back().is_some_and(char::is_whitespace) || matches!(bytes[i - 1], b':' | b'=' | b'(' | b'[' | b',' | b';');
            if let Some(frame) = frames.last_mut() { frame.value(false); }
            let node = nodes.len();
            nodes.push((i, 0, false, eligible));
            frames.push(JsonFrame { node, close: if byte == b'{' { b'}' } else { b']' }, expect: if byte == b'{' { JsonExpect::ObjectStart } else { JsonExpect::ArrayStart }, valid: true, depth: 1 });
            i += 1;
            continue;
        }
        if let Some(frame) = frames.last_mut() {
            match byte {
                b'}' | b']' => {
                    let frame = frames.pop().unwrap();
                    let valid = frame.valid && byte == frame.close
                        && matches!(frame.expect, JsonExpect::ArrayStart | JsonExpect::Comma | JsonExpect::ObjectStart | JsonExpect::ObjectComma);
                    nodes[frame.node].1 = i + 1;
                    nodes[frame.node].2 = valid && frame.depth <= 128;
                    if let Some(parent) = frames.last_mut() {
                        parent.valid &= valid;
                        parent.depth = parent.depth.max(frame.depth + 1);
                    }
                    tracker.reset(i + 1);
                }
                b':' => {
                    if matches!(frame.expect, JsonExpect::Colon) { frame.expect = JsonExpect::ObjectValue; }
                    else { frame.valid = false; }
                }
                b',' => {
                    frame.expect = match frame.expect {
                        JsonExpect::Comma => JsonExpect::Value,
                        JsonExpect::ObjectComma => JsonExpect::Key,
                        other => { frame.valid = false; other }
                    };
                }
                b' ' | b'\r' | b'\n' | b'\t' => {}
                _ => {
                    let start = i;
                    while i < bytes.len() && !matches!(bytes[i], b'{' | b'[' | b'}' | b']' | b'"' | b':' | b',' | b' ' | b'\r' | b'\n' | b'\t') { i += 1; }
                    frame.value(false);
                    frame.valid &= valid_json_atom(&line[start..i]);
                    if i == start { i += line[i..].chars().next().unwrap().len_utf8(); }
                    continue;
                }
            }
        }
        i += line[i..].chars().next().unwrap().len_utf8();
    }
    let mut budget = 2 * line.len().max(8192);
    let mut selected_end = 0;
    let mut tail_end = 0;
    let mut proxy_at = None;
    nodes.into_iter().filter_map(move |(start, end, valid, eligible)| {
        if !valid || !eligible || end == 0 || start < selected_end || end - start > budget { return None; }
        budget -= end - start;
        if serde_json::from_str::<serde::de::IgnoredAny>(&line[start..end]).is_err() { return None; }
        selected_end = end;
        if end >= tail_end {
            tail_end = line[end..].find(char::is_whitespace).map_or(line.len(), |i| end + i);
            let tail = &line[end..tail_end];
            proxy_at = has_bare_proxy_at(tail).then(|| tail.rfind(['@', '\\']).map(|i| end + i)).flatten();
        }
        if proxy_at.is_some_and(|at| at >= end) { None } else { Some((start, end)) }
    })
}

/// Cache the next raw authority boundary and its last literal/encoded at-sign.
struct LiteralTail<'a> { line: &'a str, end: usize, last_at: Option<usize> }

impl<'a> LiteralTail<'a> {
    fn new(line: &'a str) -> Self { Self { line, end: 0, last_at: None } }
    fn has_at(&mut self, start: usize) -> bool {
        if start >= self.end {
            self.end = start + unescaped_authority_terminator(&self.line[start..]).unwrap_or(self.line.len() - start);
            self.last_at = self.line[start..self.end].char_indices().filter_map(|(i, ch)| {
                let at = start + i;
                (ch == '@' || (ch == '\\' && has_escaped_at(&self.line[at..self.end].chars().take(12).collect::<String>()))).then_some(at)
            }).next_back();
        }
        self.last_at.is_some_and(|at| at >= start)
    }
}

fn json_literals(json: &str) -> impl Iterator<Item = Result<(usize, usize, String), serde_json::Error>> + '_ {
    let bytes = json.as_bytes();
    let mut index = 0;
    std::iter::from_fn(move || {
        while index < bytes.len() {
            if bytes[index] != b'"' { index += 1; continue; }
            let start = index;
            index = quoted_end(json, start).0;
            return Some(serde_json::from_str::<String>(&json[start..index]).map(|decoded| (start, index, decoded)));
        }
        None
    })
}

/// Decode complete or truncated literals, keeping password quotes inside their URL authority.
fn standalone_literals(line: &str) -> impl Iterator<Item = (usize, usize, String, bool)> + '_ {
    let mut index = 0;
    let mut tracker = AuthorityTracker::new();
    let mut after = LiteralTail::new(line);
    std::iter::from_fn(move || {
        while index < line.len() {
            let start = index;
            index += 1;
            if line.as_bytes()[start] != b'"' { continue; }
            tracker.advance_to(line, start);
            if tracker.is_open() { continue; }
            let (end, closed) = quoted_end(line, start);
            index = end;
            let raw = &line[start..end];
            let inner = if closed { &raw[1..raw.len() - 1] } else { &raw[1..] };
            let decoded = if closed {
                serde_json::from_str::<String>(raw).unwrap_or_else(|_| decode_common_escapes(inner))
            } else {
                let slashes = raw.bytes().rev().take_while(|b| *b == b'\\').count();
                let repaired = if slashes % 2 == 1 { &raw[..raw.len() - 1] } else { raw };
                serde_json::from_str::<String>(&format!("{repaired}\""))
                    .unwrap_or_else(|_| decode_common_escapes(inner))
            };
            let stripped = strip_escapes(&decoded);
            if !closed || stripped.contains('@') || !after.has_at(end) { tracker.reset(end); }
            return Some((start, end, decoded, closed));
        }
        None
    })
}

fn redact_non_container(line: &str) -> String {
    // Userinfo quotes belong to the proxy token, before isolating standalone string literals.
    let bare_redacted = redact_bare_proxy_credentials(line);
    let whole = if bare_redacted.contains('@') && (bare_redacted.contains("://") || bare_redacted.contains('\\')) {
        sanitize_plain(&bare_redacted)
    } else { bare_redacted.clone() };
    let line = if whole == OMITTED { bare_redacted.as_str() } else { whole.as_str() };
    let mut after = LiteralTail::new(line);
    let mut result = String::with_capacity(line.len());
    let mut copied = 0;
    for (start, end, decoded, closed) in line.contains('"').then(|| standalone_literals(line)).into_iter().flatten() {
        let stripped = strip_escapes(&decoded);
        if closed && !stripped.contains('@') && after.has_at(end) {
            continue;
        }
        let prefix = sanitize_plain(&line[copied..start]);
        let sanitized = sanitize_plain(&stripped);
        let sanitized = if sanitized == OMITTED { sanitized } else { redact_inline_secrets(&sanitized) };
        if prefix == OMITTED || sanitized == OMITTED { return OMITTED.to_owned(); }
        result.push_str(&prefix);
        if sanitized != decoded {
            let Ok(mut encoded) = serde_json::to_string(&sanitized) else { return OMITTED.to_owned(); };
            if !closed { encoded.pop(); }
            result.push_str(&encoded);
        } else {
            result.push_str(&line[start..end]);
        }
        copied = end;
    }
    let suffix = sanitize_plain(&line[copied..]);
    if suffix == OMITTED { return OMITTED.to_owned(); }
    result.push_str(&suffix);
    result
}

/// Validate JSON containers, then splice only changed string literals. Re-serializing
/// the object would reorder keys and erase useful diagnostic formatting.
fn redact_url_credentials(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut copied = 0;
    for (index, end) in line.contains(['{', '[']).then(|| json_containers(line)).into_iter().flatten() {
        let prefix = redact_non_container(&line[copied..index]);
        if prefix == OMITTED { return OMITTED.to_owned(); }
        result.push_str(&prefix);
        let mut json_copied = index;
        for literal in json_literals(&line[index..end]) {
            let Ok((start, stop, decoded)) = literal else { return OMITTED.to_owned(); };
            let stripped = strip_escapes(&decoded);
            let sanitized = sanitize_plain(&stripped);
            let sanitized = if sanitized == OMITTED { sanitized } else { redact_inline_secrets(&sanitized) };
            if sanitized != decoded {
                if sanitized == OMITTED { return OMITTED.to_owned(); }
                result.push_str(&line[json_copied..index + start]);
                let Ok(encoded) = serde_json::to_string(&sanitized) else { return OMITTED.to_owned(); };
                result.push_str(&encoded);
                json_copied = index + stop;
            }
        }
        result.push_str(&line[json_copied..end]);
        copied = end;
    }
    let suffix = redact_non_container(&line[copied..]);
    if suffix == OMITTED { return OMITTED.to_owned(); }
    result.push_str(&suffix);
    let mut checked = 0;
    for (start, end) in result.contains(['{', '[']).then(|| json_containers(&result)).into_iter().flatten() {
        if !verify_plain_line(&canonical_for_check(&result[checked..start])) {
            return OMITTED.to_owned();
        }
        for literal in json_literals(&result[start..end]) {
            let Ok((_, _, decoded)) = literal else { return OMITTED.to_owned(); };
            if !verify_plain_line(&canonical_for_check(&decoded)) { return OMITTED.to_owned(); }
        }
        checked = end;
    }
    if !verify_plain_line(&canonical_for_check(&result[checked..])) { return OMITTED.to_owned(); }
    result
}

/// Quoted argv values stay whole; a stray quote cannot hide later flags.
fn inline_tokens(line: &str) -> Vec<(usize, usize, bool)> {
    let mut closing = if line.contains(['"', '\'']) { vec![None; line.len()] } else { Vec::new() };
    let mut single = None;
    let mut double = None;
    let mut escaped = false;
    let mut quotes = Vec::new();
    for (i, ch) in line.char_indices() {
        if escaped { escaped = false; continue; }
        if ch == '\\' { escaped = true; continue; }
        if ch == '\'' && line[..i].chars().next_back().is_some_and(|ch| ch.is_ascii_alphanumeric())
            && line[i + 1..].chars().next().is_some_and(|ch| ch.is_ascii_alphanumeric())
            && !(i >= 2 && matches!(&line.as_bytes()[i - 2..i], b"-u" | b"-U")) { continue; }
        if matches!(ch, '"' | '\'') { quotes.push((i, ch)); }
    }
    for (i, ch) in quotes.into_iter().rev() {
        if ch == '"' { closing[i] = double; double = Some(i); }
        else { closing[i] = single; single = Some(i); }
    }
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < line.len() {
        let ch = line[i..].chars().next().unwrap();
        if ch.is_whitespace() || ch == ',' { i += ch.len_utf8(); continue; }
        let start = i;
        if line[i..].starts_with("[redacted]") {
            i += "[redacted]".len();
            tokens.push((start, i, false));
            continue;
        }
        let curl_value = tokens.last().is_some_and(|&(start, end, _)| end == i && matches!(&line[start..end], "-u" | "-U"));
        let quoted = ch == '"' || (ch == '\'' && (curl_value || line[..i].chars().next_back().is_none_or(|ch| !ch.is_ascii_alphanumeric())));
        if quoted {
            if let Some(close) = closing[i] {
                i = close + 1;
                tokens.push((start, i, true));
                continue;
            }
        }
        i += ch.len_utf8();
        while i < line.len() {
            let ch = line[i..].chars().next().unwrap();
            if ch.is_whitespace() || ch == ',' { break; }
            if matches!(ch, '"' | '\'') && (matches!(line.as_bytes()[i - 1], b'[' | b'(' | b'{' | b'=' | b':') || matches!(&line[start..i], "-u" | "-U")) { break; }
            i += ch.len_utf8();
        }
        tokens.push((start, i, false));
    }
    tokens
}

fn nonsecret_auth_value(word: &str) -> bool {
    matches!(word, "true" | "false" | "0" | "1" | "yes" | "no" | "on" | "off" | "ok" | "none" | "null"
        | "basic" | "oauth" | "sso" | "session" | "token" | "tokens" | "account" | "user" | "login" | "signin"
        | "sign" | "credentials" | "credential" | "certificate" | "cert" | "request" | "response" | "connection"
        | "server" | "service" | "client" | "proxy" | "refresh" | "access" | "bearer" | "key" | "keys" | "password"
        | "cookie" | "cookies" | "header" | "headers" | "timeout" | "timed" | "network" | "dns" | "handshake")
}

/// Reuse argv/phrase matching inside quoted command payloads, with bounded nesting.
fn collect_token_ranges(slice: &str, base: usize, depth: u8, add: &mut impl FnMut(usize, usize)) {
    fn status(word: &str) -> bool {
        matches!(word, "is" | "was" | "are" | "were" | "not" | "missing" | "required" | "expected" | "invalid" | "expired" | "empty" | "absent" | "needed" | "must" | "cannot" | "can't" | "length" | "fail" | "failed" | "from" | "in" | "for" | "or" | "and" | "to" | "with" | "without" | "found" | "provided" | "configured" | "supplied" | "set" | "present" | "unspecified" | "unknown" | "denied" | "rejected" | "error" | "warning" | "header" | "option" | "flag" | "field" | "value" | "provider" | "providers" | "basic" | "digest" | "ntlm" | "negotiate" | "aws4-hmac-sha256" | "hoba" | "mutual" | "vapid" | "format" | "authentication" | "auth" | "check" | "validation" | "settings" | "config" | "configuration" | "env" | "environment" | "variable" | "file" | "path" | "limit" | "count" | "quota" | "balance" | "billing" | "credits" | "usage" | "none" | "null" | "blank" | "unset" | "unconfigured" | "unauthorized" | "forbidden" | "revoked" | "disabled" | "enabled" | "of" | "on" | "at" | "by" | "incorrect" | "wrong" | "too" | "valid" | "good" | "bad" | "weak" | "short" | "long" | "accepted" | "changed" | "updated" | "reset" | "locked")
    }
    fn value_span(line: &str, mut start: usize, mut end: usize) -> (usize, usize) {
        if line[start..end].starts_with(r#"\""#) && line[start..end].ends_with(r#"\""#) && end - start >= 4 {
            start += 2;
            end -= 2;
        }
        while start < end && matches!(line.as_bytes()[start], b'\'' | b'"') { start += 1; }
        while end > start && !line[start..end].ends_with("[redacted]") && matches!(line.as_bytes()[end - 1], b'\'' | b'"' | b',' | b';' | b')' | b'}' | b']') { end -= 1; }
        (start, end)
    }
    fn clause_break(slice: &str, a: usize, b: usize) -> bool { slice[a..b].contains([',', ';', '.']) }
    let tokens = inline_tokens(slice);
    let name_at = |i: usize| {
        let raw = &slice[tokens[i].0..tokens[i].1];
        raw.rsplit(['[', '(', '{']).next().unwrap_or(raw)
            .trim_matches(['"', '\'', '[', '(', '{', ',', ';', ']', ')', '}', '\\'])
    };
    let eligible = |value: &str, allow_leading_dash: bool| {
        let word = value.trim_matches(|ch: char| !ch.is_ascii_alphanumeric()).to_ascii_lowercase();
        !value.is_empty() && value != "[redacted]" && (allow_leading_dash || !value.starts_with('-'))
            && value.bytes().any(|b| b.is_ascii_alphanumeric()) && !status(&word)
    };
    let span_at = |i: usize| {
        let (start, mut end, closed) = tokens[i];
        if !closed && slice[start..].starts_with(['"', '\'']) { end = slice.len(); }
        value_span(slice, start, end)
    };
    let same_clause = |a: usize, b: usize| !clause_break(slice, tokens[a].1, tokens[b].0);
    let array_pair = |a: usize, b: usize| same_clause(a, b)
        || (tokens[a].2 && tokens[b].2 && slice[tokens[a].1..tokens[b].0].trim() == ",");
    let keyword_ends_clause = |i: usize| slice[tokens[i].0..tokens[i].1]
        .trim_end_matches(['"', '\'', ']', ')', '}']).ends_with([',', ';', '.']);
    let bare_value = |i: usize| !tokens[i].2 && !slice[tokens[i].0..].starts_with(['"', '\'']);
    for i in 0..tokens.len() {
        let name = name_at(i);
        let lower = name.trim_end_matches(':').to_ascii_lowercase();
        let flag = lower.strip_prefix("--").is_some_and(|name| matches!(name, "api-key" | "apikey" | "api_key" | "token" | "access-token" | "access_token" | "auth-token" | "auth_token" | "password" | "passwd" | "pwd" | "secret" | "client-secret" | "client_secret" | "auth"));
        let structured = (name.contains('_') || name.matches('-').count() >= 2 || matches!(lower.as_str(), "proxy-authorization" | "set-cookie")) && is_credential_key(name);
        if (flag || structured) && i + 1 < tokens.len() {
            let (start, end) = span_at(i + 1);
            if eligible(&slice[start..end], !bare_value(i + 1)) { add(base + start, base + end); }
        }
        if let Some(rest) = name.strip_prefix("-p") {
            if rest != "[redacted]" && rest.len() >= 6 && !rest.bytes().all(|b| b.is_ascii_digit())
                && !rest.bytes().all(|b| b.is_ascii_lowercase()) && rest.bytes().all(|b| b.is_ascii_graphic())
            {
                let raw = &slice[tokens[i].0..tokens[i].1];
                if let Some(offset) = raw.find("-p") {
                    let start = tokens[i].0 + offset + 2;
                    add(base + start, base + start + rest.len());
                }
            }
        }
        let raw = &slice[tokens[i].0..tokens[i].1];
        let option = raw.trim_start_matches(['[', '(', '{', '"', '\'']);
        let attached = ["--user=", "--proxy-user=", "-u", "-U"].into_iter().find_map(|prefix| {
            let matches = if prefix.starts_with("--") { option.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(prefix)) }
                else { option.starts_with(prefix) };
            matches.then(|| { let rest = &option[prefix.len()..]; (tokens[i].0 + raw.len() - rest.len(), rest) })
        });
        let span = if matches!(name, "-u" | "-U") || matches!(lower.as_str(), "--user" | "--proxy-user") {
            (i + 1 < tokens.len()).then(|| (span_at(i + 1), tokens[i + 1].2))
        } else if let Some((start, rest)) = attached {
            if rest.is_empty() && i + 1 < tokens.len() { Some((span_at(i + 1), tokens[i + 1].2)) }
            else if !rest.is_empty() { Some((value_span(slice, start, tokens[i].1), tokens[i].2)) }
            else { None }
        } else { None };
        if let Some(((start, mut end), closed)) = span {
            if !closed && !slice[start..].starts_with(['"', '\'']) {
                end = start;
                while end < slice.len() {
                    if slice[end..].starts_with("[redacted]") { end += "[redacted]".len(); continue; }
                    let ch = slice[end..].chars().next().unwrap();
                    if ch.is_whitespace() || matches!(ch, ')' | ']' | '}' | '"' | '\'') { break; }
                    end += ch.len_utf8();
                }
            }
            if let Some((user, password)) = slice[start..end].split_once(':') {
                if !password.is_empty() && password != "[redacted]" && !password.starts_with("//") {
                    add(base + start + user.len() + 1, base + end);
                }
            }
        }
        let mut value_index = None;
        let mut allow_dash = false;
        if matches!(lower.as_str(), "authorization" | "proxy-authorization" | "x-api-key" | "api-key" | "apikey" | "api_key" | "cookie" | "set-cookie" | "token" | "secret" | "password" | "credential" | "credentials")
            && i + 1 < tokens.len() && same_clause(i, i + 1)
            && matches!(name_at(i + 1).trim_end_matches(':').to_ascii_lowercase().as_str(), "header" | "headers" | "value" | "field" | "option" | "flag")
        {
            let mut k = i + 2;
            if k < tokens.len() && same_clause(k - 1, k) && matches!(name_at(k).to_ascii_lowercase().as_str(), "is" | "was") { k += 1; }
            let mut scheme = false;
            if k < tokens.len() && same_clause(k - 1, k)
                && matches!(name_at(k).to_ascii_lowercase().as_str(), "basic" | "bearer" | "digest" | "token" | "apikey" | "api-key" | "ntlm" | "negotiate")
            { scheme = true; k += 1; }
            if k < tokens.len() && same_clause(k - 1, k) {
                let (start, end) = span_at(k);
                if !bare_value(k) || scheme || name_at(k - 1).ends_with(':') || slice[start..end].bytes().any(|b| !b.is_ascii_lowercase()) {
                    value_index = Some(k);
                    allow_dash = !bare_value(k) || scheme;
                }
            }
        }
        if lower == "api" && i + 2 < tokens.len() && name_at(i + 1).trim_end_matches(':').eq_ignore_ascii_case("key")
            && !keyword_ends_clause(i) && !keyword_ends_clause(i + 1) && same_clause(i, i + 1) && same_clause(i + 1, i + 2)
        {
            let mut next = i + 2;
            let next_name = name_at(next);
            let word = next_name.trim_end_matches(':').to_ascii_lowercase();
            let linked = matches!(word.as_str(), "is" | "was")
                || (next_name.ends_with(':') && matches!(word.as_str(), "provided" | "supplied" | "given" | "used" | "received" | "found" | "configured"));
            if linked { next += 1; }
            let mut linked = linked;
            for probe in i + 2..tokens.len().min(i + 5) {
                let word = name_at(probe);
                if !same_clause(probe - 1, probe) || keyword_ends_clause(probe)
                    || !matches!(word.trim_end_matches(':').to_ascii_lowercase().as_str(), "is" | "was" | "not" | "valid" | "invalid" | "provided" | "supplied" | "given" | "used" | "received" | "found" | "configured" | "rejected" | "expired" | "missing")
                { break; }
                if word.ends_with(':') { next = probe + 1; linked = true; break; }
            }
            if next < tokens.len() && (!linked || (!keyword_ends_clause(next - 1) && same_clause(next - 1, next))) {
                let (start, end) = span_at(next);
                let bare = !name_at(i + 1).ends_with(':') && !linked && bare_value(next);
                if !bare || slice[start..end].bytes().any(|b| !b.is_ascii_lowercase()) { value_index = Some(next); }
            }
        } else if matches!(lower.as_str(), "authorization" | "proxy-authorization") && i + 2 < tokens.len()
            && !keyword_ends_clause(i) && !keyword_ends_clause(i + 1) && array_pair(i, i + 1) && array_pair(i + 1, i + 2)
            && matches!(name_at(i + 1).to_ascii_lowercase().as_str(), "bearer" | "basic" | "digest" | "token" | "apikey" | "api-key" | "ntlm" | "negotiate" | "aws4-hmac-sha256" | "hoba" | "mutual" | "vapid")
        {
            value_index = Some(i + 2);
            allow_dash = true;
        } else if lower == "bearer" && i + 1 < tokens.len() && !keyword_ends_clause(i) && array_pair(i, i + 1) {
            let (start, end) = span_at(i + 1);
            let word = slice[start..end].to_ascii_lowercase();
            if !matches!(word.as_str(), "token" | "tokens" | "auth" | "authentication" | "authorization" | "header" | "headers" | "scheme" | "prefix" | "credential" | "credentials") {
                value_index = Some(i + 1);
            }
        } else if matches!(lower.as_str(), "invalid" | "bad" | "wrong" | "unknown" | "expired" | "revoked" | "rejected" | "unauthorized")
            && i + 2 < tokens.len() && name_at(i + 1).trim_end_matches(':').eq_ignore_ascii_case("key")
            && !keyword_ends_clause(i) && !keyword_ends_clause(i + 1) && same_clause(i, i + 1) && same_clause(i + 1, i + 2)
        {
            let (start, end) = span_at(i + 2);
            if name_at(i + 1).ends_with(':') || !bare_value(i + 2) || slice[start..end].bytes().any(|b| !b.is_ascii_lowercase()) {
                value_index = Some(i + 2);
            }
        } else if matches!(lower.as_str(), "auth" | "pass") || ["_pass", "-pass", "_auth", "-auth"].iter().any(|suffix| lower.ends_with(suffix)) {
            let next = if name.ends_with(':') { Some(i + 1) }
                else if i + 1 < tokens.len() && slice[tokens[i].1..tokens[i + 1].0].trim() == ":" { Some(i + 1) }
                else if i + 1 < tokens.len() && name_at(i + 1) == ":" { Some(i + 2) }
                else { None };
            if let Some(j) = next.filter(|j| *j < tokens.len() && same_clause(i, *j)) {
                let (start, end) = span_at(j);
                let val = &slice[start..end];
                if !nonsecret_auth_value(&val.to_ascii_lowercase())
                    && (!bare_value(j) || val.bytes().any(|b| !b.is_ascii_lowercase()))
                { value_index = Some(j); }
            }
        } else if matches!(lower.as_str(), "token" | "secret") && i + 1 < tokens.len()
            && !keyword_ends_clause(i) && same_clause(i, i + 1)
        {
            let (start, end) = span_at(i + 1);
            let val = &slice[start..end];
            let letter = val.bytes().any(|b| b.is_ascii_alphabetic());
            let digit = val.bytes().any(|b| b.is_ascii_digit());
            let mixed = val.bytes().any(|b| b.is_ascii_uppercase()) && val.bytes().any(|b| b.is_ascii_lowercase());
            let named_token = lower == "token" && i > 0 && same_clause(i - 1, i) && !keyword_ends_clause(i - 1)
                && matches!(name_at(i - 1).to_ascii_lowercase().as_str(), "access" | "refresh" | "session" | "auth" | "bearer" | "id" | "oauth" | "api")
                && (name.ends_with(':') || !bare_value(i + 1) || val.bytes().any(|b| !b.is_ascii_lowercase()));
            let previous = if i > 0 { name_at(i - 1).trim_end_matches(':').to_ascii_lowercase() } else { String::new() };
            let parser = matches!(previous.as_str(), "unexpected" | "expected" | "syntax" | "parse" | "lex" | "eof");
            let quoted_invalid = !bare_value(i + 1) && val.len() >= 6
                && matches!(previous.as_str(), "invalid" | "bad" | "wrong" | "expired" | "revoked" | "rejected" | "unauthorized")
                && !matches!(val, "export" | "import" | "function" | "return" | "const" | "let" | "var" | "class" | "if" | "else" | "await");
            if !parser && (named_token || quoted_invalid || val.len() >= 6 && ((letter && digit) || (val.len() >= 8 && mixed) || val.starts_with("eyJ"))) {
                value_index = Some(i + 1);
            }
        } else if matches!(lower.as_str(), "password" | "passphrase" | "passwd") && i + 1 < tokens.len()
            && !keyword_ends_clause(i) && same_clause(i, i + 1)
        {
            let (start, end) = span_at(i + 1);
            if eligible(&slice[start..end], !bare_value(i + 1) || name.ends_with(':')) && (name.ends_with(':') || !bare_value(i + 1)
                || slice[start..end].bytes().any(|b| !b.is_ascii_lowercase()))
            {
                value_index = Some(i + 1);
            } else {
                for j in i + 1..tokens.len().min(i + 6) {
                    if !same_clause(j - 1, j) || slice[tokens[j].0..tokens[j].1].contains(['.', ';', ',']) { break; }
                    if matches!(name_at(j).to_ascii_lowercase().as_str(), "is" | "was")
                        && j + 1 < tokens.len() && same_clause(j, j + 1)
                    {
                        value_index = Some(j + 1);
                        break;
                    }
                }
            }
        }
        if let Some(j) = value_index {
            let (start, mut end) = span_at(j);
            if bare_value(j) {
                while end > start && slice.as_bytes()[end - 1] == b'.' { end -= 1; }
            }
            let allow = allow_dash || !bare_value(j) || name.ends_with(':') || (j > 0 && name_at(j - 1).ends_with(':'));
            if eligible(&slice[start..end], allow) { add(base + start, base + end); }
        }
    }
    if depth < 2 {
        for (start, end, closed) in tokens {
            if !closed { continue; }
            let inner = &slice[start + 1..end - 1];
            if inner.contains(|ch: char| ch.is_whitespace() || ch == ',') {
                collect_token_ranges(inner, base + start + 1, depth + 1, add);
            }
        }
    }
}

/// Replace values in otherwise useful errors, retaining their surrounding context.
fn redact_inline_secrets(line: &str) -> String {
    fn provider_key_len(text: &str, offset: usize, jwt_skip_until: &mut usize) -> usize {
        for (prefix, minimum, hyphen) in [
            ("sk-", 5, true), ("AIza", 10, true), ("ghp_", 8, false), ("gho_", 8, false),
            ("ghu_", 8, false), ("ghs_", 8, false), ("ghr_", 8, false),
            ("github_pat_", 8, false), ("glpat-", 8, true),
        ] {
            if let Some(rest) = text.strip_prefix(prefix) {
                let length = rest.bytes().take_while(|b| b.is_ascii_alphanumeric() || *b == b'_' || (hyphen && *b == b'-')).count();
                if length >= minimum { return prefix.len() + length; }
            }
        }
        if text.starts_with("xox") && text.as_bytes().get(3).is_some_and(|b| b"bporas".contains(b)) && text.as_bytes().get(4) == Some(&b'-') {
            let length = text[5..].bytes().take_while(|b| b.is_ascii_alphanumeric() || *b == b'-').count();
            if length >= 8 { return length + 5; }
        }
        if let Some(rest) = text.strip_prefix("AKIA") {
            let length = rest.bytes().take_while(|b| b.is_ascii_uppercase() || b.is_ascii_digit()).count();
            if length >= 16 { return length + 4; }
        }
        let base64_len = |text: &str| text.bytes().take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')).count();
        if text.len() > 33 && text.as_bytes()[..32].iter().all(u8::is_ascii_hexdigit) && text.as_bytes()[32] == b'.' {
            let length = base64_len(&text[33..]);
            let suffix = &text[33..33 + length];
            if length >= 8 && (length >= 12 || suffix.bytes().any(|b| b.is_ascii_digit())
                || (suffix.bytes().any(|b| b.is_ascii_uppercase()) && suffix.bytes().any(|b| b.is_ascii_lowercase()))) {
                return 33 + length;
            }
        }
        if text.starts_with("eyJ") && offset >= *jwt_skip_until {
            let first = base64_len(text);
            // Later eyJ prefixes in this run share the same suffix and cannot rescue a failed JWT.
            *jwt_skip_until = (*jwt_skip_until).max(offset + first);
            if first >= 11 && text[first..].starts_with(".eyJ") {
                let second = base64_len(&text[first + 1..]);
                let signature = first + 1 + second + 1;
                if second >= 11 && text.as_bytes().get(signature - 1) == Some(&b'.') {
                    let third = base64_len(&text[signature..]);
                    if third >= 8 { return signature + third; }
                }
            }
        }
        0
    }
    let mut ranges = Vec::<(usize, usize)>::new();
    let mut add = |start: usize, end: usize| {
        if start < end && &line[start..end] != "[redacted]" { ranges.push((start, end)); }
    };
    // Query values are bounded by the URL, not by punctuation in the surrounding error.
    let mut prev_end = 0;
    let mut raw_schemes = raw_scheme_separators(line).into_iter().peekable();
    let mut encoded_schemes = line.match_indices('%').filter_map(|(start, _)| {
        line[start..].get(..9).is_some_and(|unit| unit.eq_ignore_ascii_case("%3a%2f%2f")).then_some((start, start + 9))
    }).peekable();
    let schemes = std::iter::from_fn(move || match (raw_schemes.peek(), encoded_schemes.peek()) {
        (Some(raw), Some(encoded)) if raw.0 <= encoded.0 => raw_schemes.next(),
        (Some(_), Some(_)) => encoded_schemes.next(),
        (Some(_), None) => raw_schemes.next(),
        _ => encoded_schemes.next(),
    });
    for (_, after_scheme) in schemes {
        if after_scheme < prev_end { continue; }
        let mut end = after_scheme;
        let mut query = None;
        while end < line.len() {
            if line[end..].starts_with("[redacted]") { end += "[redacted]".len(); continue; }
            let ch = line[end..].chars().next().unwrap();
            if ch.is_whitespace() || matches!(ch, '"' | '\'' | ')' | '}') || (query.is_some() && ch == ']') { break; }
            if query.is_none() && (matches!(ch, '?' | '#') || line[end..].get(..3).is_some_and(|unit| unit.eq_ignore_ascii_case("%3f") || unit.eq_ignore_ascii_case("%23"))) {
                query = Some((end, if ch == '%' { 3 } else { 1 }));
            }
            end += ch.len_utf8();
        }
        prev_end = prev_end.max(end);
        let Some((query, width)) = query else { continue; };
        let mut start = query + width;
        let mut cursor = start;
        loop {
            let width = if cursor == end { 0 } else {
                let rest = &line[cursor..end];
                if rest.starts_with(['&', ';', '?', '#']) { 1 }
                else if rest.get(..3).is_some_and(|unit| ["%26", "%3f", "%23", "%3b"].iter().any(|encoded| unit.eq_ignore_ascii_case(encoded))) { 3 }
                else { cursor += rest.chars().next().unwrap().len_utf8(); continue; }
            };
            let pair = &line[start..cursor];
            let eq = pair.char_indices().find_map(|(i, ch)| {
                if ch == '=' { Some((i, 1)) }
                else if ch == '%' && pair[i..].get(..3).is_some_and(|unit| unit.eq_ignore_ascii_case("%3d")) { Some((i, 3)) }
                else { None }
            });
            if let Some((eq, eq_len)) = eq {
                let key = pair[..eq].to_ascii_lowercase();
                if is_credential_key(&key) || matches!(key.as_str(), "key" | "auth" | "pass") {
                    add(start + eq + eq_len, cursor);
                }
            }
            if cursor == end { break; }
            cursor += width;
            start = cursor;
        }
    }
    let mut provider_end = 0;
    let mut jwt_skip_until = 0;
    for (start, _) in line.char_indices() {
        if start < provider_end { continue; }
        if line[..start].chars().next_back().is_some_and(|ch| ch.is_ascii_alphanumeric()) { continue; }
        let length = provider_key_len(&line[start..], start, &mut jwt_skip_until);
        if length > 0 { provider_end = start + length; add(start, provider_end); }
    }
    collect_token_ranges(line, 0, 0, &mut add);
    let mut covered_end = 0usize;
    for (eq, _) in line.match_indices('=') {
        if eq < covered_end { continue; }
        let before = line[..eq].trim_end();
        let start = before.rfind(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '_' | '-')).map_or(0, |i| i + before[i..].chars().next().unwrap().len_utf8());
        let key = before[start..].to_ascii_lowercase();
        if !matches!(key.as_str(), "pass" | "auth" | "key") && !["_pass", "-pass", "_auth", "-auth"].iter().any(|suffix| key.ends_with(suffix)) { continue; }
        let mut start = eq + 1;
        while line.as_bytes().get(start).is_some_and(|b| matches!(b, b' ' | b'\t')) { start += 1; }
        if line[start..].starts_with("[redacted]") { continue; }
        let slashes = line[start..].bytes().take_while(|b| *b == b'\\').count();
        let opener = line[start + slashes..].chars().next().filter(|ch| matches!(ch, '"' | '\''));
        let end = if let Some(q) = opener {
            start += slashes + 1;
            let mut run = 0;
            let mut end = line.len();
            for (i, ch) in line[start..].char_indices() {
                if ch == q && run % 2 == slashes % 2 {
                    end = start + i - usize::from(slashes % 2 == 1);
                    break;
                }
                run = if ch == '\\' { run + 1 } else { 0 };
            }
            end
        } else {
            line[start..].find(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '&' | ';' | ',' | ')' | ']' | '}')).map_or(line.len(), |i| start + i)
        };
        let value = &line[start..end];
        let lower = value.to_ascii_lowercase();
        let redact = if key == "key" {
            !matches!(lower.as_str(), "true" | "false" | "0" | "1" | "none" | "null" | "enter" | "escape" | "tab" | "space" | "id" | "name" | "value" | "default" | "index" | "type" | "kind")
                && (value.len() >= 6 || (value.bytes().any(|b| b.is_ascii_uppercase()) && value.bytes().any(|b| b.is_ascii_digit())) || value.contains(['-', '_']))
        } else {
            !nonsecret_auth_value(&lower) && !matches!(lower.as_str(), "required" | "missing" | "failed" | "disabled" | "enabled")
        };
        if redact { covered_end = covered_end.max(end); add(start, end); }
    }
    ranges.sort_unstable();
    let mut merged = Vec::<(usize, usize)>::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut().filter(|last| start <= last.1) { last.1 = last.1.max(end); }
        else { merged.push((start, end)); }
    }
    let mut result = String::with_capacity(line.len());
    let mut copied = 0;
    for (start, end) in merged {
        result.push_str(&line[copied..start]);
        result.push_str("[redacted]");
        copied = end;
    }
    result.push_str(&line[copied..]);
    result
}

fn valid_host_port(seg: &str) -> bool {
    let seg = seg.strip_prefix("[redacted]@").unwrap_or(seg);
    let port_ok = |port: &str| (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit());
    if seg.starts_with('[') {
        let Some(close) = seg.find(']') else { return false; };
        return seg[1..close].parse::<std::net::Ipv6Addr>().is_ok()
            && (close + 1 == seg.len() || seg[close + 1..].strip_prefix(':').is_some_and(port_ok));
    }
    seg.split_once(':').map_or_else(|| strict_host(seg), |(host, port)| strict_host(host) && port_ok(port))
}

fn url_host_segment(text: &str) -> &str {
    let start = if text.starts_with('[') { text.find(']').map_or(0, |i| i + 1) } else { 0 };
    let end = text[start..].find(|ch: char| ch.is_whitespace() || matches!(ch, '/' | '?' | '#' | ',' | ';' | '"' | '\'' | ')' | '}' | ']' | '>'))
        .map_or(text.len(), |i| start + i);
    text[..end].trim_end_matches(['.', ':', '!', ',', ';'])
}

fn redact_bare_proxy_credentials(line: &str) -> String {
    if !line.contains('@') && !line.contains("%40") { return line.to_owned(); }
    fn colon(text: &str) -> Option<(usize, usize)> {
        let literal = text.find(':').map(|i| (i, 1));
        let prefix = &text[..literal.map_or(text.len(), |(i, _)| i)];
        let encoded = if prefix.contains('%') {
            prefix.as_bytes().windows(3).position(|bytes| bytes.eq_ignore_ascii_case(b"%3a")).map(|i| (i, 3))
        } else { None };
        literal.into_iter().chain(encoded).min_by_key(|(i, _)| *i)
    }
    let mut result = String::with_capacity(line.len());
    let mut copied = 0;
    let mut prev_host_port_end = 0usize;
    for (at, ch) in line.char_indices() {
        let at_len = if ch == '@' { 1 } else if ch == '%' && line[at..].starts_with("%40") { 3 } else { continue; };
        if at < copied { continue; }
        let after = host_port_prefix(&line[at + at_len..]);
        let host_port = if after.starts_with('[') {
            after.find(']').and_then(|end| {
                after[1..end].parse::<std::net::Ipv6Addr>().ok()?;
                let (_, sep_len) = colon(&after[end + 1..]).filter(|(i, _)| *i == 0)?;
                Some((&after[..=end], &after[end + 1 + sep_len..]))
            })
        } else {
            colon(after).filter(|(i, _)| strict_host(&after[..*i]))
                .map(|(i, len)| (&after[..i], &after[i + len..]))
        };
        let Some((host, port)) = host_port else { continue; };
        let digits = port.bytes().take_while(u8::is_ascii_digit).count();
        if !(1..=5).contains(&digits)
            || port[digits..].chars().next().is_some_and(|ch| !ch.is_whitespace() && !matches!(ch, '/' | '?' | '#' | ',' | ';' | '"' | '\'' | '>' | ')' | ']' | '}' | '.' | ':' | '!'))
        { continue; }
        let host_port_end = at + at_len + after.len() - port.len() + digits;
        let floor = copied.max(prev_host_port_end);
        let ws_start = line[floor..at].rfind(char::is_whitespace).map_or(floor, |i| {
            floor + i + line[floor + i..].chars().next().unwrap().len_utf8()
        });
        prev_host_port_end = host_port_end;
        let span = &line[ws_start..at];
        let Some(mut next_colon) = colon(span) else { continue; };
        let mut start = None;
        for (pos, _) in span.char_indices() {
            if pos != 0 && !matches!(span.as_bytes()[pos - 1], b',' | b';' | b'(' | b'[' | b'{' | b'<' | b'"' | b'\'' | b'=' | b')' | b']' | b'}' | b'>' | b'?' | b'#') {
                continue;
            }
            if pos >= next_colon.0 {
                let Some((offset, len)) = colon(&span[pos..]) else { break; };
                next_colon = (pos + offset, len);
            }
            let candidate = &span[pos..];
            if candidate == "[redacted]" { continue; }
            let (colon, len) = (next_colon.0 - pos, next_colon.1);
            let (user, password) = (&candidate[..colon], &candidate[colon + len..]);
            if ["//", r"\/\/", r"/\/", r"\//"].iter().any(|slash| password.starts_with(slash)) { continue; }
            if !user.is_empty() && !password.is_empty() && password != "[redacted]"
                && user.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+' | b'%'))
            {
                start = Some(ws_start + pos);
                break;
            }
        }
        if let Some(start) = start {
            result.push_str(&line[copied..start]);
            result.push_str("[redacted]@");
            result.push_str(host);
            result.push(':');
            result.push_str(&port[..digits]);
            copied = host_port_end;
        }
    }
    result.push_str(&line[copied..]);
    result
}

fn sanitize_plain(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut copied = 0;
    let mut skip_until = 0;
    let mut ws_end = 0;
    let mut last_at = None;
    let mut enclosing = EnclosingTracker::new();
    let mut separators = raw_scheme_separators(line).into_iter().peekable();
    while let Some((sep, start)) = separators.next() {
        if sep < skip_until { continue; }
        if start >= ws_end {
            ws_end = line[start..].find(|ch: char| ch.is_whitespace() && !matches!(ch, '\r' | '\n' | '\t')).map_or(line.len(), |i| start + i);
            last_at = line[start..ws_end].rfind('@').map(|i| start + i);
        }
        let limit = separators.peek().map_or(line.len(), |(next, _)| *next);
        let end = unescaped_authority_terminator(&line[start..limit]).map_or(limit, |offset| start + offset);
        let span = &line[start..end];
        // Walk the full original slice: the previous authority may include this scheme.
        let prefix = line[..sep].trim_end_matches(|c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        let opener = prefix.chars().next_back();
        enclosing.advance_to(line, prefix.len().saturating_sub(opener.map_or(0, char::len_utf8)));
        let closer = match opener { Some('\'') => Some('\''), Some('"') => Some('"'), Some('<') => Some('>'), _ => None };
        let authority_end = closer.and_then(|closer| strict_wrapped_host_end(span, closer, enclosing.closers())).unwrap_or(span.len());
        let authority = &span[..authority_end];
        if let Some(at) = authority.rfind('@') {
            result.push_str(&line[copied..start]);
            result.push_str("[redacted]@");
            result.push_str(&authority[at + 1..]);
            copied = start + authority_end;
        } else if let Some(at) = authority.to_ascii_lowercase().rfind("%40") {
            result.push_str(&line[copied..start]);
            result.push_str("[redacted]@");
            result.push_str(&authority[at + 3..]);
            copied = start + authority_end;
        } else if span.contains(':') && authority_end == span.len() {
            let embedded_scheme = end == limit && limit < ws_end;
            let suspect = !valid_host_port(span) || embedded_scheme;
            let scan_end = if suspect { ws_end } else { limit.min(ws_end) };
            let at = if suspect { last_at.filter(|at| *at >= end) }
                else { line[end..scan_end].rfind('@').map(|i| end + i) };
            if let Some(at) = at {
                let host = url_host_segment(&line[at + 1..scan_end]);
                let explicit_port = host.rsplit_once(':').is_some_and(|(_, port)| (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit()));
                if valid_host_port(host) && (suspect || explicit_port) {
                    result.push_str(&line[copied..start]);
                    result.push_str("[redacted]@");
                    copied = at + 1;
                    skip_until = copied;
                }
            }
        }
    }
    result.push_str(&line[copied..]);
    let result = redact_bare_proxy_credentials(&result);
    if verify_plain_line(&result) { result } else { OMITTED.to_owned() }
}

fn strict_host(host: &str) -> bool {
    if let Some(ip) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return !ip.is_empty() && ip.contains(':') && ip.bytes().all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'));
    }
    !host.is_empty() && !host.starts_with(['.', '-']) && !host.ends_with(['.', '-'])
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

struct EnclosingTracker { pos: usize, quote: Option<char>, escaped: bool, closers: Vec<char>, invalid: bool }

impl EnclosingTracker {
    fn new() -> Self { Self { pos: 0, quote: None, escaped: false, closers: Vec::new(), invalid: false } }
    fn advance_to(&mut self, line: &str, end: usize) {
        for ch in line[self.pos..end].chars() {
            if let Some(close) = self.quote {
                if self.escaped { self.escaped = false; }
                else if ch == '\\' { self.escaped = true; }
                else if ch == close { self.quote = None; }
            } else {
                match ch {
                    '\'' | '"' => self.quote = Some(ch),
                    '<' => self.quote = Some('>'),
                    '(' => self.closers.push(')'),
                    '[' => self.closers.push(']'),
                    '{' => self.closers.push('}'),
                    ')' | ']' | '}' if self.closers.pop() != Some(ch) => self.invalid = true,
                    _ => {}
                }
            }
        }
        self.pos = end;
    }
    fn closers(&self) -> &[char] { if self.invalid { &[] } else { &self.closers } }
}

fn strict_wrapped_host_end(span: &str, closer: char, enclosing: &[char]) -> Option<usize> {
    let allow_tail = !span.contains('@') || !enclosing.is_empty();
    let i = span.find(closer)?;
    (allow_tail && strict_host(&span[..i]) && balanced_tail(&span[i + closer.len_utf8()..], enclosing)).then_some(i)
}

/// Only matched container closers and separated scalar items can follow the host.
fn balanced_tail(mut tail: &str, mut enclosing: &[char]) -> bool {
    let mut consume_closers = |tail: &mut &str| {
        while let Some(ch @ (')' | ']' | '}')) = tail.chars().next() {
            if enclosing.last() != Some(&ch) { return false; }
            enclosing = &enclosing[..enclosing.len() - 1];
            *tail = &tail[1..];
        }
        true
    };
    if !consume_closers(&mut tail) { return false; }
    while !tail.is_empty() {
        if !tail.starts_with([',', ';']) { return false; }
        tail = &tail[1..];
        if !consume_closers(&mut tail) { return false; }
        if tail.is_empty() { return true; }
        let Some((first, rest)) = scalar_item(tail) else { return false; };
        tail = rest;
        if tail.starts_with(':') {
            let quoted_key = first.starts_with(['\'', '"', '<']) && !first.contains('@');
            let identifier = first.bytes().enumerate().all(|(i, b)| b.is_ascii_alphabetic() || b == b'_' || (i > 0 && b.is_ascii_digit()));
            if !quoted_key && !identifier { return false; }
            let Some((_, rest)) = scalar_item(&tail[1..]) else { return false; };
            tail = rest;
        }
        if !consume_closers(&mut tail) { return false; }
    }
    true
}

fn scalar_item(text: &str) -> Option<(&str, &str)> {
    let first = *text.as_bytes().first()?;
    if matches!(first, b'\'' | b'"' | b'<') {
        let closer = if first == b'<' { b'>' } else { first };
        let mut escaped = false;
        for (i, byte) in text.bytes().enumerate().skip(1) {
            if escaped { escaped = false; continue; }
            if byte == b'\\' { escaped = true; continue; }
            if byte == closer {
                let literal = &text[..=i];
                let inner = &literal[1..literal.len() - 1];
                if let Some((local, domain)) = inner.split_once('@') {
                    if local.is_empty()
                        || !local.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
                        || !domain.contains('.') || domain.contains(':') || !strict_host(domain)
                    {
                        return None;
                    }
                }
                return Some((literal, &text[i + 1..]));
            }
        }
        None
    } else {
        let end = text.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))).unwrap_or(text.len());
        (end > 0).then_some((&text[..end], &text[end..]))
    }
}

/// Independently inspect the result, without the redactor's wrapper or scalar parsers.
fn verify_plain_line(line: &str) -> bool {
    if line.contains('%') {
        let decoded = line.replace("%3a", ":").replace("%3A", ":").replace("%40", "@").replace("%2f", "/").replace("%2F", "/");
        if decoded != line && !verify_plain_line(&decoded) { return false; }
    }
    let host_ok = |host: &str| {
        let hostname = !host.is_empty() && host.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            && host.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        let ipv6 = host.starts_with('[') && host.ends_with(']') && host.len() > 2
            && host[1..host.len() - 1].contains(':')
            && host[1..host.len() - 1].bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        hostname || ipv6
    };
    let map_colon = |left: &str, right: &str| {
        let Some(q @ ('\'' | '"')) = left.chars().next_back() else { return false; };
        if !right.starts_with(q) { return false; }
        let before_close = &left[..left.len() - 1];
        if before_close.bytes().rev().take_while(|b| *b == b'\\').count() % 2 == 1 { return false; }
        for (opening, ch) in before_close.char_indices().rev() {
            if ch != q || before_close[..opening].bytes().rev().take_while(|b| *b == b'\\').count() % 2 == 1 { continue; }
            return !before_close[opening + 1..].contains([':', '@'])
                && before_close[..opening].ends_with(['{', ',']);
        }
        false
    };
    let unsafe_colon = |text: &str| text.match_indices(':').any(|(colon, _)| {
        let (left, right) = (&text[..colon], &text[colon + 1..]);
        !left.is_empty() && !right.is_empty() && !map_colon(left, right)
    });
    let mut prev_host_port_end = 0usize;
    for (at, _) in line.match_indices('@') {
        let after = host_port_prefix(&line[at + 1..]);
        let host_port = if after.starts_with('[') {
            after.find("]:").map(|end| (&after[..=end], &after[end + 2..]))
        } else { after.split_once(':') };
        let Some((host, port)) = host_port else { continue; };
        let digits = port.bytes().take_while(u8::is_ascii_digit).count();
        if !host_ok(host) || !(1..=5).contains(&digits)
            || port[digits..].chars().next().is_some_and(|ch| !ch.is_whitespace() && !matches!(ch, '/' | '?' | '#' | ',' | ';' | '"' | '\'' | '>' | ')' | ']' | '}' | '.' | ':' | '!'))
        { continue; }
        let floor = prev_host_port_end;
        let ws_start = line[floor..at].rfind(char::is_whitespace).map_or(floor, |i| {
            floor + i + line[floor + i..].chars().next().unwrap().len_utf8()
        });
        let token = &line[ws_start..at];
        prev_host_port_end = at + 1 + host.len() + 1 + digits;
        let check_token = token.strip_suffix("[redacted]")
            .filter(|before| before.is_empty() || before.ends_with(['/', '=', ',', ';', '(', '[', '{', '<', '"', '\'', ')', ']', '}', '>', '?', '#']))
            .unwrap_or(token);
        let scheme = raw_scheme_separators(check_token).into_iter().next_back();
        if let Some((scheme_start, scheme_end)) = scheme {
            let after = &check_token[scheme_end..];
            let (pre, post) = after.find(['/', '?', '#', ',', ';']).map_or((after, ""), |i| (&after[..i], &after[i + 1..]));
            let prefix = &check_token[..scheme_start];
            let prior = prefix.trim_end_matches(|ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'));
            let completed_url = prior.ends_with([',', ';']) && raw_scheme_separators(prior).first().is_some_and(|(sep, start)| {
                let end = unescaped_authority_terminator(&prior[*start..]).map_or(prior.len(), |i| start + i);
                !unsafe_colon(&prior[..*sep]) && valid_host_port(&prior[*start..end])
                    && verify_plain_line(prior.trim_end_matches([',', ';']))
            });
            if (!completed_url && unsafe_colon(prefix)) || unsafe_colon(post)
                || (pre.contains(':') && !pre.starts_with("[redacted]@")) { return false; }
        } else if unsafe_colon(check_token) { return false; }
    }
    let atom_len = |text: &str| -> Option<usize> {
        let first = *text.as_bytes().first()?;
        if !matches!(first, b'\'' | b'"' | b'<') {
            let count = text.bytes().take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+')).count();
            return (count > 0).then_some(count);
        }
        let close = if first == b'<' { b'>' } else { first };
        let mut slashes = 0;
        for (i, byte) in text.bytes().enumerate().skip(1) {
            if byte == close && slashes % 2 == 0 {
                let inside = &text[1..i];
                if let Some((local, domain)) = inside.split_once('@') {
                    if local.is_empty() || inside.contains(':')
                        || !local.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' || b == b'+')
                        || !domain.contains('.') || !host_ok(domain)
                    {
                        return None;
                    }
                }
                return Some(i + 1);
            }
            slashes = if byte == b'\\' { slashes + 1 } else { 0 };
        }
        None
    };
    let mut prefix_pos = 0;
    let mut prefix_quote = None;
    let mut prefix_escaped = false;
    let mut prefix_closers = Vec::new();
    let mut prefix_invalid = false;
    let mut skip_until = 0;
    let mut ws_end = 0;
    let mut last_valid_at = None;
    let mut separators = raw_scheme_separators(line).into_iter().peekable();
    while let Some((sep, start)) = separators.next() {
        if sep < skip_until { continue; }
        if start >= ws_end {
            ws_end = line[start..].find(|ch: char| ch.is_whitespace() && !matches!(ch, '\r' | '\n' | '\t')).map_or(line.len(), |i| start + i);
            last_valid_at = line[start..ws_end].match_indices('@').filter_map(|(at, _)| {
                let at = start + at;
                valid_host_port(url_host_segment(&line[at + 1..ws_end])).then_some(at)
            }).next_back();
        }
        let limit = separators.peek().map_or(line.len(), |(next, _)| *next);
        let bounded = &line[start..limit];
        let span = &bounded[..unescaped_authority_terminator(bounded).unwrap_or(bounded.len())];
        if has_escaped_at(span) || span.to_ascii_lowercase().contains("%40") { return false; }
        if !span.contains('@') {
            let embedded_scheme = start + span.len() == limit && limit < ws_end;
            if start + span.len() < ws_end && span.contains(':') && (!valid_host_port(span) || embedded_scheme) {
                if last_valid_at.is_some_and(|at| at >= start + span.len()) { return false; }
            }
            continue;
        }
        if let Some(host) = span.strip_prefix("[redacted]@") {
            if !host.contains('@') { skip_until = start + span.len(); continue; }
            return false;
        }
        let Some(opener_index) = line[..sep].rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))) else { return false; };
        let closer = match line.as_bytes()[opener_index] { b'\'' => '\'', b'"' => '"', b'<' => '>', _ => return false };
        let Some((host, after)) = span.split_once(closer) else { return false; };
        if !host_ok(host) { return false; }

        for ch in line[prefix_pos..opener_index].chars() {
            if let Some(close) = prefix_quote {
                if prefix_escaped { prefix_escaped = false; }
                else if ch == '\\' { prefix_escaped = true; }
                else if ch == close { prefix_quote = None; }
            } else {
                match ch {
                    '\'' | '"' => prefix_quote = Some(ch),
                    '<' => prefix_quote = Some('>'),
                    '(' => prefix_closers.push(')'),
                    '[' => prefix_closers.push(']'),
                    '{' => prefix_closers.push('}'),
                    ')' | ']' | '}' if prefix_closers.pop() != Some(ch) => prefix_invalid = true,
                    _ => {}
                }
            }
        }
        prefix_pos = opener_index;
        if prefix_invalid || prefix_closers.is_empty() { return false; }
        let mut enclosing_len = prefix_closers.len();
        let mut offset = 0;
        let mut separator_required = true;
        while offset < after.len() {
            let byte = after.as_bytes()[offset];
            if matches!(byte, b')' | b']' | b'}') {
                if enclosing_len == 0 || prefix_closers[enclosing_len - 1] != char::from(byte) { return false; }
                enclosing_len -= 1;
                offset += 1;
            } else if separator_required {
                if !matches!(byte, b',' | b';') { return false; }
                offset += 1;
                separator_required = false;
            } else {
                let Some(length) = atom_len(&after[offset..]) else { return false; };
                let key = &after[offset..offset + length];
                offset += length;
                if after.as_bytes().get(offset) == Some(&b':') {
                    let quoted_key = matches!(key.as_bytes()[0], b'\'' | b'"' | b'<') && !key.contains('@');
                    let identifier = key.bytes().enumerate().all(|(i, b)| b.is_ascii_alphabetic() || b == b'_' || (i > 0 && b.is_ascii_digit()));
                    if !quoted_key && !identifier { return false; }
                    offset += 1;
                    let Some(length) = atom_len(&after[offset..]) else { return false; };
                    offset += length;
                }
                separator_required = true;
            }
        }
    }
    true
}

pub(super) fn truncate_grapheme_safe(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars { return text.to_owned(); }
    if max_chars == 0 { return String::new(); }
    let mut used = 0;
    let mut end = 0;
    for (i, cluster) in text.grapheme_indices(true) {
        used += cluster.chars().count();
        if used >= max_chars { break; }
        end = i + cluster.len();
    }
    format!("{}…", &text[..end])
}

fn tail(text: &str, limit: usize) -> String {
    let mut used = 0;
    let mut start = text.len();
    for (i, cluster) in text.grapheme_indices(true).rev() {
        used += cluster.chars().count();
        if used > limit { break; }
        start = i;
    }
    if start == 0 { text.to_owned() } else { format!("…{}", &text[start..]) }
}

pub(super) fn truncate_bytes_grapheme_safe(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes { return text.to_owned(); }
    if max_bytes < '…'.len_utf8() { return String::new(); }
    let budget = max_bytes - '…'.len_utf8();
    let end = text.grapheme_indices(true).take_while(|(i, cluster)| i + cluster.len() <= budget)
        .last().map_or(0, |(i, cluster)| i + cluster.len());
    format!("{}…", &text[..end])
}

fn suffix_bytes_grapheme_safe(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes { return text.to_owned(); }
    if max_bytes < '…'.len_utf8() { return String::new(); }
    let budget = max_bytes - '…'.len_utf8();
    let start = text.grapheme_indices(true).rev().take_while(|(i, _)| text.len() - i <= budget)
        .last().map_or(text.len(), |(i, _)| i);
    format!("…{}", &text[start..])
}

/// Caller redacts transport credentials before passing either value here.
pub(super) fn failure(error: &str, diagnostic: &str) -> String {
    let error = clean_bounded(error);
    let diagnostic = clean_bounded(diagnostic);
    let lines: Vec<_> = diagnostic
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let cause = lines.iter().rev().find(|line| {
        let lower = line.to_ascii_lowercase();
        !lower.contains("warning")
            && !lower.starts_with("at ")
            && !lower.starts_with("file ")
            && (lower.contains("error")
                || lower.contains("exception")
                || lower.contains("failed")
                || lower.contains("fatal"))
    });
    let headline = error.trim();
    let mut result = truncate_grapheme_safe(headline, 1200);
    if let Some(cause) = cause.filter(|cause| !error.contains(**cause)) {
        result.push('\n');
        result.push_str(&tail(cause, 800));
    }
    // Keep the end of stderr (exception details / Node error properties), not
    // the first several kilobytes of a warning or Python traceback.
    let details = tail(diagnostic.trim(), 2400);
    if !details.is_empty() && details != result && Some(details.as_str()) != cause.copied() {
        result.push_str("\nDetails:\n");
        result.push_str(&details);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;











    #[test]
    fn r23_yaml_curl_escaped_assignments_and_encoded_query_values_are_private() {
        for text in [
            "api_key: # rotated daily\n  SECRET999\nok",
            "api_key: # rotated daily\n  |\n  SECRET999\nok",
            "api_key: # rotated daily\n  {\n    \"v\": \"SECRET999\"\n  }\nok",
            "api_key: !!str # rotated daily\n  |\n  SECRET999\nok",
            "curl -u\"user:SECRET PASS999\" https://api.example.com",
            "curl -U\"user:SECRET PASS999\" https://api.example.com",
            "curl -u'user:SECRET PASS999' https://api.example.com",
            "curl -u\"user:SECRET,PASS999\" https://api.example.com",
            "curl --user=user:SECRET,PASS999 https://api.example.com",
            "curl -u user:SECRET,PASS999 https://api.example.com",
            "curl -uuser:SECRET,PASS999 https://api.example.com",
            "curl -u :SECRET999 https://api.example.com",
            "curl --user=:SECRET999 https://api.example.com",
            "curl --USER=user:SECRET999 https://api.example.com",
            "curl --PROXY-USER=user:SECRET999 https://api.example.com",
            r#"Error: db_pass=\"first SECRET999\""#,
            r#"Error: auth=\"abc&SECRET999\""#,
            r#"Error: pass=\'first SECRET999\'"#,
            "Failed: https%3A%2F%2Fapi.example.com%2Fv1%3Fapi_key%3DSECRET999",
            "Failed: https%3A%2F%2Fapi.example.com%2Fv1%3Fkey%3DSECRET999",
            "https://api.example.com/v1%23access_token%3DSECRET999",
            "https://api.example.com/v1?x=1%3Bapi_key%3DSECRET999",
        ] {
            for result in [clean(text), clean_bounded(text), failure("Failed", text)] {
                assert!(!result.contains("SECRET") && !result.contains("PASS999"), "{text}\n{result}");
                if text.ends_with("\nok") { assert!(result.trim_end().ends_with("ok"), "{text}\n{result}"); }
                assert_eq!(clean(&result), result, "{text}");
            }
        }
        for text in ["curl -utf8 file", "mysql -u root", "auth: session expired", r#"["-u", "user:[redacted]", "https://api.example.com"]"#] {
            assert_eq!(clean(text), text, "{text}");
        }
    }

    #[test]
    fn r23_repeated_authorities_wrappers_and_jwt_prefixes_are_linear() {
        for text in ["a://b:c/@!".repeat(6000), format!("'http://{}{}", "a".repeat(30000), "'".repeat(30000)), "-eyJ".repeat(15000), "_eyJ".repeat(15000)] {
            let started = std::time::Instant::now();
            let result = clean_bounded(&text);
            assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}: {:?}", &text[..12], started.elapsed());
            assert_eq!(clean_bounded(&result), result);
        }
    }

    #[test]
    fn r23_extended_graphemes_stay_whole_in_failure_tail_and_bounded_edges() {
        for cluster in ["कि", "কি", "ကိ", "កិ", "กิ", "か\u{3099}", "بِ", "אִ", "ᠠ\u{180b}", "a\u{200c}", "🇺🇸", "👨‍👩‍👧", "ᄀ각", "\u{1f3f4}\u{e0067}\u{e0062}\u{e007f}"] {
            assert_eq!(failure(&format!("{}{cluster}end", "a".repeat(1198)), ""), format!("{}…", "a".repeat(1198)), "{cluster}");
            assert_eq!(tail(&format!("lead{cluster}end"), cluster.chars().count() + 2), "…end", "{cluster}");
            assert_eq!(truncate_bytes_grapheme_safe(&format!("ab{cluster}end"), 6), "ab…", "{cluster}");
            assert_eq!(suffix_bytes_grapheme_safe(&format!("lead{cluster}end"), cluster.len() + 5), "…end", "{cluster}");
            let result = clean_bounded(&format!("{}{cluster}{}", "x".repeat(RETAINED_EDGE - 1), "y".repeat(RETAINED_EDGE + 100)));
            let without_cluster = result.replace(cluster, "");
            assert!(without_cluster.chars().all(|ch| ch.is_ascii() || ch == '…'), "{cluster}: {without_cluster}");
        }
    }

    #[test]
    fn r22_deep_and_unicode_separated_json_keeps_sensitive_leaves_visible_to_cleaner() {
        let object = r#"{"headers":{"\u0061uthorization":"Custom SECRET999"}}"#;
        for text in [format!("{}{}{}", "[".repeat(200), object, "]".repeat(200)),
            format!("http://example.com\u{a0}{object}")]
        {
            assert!(json_containers(&text).any(|(start, end)| text[start..end].contains(r#""headers""#)), "{text}");
            assert!(json_containers(&text).all(|(start, end)| text[start..end].bytes().filter(|b| *b == b'[').count() <= 128));
            for result in [clean(&text), clean_bounded(&text)] {
                assert!(!result.contains("SECRET999"), "{text}\n{result}");
                assert_eq!(clean(&result), result);
            }
        }
    }

    #[test]
    fn r22_repeated_assignments_and_proxy_delimiters_scale_linearly() {
        for text in ["auth=".repeat(12000), ",@p:1".repeat(12000), format!("{}:x@p:1", ",a".repeat(25000))] {
            let started = std::time::Instant::now();
            let result = clean_bounded(&text);
            assert!(started.elapsed() < std::time::Duration::from_secs(5), "{} bytes starting {:?}: {:?}", text.len(), &text[..text.len().min(12)], started.elapsed());
            assert_eq!(clean_bounded(&result), result);
        }
    }

    #[test]
    fn r21_url_whitespace_never_panics_or_hides_json() {
        for text in ["http://example.com:8080\tfoo", "http://example.com\tstatus:ok", "http://example.com\u{a0}status:ok", "prefix\u{a0}http://example.com:8080", "prefix🚀http://example.com:8080"] {
            assert_eq!(clean(text), text, "{text}");
            assert!(verify_plain_line(text));
        }
        let text = "http://example.com\t{\"url\":\"http://user:SECRET999@proxy\"}";
        assert!(!clean(text).contains("SECRET999"));
    }

    #[test]
    fn r21_adversarial_json_brackets_and_repeated_wrappers_are_linear() {
        for text in [
            format!("{}x{}", "[".repeat(30000), "]".repeat(30000)),
            format!(r#"{}{{"\u0061pi_key":"SECRET999"}} x{}"#, "[".repeat(200), "]".repeat(200)),
            format!("token={}{}", "{".repeat(4094), "]".repeat(200000)),
            "'http://a' ".repeat(5500),
        ] {
            let started = std::time::Instant::now();
            let result = clean(&text);
            assert!(!result.contains("SECRET999"));
            assert!(started.elapsed() < std::time::Duration::from_secs(5), "{} bytes: {:?}", text.len(), started.elapsed());
            assert_eq!(clean(&result), result);
        }
        assert_eq!(clean(&"'http://a' ".repeat(5500)), "'http://a' ".repeat(5500));
    }

    #[test]
    fn r21_proxy_punctuation_yaml_sequences_and_inline_variants_are_private() {
        for text in [
            "connect to user:SECRET999@proxy:8080: connection refused",
            "Proxy failed via user:SECRET999@proxy:8080.",
            "Failed to connect to https://user:SECRET999/abc@proxy.example.com.",
            "connect to https://user:SECRET999/abc@proxy:8080: connection refused",
            "https://user:SECRET999?abc@proxy.example.com!",
            "- api_key: |\n  SECRET999\nok", "  - api_key: |\n    SECRET999\n  ok",
            "- api_key:\n  SECRET999\nok", "- cookie: sid=SECRET999",
            "- secret: supersecretvalue", "- authorization: CustomScheme SECRET999",
            "api_key: !!str\n  |\n  SECRET999\nok", "- api_key: |\n  SECRET999\n- ok: 1",
            "curl --user=user:SECRET999 https://api.example.com",
            "curl --user=\"user:SECRET999\" https://api.example.com",
            "curl -uuser:SECRET999 https://api.example.com",
            "curl -u\"user:SECRET999\" https://api.example.com",
            "curl --proxy-user user:SECRET999 https://api.example.com",
            "curl --proxy-user=user:SECRET999 https://api.example.com",
            "curl -U user:SECRET999 https://api.example.com",
            "https://api.example.com/v1%3Fapi_key%3DSECRET999",
            "https://api.example.com/v1?x=1%26refresh_token%3DSECRET999",
            "https%3A%2F%2Fuser%3ASECRET999%40api.example.com/v1",
            "db_pass=\"first SECRET999\"", "db_pass=\"abc;SECRET999\"",
            "auth=\"abc&SECRET999\"", "key=\"abc,SECRET999\"",
        ] {
            let result = clean(text);
            assert!(!result.contains("SECRET999") && !result.contains("supersecretvalue"), "{text}\n{result}");
            assert!(!failure("Failed", text).contains("SECRET999"), "{text}");
            assert_eq!(clean(&result), result, "{text}");
            if text.ends_with("ok") { assert!(result.trim_end().ends_with("ok"), "{result}"); }
            if text.ends_with("- ok: 1") { assert!(result.ends_with("- ok: 1"), "{result}"); }
        }
        for text in ["user@example.com.", "auth: session expired", "curl -utf8 file", "mysql -u root"] { assert_eq!(clean(text), text); }
    }

    #[test]
    fn r21_flags_hangul_and_tag_clusters_are_not_split() {
        let flags = "🇺🇸".repeat(700);
        let headline = failure(&flags, "");
        assert_eq!(headline.trim_end_matches('…').chars().count() % 2, 0);
        let end = tail(&flags, 801);
        assert_eq!(end.trim_start_matches('…').chars().count() % 2, 0);
        let text = format!("{}각tail", "a".repeat(1198));
        assert_eq!(failure(&text, ""), format!("{}…", "a".repeat(1198)));
        assert!(!tail("prefix각tail", 6).starts_with("…ᅡ"));
        assert_eq!("\u{1f3f4}\u{e0067}\u{e007f}".graphemes(true).count(), 1);
    }

    #[test]
    fn r20_bounded_cleaner_keeps_head_tail_context_and_private_state() {
        let short = format!("Error: {} http://user:SECRET999{}@proxy", "x".repeat(1000), "y".repeat(4000));
        assert_eq!(clean_bounded(&short), clean(&short));
        assert!(clean_bounded(&short).contains(&"x".repeat(1000)));
        let huge = format!("Error: root cause\n{}api_key:\n  SECRET999\nError: final cause", "ordinary\n".repeat(40000));
        let result = clean_bounded(&huge);
        assert!(result.starts_with("Error: root cause"), "{result}");
        assert!(result.ends_with("Error: final cause"), "{result}");
        assert!(!result.contains("SECRET999"));
        assert_eq!(result.matches("[Output truncated]").count(), 1);
        assert!(result.len() <= 32 * 1024 + 100, "{}", result.len());
        assert_eq!(clean_bounded("http://user:SECRET999/abc\r@proxy:8080"), "http://[redacted]@proxy:8080");
        let oversized = format!("{}\n{}\n", "x".repeat(70000), "x".repeat(70000));
        assert_eq!(clean_bounded(&oversized), "[Line over 64 KB omitted]");
        let private = format!("cookies: [\n  \"{}\",\n  \"SECRET999\"\n]\nError: done", "x".repeat(70000));
        let result = clean_bounded(&private);
        assert!(!result.contains("SECRET999"));
        assert!(result.ends_with("Error: done"));
        let huge_line = format!("Error: {}SECRET999", "x".repeat(2 * 1024 * 1024));
        assert_eq!(clean_bounded(&huge_line), "[Line over 64 KB omitted]");
        assert!(!failure(&huge_line, &private).contains("SECRET999"));
    }

    #[test]
    fn r20_unclipped_url_passwords_and_cr_never_leak() {
        for text in [
            "https://user:SECRET999://bar@api.example.com/v1",
            "http://user:SECRET999/abc)def@proxy:8080",
            "http://user:SECRET999?abc]def@proxy:8080",
            "http://user:SECRET999#abc}def@proxy:8080",
            "http://user:SECRET999/abc'def@proxy:8080",
            "http://user:SECRET999/abc\"def@proxy:8080",
            "http://user:SECRET999/abc>def@proxy:8080",
            "http://user:SECRET999/abc\r@proxy:8080",
        ] {
            assert!(!verify_plain_line(text), "{text}");
            let result = clean(text);
            assert!(!result.contains("SECRET999"), "{text}\n{result}");
            assert!(result.contains("[redacted]@"), "{text}\n{result}");
            assert_eq!(clean(&result), result, "{text}");
            assert!(!failure("Failed", text).contains("SECRET999"));
        }
        assert_eq!(clean("http://user:SECRET999/abc\r@proxy:8080"), "http://[redacted]@proxy:8080");
        assert_eq!(clean("http://example.com/path\rError: done"), "http://example.com/path\nError: done");
        assert_eq!(clean("http://example.com:8080/a,http://user:pass@h2:9000"), "http://example.com:8080/a,http://[redacted]@h2:9000");
    }

    #[test]
    fn r20_yaml_headers_triple_templates_and_value_siblings() {
        for text in [
            "api_key:\n  |\n  SECRET999_LINE1\nok",
            "api_key: |                                                                                                    \n  SECRET999_LINE1\nok",
            "api_key: !!str |-\n  SECRET999_LINE1\nok",
            "api_key: !secret &k >2-\n  SECRET999_LINE1\nok",
            "https://api.z.ai\rapi_key: |\n  SECRET999_LINE1\nok",
            "token=\x60\x60\x60\nline1 \x60\nSECRET999_LINE3\n\x60\x60\x60\nok",
        ] {
            let result = clean(text);
            assert!(!result.contains("SECRET999"), "{text}\n{result}");
            assert!(result.ends_with("ok"), "{text}\n{result}");
            assert_eq!(clean(&result), result);
            assert!(!failure("Failed", text).contains("SECRET999"));
        }
        for (text, expected) in [
            ("token:\nError: real cause", format!("{OMITTED}\nError: real cause")),
            ("apiKey:\nbaseUrl: https://api.z.ai", format!("{OMITTED}\nbaseUrl: https://api.z.ai")),
            ("token:\napi_key: SECRET999\nok", format!("{OMITTED}\n{OMITTED}\nok")),
        ] { assert_eq!(clean(text), expected); assert_eq!(clean(&expected), expected); }
        for value in ["SECRET999", "\"SECRET999\"", "  SECRET999", "user:SECRET999", "http://user:SECRET999@proxy", "{\"token\":\"SECRET999\"}", "[\"SECRET999\"]"] {
            let text = format!("token:\n{value}");
            assert!(!clean(&text).contains("SECRET999"), "{text}");
        }
        for header in ["!!str |-", "!secret &k >2-", "!<tag> |+", "&k |"] { assert!(is_yaml_block_header(header)); }
        for header in ["text |", "!!str wrong", "| x", "!!str", "&k"] { assert!(!is_yaml_block_header(header)); }
    }

    #[test]
    fn r20_inline_headers_flags_aliases_queries_and_curl_user() {
        for text in [
            "Error: zcode --token 'can't_SECRET999' failed",
            "zcode --token \"-SECRET999\"", "Authorization Basic -SECRET999", "Error: API key \"-SECRET999\"",
            "zcode --AUTH SECRET999", "zcode --TOKEN SECRET999", "zcode --API-KEY SECRET999",
            "Error: invalid authorization header 'SENTINEL9'",
            "Error: invalid x-api-key header 'SENTINEL9'",
            "Error: Authorization header was Basic SENTINEL9",
            "Error: invalid cookie header \"sid=SENTINEL9\"",
            "Error: API key not valid: SENTINEL9", "Error: API key is invalid: SENTINEL9",
            "Invalid token 'SENTINEL9'", "token SENTINEL9 is invalid",
            r#"{"auth": "SECRET999"}"#, r#"{"pass": "SECRET999"}"#,
            r#"{"auth":"SECRET999"}"#, r#"{"auth" : "SECRET999"}"#,
            "auth = SECRET999", "pass = SECRET999", "DB_PASS=SECRET999", "PROXY_AUTH=SECRET999",
            "https://auth.example.com/login?next=https://api.example.com/v1?a=1%26key=SECRET999",
            "https://api.example.com/v1?a=1%26key%3DSECRET999",
            "https://api.example.com/v1?a=1%3Fkey%3dSECRET999",
            "curl -u user:SECRET999 https://api.example.com", "curl --user user:SECRET999 https://api.example.com",
        ] {
            let inline = redact_inline_secrets(text);
            assert!(!inline.contains("SECRET999") && !inline.contains("SENTINEL9"), "{text}\n{inline}");
            let result = clean(text);
            assert!(!result.contains("SECRET999") && !result.contains("SENTINEL9"), "{text}\n{result}");
            assert_eq!(clean(&result), result, "{text}");
            assert!(!failure("Failed", text).contains("SENTINEL9"), "{text}");
        }
        assert_eq!(clean("Error: zcode --token 'can't_SECRET999' failed"), "Error: zcode --token '[redacted]' failed");
        assert_eq!(clean("curl -u user:SECRET999 https://api.example.com"), "curl -u user:[redacted] https://api.example.com");
        for text in [
            "zcode --token --verbose", "Error: authorization header missing", "Error: Cookie header too large",
            "SyntaxError: Unexpected token 'export'", "token count 128000", "token expired",
            "error: auth: session expired", "[ERROR] auth: token expired, please sign in",
            "USE_AUTH=true", "PROXY_AUTH=basic", "git diff -u file.rs", "mysql -u root",
        ] { assert_eq!(clean(text), text, "{text}"); assert_eq!(clean(&clean(text)), text); }
    }

    #[test]
    fn r20_headline_and_tail_keep_combining_and_zwj_clusters() {
        for (text, expected) in [
            (format!("{}e\u{301}tail", "a".repeat(1198)), format!("{}…", "a".repeat(1198))),
            (format!("{}👨‍👩‍👧tail", "a".repeat(1195)), format!("{}…", "a".repeat(1195))),
        ] { assert_eq!(failure(&text, ""), expected); }
        for (text, limit) in [
            ("prefixe\u{301}tail", 5), ("prefix👨‍👩‍👧tail", 7), ("prefix👨‍👩‍👧tail", 8),
        ] {
            let result = tail(text, limit);
            assert!(!result.starts_with("…\u{301}") && !result.starts_with("…\u{200d}"), "{result}");
            assert!(!result.contains("…👩") && !result.contains("…👧"), "{result}");
        }
    }

    #[test]
    fn r19_url_password_terminators_and_percent_delimiters_are_private() {
        for (text, expected) in [
            ("http://user:SECRET999/abc@proxy:8080", "http://[redacted]@proxy:8080"),
            ("http://user:SECRET999?abc@proxy:8080", "http://[redacted]@proxy:8080"),
            ("http://user:SECRET999#abc@proxy:8080", "http://[redacted]@proxy:8080"),
            ("https://user:SECRET999/p4ss@api.example.com:443/v1", "https://[redacted]@api.example.com:443/v1"),
            ("https://user:SECRET999/abc@github.com/org/repo", "https://[redacted]@github.com/org/repo"),
            ("http://user:SECRET999\\\\/abc@proxy:8080", "http://[redacted]@proxy:8080"),
            ("http://user:12345/abc@proxy:8080", "http://[redacted]@proxy:8080"),
            ("http://user%3Apass%40host", "http://[redacted]@host"),
            ("Error: proxy user%3Apass%40proxy:8080 failed", "Error: proxy [redacted]@proxy:8080 failed"),
            ("user%3apass%40proxy%3A8080", "[redacted]@proxy:8080"),
        ] {
            assert!(!verify_plain_line(text), "{text}");
            assert_eq!(clean(text), expected, "{text}");
            assert_eq!(clean(&clean(text)), expected, "{text}");
            assert!(!failure("Failed", text).contains("SECRET999"));
        }
        for text in [
            "https://registry.npmjs.org/@napi-rs/keyring", "https://registry.npmjs.org/%40napi-rs/keyring",
            "https://example.com:8443/users/alice@example.com", "http://[::1]:8080/@scope/pkg",
            "http://[redacted]@proxy:8080/foo@bar",
        ] { assert_eq!(clean(text), text); assert!(verify_plain_line(text)); assert_eq!(clean(&clean(text)), text); }
    }

    #[test]
    fn r19_key_suffixes_arrays_and_additional_inline_forms() {
        for key in ["AZURE_OPENAI_KEY", "OPENAI_KEY", "ZHIPUAI_KEY", "ZAI_KEY", "openaiKey", "app.privateKey", "bearer"] {
            assert!(is_credential_key(key), "{key}");
            for text in [format!("{key}=S3CR3TXYZ"), format!("{key}: S3CR3TXYZ")] {
                assert_eq!(clean(&text), OMITTED, "{text}");
                assert_eq!(clean(&clean(&text)), OMITTED);
            }
        }
        for key in ["public_key", "primary_key", "cache_key", "sort_key", "shortcut_key", "storage_key", "header_key", "userPublicKey", "API_SORT_KEY"] {
            assert!(!is_credential_key(key), "{key}");
            let text = format!("{key}: ordinary");
            assert_eq!(clean(&text), text);
        }
        for text in [
            r#"["Authorization", "Basic", "dXNlcjpTRUNSRVQ="]"#,
            "['Authorization', 'Basic', 'dXNlcjpTRUNSRVQ=']",
            r#"spawn ["curl", "-H", "Authorization", "Basic", "dXNlcjpTRUNSRVQ="]"#,
            "['Authorization', 'Bearer', 'S3CR3TXYZ']", "['Bearer', 'S3CR3TXYZ']",
            r#"["Bearer", "S3CR3TXYZ"]"#,
            "Error: Incorrect API key provided: S3CR3TXYZ",
            r#"{"error":"invalid key S3CR3TXYZ"}"#, "Error: invalid key S3CR3TXYZ",
            "Error: access token S3CR3TXYZ expired", "auth: S3CR3TXYZ", "pass: S3CR3TXYZ",
            "mysql -u root -pS3CR3TXYZ",
        ] {
            let inline = redact_inline_secrets(text);
            assert!(!inline.contains("S3CR3TXYZ") && !inline.contains("dXNlcjpTRUNSRVQ="), "{text}\n{inline}");
            let result = clean(text);
            assert!(!result.contains("S3CR3TXYZ") && !result.contains("dXNlcjpTRUNSRVQ="), "{text}\n{result}");
            assert_eq!(clean(&result), result, "{text}");
            assert!(!failure("Failed", text).contains("S3CR3TXYZ"));
        }
        for text in [
            "Bearer: required", "Bearer: missing", "Bearer token is missing", "Error: invalid key format",
            "Error: invalid key length", "Error: access token expired", "Error: access token is missing",
            "auth: failed", "auth: oauth", "auth: basic", "auth: required", "auth: none",
            "mysql -p8080", "ssh -p22", "find -print", "cmd -path", "cmd -p \"hello\"",
        ] { assert_eq!(clean(text), text, "{text}"); assert_eq!(clean(&clean(text)), text); }
        assert_eq!(clean("Error: Incorrect API key provided: S3CR3TXYZ"), "Error: Incorrect API key provided: [redacted]");
        assert_eq!(clean("auth: S3CR3TXYZ"), "auth: [redacted]");
        assert_eq!(clean("mysql -u root -pS3CR3TXYZ"), "mysql -u root -p[redacted]");
    }

    #[test]
    fn r19_yaml_backticks_and_parenthesized_continuations() {
        for header in ["|", ">", "|-", "|+2 # note", ">2-", ">9+ # note"] { assert!(is_yaml_block_header(header)); }
        for header in ["|--", ">22", "|0", ">word", "|+-", "ordinary"] { assert!(!is_yaml_block_header(header)); }

        for text in [
            "private_key: |\n  SECRET999_LINE1\n  SECRET999_LINE2\nok",
            "api_key: |-\n  SECRET999_LINE1\nok", "api_key: >\n  SECRET999_LINE1\nok",
            "  private_key: |+2 # note\n    SECRET999_LINE1\n\n    SECRET999_LINE2\n  ok",
            "api_key: >2-\n  SECRET999_LINE1\ntoken: |\n  SECRET999_LINE2\nok",
            "token=\x60line1\nSECRET999\n\x60\nok", "token=(\n  \"SECRET999\"\n)\nok",
            "cookies: [\n  \x60line1\n  ] SECRET999\n  \x60\n]\nok",
        ] {
            let result = clean(text);
            assert!(!result.contains("SECRET999"), "{text}\n{result}");
            assert!(result.trim_end().ends_with("ok"), "{text}\n{result}");
            assert_eq!(clean(&result), result, "{text}");
            assert!(!failure("Failed", text).contains("SECRET999"));
        }
        assert_eq!(clean("Run \x60zcode\x60 to continue\nok"), "Run \x60zcode\x60 to continue\nok");
    }

    #[test]
    fn r19_control_whitespace_and_secret_free_indexed_statuses() {
        for text in [
            r#"{"h":"Bearer\fSECRET999"}"#, "Bearer\u{c}SECRET999", "Bearer\u{b}SECRET999",
            "Bearer\u{85}SECRET999", r#"{"cmd":"zcode --token\fSECRET999"}"#,
        ] {
            assert!(!clean(text).contains("SECRET999"), "{text}");
            assert!(!failure("Failed", text).contains("SECRET999"));
            assert_eq!(clean(&clean(text)), clean(text));
        }
        for text in [
            "Provider config invalid: providers[0].apiKey: Required",
            "Invalid provider config at providers[0]: apiKey: Required",
            "Error: Cookie: header too large", "Error: password: can't be blank",
        ] {
            assert_eq!(clean(text), text, "{text}");
            assert!(failure(text, "").contains(text));
            assert_eq!(clean(&clean(text)), text);
        }
        for text in [r#"["SECRET999"] api_key: required"#, "api_key: [required]", "sk-SECRET999 api_key: required", "token: SECRET999, api_key: required"] {
            assert_eq!(clean(text), OMITTED, "{text}");
            assert_eq!(clean(&clean(text)), OMITTED);
        }
    }

    #[test]
    fn r18_nested_commands_redact_without_losing_surrounding_text() {
        for (text, expected) in [
            ("Error: 'zcode --token SECRET999'", "Error: 'zcode --token [redacted]'"),
            ("Command 'zcode --token SECRET999' exited", "Command 'zcode --token [redacted]' exited"),
            ("spawn ['sh', '-c', 'zcode --token SECRET999']", "spawn ['sh', '-c', 'zcode --token [redacted]']"),
            (r#"Command 'zcode --token "SECRET999 EXTRA999"' exited"#, r#"Command 'zcode --token "[redacted]"' exited"#),
            (r#"spawn ["zcode --token SECRET999"]"#, r#"spawn ["zcode --token [redacted]"]"#),
            ("Command 'Authorization Basic dXNlcjpwYXNz' failed", "Command 'Authorization Basic [redacted]' failed"),
            ("Command 'Using api key SECRET999' failed", "Command 'Using api key [redacted]' failed"),
            ("zcode --token 'SECRET999 EXTRA999'", "zcode --token '[redacted]'"),
            (r#"["--token","SECRET999"]"#, r#"["--token","[redacted]"]"#),
            ("API key \"alllower\"", "API key \"[redacted]\""),
            ("password \"alllower\"", "password \"[redacted]\""),
            ("Invalid API key: alllower", "Invalid API key: [redacted]"),
            ("password for user admin is mypass", "password for user admin is [redacted]"),
            ("Using api key mysecretvalue123 for provider zai", "Using api key [redacted] for provider zai"),
            ("Using api key MYSECRET for provider zai", "Using api key [redacted] for provider zai"),
        ] {
            assert_eq!(redact_inline_secrets(text), expected, "{text}");
            assert_eq!(clean(text), expected, "{text}");
            assert_eq!(clean(&clean(text)), clean(text), "{text}");
            assert!(!failure("Failed", text).contains("SECRET999"), "{text}");
        }
    }

    #[test]
    fn r18_phrase_redaction_preserves_benign_prose_and_clause_boundaries() {
        for text in [
            "Error: No API key available",
            "Error: Please set your API key before running",
            "Error: Invalid API key, please check settings.",
            "Error: Invalid API key — check settings",
            "Error: Invalid API key -> check settings",
            "Error: password prompt cancelled",
            "Error: 'Enter password: fail'",
            "Error: password verification failed",
            r#"{"error":"Invalid API key, please check settings\n"}"#,
            "Error: password failed; status is active",
            "Error: password failed, status is active",
            "Error: password failed. status is active",
            "Error: API, key SECRET999",
            "Error: API key; SECRET999",
            "Error: API key. SECRET999",
            "Error: token, abcdef123456SECRET expired",
            "Error: secret; AbcdefGHIJKLmno",
            "Error: Authorization, Basic missing",
            "Error: Authorization Basic, missing",
            "Error: password; USERNAME is active",
            "Error: password for user admin; status is active",
            "Error: API key is —",
            "Error: password is ->",
        ] {
            assert_eq!(redact_inline_secrets(text), text, "{text}");
            assert_eq!(clean(text), text, "{text}");
            assert_eq!(clean(&clean(text)), text, "{text}");
        }
    }

    #[test]
    fn r17_triple_quotes_inside_blocks_preserve_structure() {
        for text in [
            "cookies: [\n  \"\"\"\n  \" ]\n  SECRET999\n  \"\"\"\n]\nok",
            "cookies: [\n  \x27\x27\x27\n  \x27 ]\n  SECRET999\n  \x27\x27\x27\n]\nok",
            "cookies: [\n  \"\"\"a\" ] b\"\"\",\n  \"SECRET999\"\n]\nok",
            "cookies: [\n  r\"\"\"\n  \" ]\n  SECRET999\n  \"\"\"\n]\nok",
            "cookies: [\n  r\x27\x27\x27\n  \x27 ]\n  SECRET999\n  \x27\x27\x27\n]\nok",
            "cookies: [\"\"]\nok", "cookies: [\"\"\"\"\"\"]\nok",
        ] {
            let result = clean(text);
            assert!(!result.contains("SECRET999"), "{text}\n{result}");
            assert!(result.ends_with("ok"), "{text}\n{result}");
            assert!(!failure("Failed", text).contains("SECRET999"));
            assert_eq!(clean(&result), result);
        }
    }

    #[test]
    fn r17_bearer_handles_unicode_whitespace() {
        for text in ["Bearer\u{00a0}SECRET999", "Authorization\u{00a0}Bearer\u{2003}SECRET999", r#"{"h":"Bearer\u{00a0}SECRET999"}"#] {
            assert_eq!(clean(text), OMITTED, "{text}");
            assert!(!failure("Failed", text).contains("SECRET999"));
            assert_eq!(clean(&clean(text)), clean(text));
        }
        let benign = "Bearer\u{00a0}token is missing";
        assert_eq!(clean(benign), benign);
    }

    #[test]
    fn r17_inline_argv_phrases_and_provider_formats() {
        for (text, expected) in [
            (r#"spawn ["zcode","--token","SECRET999"] failed"#, r#"spawn ["zcode","--token","[redacted]"] failed"#),
            ("spawn ['zcode','--password','SECRET999'] failed", "spawn ['zcode','--password','[redacted]'] failed"),
            (r#"args=["zcode","--password","SECRET999"]"#, r#"args=["zcode","--password","[redacted]"]"#),
            (r#"zcode --token "SECRET999 EXTRA999""#, r#"zcode --token "[redacted]""#),
            ("zcode --token 'SECRET999, EXTRA999'", "zcode --token '[redacted]'"),
            (r#"zcode --token "SECRET999 EXTRA999"#, r#"zcode --token "[redacted]"#),
            (r#"Error: unmatched " before --token SECRET999"#, r#"Error: unmatched " before --token [redacted]"#),
            ("zcode --token abc[123]def", "zcode --token [redacted]"),
            (r#"zcode --token \"SECRET999\""#, r#"zcode --token \"[redacted]\""#),
            ("Invalid key 4f3c8e2a1b9d4e7f0a2c5b8d1e4f7a9c.ABCdefGHIjkl1234.", "Invalid key [redacted]."),
            ("JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234", "JWT [redacted]"),
            ("Using api key SECRET999", "Using api key [redacted]"),
            ("Using api key is SECRET999", "Using api key is [redacted]"),
            (r#"API key "SECRET999 EXTRA999" is invalid"#, r#"API key "[redacted]" is invalid"#),
            ("Error: Invalid API key: SECRET999", "Error: Invalid API key: [redacted]"),
            ("Authorization Basic dXNlcjpTRUNSRVQ=", "Authorization Basic [redacted]"),
            ("Proxy-Authorization Digest SECRET999", "Proxy-Authorization Digest [redacted]"),
            ("Error: token abcdef123456SECRET expired", "Error: token [redacted] expired"),
            ("Error: secret AbcdefGHIJKLmno", "Error: secret [redacted]"),
            ("password for user admin is SECRETVAL", "password for user admin is [redacted]"),
            ("password SECRETVAL", "password [redacted]"),
        ] {
            assert_eq!(redact_inline_secrets(text), expected, "{text}");
            let result = clean(text);
            assert!(!result.contains("SECRET999") && !result.contains("EXTRA999") && !result.contains("SECRETVAL"), "{text}\n{result}");
            assert_eq!(clean(&result), result, "{text}");
        }
        for text in [
            "4f3c8e2a1b9d4e7f0a2c5b8d1e4f7a9c.snapshot", "GLM_API_KEY is not set",
            "SyntaxError: Unexpected token 'export'", "Error: token limit exceeded", "Error: token count 128000",
            "Error: token expired", "Error: secret not found", "password for user admin is incorrect",
            "password is too short", "password authentication failed for user \"postgres\"",
            "API key authentication failed", "API key configuration file is missing", "Use API key settings",
            "couldn't load models", "don't retry", "https://api.z.ai/v1/models?page=2",
        ] { assert_eq!(clean(text), text, "{text}"); assert_eq!(clean(&clean(text)), text); }
    }

    #[test]
    fn r17_decoded_inline_values_and_long_escaped_pem() {
        for text in [
            r#"{"url":"https://api.example.com/v1?a=1\u0026key=SECRET9999"}"#,
            r#"{"url":"https://api.example.com/v1\u003fkey=SECRET9999"}"#,
            r#"{"url":"https://api.example.com/v1?a=1\u0026auth=SECRET9999"}"#,
            r#"{"msg":"Invalid key \u0073k-SECRET9999"}"#,
            r#"https://api.example.com/v1?a=1\u0026key=SECRET9999"#,
            r#"{"argv":["\u002d\u002dtoken","SECRET9999"]}"#,
        ] {
            let result = clean(text);
            assert!(!result.contains("SECRET9999"), "{text}\n{result}");
            assert!(!failure("Failed", text).contains("SECRET9999"));
            assert_eq!(clean(&result), result);
        }
        assert_eq!(clean(r#"{"url":"https://api.example.com/v1?a=1\u0026key=SECRET9999"}"#), r#"{"url":"https://api.example.com/v1?a=1&key=[redacted]"}"#);
        let benign = r#"{"url":"https://api.example.com/v1?a=1\u0026b=2"}"#;
        assert_eq!(clean(benign), benign);
        for (header, braced) in [("-----BEGIN ENCRYPTED PRIVATE KEY-----", false), ("-----BEGIN PRIVATE KEY-----", true)] {
            let encoded: String = header.chars().map(|ch| if braced { format!(r"\u{{{:06x}}}", ch as u32) } else { format!(r"\u{:04x}", ch as u32) }).collect();
            assert!(encoded.len() > 128);
            let end = header.replace("BEGIN", "END");
            let text = format!("{encoded}\nMIIE_SECRET999_BODY\n{end}\nok");
            let result = clean(&text);
            assert!(!result.contains("MIIE_SECRET999_BODY"), "{result}");
            assert!(result.ends_with("ok"), "{result}");
            assert_eq!(clean(&result), result);
            let mut cleaner = Cleaner::new();
            let mut scanner = cleaner.begin_overflow();
            for chunk in encoded.as_bytes().chunks(17) { scanner.push_str(std::str::from_utf8(chunk).unwrap()); }
            cleaner.finish_overflow(scanner);
            assert_eq!(cleaner.clean_line("MIIE_SECRET999_BODY"), OMITTED);
            cleaner.clean_line(&end);
            assert_eq!(cleaner.clean_line("ok"), "ok");
        }
    }

    #[test]
    fn r17_long_quote_and_truncated_json_scans_are_linear() {
        let flat = format!(r#"{{"items":[{}"#, r#"{"text":"abcdefghijklmnop"},"#.repeat(3400));
        let nested = format!("{}{}", r#"{"items":["#.repeat(200), "x".repeat(87_000));
        for input in [
            format!("Request to http://localhost:8080{}", "\"".repeat(65536)),
            flat, nested, "http://".repeat(5000), "a@b.com ".repeat(8192), "a@b:1 ".repeat(8192),
        ] {
            let started = std::time::Instant::now();
            let result = clean(&input);
            assert!(started.elapsed() < std::time::Duration::from_secs(5), "{} bytes took {:?}", input.len(), started.elapsed());
            assert_eq!(clean(&result), result);
        }
        for make in [
            (|n| format!("Request to http://localhost:8080{}", "\"".repeat(n))) as fn(usize) -> String,
            |n| format!(r#"{{"items":[{}"#, r#"{"text":"abcdefghijklmnop"},"#.repeat(n / 28)),
            |n| "a@b.com ".repeat(n / 8),
            |n| "a@b:1 ".repeat(n / 6),
        ] {
            let measure = |size| {
                let text = make(size);
                let started = std::time::Instant::now();
                std::hint::black_box(clean(&text));
                started.elapsed()
            };
            let t_1x = measure(8192);
            let t_4x = measure(32768);
            assert!(t_4x <= t_1x.mul_f64(10.0).max(std::time::Duration::from_millis(250)), "{t_1x:?} -> {t_4x:?}");
        }
    }

    #[test]
    fn escaped_userinfo_colons_never_allow_json_container_isolation() {
        for text in [
            r#"user\u003aSECRET999,{"a":1}@proxy:8080"#,
            r#"user\x3aSECRET999,{"a":1}\x40proxy:8080"#,
            r#"user\u{3a}SECRET999,{"a":1}\u{40}proxy:8080"#,
        ] {
            let result = clean(text);
            assert!(!result.contains("SECRET999"), "{text} => {result}");
            assert!(!failure("Provider failed", text).contains("SECRET999"), "{text}");
            assert_eq!(clean(&result), result);
            assert!(json_containers(text).next().is_none(), "{text}");
        }
    }

    #[test]
    fn r16_mixed_and_encoded_schemes_keep_raw_authority_continuity() {
        for separator in [r"://", r":\/\/", r":/\/", r":\//", r":\u002f\u002f", r"\x3a\x2f\x2f", r"\u003A\u{002F}\/"] {
            let text = format!(r#"http{separator}user:SECRET999\/x,{{"a":1}}@proxy:8080"#);
            let result = clean(&text);
            assert!(!result.contains("SECRET999"), "{text} => {result}");
            assert_eq!(clean(&result), result);
        }
        for at in [r"\u0040", r"\x40", r"\u{40}"] {
            let text = format!(r#"user:SECRET999,{{"a":1}}{at}proxy:8080"#);
            assert!(json_containers(&text).next().is_none(), "{text}");
            assert!(!clean(&text).contains("SECRET999"), "{text}");
        }
    }

    #[test]
    fn r16_schemeless_password_schemes_and_placeholder_prefixes_fail_closed() {
        for text in ["user:SECRET999://x@proxy:8080", "proxy=user:SECRET999http://x@proxy:8080", "user:SECRET999://@proxy:8080"] {
            assert_eq!(redact_bare_proxy_credentials(text), if text.starts_with("proxy=") { "proxy=[redacted]@proxy:8080" } else { "[redacted]@proxy:8080" });
            assert!(!clean(text).contains("SECRET999"), "{text}");
        }
        for text in ["user:SECRET999://[redacted]@proxy:8080", "proxy=user:SECRET999http://[redacted]@proxy:8080"] {
            assert!(!verify_plain_line(text), "{text}");
        }
        assert!(verify_plain_line("https://[redacted]@proxy:8080"));
        assert_eq!(clean(r#"{"url":"https://[redacted]@proxy:8080"}"#), r#"{"url":"https://[redacted]@proxy:8080"}"#);
    }

    #[test]
    fn r16_map_entry_exemption_requires_real_balanced_matching_quotes() {
        for text in [r#"a':'SECRET999@proxy:8080"#, r#"user\":\"SECRET999@proxy:8080"#] {
            assert!(!verify_plain_line(text), "{text}");
            assert!(!clean(text).contains("SECRET999"), "{text}");
        }
        for text in [r#"{'host':'alice@proxy:8080'}"#, r#"{"proxy":"[redacted]@proxy:8080"}"#] {
            assert!(verify_plain_line(text), "{text}");
            assert_eq!(clean(text), text);
        }
    }

    #[test]
    fn r16_triple_quoted_scalars_wait_for_three_closing_quotes() {
        for q in ["\"\"\"", "\x27\x27\x27"] {
            let text = format!("token={q}line1\nline2{}mid\nSECRET999{q}\nok", &q[..1]);
            let result = clean(&text);
            assert!(!result.contains("SECRET999") && !result.contains("line2"), "{text} => {result}");
            assert!(result.ends_with("ok"), "{result}");
            assert_eq!(clean(&result), result);
        }
        assert_eq!(clean("token=\"\"\nok"), format!("{OMITTED}\nok"));
    }

    #[test]
    fn r16_quoted_argv_escaped_queries_and_unicode_whitespace_are_sanitized() {
        for flag in ["--token", "--secret", "--auth"] {
            let text = format!(r#"spawn ["zcode", "{flag}", "SECRET999"] failed"#);
            let expected = format!(r#"spawn ["zcode", "{flag}", "[redacted]"] failed"#);
            assert_eq!(clean(&text), expected);
            assert_eq!(clean(&expected), expected);
        }
        let text = r#"{"url":"https:\/\/api.example.com/v1?key=abcde"}"#;
        let expected = r#"{"url":"https://api.example.com/v1?key=[redacted]"}"#;
        assert_eq!(clean(text), expected);
        assert_eq!(clean(expected), expected);
        assert_eq!(clean("token\u{00a0}: SECRET999"), OMITTED);
    }

    #[test]
    fn r16_escaped_pem_dash_arms_before_marker_leaves_the_tail() {
        for dash in [r"\u002d", r"\x2d"] {
            let text = format!("-----BEGIN PRIVATE KEY----{dash}{}\nMIIE_SECRET999_BODY\n-----END PRIVATE KEY-----\nok", "a".repeat(128));
            let result = clean(&text);
            assert!(!result.contains("MIIE_SECRET999_BODY"), "{result}");
            assert!(result.ends_with("ok"), "{result}");
        }
    }

    #[test]
    fn r15_closed_credential_containers_and_multiline_quotes_arm_pem_omission() {
        for text in [
            "{\"private_key\": [\"-----BEGIN PRIVATE KEY-----\"]}\nMIIE_SECRET999_BODY\n-----END PRIVATE KEY-----\nok",
            "{\"private_key\": {\"pem\": \"-----BEGIN PRIVATE KEY-----\"}}\nMIIE_SECRET999_BODY\n-----END PRIVATE KEY-----\nok",
            "token=\"line1\n-----BEGIN PRIVATE KEY-----\"\nMIIE_SECRET999_BODY\n-----END PRIVATE KEY-----\nok",
        ] {
            let result = clean(text);
            assert!(!result.contains("MIIE_SECRET999_BODY"), "{text} => {result}");
            assert!(!failure("Provider failed", text).contains("MIIE_SECRET999_BODY"));
            assert!(result.ends_with("ok"), "{result}");
            assert_eq!(clean(&result), result);
        }
        assert!(clean("cookies: [\n  \"-----BEGIN PRIVATE KEY-----\"\n  \"SECRET_COOKIE_2\"\n]\nok").ends_with("]\nok"));
    }

    #[test]
    fn r15_status_exemption_rejects_quoted_values_and_carriage_returns() {
        for text in ["\"apiKey\": \"SECRET999\" secret: required", "'apiKey': 'SECRET999' secret: required"] {
            assert!(!is_secret_free_status_line(text, text));
            assert_eq!(clean(text), OMITTED);
            assert!(!failure("Provider failed", text).contains("SECRET999"));
            assert_eq!(clean(&clean(text)), OMITTED);
        }
        assert!(!is_secret_free_status_line("secret: required\r", "secret: required\r"));
    }

    #[test]
    fn r15_bearer_prose_requires_only_short_lowercase_remainder_words() {
        for text in ["Error: Bearer token missing from request", "Missing Bearer token"] {
            assert!(!has_bearer_value(text));
            assert_eq!(clean(text), text);
        }
        for text in ["Bearer token is MY_RAW_SECRET_999", "Bearer token is eyJhbGciOiJIUzI1NiJ9", "Bearer token is abc123", "Bearer token is abc_def"] {
            assert!(has_bearer_value(text));
            assert_eq!(clean(text), OMITTED, "{text}");
            assert_eq!(clean(&clean(text)), OMITTED);
        }
    }

    #[test]
    fn r15_escaped_slash_after_a_password_quote_never_ends_authority_early() {
        let text = "\"http://user:SECRET999\"\\/x\\x40proxy:8080";
        let result = clean(text);
        assert!(!result.contains("SECRET999"), "{result}");
        assert!(!redact_url_credentials(text).contains("SECRET999"));
        assert!(!failure("Provider failed", text).contains("SECRET999"));
        assert_eq!(clean(&result), result);
    }

    #[test]
    fn r15_hyphenated_english_prose_is_not_a_structured_credential_name() {
        for text in ["Configure API-key settings", "Use API-key authentication"] {
            assert_eq!(clean(text), text);
        }
        for (text, expected) in [
            ("zcode --api-key sk-LEAK1", "zcode --api-key [redacted]"),
            ("x-goog-api-key LEAK13", "x-goog-api-key [redacted]"),
            ("GLM_API_KEY LEAK22", "GLM_API_KEY [redacted]"),
            ("proxy-authorization LEAK23", "proxy-authorization [redacted]"),
            ("set-cookie LEAK24", "set-cookie [redacted]"),
        ] {
            assert_eq!(clean(text), expected);
            assert_eq!(clean(expected), expected);
        }
    }

    #[test]
    fn r14_raw_authorities_and_bare_proxy_json_fragments_never_split_secrets() {
        for text in [
            r#"http://user:SECRET999\/s,{"a":1}@proxy:8080"#,
            r#"http://user:SECRET999\x2f,{"a":1}@proxy:8080"#,
            r#"http://user:SECRET999\/s,"x"@proxy:8080"#,
            r#"user:SECRET999,{"a":1}@proxy:8080"#,
            r#"user:{"a":"SECRET999"}@proxy:8080"#,
            r#"user:SECRET999=[1]@proxy:8080"#,
            r#"http://ok.test/path/user:SECRET999,{"a":1}@proxy:8080"#,
            r#"http://ok.test/path/user:SECRET999=[redacted]@proxy:8080"#,
            r#"foo/user:SECRET999=[redacted]@proxy:8080"#,
            r#"{"msg":"foo/user:SECRET999=[redacted]@proxy:8080"}"#,
        ] {
            let result = clean(text);
            assert!(!result.contains("SECRET999"), "{text} => {result}");
            assert!(!failure("Provider failed", text).contains("SECRET999"));
            assert_eq!(clean(&result), result);
        }
        for text in [r#"user:SECRET999,{"a":1}@proxy:8080"#, r#"user:{"a":1}@proxy:8080"#, r#"user:SECRET999=[1]@proxy:8080"#] {
            assert!(json_containers(text).next().is_none(), "{text}");
        }
        for text in ["foo/user:SECRET999=[redacted]@proxy:8080", "http://ok.test/path/user:SECRET999=[redacted]@proxy:8080"] {
            assert!(!verify_plain_line(text), "{text}");
        }
        for text in ["[redacted]@p1:8080,[redacted]@p2:8080", "http://[redacted]@proxy:8080"] {
            assert_eq!(clean(text), text);
            assert!(verify_plain_line(text));
        }
    }

    #[test]
    fn r14_escaped_at_variants_and_slashes_cannot_hide_userinfo() {
        for at in [r"\u0040", r"\x40", r"\u{40}", r"\u{0040}", r"\u{000040}"] {
            for slash in ["", r"\/s", r"\x2f"] {
                let text = format!("\"http://user:SECRET999{slash}\"ss{at}proxy:8080\"");
                let result = clean(&text);
                assert!(!result.contains("SECRET999"), "{text} => {result}");
                assert_eq!(clean(&result), result);
                assert!(!verify_plain_line(&format!("http://user:SECRET999{at}proxy:8080")));
            }
        }
    }

    #[test]
    fn r14_pem_markers_survive_blocks_quotes_and_escaped_final_dash() {
        for text in [
            "cookies: [\n \"-----BEGIN PRIVATE KEY-----\"\n \"SECRET999\"\n \"-----END PRIVATE KEY-----\"\n]\nok",
            "private_key: \"prefix\n-----BEGIN PRIVATE KEY-----\nSECRET999\n-----END PRIVATE KEY-----\nMORE_SECRET\"\nok",
            "note=\"-----BEGIN PRIVATE KEY----\\u002d\"\nSECRET999\n-----END PRIVATE KEY-----\nok",
            "-----BEGIN PRIVATE KEY----\\u002d\nSECRET999\n-----END PRIVATE KEY-----\nok",
        ] {
            let result = clean(text);
            assert!(!result.contains("SECRET999") && !result.contains("MORE_SECRET"), "{text} => {result}");
            assert!(result.ends_with("ok"), "{result}");
            assert_eq!(clean(&result), result);
        }
        for text in [
            "note=\"-----BEGIN PRIVATE KEY----- -----END PRIVATE KEY-----\"\nError: done",
            "cookies: [\"-----BEGIN PRIVATE KEY----- -----END PRIVATE KEY-----\"]\nError: done",
        ] { assert!(clean(text).ends_with("Error: done"), "{text}"); }
    }

    #[test]
    fn r14_secret_free_validation_and_bearer_prose_stay_readable() {
        for text in [
            "Error: apiKey: required", "Provider config invalid: apiKey: Required",
            "Error: secret: not found", "Failed: credentials: none configured",
            "Error: Bearer token missing from request", "Missing Bearer token",
            "GLM_API_KEY is not set", "Configure an API-key provider in Settings.",
        ] {
            assert_eq!(clean(text), text, "{text}");
            assert_eq!(failure(text, ""), text, "{text}");
        }
        for text in ["apiKey: sk-1234", "api_key=required", "Error: apiKey: required, token: sk-1234",
            "Bearer sk-live-123", "Bearer token sk-live-123", "Bearer\nsk-live-123", "https://api.z.ai\rBearer\nsk-live-123"] {
            let result = clean(text);
            assert!(!result.contains("sk-1234") && !result.contains("sk-live-123") && !result.contains("=required"), "{text} => {result}");
            assert_eq!(clean(&result), result);
        }
    }

    #[test]
    fn r14_inline_values_queries_flags_and_structured_names_are_redacted() {
        for (text, expected) in [
            ("zcode --api-key sk-LEAK1", "zcode --api-key [redacted]"),
            ("Incorrect API key provided: sk-LEAK2", "Incorrect API key provided: [redacted]"),
            ("https://h/v1?key=LEAK5", "https://h/v1?key=[redacted]"),
            ("https://h/v1#key=LEAK5", "https://h/v1#key=[redacted]"),
            ("x-goog-api-key LEAK13", "x-goog-api-key [redacted]"),
            ("GLM_API_KEY LEAK22", "GLM_API_KEY [redacted]"),
            ("OPENAI_API_KEY LEAK23", "OPENAI_API_KEY [redacted]"),
            ("pass=LEAK9", "pass=[redacted]"), ("auth=LEAK10", "auth=[redacted]"),
            ("key=LEAK5", "key=[redacted]"), ("key=abc12345", "key=[redacted]"),
        ] {
            assert_eq!(clean(text), expected, "{text}");
            assert_eq!(clean(expected), expected);
        }
        for key in ["AIzaABCDEFGHIJ123", "ghp_abcdefgh123", "gho_abcdefgh123", "ghu_abcdefgh123", "ghs_abcdefgh123", "ghr_abcdefgh123", "github_pat_abcdefgh123", "glpat-abcdefgh123", "xoxb-abcdefgh123", "xoxp-abcdefgh123", "xoxo-abcdefgh123", "xoxr-abcdefgh123", "xoxa-abcdefgh123", "xoxs-abcdefgh123", "AKIAABCDEFGHIJKLMNOP"] {
            assert_eq!(clean(&format!("Rejected {key}")), "Rejected [redacted]", "{key}");
        }
        for text in ["https://api.z.ai/v1/models?page=2", "GLM_API_KEY is not set", "key=id", "key=Enter", "auth=oauth", "pass=none", "pass=required", "auth=disabled"] {
            assert_eq!(clean(text), text, "{text}");
        }
    }

    #[test]
    fn r14_cr_and_quote_dense_lines_have_bounded_processing_time() {
        let start = std::time::Instant::now();
        for scheme in [r"http\u003a\u002f\u002f", r"http\x3a\u002f\u002f"] {
            let text = format!("{scheme}user:SECRET999\r@proxy:8080");
            let result = clean(&text);
            assert!(!result.contains("SECRET999"), "{result}");
            assert_eq!(clean(&result), result);
        }
        let text = format!("http://user:SECRET999{}@proxy:8080", "\r".repeat(20000));
        assert_eq!(clean(&text), "http://[redacted]@proxy:8080");
        let dense = format!("Error: {}", "\"".repeat(16000));
        assert_eq!(clean(&dense), dense);
        assert!(start.elapsed() < std::time::Duration::from_secs(5), "{:?}", start.elapsed());
    }

    #[test]
    fn r14_long_error_headlines_show_a_unicode_safe_truncation_marker() {
        let text = "é".repeat(1201);
        assert_eq!(failure(&text, ""), format!("{}…", "é".repeat(1199)));
        assert_eq!(failure(&"x".repeat(1200), ""), "x".repeat(1200));
    }

    #[test]
    fn r13_verifier_inspects_proxy_credentials_after_url_authority_terminators() {
        for text in [
            "http://ok.test/path?x=user:pass@proxy:8080",
            "http://ok.test/path,user:p,q@proxy:8080",
            "http://ok.test/path/user:SECRET@proxy:8080",
        ] { assert!(!verify_plain_line(text), "{text}"); }
        assert!(!verify_plain_line("http://ok.test:8080/path?x=alice@proxy:8080"));
        for (text, expected) in [
            ("http://ok.test/path?user:SECRET@proxy:8080", "http://ok.test/path?[redacted]@proxy:8080"),
            ("http://ok.test/path#user:SECRET@proxy:8080", "http://ok.test/path#[redacted]@proxy:8080"),
            ("http://ok.test/path/user:SECRET@proxy:8080", OMITTED),
            ("http://ok.test/path,user:p,q@proxy:8080", "http://ok.test/path,[redacted]@proxy:8080"),
        ] {
            assert_eq!(clean(text), expected, "{text}");
            assert_eq!(clean(expected), expected);
            assert!(verify_plain_line(expected), "{expected}");
        }
    }

    #[test]
    fn r13_rescanned_python_prefix_keeps_multiline_scalar_private() {
        let text = "token=\\u0062'line1-secret\nline2-secret'\nok";
        assert_eq!(clean(text), format!("{OMITTED}\n{OMITTED}\nok"));
        assert_eq!(clean(&clean(text)), clean(text));
        let result = failure("Provider failed", text);
        assert!(!result.contains("line1-secret") && !result.contains("line2-secret"), "{result}");
    }

    #[test]
    fn r12_bare_proxy_scanner_preserves_password_delimiters_and_prefixes() {
        for (text, expected) in [
            ("proxy user:dG9rZW4=@proxy:8080", "proxy [redacted]@proxy:8080"),
            ("proxy=user:p=ss@proxy:8080", "proxy=[redacted]@proxy:8080"),
            ("proxies=[a,user:SECRETVALUE@proxy:8080]", "proxies=[a,[redacted]@proxy:8080]"),
            ("proxy user:p)ss@proxy:8080", "proxy [redacted]@proxy:8080"),
            ("proxy user:p\"ss@proxy:8080", "proxy [redacted]@proxy:8080"),
            ("user1:pass1@p1:8080,user2:pass2@p2:8080", "[redacted]@p1:8080,[redacted]@p2:8080"),
            ("https://ok.test,user:pass@proxy:8080", "https://ok.test,[redacted]@proxy:8080"),
            ("u+name%20:p@ss@[::1]:8080/path", "[redacted]@[::1]:8080/path"),
        ] {
            assert_eq!(redact_bare_proxy_credentials(text), expected, "{text}");
            assert_eq!(redact_bare_proxy_credentials(expected), expected);
            assert!(!verify_plain_line(text), "{text}");
            let result = clean(text);
            for secret in ["dG9rZW4", "p=ss", "SECRETVALUE", "p)ss", "p\"ss", "pass1", "pass2", "user:pass", "p@ss"] {
                assert!(!result.contains(secret), "{text} => {result}");
            }
            assert_eq!(clean(&result), result, "{text}");
        }
        for delimiter in ['=', ')', '"', '\'', '<', '>', '{', '}', ',', ';', '@'] {
            let text = format!("user:TOK{delimiter}SENTINEL@proxy:8080");
            assert_eq!(redact_bare_proxy_credentials(&text), "[redacted]@proxy:8080", "{text}");
            assert!(!verify_plain_line(&text), "{text}");
            assert!(!clean(&text).contains("SENTINEL"), "{text}");
        }
        assert!(!verify_plain_line("user:secret[redacted]@proxy:8080"));
    }

    #[test]
    fn r12_bare_proxy_verifier_preserves_mail_maps_and_redacted_tokens() {
        for text in ["proxy=[redacted]@proxy:8080", "alice@example.com", "ssh alice@host:2222", "{'host':'alice@proxy:8080'}", "mailto:user@example.com", "email:user@example.com"] {
            assert_eq!(clean(text), text, "{text}");
            assert!(verify_plain_line(text), "{text}");
        }
        for host in ["proxy:1", "127.0.0.1:65535", "[::1]:8080"] {
            for end in ["", " ", "/path", "?q", "#frag", ",", ";", "\"", "'", ">", ")", "]", "}"] {
                let text = format!("user:TOK@{host}{end}");
                assert_eq!(redact_bare_proxy_credentials(&text), format!("[redacted]@{host}{end}"), "{text}");
                assert!(!verify_plain_line(&text), "{text}");
            }
        }
        for text in ["user:p@host:123456", "user:p@host:80abc", "user:p@[not-ip]:8080"] {
            assert_eq!(redact_bare_proxy_credentials(text), text);
        }
    }

    #[test]
    fn r12_bare_bearer_after_open_url_cr_keeps_continuation_private() {
        for padding in [0, 5000, 20000] {
            let text = format!("https://api.z.ai{}\rBearer\nsk-live-secret-999\nok", "x".repeat(padding));
            let result = clean(&text);
            assert!(!result.contains("sk-live-secret-999"), "{result}");
            assert!(result.ends_with("ok"), "{result}");
            assert_eq!(clean(&result), result);
        }
    }

    #[test]
    fn r12_python_string_prefixes_keep_block_and_scalar_quotes_balanced() {
        let text = "cookies: [\n  b'sid=abc]def',\n  b'SENSITIVE_COOKIE_2'\n]\nok";
        let result = clean(text);
        assert!(!result.contains("SENSITIVE_COOKIE_2") && result.ends_with("ok"), "{result}");
        assert_eq!(clean(&result), result);
        for prefix in ["b", "r", "f", "u", "br", "rb", "fr", "rf"] {
            let text = format!("token={prefix}'line1-secret\nline2-secret'\nok");
            let result = clean(&text);
            assert!(!result.contains("line1-secret") && !result.contains("line2-secret"), "{text} => {result}");
            assert!(result.ends_with("ok"), "{result}");
            assert_eq!(clean(&result), result);
        }
        for text in ["auth: can't login\nok", "job's\nok"] { assert_eq!(clean(text), text); }
        let result = clean("cookies: [\n  \"can't]keep\"\n]\nok");
        assert!(result.ends_with("]\nok"), "{result}");
    }

    #[test]
    fn r12_closed_quoted_pem_begin_keeps_body_private_until_end() {
        for text in [
            "{\"private_key\": \"-----BEGIN PRIVATE KEY-----\"}\nMIIE_SECRET_BODY\n-----END PRIVATE KEY-----\nok",
            "api_key=sk-1 note=\"-----BEGIN PRIVATE KEY-----\"\nMIIE_SECRET_BODY\n-----END PRIVATE KEY-----\nok",
            "private_key: \"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\nSTILL_SECRET\"\nok",
        ] {
            let result = clean(text);
            for secret in ["MIIE", "STILL_SECRET", "sk-1"] { assert!(!result.contains(secret), "{text} => {result}"); }
            assert!(result.ends_with("ok"), "{result}");
            assert_eq!(clean(&result), result);
        }
    }

    #[test]
    fn pem_markers_preserve_credential_quotes_and_block_parity() {
        for text in [
            "private_key: \"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\nSTILL_SECRET\"\nok",
            "cookies: [\n  \"-----BEGIN PRIVATE KEY-----\"\n  \"SECRET_COOKIE_2\"\n]\nok",
        ] {
            let result = clean(text);
            for secret in ["MIIE", "STILL_SECRET", "SECRET_COOKIE_2"] {
                assert!(!result.contains(secret), "{text} => {result}");
                assert!(!failure("Provider failed", text).contains(secret));
            }
            assert!(result.ends_with("ok"), "{result}");
            assert_eq!(clean(&result), result);
        }
    }

    #[test]
    fn nested_payload_newlines_reset_bare_word_context() {
        for text in [
            "Error: body=\"hello\ntoken:\n  sk-1\"",
            "Error: body=\"hello\\ntoken:\n  sk-1\"",
            r#"Error: body="hello\ntoken:\n  sk-1""#,
        ] {
            let result = clean(text);
            assert!(!result.contains("sk-1"), "{text} => {result}");
            assert_eq!(clean(&result), result);
        }
    }

    #[test]
    fn schemeless_proxy_assignment_keeps_the_assignment_prefix() {
        let text = "proxy=user:SECRETVALUE@proxy:8080";
        let expected = "proxy=[redacted]@proxy:8080";
        assert_eq!(clean(text), expected);
        assert_eq!(clean(expected), expected);
        assert!(!verify_plain_line(text));
        assert!(verify_plain_line(expected));
    }

    #[test]
    fn r11_c1_introducers_and_cr_cancel_every_escape_state() {
        for initial in [Esc::None, Esc::Start, Esc::Intermediate, Esc::Csi, Esc::Osc, Esc::OscEsc, Esc::StringTerm, Esc::StringEsc] {
            for (ch, expected) in [('\u{90}', Esc::StringTerm), ('\u{98}', Esc::StringTerm), ('\u{9e}', Esc::StringTerm), ('\u{9f}', Esc::StringTerm), ('\u{9b}', Esc::Csi), ('\u{9d}', Esc::Osc)] {
                let mut state = initial;
                step_escape(&mut state, ch, |_| panic!("introducer must not be emitted"));
                assert_eq!(std::mem::discriminant(&state), std::mem::discriminant(&expected));
            }
            let mut state = initial;
            let mut emitted = String::new();
            step_escape(&mut state, '\r', |ch| emitted.push(ch));
            assert_eq!(emitted, "\r");
            assert!(matches!(state, Esc::None));
        }
        for prefix in ["\u{1b}]unfinished\r", "\u{90}unfinished\r", "\u{1b}]unfinished\u{9b}0m", "\u{90}unfinished\u{9d}title\u{7}"] {
            let result = clean(&format!("{prefix}cookies: [\n  \"sid=hunter2\"\n]\nError: done"));
            assert!(!result.contains("hunter2"), "{result}");
            assert!(result.ends_with("Error: done"), "{result}");
            assert_eq!(clean(&result), result);
        }
    }

    #[test]
    fn r11_unkeyed_private_pem_blocks_omit_until_end_and_resume_markers() {
        for kind in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK"] {
            let text = format!("-----BEGIN {kind}-----\nSECRETVALUE\n-----END {kind}-----\nok");
            let result = clean(&text);
            assert_eq!(result, format!("{OMITTED}\n{OMITTED}\n{OMITTED}\nok"), "{kind}");
            assert_eq!(clean(&result), result);
            assert!(!failure("Provider failed", &text).contains("SECRETVALUE"));
        }
        let result = clean("-----begin private key-----\nSECRETVALUE\n-----end private key-----, token:\n  hunter2\nok");
        assert!(!result.contains("SECRETVALUE") && !result.contains("hunter2"), "{result}");
        assert!(result.ends_with("ok"), "{result}");
        assert_eq!(clean("-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----"), "-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----");
    }

    #[test]
    fn r11_double_quoted_payloads_keep_outer_quote_parity() {
        for text in [
            "Error: body=\"{\\\"cookies\\\": [\n  \"sid=hunter2\"\n]}\"\nError: done",
            "Error: body=\"api_key:\n  hunter2\"",
            "{\"note\": \"bad api_key: invalid\", \"cookies\": [\n  \"sid=hunter2\"\n]}\nError: done",
        ] {
            let result = clean(text);
            assert!(!result.contains("hunter2"), "{text} => {result}");
            assert_eq!(clean(&result), result);
        }
        assert_eq!(clean("\"hello\nworld\""), "\"hello\nworld\"");
    }

    #[test]
    fn r11_escaped_bare_openers_are_rescanned_as_structure() {
        for text in [
            "cookies: \\u005b\n  \"sid=hunter2\"\n]\nError: done",
            "private_key: \\u0022-----BEGIN PRIVATE KEY-----\nMIIE_HUNTER2\n-----END PRIVATE KEY-----\\u0022",
            "export\\u0020GITHUB_TOKEN\\u003d{\n  \"v\": \"hunter2\"\n}\nError: done",
        ] {
            let result = clean(text);
            assert!(!result.contains("hunter2") && !result.contains("MIIE_HUNTER2"), "{text} => {result}");
            assert_eq!(clean(&result), result);
        }
        assert!(has_credential_key_assignment(r"export\u0020GITHUB_TOKEN\u003d"));
    }

    #[test]
    fn r11_password_alias_and_schemeless_proxy_credentials_are_sanitized() {
        for text in ["pwd=hunter2", "db.pwd: hunter2"] { assert_eq!(clean(text), OMITTED); }
        for (text, expected) in [
            ("proxy user:SECRETVALUE@proxy:8080", "proxy [redacted]@proxy:8080"),
            ("'user:SECRETVALUE@127.0.0.1:80/path'", "'[redacted]@127.0.0.1:80/path'"),
            ("proxy user:SECRETVALUE@[::1]:8080", "proxy [redacted]@[::1]:8080"),
            ("proxy user:a@SECRETVALUE@proxy:8080", "proxy [redacted]@proxy:8080"),
        ] {
            assert_eq!(clean(text), expected, "{text}");
            assert_eq!(clean(expected), expected);
            assert!(!verify_plain_line(text), "{text}");
        }
        for text in ["mailto:user@example.com", "email:user@example.com", "npm ERR! 404 @napi-rs/keyring@1.2.0", "http://[redacted]@proxy:8080", "proxy [redacted]@proxy:8080"] {
            assert_eq!(clean(text), text);
            assert!(verify_plain_line(text));
        }
    }

    #[test]
    fn r11_surviving_cr_is_normalized_after_url_redaction() {
        let text = "Connecting to https://api.z.ai\rError: ECONNRESET\n";
        assert_eq!(clean(text), "Connecting to https://api.z.ai\nError: ECONNRESET");
        assert!(failure("Provider failed", text).starts_with("Provider failed\nError: ECONNRESET"));
        assert!(!clean("https://api.z.ai\rtoken: sk-1").contains("sk-1"));
    }

    #[test]
    fn token_domain_exclusions_require_segment_or_camel_case_boundaries() {
        for text in [
            "ADMIN_TOKEN=sk-1", "BACKEND_TOKEN=sk-1", "GOOGLE_ADMIN_TOKEN=sk-1",
            "adminToken: \"sk-1\"", "backendToken: \"sk-1\"",
        ] {
            assert_eq!(clean(text), OMITTED, "{text}");
            assert_eq!(clean(&clean(text)), OMITTED);
        }
        for text in [
            "max_token=8192", "MAX_TOKEN=8192", "API_MAX_TOKEN=8192", "nextPageToken: abc",
            "userNextPageToken: abc", "cancellationToken: x", "nextpage_token=abc",
        ] { assert_eq!(clean(text), text, "{text}"); }
    }

    #[test]
    fn single_quoted_escaped_assignments_preserve_credential_blocks() {
        for text in [
            "Error: body='cookies\\u003a [\n  \"sid=SENSITIVE\"\n]'\nError: done",
            "Error: body='api_key\\u003d{\n  \"v\": \"sk-1\"\n}'\nError: done",
            "Error: body='export GITHUB_TOKEN\\u003d{\n  \"v\": \"sk-1\"\n}'\nError: done",
        ] {
            let result = clean(text);
            assert!(!result.contains("SENSITIVE") && !result.contains("sk-1"), "{text} => {result}");
            assert!(result.ends_with("Error: done"), "{result}");
            assert_eq!(clean(&result), result);
            let result = failure("Provider failed", text);
            assert!(!result.contains("SENSITIVE") && !result.contains("sk-1"), "{result}");
        }
    }

    #[test]
    fn r10_prose_and_non_secret_token_keys_stay_readable() {
        for text in [
            "Error: authorization failed", "FATAL: password authentication failed for user \"me\"",
            "Error: unable to open cookie database: database is locked", "Error: API key not found. Set ZCODE_API_KEY.",
            "Error: password must not be empty", "Error: cookie support is disabled",
            "Error: Authorization header is missing", "Note: cookie consent banner skipped",
            "Error: no credentials: run login first", "Failed to refresh token:\nError: 401 Unauthorized from api.z.ai",
            "Enter password:\nError: keyring unavailable", "Request failed: max_token=8192",
            "Error: invalid nextPageToken: abc", "SyntaxError: Unexpected token '}' in JSON at position 0",
            "Error: max_tokens: 4096", "Error: could not read secret store: permission denied",
            "Design token missing", "Error: cookie jar load failed: [object\nError: real cause",
            "Error: EISDIR: illegal operation on a directory, lstat 'C:'",
            "{'url':'https://example.com','email':'user@example.com'}", "Error: 'Enter password: fail'",
        ] { assert_eq!(clean(text), text, "{text}"); }
        for key in ["max_token", "nextPageToken", "page_token", "continuationToken", "cancellationToken", "totalTokens", "prompt_tokens", "not a password", "Error: api_key"] {
            assert!(!is_credential_key(key), "{key}");
        }
        for prefix in ["max", "min", "input", "output", "prompt", "completion", "context", "total", "cached", "reasoning", "thinking", "page", "nextpage", "prevpage", "previouspage", "continuation", "cursor", "sync", "cancel", "cancellation", "design", "eof", "syntax", "unexpected", "invalid", "parse", "lex", "next", "prev", "last", "first", "start", "end", "current"] {
            assert!(!is_credential_key(&format!("sdk_{prefix}_token")), "{prefix}");
        }
        for key in ["access_token", "refresh_token", "auth_token", "id_token", "session_token", "bearer_token", "GITHUB_TOKEN", "githubToken", "NPM_TOKEN", "x-api-token", "webhookSecret", "app.secret", "api_key.max_token", "access_token.page_token", "cookie_nextPageToken"] {
            assert!(is_credential_key(key), "{key}");
        }
    }

    #[test]
    fn r10_single_quoted_payloads_and_escaped_assignments_are_sensitive() {
        for text in [
            r#"Error: payload='{"token":"sk-live-secret-999"}'"#, r#"body: '{"githubToken":"ghp_live_secret_999"}'"#,
            "env: 'GITHUB_TOKEN=ghp_live_secret_999'", "Error: invalid config 'token=sk-live-secret-999'",
            "Error: body='{\"cookies\": [\n  \"sid=SENSITIVE_SECRET\"\n]}'",
            r#""token"\: "sk-1""#, r#""secret"\="sk-1""#, r#"token \: sk-1"#,
            "\"cookies\"\\u003a [\n  \"sid=sk-1\"\n]", "\"api_key\"\\u003a\n  \"sk-1\"",
            "api_key \\u003a {\n  \"value\": \"sk-1\"\n}", "\"cookies\"\\: [\n  \"sid=sk-1\"\n]",
            "token\\u003d{\n  \"value\": \"sk-1\"\n}", "export GITHUB_TOKEN=ghp_live_secret_999",
            "password: sk-1", "Error: password: sk-1", "foo=1, secret: sk-1",
        ] {
            let result = clean(text);
            for secret in ["sk-live-secret-999", "ghp_live_secret_999", "SENSITIVE_SECRET", "sk-1"] {
                assert!(!result.contains(secret), "{text} => {result}");
            }
            assert_eq!(clean(&result), result, "{text}");
        }
        for escape in [r"\:", r"\=", r"\u003a", r"\u003d", r"\x3a", r"\x3d"] {
            for key in ["\"token\"", "token "] {
                let text = format!("{key}{escape} \"sk-1\"");
                assert!(!clean(&text).contains("sk-1"), "{text}");
            }
        }
    }

    #[test]
    fn r10_multiline_scalar_and_mismatched_blocks_recover_after_secrets() {
        for (text, secrets) in [
            ("private_key: \"-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\"\nError: done", vec!["BEGIN", "MIIE", "END PRIVATE"]),
            ("token=\"line1-secret\nline2-secret\"\nError: done", vec!["line1-secret", "line2-secret"]),
            ("private_key:\n  \"-----BEGIN...\nMIIE...\n-----END-----\"\nError: done", vec!["BEGIN", "MIIE", "END-----"]),
            ("token=\"line1\nend\", \"api_key\":\n  \"sk-2\"\nError: done", vec!["line1", "sk-2"]),
            ("api_key: {\n  a: [1, 2}\n}\nError: real cause", vec![]),
            ("api_key: {\n  a: [1, 2}\n  secret: \"S3CR3T\"\n}\nError: real cause", vec!["S3CR3T"]),
            ("{\n  \"cookies\": [\n    }\n    \"SECRET\"\n  ]\n}\nError: done", vec!["SECRET"]),
        ] {
            let result = clean(text);
            for secret in secrets { assert!(!result.contains(secret), "{text} => {result}"); }
            assert!(result.ends_with("Error: done") || result.ends_with("Error: real cause"), "{result}");
            assert_eq!(clean(&result), result);
        }
    }

    #[test]
    fn r10_can_sub_cancel_control_strings_before_credential_blocks() {
        for sequence in ["\u{1b}]unfinished", "\u{1b}Punfinished", "\u{90}unfinished", "\u{9d}unfinished"] {
            for cancel in ['\u{18}', '\u{1a}'] {
                let text = format!("{sequence}{cancel}cookies: [\n  \"sid=secret\"\n]\nError: done");
                let result = clean(&text);
                assert!(!result.contains("sid=secret"), "{result}");
                assert!(result.ends_with("Error: done"), "{result}");
                assert_eq!(clean(&result), result);
            }
        }
    }

    #[test]
    fn r10_bare_cr_splits_progress_but_keeps_url_authorities_whole() {
        assert_eq!(clean("first\rsecond"), "first\nsecond");
        assert_eq!(clean("first\r\nsecond"), "first\nsecond");
        assert_eq!(clean("http://user:sk-secret\r@proxy:8080"), "http://[redacted]@proxy:8080");
        for text in ["Bearer\rsk-secret", "Bearer\rsk-secret\rError: done"] {
            let result = clean(text);
            assert!(!result.contains("sk-secret"), "{result}");
            assert_eq!(clean(&result), result);
        }
    }


    #[test]
    fn startup_warnings_never_hide_the_final_exception() {
        let noise = "Python DeprecationWarning: startup compatibility warning\n".repeat(400);
        let result = failure("Provider exited before responding", &format!("{noise}Traceback (most recent call last):\n  File runtime.py, line 42\nValueError: invalid cwd \\\\?\\C:\\project\n"));
        assert!(result
            .lines()
            .nth(1)
            .unwrap()
            .starts_with("ValueError: invalid cwd"));
        assert!(result.ends_with("ValueError: invalid cwd \\\\?\\C:\\project"));
        assert!(result.chars().count() < 3500);
    }

    #[test]
    fn node_error_properties_and_structured_provider_error_are_preserved() {
        let result = failure("ACP session/new: Internal error", "\u{1b}[31mError: EISDIR: illegal operation on a directory, lstat 'C:'\u{1b}[0m\n at realpathSync (node:fs:2706)\n code: 'EISDIR',\n syscall: 'lstat',\n path: 'C:'\n");
        assert!(result.starts_with("ACP session/new: Internal error\nError: EISDIR:"));
        assert!(result.contains("path: 'C:'"));
        assert!(!result.contains('\u{1b}'));
        assert_eq!(
            failure("An explicit provider error", ""),
            "An explicit provider error"
        );
    }

    #[test]
    fn bounded_tail_is_unicode_safe_and_warnings_are_not_promoted() {
        assert_eq!(tail("😀éabc", 3), "…abc");
        let result = failure(
            "Provider failed",
            "DeprecationWarning: ErrorClass is deprecated",
        );
        assert!(result.starts_with("Provider failed\nDetails:"));
    }

    #[test]
    fn diagnostic_credentials_are_not_sent_to_the_ui() {
        let result = failure("Authentication failed", "Authorization: Bearer fixture-secret\napi_key=fixture-key\nrefresh_token: fixture-refresh\nError: credentials expired");
        assert!(!result.contains("fixture-"));
        assert!(result.contains("credentials expired"));
    }

    #[test]
    fn url_userinfo_is_redacted_and_the_host_kept() {
        assert_eq!(
            redact_url_credentials("Error: connect ECONNREFUSED via http://user:pass@proxy:8080"),
            "Error: connect ECONNREFUSED via http://[redacted]@proxy:8080"
        );
        // The last `@` ends the userinfo, so an `@` inside the password leaks nothing.
        assert_eq!(
            redact_url_credentials("socks5://u:p@ss@127.0.0.1:1080 refused"),
            "socks5://[redacted]@127.0.0.1:1080 refused"
        );
        assert_eq!(
            redact_url_credentials("https://alice:s3cret@registry.example.com/pkg?x=1#y"),
            "https://[redacted]@registry.example.com/pkg?x=1#y"
        );
        assert_eq!(
            redact_url_credentials("token-only https://ghp_fixture@github.com/org/repo.git"),
            "token-only https://[redacted]@github.com/org/repo.git"
        );
        // Every URL on a line, in quotes, parentheses or angle brackets.
        assert_eq!(
            redact_url_credentials(
                "HTTPS_PROXY='http://a:b@one:1' (https://c:d@two:2) <ftp://e@three> \"wss://f:g@four\""
            ),
            "HTTPS_PROXY='http://[redacted]@one:1' (https://[redacted]@two:2) <ftp://[redacted]@three> \"wss://[redacted]@four\""
        );
        assert_eq!(
            redact_url_credentials("first http://x:y@h1/a then http://h2/b@c and http://z:w@h3"),
            "first http://[redacted]@h1/a then http://h2/b@c and http://[redacted]@h3"
        );
        assert_eq!(
            redact_url_credentials("ipv6 http://user:pass@[::1]:8080/path"),
            "ipv6 http://[redacted]@[::1]:8080/path"
        );
    }

    #[test]
    fn urls_and_addresses_without_userinfo_are_unchanged() {
        for line in [
            "See https://github.com/zai-org/ZCode for setup",
            "Cannot find module https://registry.npmjs.org/@napi-rs/keyring",
            "Contact user@example.com for access",
            "npm ERR! 404 @napi-rs/keyring@1.2.0 is not in this registry",
            "https://example.com/path?email=user@example.com#me@frag",
            "trailing scheme with nothing after ://",
            "",
            "plain text, no URL",
            r#"{"url":"https://example.com","email":"user@example.com"}"#,
            "<https://example.com> user@example.com",
        ] {
            assert_eq!(redact_url_credentials(line), line);
        }
    }

    #[test]
    fn delimiter_chars_inside_a_password_never_leak_it() {
        for (line, expected) in [
            ("Error: tunnel via http://alice:p)ss@proxy:8080 failed", "Error: tunnel via http://[redacted]@proxy:8080 failed"),
            ("Error: connect ECONNREFUSED via http://alice:p'ass@proxy:8080", "Error: connect ECONNREFUSED via http://[redacted]@proxy:8080"),
            ("(http://alice:p)ss@proxy:8080)", "(http://[redacted]@proxy:8080)"),
            ("\"http://alice:p'ass)1@proxy:8080\"", "\"http://[redacted]@proxy:8080\""),
            ("http://user:p]ss@[::1]:8080/path", "http://[redacted]@[::1]:8080/path"),
            ("http://alice:p>ss@proxy:8080", "http://[redacted]@proxy:8080"),
            ("http://alice:p\"ss@proxy:8080", "http://[redacted]@proxy:8080"),
        ] {
            assert_eq!(redact_url_credentials(line), expected, "{line}");
        }
    }

    #[test]
    fn a_wrapper_char_inside_a_wrapped_password_never_leaks_it() {
        for (line, expected) in [
            ("'http://alice:p'ass@proxy:8080'", "'http://[redacted]@proxy:8080'"),
            ("'http://alice:p'ss@proxy:8080'", "'http://[redacted]@proxy:8080'"),
            ("'http://alice:p')ss@proxy:8080'", "'http://[redacted]@proxy:8080'"),
            (
                r#"{"proxy":"http://alice:p\"ss@proxy:8080","email":"user@example.com"}"#,
                r#"{"proxy":"http://[redacted]@proxy:8080","email":"user@example.com"}"#,
            ),
            ("proxy: 'http://alice:p\\'ss@proxy:8080'", "proxy: 'http://[redacted]@proxy:8080'"),
            ("<http://alice:p>ss@proxy:8080>", "<http://[redacted]@proxy:8080>"),
            // An escaped backslash does not escape the quote after it.
            ("'http://alice:p\\\\'ss@proxy:8080'", "'http://[redacted]@proxy:8080'"),
        ] {
            assert_eq!(redact_url_credentials(line), expected, "{line}");
        }
        // A wrapper that really closes still ends the authority before a following address.
        for line in [
            "('https://example.com','user@example.com')",
            r#"{"url":"https://example.com","email":"user@example.com"}"#,
            "<https://example.com> user@example.com",
        ] {
            assert_eq!(redact_url_credentials(line), line);
        }
        let result = failure("Provider failed", "'http://alice:p'ass@proxy:8080'");
        assert!(!result.contains("p'ass"), "{result}");
        assert!(!result.contains("alice"), "{result}");
        assert!(result.contains("'http://[redacted]@proxy:8080'"), "{result}");
    }

    #[test]
    fn an_esc_inside_any_sequence_starts_a_new_one() {
        assert_eq!(clean("\u{1b}\u{1b}[31mError"), "Error");
        assert_eq!(clean("\u{1b}]0;t\u{1b}\u{1b}[31mError"), "Error");
        assert_eq!(clean("\u{1b}]0;t\u{1b}Pignored\u{1b}\\Error"), "Error");
        assert_eq!(clean("\u{1b}]0;t\u{1b}(BError"), "Error");
    }

    #[test]
    fn escape_sequences_cannot_hide_a_credential_line() {
        for text in [
            "\u{1b}]8;;\u{07}api_key=sk-secret",
            "\u{1b}7\nBearer super-secret",
            "\u{1b}[200~api_key=sk-secret",
            "\u{1b}]8;;https://example.com\u{1b}\\api_key=sk-secret",
            "\u{1b}(Bapi_key=sk-secret",
        ] {
            let result = clean(text);
            assert!(!result.contains("secret"), "{text:?} -> {result:?}");
            assert!(result.contains("[Credential detail omitted]"), "{text:?} -> {result:?}");
            assert!(!result.contains('\u{1b}'), "{text:?} -> {result:?}");
        }
        // Text after a sequence's final byte, and the line breaks, survive.
        assert_eq!(clean("\u{1b}[1;31mError\u{1b}[0m: x\n\u{1b}7next"), "Error: x\nnext");
        assert_eq!(clean("\u{1b}]0;title\nkept"), "\nkept");
    }

    #[test]
    fn camel_case_and_hyphenated_token_fields_are_redacted() {
        for line in [
            "\"accessToken\": \"tok-1\"",
            "\"refreshToken\": \"tok-2\"",
            "\"clientSecret\": \"sec-3\"",
            "\"authToken\": \"tok-4\"",
            "Set-Cookie: session=abc",
            "Authorization: Bearer\ttab-secret",
        ] {
            assert_eq!(clean(line), "[Credential detail omitted]", "{line}");
        }
    }

    #[test]
    fn failure_redacts_url_credentials_in_errors_and_stderr() {
        let result = failure(
            "Request via http://user:hunter2@proxy:8080 failed",
            "Error: tunnel to socks5://u:p@ss@127.0.0.1:1080 failed\nsee https://registry.npmjs.org/@napi-rs/keyring",
        );
        assert!(!result.contains("hunter2"), "{result}");
        assert!(!result.contains("u:p@ss"), "{result}");
        assert!(result.contains("http://[redacted]@proxy:8080"), "{result}");
        assert!(result.contains("socks5://[redacted]@127.0.0.1:1080"), "{result}");
        assert!(result.contains("https://registry.npmjs.org/@napi-rs/keyring"), "{result}");
    }
}

#[cfg(test)]
mod redaction_oracle {
    use super::*;

    #[test]
    fn overflowed_string_tail_cannot_close_a_credential_block() {
        for (marker, head) in [("cookies: [", r#"  "xxxx..."#), ("cookies:", r#"  ["xxxx..."#)] {
            let mut cleaner = Cleaner::new();
            assert_eq!(cleaner.clean_line(marker), OMITTED);
            let mut line = cleaner.begin_overflow();
            line.push_str(head);
            line.push_str(r#"xxxx]","#);
            cleaner.finish_overflow(line);
            assert_eq!(cleaner.clean_line(r#"  "SENSITIVE_SENTINEL_725""#), OMITTED);
            assert_eq!(cleaner.clean_line("  ]"), "  ]");
            assert_eq!(cleaner.clean_line("Error: done"), "Error: done");
        }
    }

    #[test]
    fn overflowed_escapes_are_contiguous_across_chunks() {
        let mut cleaner = Cleaner::new();
        let mut line = cleaner.begin_overflow();
        for chunk in ["cookies: [\"quote: ", "\\", "\" ]\", \"ok\"]"] { line.push_str(chunk); }
        cleaner.finish_overflow(line);
        assert_eq!(cleaner.clean_line("Error: done"), "Error: done");
    }

    #[test]
    fn escaped_assignment_delimiters_start_credential_blocks() {
        for input in [
            "api_key\\:{\n  \"value\": \"sk-1\"\n}\nError: done",
            "api_key\\u003a {\n  \"value\": \"sk-1\"\n}\nError: done",
            "token\\u003a {\n  \"value\": \"sk-1\"\n}\nError: done",
        ] {
            let cleaned = clean(input);
            assert!(!cleaned.contains("sk-1"), "{input:?} -> {cleaned:?}");
            assert!(cleaned.ends_with("Error: done"), "{cleaned}");
            assert_eq!(clean(&cleaned), cleaned);
        }
        assert_eq!(clean(r#"\"token\": "X""#), OMITTED);
        assert_eq!(clean(&clean(r#"\"token\": "X""#)), OMITTED);
        assert!(is_credential_key("token\\"));
        assert!(is_credential_key("\\secret\\"));
        for delimiter in [':', '=', '{', '[', '}', ']', ',', ';', '"', '\'', ' ', '\t'] {
            let mut scanner = OverflowLine::new(OmitNext::None);
            scanner.token = "token\\".into();
            scanner.in_bare_token = true;
            scanner.bare_esc_remaining = u8::MAX;
            assert!(!scanner.bare_char(delimiter), "{delimiter:?}");
            assert_eq!(scanner.bare_esc_remaining, 0);
        }
    }

    #[test]
    fn adjacent_block_quotes_update_the_outside_quote_context() {
        let input = "cookies: [a\"x\"'line1\n  ]\n  SENSITIVE'\n]\nError: done";
        let cleaned = clean(input);
        assert!(!cleaned.contains("SENSITIVE"), "{cleaned}");
        assert!(!failure(input, input).contains("SENSITIVE"));
        assert!(cleaned.ends_with("Error: done"));
        assert_eq!(clean(&cleaned), cleaned);
    }

    #[test]
    fn r9_key_classification_and_scanner_memory_are_bounded() {
        for key in ["token", "secret", "secrets", "credentials", "GITHUB_TOKEN", "NPM_TOKEN", "X-Token", "app.secret", "githubToken", "webhookSecret", r"\u0074oken"] { assert!(is_credential_key(key), "{key}"); }
        for key in ["", "max_tokens", "prompt_tokens", "totalTokens", "store", "limit", "count"] { assert!(!is_credential_key(key), "{key}"); }
        let mut cleaner = Cleaner::new();
        let mut line = cleaner.begin_overflow();
        line.push_str("cookies: ");
        line.push_str(&"[".repeat(MAX_BLOCK_DEPTH + 1));
        assert_eq!(line.cred_stack.len(), MAX_BLOCK_DEPTH);
        assert!(line.block_overflowed);
        line.push_str(&"]".repeat(MAX_BLOCK_DEPTH + 1));
        cleaner.finish_overflow(line);
        assert_eq!(cleaner.clean_line("SECRET_OVERFLOW"), OMITTED);
        let mut line = OverflowLine::new(OmitNext::None);
        line.push_str(&"x".repeat(100_000));
        assert!(line.token.len() <= 256);
        assert!(line.tail.len() <= 128);
    }

    #[test]
    fn r9_generic_credential_assignments_preserve_prose_and_token_counts() {
        for input in ["GITHUB_TOKEN=ghp_X", r#"{"token":"X"}"#, r#"{"\u0074oken":"X"}"#, "secret: X", "private_key=X", r#"{"githubToken":"ghp_X"}"#, "webhookSecret=X", "app.secret=X", "api-secret=X", "passphrase=X"] {
            assert_eq!(clean(input), OMITTED, "{input}");
            assert_eq!(clean(&clean(input)), clean(input));
        }
        for input in ["SyntaxError: Unexpected token '}' in JSON at position 0", "Error: max_tokens: 4096", "Error: could not read secret store: permission denied", "Design token missing"] {
            assert_eq!(clean(input), input);
        }
        let input = "Error: cookie jar load failed: [object\nError: real cause";
        assert!(clean(input).ends_with("Error: real cause"));
    }

    #[test]
    fn r9_block_close_resumes_marker_scanning_on_the_same_line() {
        for suffix in [
            "  ], \"api_key\":\n  \"sk-live-secret-999\"\n}",
            "  ], \"Authorization\": \"Bearer\n  sk-live-secret-999\"\n}",
            "  ], \"cookies\": [\n  \"sid=secret2\"\n]\n}",
        ] {
            let input = format!("{{\n  \"cookies\": [\n    \"sid=secret1\"\n{suffix}");
            let cleaned = clean(&input);
            assert!(!cleaned.contains("secret1") && !cleaned.contains("secret2") && !cleaned.contains("sk-live-secret-999"), "{cleaned}");
            assert_eq!(clean(&cleaned), cleaned);
        }
    }

    #[test]
    fn r9_escaped_bare_keys_and_backslash_continuations() {
        for input in [
            "\\u0061pi_key: {\n  \"value\": \"sk-live-secret-999\"\n}",
            "\\u{61}pi_key: {\n  \"value\": \"sk-live-secret-999\"\n}",
            "Authorization: Bearer \\\n  sk-live-secret-999",
            "Authorization: Bearer \\\\\n  sk-live-secret-999",
            "api_key: \\\n  sk-live-secret-999",
            "Bearer \\\n  sk-live-secret-999",
        ] {
            let cleaned = clean(input);
            assert!(!cleaned.contains("sk-live-secret-999"), "{input:?} -> {cleaned:?}");
            assert_eq!(clean(&cleaned), cleaned);
        }
        assert_eq!(clean("Error: missing Bearer\nError: real cause"), "Error: missing Bearer\nError: real cause");
    }

    #[test]
    fn r9_block_quotes_carry_across_lines_without_treating_contractions_as_quotes() {
        let input = "cookies: [\n  \"line1\n  ]\n  SENSITIVE_SENTINEL\"\n]\nError: done";
        let cleaned = clean(input);
        assert!(!cleaned.contains("SENSITIVE_SENTINEL"), "{cleaned}");
        assert!(cleaned.ends_with("Error: done"));
        assert_eq!(clean(&cleaned), cleaned);
        assert!(clean("cookies: [\n  can't\n]\nError: done").ends_with("Error: done"));
    }

    #[test]
    fn r8_obfuscated_authorities_never_split_around_json() {
        for input in [
            r#"http:\u002f\u002falice:sk-live-secret-999,{"a":1}@proxy:8080"#,
            r#"http:/\/alice:sk-live-secret-999,{"a":1}@proxy:8080"#,
            r#"http:\u{2f}\u{2f}alice:sk-live-secret-999,{"a":1}@proxy:8080"#,
            r#"http\x3a\x2f\x2falice:sk-live-secret-999,{"a":1}@proxy:8080"#,
            r#"http:\u001b[31m//\u001b[0malice:sk-live-secret-999,{"a":1}@proxy:8080"#,
            r#"'http:\u002f\u002falice:sk-live-secret-999,{"a":1}@proxy:8080'"#,
        ] {
            let cleaned = clean(input);
            assert!(!cleaned.contains("sk-live-secret-999"), "{input} -> {cleaned}");
            assert!(!failure(input, input).contains("sk-live-secret-999"));
            assert_eq!(clean(&cleaned), cleaned, "{input}");
        }
    }

    #[test]
    fn r8_credential_blocks_preserve_raw_quote_polarity_and_bracket_types() {
        for input in [
            "{\n  \"cookies\": [\n    \"\\\"}\",\n    \"SECRET_COOKIE_VALUE\"\n  ]\n}",
            "{\n  \"cookies\": [\n    \"\\\"]\",\n    \"SECRET_COOKIE_VALUE\"\n  ]\n}",
            "{\n  \"cookies\": [\n    }\n    \"SECRET_COOKIE_VALUE\"\n  ]\n}",
        ] {
            let cleaned = clean(input);
            assert!(!cleaned.contains("SECRET_COOKIE_VALUE"), "{cleaned}");
            assert!(!failure(input, input).contains("SECRET_COOKIE_VALUE"));
            assert!(cleaned.ends_with("  ]\n}"), "{cleaned}");
            assert_eq!(clean(&cleaned), cleaned);
        }
    }

    #[test]
    fn r8_marker_scanning_starts_at_byte_zero_and_handles_bearer_suffixes() {
        for input in [
            "{\"note\": \"bad api_key: invalid\", \"cookies\": [\n  \"sid=sk-live-secret-999\"\n]}",
            "{\"note\": \"api_key: missing\", \"api_key\": {\n  \"value\": \"sk-live-secret-999\"\n}}",
            "Authorization:\tBearer\n  sk-live-secret-999",
            "Authorization:Bearer\n  sk-live-secret-999",
            "Authorization: \"Bearer\n  sk-live-secret-999\"",
            "api_key:\n  ]sk-live-secret-999",
        ] {
            let cleaned = clean(input);
            assert!(!cleaned.contains("sk-live-secret-999"), "{input:?} -> {cleaned:?}");
            assert!(!failure(input, input).contains("sk-live-secret-999"));
            assert_eq!(clean(&cleaned), cleaned);
        }
    }

    #[test]
    fn architect_inline_credential_object_hides_remaining_values_only() {
        let input = "{\n  \"cookies\": {\"name\": \"sid\",\n    \"value\": \"sk-secret\"\n  }\n}";
        let cleaned = clean(input);
        assert!(!cleaned.contains("sk-secret"), "{cleaned}");
        assert!(!cleaned.contains("\"value\""), "{cleaned}");
        assert!(cleaned.ends_with("  }\n}"), "{cleaned}");
        assert_eq!(clean(&cleaned), cleaned);
        let sibling = "{\"api_key\": \"sk-secret\",\n \"error\": \"ECONNREFUSED\"}";
        let cleaned = clean(sibling);
        assert!(!cleaned.contains("sk-secret"));
        assert!(cleaned.contains("\"error\": \"ECONNREFUSED\""), "{cleaned}");
        assert_eq!(clean(&cleaned), cleaned);
    }

    #[test]
    fn architect_es6_code_point_escapes_are_checked_without_losing_invalid_text() {
        for input in [
            r#"{"\u{61}pi_key":"sk-secret"}"#,
            r#"{"msg":"\u{1b}[31mBearer\u{1b}[0m sk-secret"}"#,
        ] {
            assert_eq!(clean(input), OMITTED, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
        for input in [r#"'http://alice:secret\u{40}proxy:8080'"#, r#"'http:\u{2f}\u{2f}alice:secret@proxy:8080'"#] {
            let cleaned = clean(input);
            assert!(!cleaned.contains("secret"), "{cleaned}");
            assert_eq!(clean(&cleaned), cleaned, "{input}");
        }
        for (input, expected) in [
            (r"\u{61}\u{1F600}\u{10ffff}", "a😀\u{10ffff}"),
            (r"\u{D800}\u{110000}", "��"),
            (r"\u{}\u{1234567}\u{xyz}\u{61", r"\u{}\u{1234567}\u{xyz}\u{61"),
        ] {
            assert_eq!(decode_common_escapes(input), expected, "{input}");
        }
    }

    #[test]
    fn round7_escape_decoder_is_total_and_preserves_unknown_sequences() {
        for (input, expected) in [
            (r"C:\project\q\u00", r"C:\project\q\u00"),
            (r"\uD83D\uDE00", "😀"),
            (r"\uD83D\u0042earer", "�Bearer"),
            (r"\uDE00rest", "�rest"),
            (r"\x41\u0042\q\u00", r"AB\q\u00"),
            (r#"\\\/\"\'\n\r\t\b\f"#, "\\/\"'\n\r\t\u{8}\u{c}"),
            ("trailing\\", "trailing\\"),
        ] {
            assert_eq!(decode_common_escapes(input), expected, "{input}");
        }
        for byte in 0u32..=255 {
            assert_eq!(decode_common_escapes(&format!(r"\x{byte:02x}")), char::from_u32(byte).unwrap().to_string());
            assert_eq!(decode_common_escapes(&format!(r"\u{byte:04x}")), char::from_u32(byte).unwrap().to_string());
        }
        assert_eq!(canonical_for_check(r"\\u0042earer\\x20secret"), "Bearer secret");
        assert_eq!(canonical_for_check(r"api\u001b[31m_key"), "api_key");
        assert_eq!(canonical_for_check(r"Bearer\rsecret"), "Bearer\rsecret");
    }

    #[test]
    fn round7_markers_survive_invalid_json_and_layered_escapes() {
        for input in [
            r#"{"url":"https://api.z.ai","\u0061pi_key":"sk-live-secret-999","email":"user@example.com"}"#,
            r#"{"url":"https://api.z.ai","auth":"\u0042earer\u0020sk-live-secret-999","email":"user@example.com"}"#,
            r#"{"url":"https://api.z.ai","headers":{"\u0041uthorization":"\u0042earer\tsk-live-secret-999"},"email":"a@b.com"}"#,
            r#"Error: http://proxy:8080:{"\u0061pi_key":"sk-live-secret-999"}"#,
            r#"ERROR {"msg":"\u0042earer sk-live-secret-999\u00"#,
            r#"ERROR {"msg":"\u0061pi_key=sk-live-secret-999\u00"#,
            r#"ERROR {"msg":"\u0042earer sk-live-secret-999\uD83D"#,
            r#"ERROR {"msg":"don\'t leak \u0042earer sk-live-secret-999"}"#,
            r#"ERROR {"msg":"\\u0042earer sk-live-secret-999"}"#,
            r#"{"msg":"\u0042earer\nsk-live-secret-999"}"#,
            r#"{"msg":"\u0042earer\rsk-live-secret-999"}"#,
        ] {
            assert_eq!(clean(input), OMITTED, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
    }

    #[test]
    fn round7_continuations_cover_blank_lines_bearer_and_blocks() {
        for input in [
            "{\n  \"api_key\":\n\n  \"sk-secret\"\n}",
            "api_key:\n\n  sk-live-secret-999",
            "{\n  \"cookies\": [\n    \"sid=secret-value-999\"\n  ]\n}",
            "{\n  \"cookies\":\n  [\n    \"sid=secret-value-999\"\n  ]\n}",
            "Authorization:\n  Bearer\n  sk-live-secret-999",
            "Bearer\n\n  sk-live-secret-999",
            "cookies: [{\n  \"sid\": \"secret-value-999\"\n}]\nError: ECONNREFUSED",
            "cookies: [\n  \"secret-value-999\"]\nError: ECONNREFUSED",
        ] {
            let cleaned = clean(input);
            assert!(!cleaned.contains("sk-secret") && !cleaned.contains("sk-live-secret-999") && !cleaned.contains("secret-value-999"), "{input:?} -> {cleaned:?}");
            assert_eq!(clean(&cleaned), cleaned, "{input}");
            if input.ends_with("  ]\n}") { assert!(cleaned.ends_with("  ]\n}"), "{cleaned}"); }
            if input.ends_with("ECONNREFUSED") { assert!(cleaned.ends_with("Error: ECONNREFUSED"), "{cleaned}"); }
        }
        let input = "{\"api_key\": \"sk-secret\",\n \"error\": \"ECONNREFUSED\"}";
        let cleaned = clean(input);
        assert!(!cleaned.contains("sk-secret"));
        assert!(cleaned.contains("ECONNREFUSED"), "{cleaned}");
        assert_eq!(clean(&cleaned), cleaned);
    }

    #[test]
    fn round7_decoded_url_whitespace_and_obfuscated_schemes() {
        for input in [
            r#"{"proxy":"http://user:sk-\nsecret@proxy"}"#,
            r#"{"proxy":"http://user:sk-\tsecret@proxy"}"#,
            r#"{"proxy":"http://user:sk-\r\nsecret@proxy"}"#,
        ] {
            assert_eq!(clean(input), r#"{"proxy":"http://[redacted]@proxy"}"#, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
        for input in [
            r#"ERROR {"proxy":"http:\u002f\u002falice:hunter2@proxy:8080\u00"#,
            r#"'http:\u002f\u002falice:hunter2@proxy:8080'"#,
            r#"'http\u003a\u002f\u002falice:hunter2@proxy:8080'"#,
            r#"{"proxy":"http:\\u002f\\u002falice:hunter2@proxy:8080"}"#,
        ] {
            let cleaned = clean(input);
            assert!(!cleaned.contains("hunter2"), "{input} -> {cleaned}");
            assert!(!failure(input, input).contains("hunter2"));
            assert_eq!(clean(&cleaned), cleaned, "{input}");
        }
    }

    #[test]
    fn round7_c1_control_strings_cannot_hide_markers() {
        for input in [
            "api\u{90}0;p\u{9c}_key=sk-live-secret-999",
            "Bea\u{9f}payload\u{9c}rer sk-live-secret-999",
            r#"{"msg":"api\u00900;p\u009c_key=sk-live-secret-999"}"#,
            r#"{"msg":"\x1b[31mapi_key=sk-live-secret-999"}"#,
        ] {
            assert_eq!(clean(input), OMITTED, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
        assert_eq!(clean("\u{90}SECRET_DCS_PAYLOAD\u{9c}Error: x"), "Error: x");
        for prefix in ["", "\u{1b}", "\u{1b}(", "\u{1b}[", "\u{1b}]payload\u{1b}", "\u{1b}Ppayload\u{1b}"] {
            for intro in ['\u{90}', '\u{98}', '\u{9e}', '\u{9f}'] {
                assert_eq!(strip_escapes(&format!("{prefix}{intro}PAYLOAD\u{9c}Error")), "Error");
            }
            assert_eq!(strip_escapes(&format!("{prefix}\u{9b}31mError")), "Error");
            assert_eq!(strip_escapes(&format!("{prefix}\u{9d}title\u{7}Error")), "Error");
        }
    }

    #[test]
    fn escaped_diagnostics_json_fragments_stay_inside_url_credentials() {
        for (input, expected) in [
            (r#"'http://alice:[{"a":1}]@host'"#, "'http://[redacted]@host'"),
            (r#""http://alice:[{"a":1}]@host""#, "\"http://[redacted]@host\""),
            (r#"http:\/\/alice:[{"a":1}]@host"#, r"http:\/\/[redacted]@host"),
        ] {
            assert_eq!(clean(input), expected, "{input}");
            assert_eq!(redact_url_credentials(input), expected, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
    }

    #[test]
    fn escaped_diagnostics_json_container_punctuation_and_ansi() {
        for (input, expected) in [
            (r#"Error:{"proxy":"http:\/\/alice:secret@proxy:8080"}"#, r#"Error:{"proxy":"http://[redacted]@proxy:8080"}"#),
            (r#"data={"proxy":"http://alice:hunter2\u0040proxy:8080"}"#, r#"data={"proxy":"http://[redacted]@proxy:8080"}"#),
            (r#"Error:({"proxy":"http:\/\/alice:hunter2@proxy:8080"})"#, r#"Error:({"proxy":"http://[redacted]@proxy:8080"})"#),
            (r#"{"proxy":"\u001b[31mhttp://alice:secret@proxy:8080\u001b[0m"}"#, r#"{"proxy":"http://[redacted]@proxy:8080"}"#),
        ] {
            assert_eq!(clean(input), expected, "{input}");
            assert_eq!(redact_url_credentials(input), expected, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
    }

    #[test]
    fn escaped_diagnostics_json_credentials_and_split_continuations() {
        for input in [
            r#"prefix={"\u0061pi_key":"sk-secret"}"#,
            r#"Error:{"\u0061pi_key":"sk-live-secret-999"}"#,
            r#"payload={"msg":"\u0042earer sk-live-secret-999"}"#,
            r#"{"msg":"\u001b[31mapi\u001b[0m_key=sk-live-secret-999"}"#,
            r#"{"msg":"Bearer\u001b[0m sk-live-secret-999"}"#,
            r#"{"msg":"Bearer\u009b0m sk-live-secret-999"}"#,
        ] {
            assert_eq!(clean(input), OMITTED, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
        for input in [
            "{\n  \"\\u0061pi_key\": \"sk-live-secret-999\"\n}",
            "{\n  \"\\u0061pi_key\":\n  \"sk-live-secret-999\"\n}",
        ] {
            let cleaned = clean(input);
            assert!(!cleaned.contains("sk-live-secret-999"), "{input} -> {cleaned}");
            assert!(cleaned.ends_with("\n}"), "{cleaned}");
            assert_eq!(clean(&cleaned), cleaned, "{input}");
        }
        assert_eq!(clean("{\n  \"\\u0061pi_key\":\n}\nkept"), format!("{{\n{OMITTED}\n}}\nkept"));
    }

    #[test]
    fn escaped_diagnostics_standalone_and_truncated_json_literals() {
        for input in [
            "{\n  \"proxy\": \"http:\\/\\/alice:hunter2@proxy:8080\"\n}",
            r#"ERROR {"proxy":"http:\/\/alice:hunter2@proxy:8080", "more":"trunc"#,
            r#"ERROR {"proxy":"http:\/\/alice:hunter2@proxy:8080"#,
            r#"ERROR {"proxy":"http:\/\/alice:hunter2@proxy:8080\"#,
            r"'http:\/\/alice:hunter2@proxy:8080'",
            r"http:\/\/alice:hunter2@proxy:8080",
            r"http://alice:hunter2\u0040proxy:8080",
        ] {
            let cleaned = clean(input);
            assert!(!cleaned.contains("hunter2"), "{input} -> {cleaned}");
            assert!(!failure(input, input).contains("hunter2"), "{input}");
            assert_eq!(clean(&cleaned), cleaned, "{input}");
        }
        let ambiguous = r#"  "url": "https:\/\/example.com","email":"mail\u0040example.com""#;
        assert_eq!(clean(ambiguous), OMITTED);
        assert_eq!(clean(&clean(ambiguous)), clean(ambiguous));
        assert!(!verify_plain_line(r"http://alice:hunter2\u0040proxy:8080"));
        assert!(!verify_plain_line(r"http:\/\/alice:hunter2\u0040proxy:8080"));
    }

    #[test]
    fn escaped_diagnostics_wrapped_password_quotes_and_email_tails() {
        for (input, expected) in [
            ("'http://alice','hunter2@proxy'", "'http://[redacted]@proxy'"),
            ("'http://alice','hunter2@proxy.internal'", "'http://[redacted]@proxy.internal'"),
            ("('http://alice','hunter2@proxy')", "('http://[redacted]@proxy')"),
            ("\"http://alice:p\"ss@proxy:8080\"", "\"http://[redacted]@proxy:8080\""),
            ("\"http://alice:p\",ss@proxy:8080\"", "\"http://[redacted]@proxy:8080\""),
            ("'http://alice:p\"ss@proxy:8080'", "'http://[redacted]@proxy:8080'"),
        ] {
            assert!(!verify_plain_line(input), "{input}");
            assert_eq!(redact_url_credentials(input), expected, "{input}");
            assert_eq!(clean(input), expected, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
    }

    #[test]
    fn review_portless_passwords_are_not_email_tail_items() {
        for (input, expected) in [
            ("'http://tok','secret:pass@proxy'", "'http://[redacted]@proxy'"),
            ("'http://tok','p!$&@proxy'", "'http://[redacted]@proxy'"),
        ] {
            assert!(!verify_plain_line(input), "{input}");
            assert_eq!(redact_url_credentials(input), expected, "{input}");
            assert_eq!(clean(input), expected, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
    }

    #[test]
    fn review_wrapper_closers_must_match_enclosing_containers() {
        for input in [
            "'http://tok'),],'mail@example.com'",
            "'http://tok'),'mail@example.com'",
            "('http://tok'],email:'mail@example.com')",
            "('http://tok',123,],'mail@example.com')",
        ] {
            assert!(!verify_plain_line(input), "{input}");
            let expected = if input.starts_with('(') { "('http://[redacted]@example.com')" } else { "'http://[redacted]@example.com'" };
            assert_eq!(redact_url_credentials(input), expected, "{input}");
            assert_eq!(clean(input), expected, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
    }

    #[test]
    fn review_clean_checks_unchanged_decoded_json_literals() {
        for (input, redacted) in [
            (r#"{"\u0061pi_key":"sk-secret"}"#, r#"{"\u0061pi_key":"[redacted]"}"#),
            (r#"{"msg":"\u0042earer sk-secret"}"#, r#"{"msg":"Bearer [redacted]"}"#),
            (r#"ERROR {"items":[{"\u0070assword":"sk-secret"}]} trailing"#, r#"ERROR {"items":[{"\u0070assword":"[redacted]"}]} trailing"#),
            (r#"["\u0042earer\tsk-secret"]"#, r#"["Bearer\t[redacted]"]"#),
        ] {
            assert_eq!(clean(input), OMITTED, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
            assert_eq!(redact_url_credentials(input), redacted, "{input}");
        }
    }

    #[test]
    fn verifier_rejects_unredacted_or_repeated_authority_at() {
        for input in [
            "http://alice:secret@proxy:8080",
            "http://[redacted]@extra@proxy:8080",
            "'http://tok','en@proxy:8080'",
            "'http://tok',(ss@proxy:8080'",
            "'http://host:80','mail@example.com'",
            r"'http://host\','mail@example.com'",
        ] {
            assert!(!verify_plain_line(input), "{input}");
        }
        for input in [
            "http://[redacted]@proxy:8080",
            "https://registry.npmjs.org/@napi-rs/keyring",
            "('https://host.example',123,'mail@example.com')",
            "{'url':'https://example.com','email':'user@example.com'}",
        ] {
            assert!(verify_plain_line(input), "{input}");
        }
    }

    #[test]
    fn clean_is_idempotent_for_redacted_benign_and_omitted_lines() {
        for input in [
            "http://user:secret@proxy:8080",
            "http://[redacted]@extra@proxy:8080",
            r#"ERROR {"proxy":"http://TOK@\u0061uthorization.example"}"#,
            r#"ERROR {"proxy":"\u0042earer hidden http://TOK@host"}"#,
            "plain diagnostic",
            "api_key=secret",
            "[Credential detail omitted]",
            "Error: failure\nAuthorization: Bearer secret\nhttps://example.com",
        ] {
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
    }

    #[test]
    fn delimiter_regressions_and_json_splicing() {
        for (input, expected) in [
            ("'http://alice:p',(ss@proxy:8080'", "'http://[redacted]@proxy:8080'"),
            ("'http://tok',(ss@proxy:8080'", "'http://[redacted]@proxy:8080'"),
            ("'http://tok','en@proxy:8080'", "'http://[redacted]@proxy:8080'"),
            ("http://a:b@h1,http://c:d@h2", "http://[redacted]@h1,http://[redacted]@h2"),
            ("http://a:b@h1.http://c:d@h2", "http://[redacted]@h1.http://[redacted]@h2"),
            ("http://[redacted]@extra@proxy:8080", "http://[redacted]@proxy:8080"),
            (r#"ERROR {"proxy":"http://alice:p\"ss@proxy:8080","email":"user@example.com"}"#,
             r#"ERROR {"proxy":"http://[redacted]@proxy:8080","email":"user@example.com"}"#),
            (r#"ERROR { "proxy" : "http:\/\/alice:p\u0040proxy:8080", "email":"user@example.com" } trailing"#,
             r#"ERROR { "proxy" : "http://[redacted]@proxy:8080", "email":"user@example.com" } trailing"#),
            (r#"http://alice:[{"a":1}]@host"#, "http://[redacted]@host"),
        ] {
            assert_eq!(redact_url_credentials(input), expected, "{input}");
            assert_eq!(clean(&clean(input)), clean(input), "{input}");
        }
    }

    #[test]
    fn golden_benign_readability() {
        for input in [
            "('https://host.example',123,'mail@example.com')",
            "{'url':'https://example.com','email':'user@example.com'}",
            r#"ERROR {"url":"https://example.com","email":"user@example.com"}"#,
            r#"ERROR { "z": ["https:\/\/example.com", "mail\u0040example.com"], "a": 1 } trailing"#,
            "can't reach https://registry.npmjs.org/@napi-rs/keyring",
            r#""https:\/\/example.com""#,
            r#""mail\u0040example.com""#,
            "('https://[::1]','mail@example.com')",
            "(['https://host.example'],email:'mail@example.com')",
            "['https://host.example'];email:'first.last_1+tag@host.example'",
            "{'url':'https://host.example','email':'mail@example.com'}",
            "[Credential detail omitted]",
            "http://[redacted]@proxy:8080",
        ] {
            assert_eq!(clean(input), input, "{input}");
            assert_eq!(clean(&clean(input)), input, "{input}");
        }
    }

    #[test]
    fn cartesian_userinfo_never_survives_clean_or_failure() {
        let mut cases = 0;
        for scheme in ["http", "https", "socks5", "custom+v1"] {
            for delimiter in ["!$&'()*+,;=", "',(", "','", "@", "\\\"", "\\\\"] {
                for wrapper in 0..10 {
                    cases += 1;
                    let sentinel = format!("TOK{cases:04}");
                    let secret = format!("{sentinel}{delimiter}{sentinel}");
                    let url = format!("{scheme}://{secret}@proxy:8080");
                    let input = match wrapper {
                        0 => url.clone(),
                        1 => format!("'{url}'"),
                        2 => format!("\"{url}\""),
                        3 => format!("<{url}>"),
                        4 => format!("({url})"),
                        5 => format!("ERROR {{\"proxy\":{},\"email\":\"mail@example.com\"}}", serde_json::to_string(&url).unwrap()),
                        6 => format!("('{url}',123,'mail@example.com')"),
                        7 => format!("{url},https://{secret}@second:8080"),
                        8 => format!("{url}.https://{secret}@second:8080"),
                        _ => format!("ERROR [{{\"proxy\":{}}},\"mail@example.com\"] trailing", serde_json::to_string(&url).unwrap()),
                    };
                    let encoded = sentinel.bytes().map(|b| format!("%{b:02X}")).collect::<String>();
                    let escaped = sentinel.bytes().map(|b| format!("\\u{b:04x}")).collect::<String>();
                    for (fixture, needle) in [
                        (input.clone(), sentinel.clone()),
                        (input.replace(&sentinel, &encoded), encoded),
                        (input.replace(&sentinel, &escaped), escaped),
                    ] {
                        let cleaned = clean(&fixture);
                        for output in [&cleaned, &failure(&fixture, &fixture)] {
                            assert!(!output.contains(&needle), "case {cases}: {fixture:?} -> {output:?}");
                            assert!(!output.contains(&sentinel), "case {cases}: {output:?}");
                        }
                        assert_eq!(clean(&cleaned), cleaned, "case {cases}: {fixture:?}");
                    }
                }
            }
        }
        assert_eq!(cases, 240);
    }
}
