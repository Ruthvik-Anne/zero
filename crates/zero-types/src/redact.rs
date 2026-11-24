//! Redaction pipeline (FND-06, OBS-05).
//!
//! Every sink runs values through the same engine. Registered literal secrets
//! always win, then known credential patterns. The engine records which rule
//! fired so audit can say "a secret was removed" without saying which value.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    RegisteredLiteral,
    OpenAiKey,
    OpenCodeKey,
    GithubToken,
    AwsAccessKey,
    GenericBearer,
    GenericAssignment,
    PrivateKeyBlock,
}

impl Rule {
    pub fn label(self) -> &'static str {
        match self {
            Rule::RegisteredLiteral => "registered",
            Rule::OpenAiKey => "openai_key",
            Rule::OpenCodeKey => "opencode_key",
            Rule::GithubToken => "github_token",
            Rule::AwsAccessKey => "aws_access_key",
            Rule::GenericBearer => "bearer",
            Rule::GenericAssignment => "assignment",
            Rule::PrivateKeyBlock => "private_key",
        }
    }
}

/// Matches a maximal token starting with `prefix` and continuing with allowed
/// characters. Used instead of regex to keep the dependency footprint small.
#[derive(Debug, Clone, Copy)]
struct PrefixRule {
    prefix: &'static str,
    rule: Rule,
    min_tail: usize,
}

const PREFIX_RULES: &[PrefixRule] = &[
    PrefixRule { prefix: "oc_sk_", rule: Rule::OpenCodeKey, min_tail: 12 },
    PrefixRule { prefix: "sk-", rule: Rule::OpenAiKey, min_tail: 20 },
    PrefixRule { prefix: "ghp_", rule: Rule::GithubToken, min_tail: 20 },
    PrefixRule { prefix: "gho_", rule: Rule::GithubToken, min_tail: 20 },
    PrefixRule { prefix: "AKIA", rule: Rule::AwsAccessKey, min_tail: 12 },
];

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

#[derive(Debug, Default, Clone)]
pub struct RedactionEngine {
    literals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redaction {
    pub text: String,
    pub rules: Vec<String>,
}

impl RedactionEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an exact secret (for example a fake key from a fixture).
    pub fn register(&mut self, secret: impl Into<String>) {
        let secret = secret.into();
        if secret.len() >= 4 && !self.literals.iter().any(|s| s == &secret) {
            self.literals.push(secret);
        }
    }

    pub fn registered(&self) -> &[String] {
        &self.literals
    }

    pub fn redact(&self, input: &str) -> Redaction {
        let mut fired: Vec<String> = Vec::new();
        let mut out = input.to_string();

        // 1. Registered literals, longest first so overlapping values are fully
        //    removed (a short prefix must not leave the tail of a longer secret).
        let mut literals = self.literals.clone();
        literals.sort_by_key(|s| std::cmp::Reverse(s.len()));
        for secret in &literals {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), &format!("[REDACTED:{}]", Rule::RegisteredLiteral.label()));
                push_once(&mut fired, Rule::RegisteredLiteral.label());
            }
        }

        // 2. Known prefixes.
        for rule in PREFIX_RULES {
            let mut result = String::with_capacity(out.len());
            let bytes = out.as_bytes();
            let mut i = 0;
            let mut replaced = false;
            while i < bytes.len() {
                if out[i..].starts_with(rule.prefix)
                    && (i == 0 || !is_token_char(bytes[i - 1]))
                {
                    let mut j = i + rule.prefix.len();
                    while j < bytes.len() && is_token_char(bytes[j]) {
                        j += 1;
                    }
                    let tail = j - (i + rule.prefix.len());
                    if tail >= rule.min_tail {
                        result.push_str(&format!("[REDACTED:{}]", rule.rule.label()));
                        i = j;
                        replaced = true;
                        continue;
                    }
                }
                let ch = out[i..].chars().next().expect("in bounds");
                result.push(ch);
                i += ch.len_utf8();
            }
            out = result;
            if replaced {
                push_once(&mut fired, rule.rule.label());
            }
        }

        // 3. Bearer and password-style assignments.
        out = redact_assignments(&out, &mut fired);
        // 4. Private key blocks.
        if let (Some(start), Some(end)) = (out.find("-----BEGIN"), out.find("PRIVATE KEY-----")) {
            if end > start {
                if let Some(stop) = out[end..].find("-----END") {
                    let stop = end + stop + "-----END".len();
                    let tail_end = out[stop..].find('\n').map(|n| stop + n).unwrap_or(out.len());
                    out.replace_range(start..tail_end, &format!("[REDACTED:{}]", Rule::PrivateKeyBlock.label()));
                    push_once(&mut fired, Rule::PrivateKeyBlock.label());
                }
            }
        }

        Redaction { text: out, rules: fired }
    }
}

fn push_once(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

fn redact_assignments(input: &str, fired: &mut Vec<String>) -> String {
    // Handles `Bearer <token>`, `api_key=...`, `token: ...`, `password = '...'`
    // without a regex engine. Only values of 8+ non-space characters are touched.
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    let mut checked_bearer = false;
    while let Some(pos) = rest.find(|c: char| c.is_ascii_alphabetic()) {
        out.push_str(&rest[..pos]);
        let word_start = pos;
        let mut word_end = word_start;
        while word_end < rest.len() && (rest.as_bytes()[word_end].is_ascii_alphanumeric() || rest.as_bytes()[word_end] == b'_') {
            word_end += 1;
        }
        let word = &rest[word_start..word_end];
        let lower = word.to_ascii_lowercase();
        if is_secret_key(&lower) {
            let after = &rest[word_end..];
            let (sep_len, value_start) = separator_prefix(after);
            if sep_len > 0 {
                let mut value_end = value_start;
                let vb = after.as_bytes();
                while value_end < vb.len()
                    && !vb[value_end].is_ascii_whitespace()
                    && vb[value_end] != b','
                    && vb[value_end] != b';'
                {
                    value_end += 1;
                }
                let raw = &after[value_start..value_end];
                let value = raw.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                if value.len() >= 8 {
                    out.push_str(word);
                    out.push_str(&after[..value_start]);
                    out.push_str(&format!("[REDACTED:{}]", Rule::GenericAssignment.label()));
                    push_once(fired, Rule::GenericAssignment.label());
                    rest = &after[value_end..];
                    continue;
                }
            }
        }
        if lower == "bearer" && !checked_bearer {
            let after = &rest[word_end..];
            let mut ws = 0;
            while ws < after.len() && after.as_bytes()[ws] == b' ' {
                ws += 1;
            }
            let mut end = ws;
            while end < after.len() && is_token_char(after.as_bytes()[end]) {
                end += 1;
            }
            if end.saturating_sub(ws) >= 12 {
                out.push_str(word);
                out.push(' ');
                out.push_str(&format!("[REDACTED:{}]", Rule::GenericBearer.label()));
                push_once(fired, Rule::GenericBearer.label());
                rest = &after[end..];
                checked_bearer = true;
                continue;
            }
        }
        out.push_str(word);
        rest = &rest[word_end..];
    }
    out.push_str(rest);
    out
}

fn is_secret_key(word: &str) -> bool {
    matches!(
        word,
        "api_key" | "apikey" | "api-key" | "token" | "password" | "passwd" | "secret" | "client_secret" | "auth"
    )
}

/// Returns (separator length, offset of the value) when `after` begins with
/// `=` or `:` (optionally spaced, optionally quoted).
fn separator_prefix(after: &str) -> (usize, usize) {
    let b = after.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i] == b' ' {
        i += 1;
    }
    if i >= b.len() || (b[i] != b'=' && b[i] != b':') {
        return (0, 0);
    }
    i += 1;
    while i < b.len() && b[i] == b' ' {
        i += 1;
    }
    if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
        i += 1;
    }
    (i, i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_literal_never_survives() {
        let seeded = "sk-test-SEEDED-FAKE-SECRET-0123456789";
        let mut e = RedactionEngine::new();
        e.register(seeded);
        let r = e.redact(&format!("prefix {seeded} suffix"));
        assert!(!r.text.contains(seeded));
        assert!(r.text.contains("[REDACTED:registered]"));
        assert_eq!(r.rules, vec!["registered".to_string()]);
    }

    #[test]
    fn overlapping_literals_are_fully_removed() {
        let mut e = RedactionEngine::new();
        e.register("abcdef123456");
        e.register("abcdef");
        let r = e.redact("x abcdef123456 y");
        assert!(!r.text.contains("abcdef"));
        assert!(!r.text.contains("123456"));
    }

    #[test]
    fn known_prefixes_are_redacted() {
        let e = RedactionEngine::new();
        for (input, rule) in [
            ("oc_sk_abcdefghijklmno123", "opencode_key"),
            ("sk-abcdefghijklmnopqrstuvwx", "openai_key"),
            ("ghp_abcdefghijklmnopqrstuvwxyz", "github_token"),
            ("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
        ] {
            let r = e.redact(input);
            assert!(!r.text.contains(input), "{input} survived: {}", r.text);
            assert!(r.rules.contains(&rule.to_string()), "{input} -> {:?}", r.rules);
        }
    }

    #[test]
    fn assignments_and_bearer_tokens_are_redacted() {
        let e = RedactionEngine::new();
        let cases = [
            ("api_key=supersecretvalue123", "assignment"),
            ("token: abcdefghijklmnop", "assignment"),
            ("password = \"hunter2hunter2\"", "assignment"),
            ("Authorization: Bearer abcdefghijklmnopqrst", "bearer"),
        ];
        for (input, rule) in cases {
            let r = e.redact(input);
            assert!(!r.text.contains("supersecretvalue123"));
            assert!(!r.text.contains("abcdefghijklmnop"));
            assert!(!r.text.contains("hunter2hunter2"), "{}", r.text);
            assert!(r.rules.contains(&rule.to_string()), "{input} -> {:?}", r.rules);
        }
    }

    #[test]
    fn ordinary_text_is_untouched() {
        let e = RedactionEngine::new();
        let text = "The token bucket refilled; task=done, sk-short has only 4 bytes.";
        let r = e.redact(text);
        assert_eq!(r.text, text);
        assert!(r.rules.is_empty());
    }

    #[test]
    fn private_key_block_is_removed() {
        let e = RedactionEngine::new();
        let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
        let r = e.redact(&format!("before\n{key}\nafter"));
        assert!(!r.text.contains("MIIEpAIBAAKCAQEA"));
        assert!(r.rules.contains(&"private_key".to_string()));
    }
}
