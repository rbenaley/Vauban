//! Fail-closed parser and evaluator for `ldaps_mapping.conf`.
//!
//! Two planes in one file:
//! - `resolve` -- how `vauban-auth` collects directory keys (LDAP I/O);
//! - `static` / `match` -- how `vauban-web` maps those keys to existing
//!   User Group names.
//!
//! `{name}` is a **capture** against keys the directory already returned.
//! It is never interpolated into a bind DN or a search filter. The only
//! blessed bind substitution is [`crate::ldap_dn::substitute_bind_dn`];
//! `{username}` is illegal in this file.
//!
//! A compiled [`MappingFile`] is never sent on the wire (one parser, no
//! version skew). Callers ship raw file bytes or the compiled
//! [`ResolvePlan`] extracted by [`MappingFile::resolve_plan`].

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Hard cap on the mapping file. Oversized input refuses parse (boot).
pub const MAX_MAPPING_FILE_BYTES: usize = 128 * 1024;

/// Maximum number of distinct `resolve` lines (union, not first-hit).
pub const MAX_RESOLVE_LINES: usize = 3;

/// Maximum captured `{name}` length (trimmed).
const MAX_CAPTURE_LEN: usize = 100;

const NAME_PLACEHOLDER: &str = "{name}";
const USERNAME_PLACEHOLDER: &str = "{username}";

/// Phase-1 allowlisted user-entry attributes.
const USER_ATTRS: &[&str] = &["memberOf", "isMemberOf", "isDirectMemberOf"];
/// Phase-1 allowlisted group-entry attributes.
const GROUP_ATTRS: &[&str] = &["member", "uniqueMember"];

/// Error raised when a mapping file cannot be parsed fail-closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// File exceeds [`MAX_MAPPING_FILE_BYTES`].
    #[error("mapping file exceeds 128 KiB")]
    FileTooLarge,
    /// Bytes are not valid UTF-8.
    #[error("mapping file is not valid UTF-8")]
    InvalidUtf8,
    /// Line kind is not `resolve`, `static`, or `match`.
    #[error("unknown mapping kind")]
    UnknownKind,
    /// `{username}` appears on a non-comment line.
    #[error("{{username}} is illegal in the mapping file")]
    UsernamePlaceholderIllegal,
    /// More than [`MAX_RESOLVE_LINES`] distinct resolve lines.
    #[error("more than {MAX_RESOLVE_LINES} resolve lines")]
    TooManyResolveLines,
    /// Attribute token is not on the Phase-1 allowlist.
    #[error("unknown resolve attribute")]
    UnknownResolveAttr,
    /// `compare uid` (POSIX `memberUid`) is not parsed in Phase 1.
    #[error("compare uid is not supported in Phase 1")]
    CompareUidNotSupported,
    /// `group-attr` line is missing `base <dn>`.
    #[error("group-attr resolve requires a base DN")]
    MissingBase,
    /// `user-attr` line carries a `base` (forbidden).
    #[error("user-attr resolve must not carry a base")]
    UnexpectedBase,
    /// A mapping-file key or base DN contains `\`.
    #[error("backslash is illegal in a mapping-file key")]
    BackslashInKey,
    /// `{name}` / `{username}` appeared in a resolve base DN.
    #[error("resolve base DN must not contain a placeholder")]
    PlaceholderInBase,
    /// `key` token is not `dn` or `mail`.
    #[error("resolve key must be dn or mail")]
    InvalidKeyKind,
    /// `match` key does not contain `{{name}}` exactly once, or the
    /// target is not exactly `{{name}}`.
    #[error("invalid match placeholders")]
    InvalidMatchPlaceholder,
    /// `static` key or target contains `{name}`.
    #[error("static line must not contain {{name}}")]
    StaticContainsName,
    /// A `static` / `match` line is missing its key or target.
    #[error("mapping line is missing a key or target")]
    MissingKeyOrTarget,
    /// A resolve line is missing tokens or carries trailing garbage.
    #[error("malformed resolve line")]
    MalformedResolve,
}

/// How a `group-attr` search identifies each matching group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GroupKeyKind {
    /// Use the group's distinguished name (default).
    Dn,
    /// Use the group's `mail` attribute (Google Secure LDAP).
    Mail,
}

/// One compiled `resolve` line (auth-side plan; no User Group names).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResolveLine {
    /// Read a multivalued attribute on the bound user entry.
    UserAttr {
        /// Allowlisted attribute (`memberOf` / `isMemberOf` / `isDirectMemberOf`).
        attr: String,
    },
    /// Search groups under `base` for `(attr=<bound user DN>)`.
    GroupAttr {
        /// Allowlisted attribute (`member` / `uniqueMember`).
        attr: String,
        /// Operator-trusted search base (no placeholder, no `\`).
        base: String,
        /// Which value to collect from each matching group.
        key: GroupKeyKind,
    },
}

/// Compiled list of resolve lines, ready for `AuthLdapAggregationProvision`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvePlan {
    /// Distinct resolve lines, declaration order, duplicates dropped.
    pub lines: Vec<ResolveLine>,
}

impl ResolvePlan {
    /// Whether the plan will perform at least one directory search / read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

/// One `static` mapping: exact directory key → User Group name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticRule {
    key_normalized: String,
    target: String,
}

/// One `match` mapping: whole-key template with a single `{name}` capture.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MatchRule {
    prefix: String,
    suffix: String,
}

/// Parsed mapping file (resolve plan + static / match AST).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingFile {
    resolve: Vec<ResolveLine>,
    static_rules: Vec<StaticRule>,
    match_rules: Vec<MatchRule>,
}

impl MappingFile {
    /// Whether the file declared at least one `resolve` line.
    ///
    /// Comments-only catalogues parse successfully with this flag false;
    /// the supervisor refuses boot when aggregation is on and this is
    /// false (lot 3).
    #[must_use]
    pub fn has_resolve(&self) -> bool {
        !self.resolve.is_empty()
    }

    /// Compiled resolve plan for `vauban-auth` (no User Group names).
    #[must_use]
    pub fn resolve_plan(&self) -> ResolvePlan {
        ResolvePlan {
            lines: self.resolve.clone(),
        }
    }
}

/// Parse `ldaps_mapping.conf` bytes. Comments-only is a successful empty AST.
pub fn parse(bytes: &[u8]) -> Result<MappingFile, ParseError> {
    if bytes.len() > MAX_MAPPING_FILE_BYTES {
        return Err(ParseError::FileTooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError::InvalidUtf8)?;

    let mut resolve = Vec::new();
    let mut seen_resolve: HashSet<ResolveLine> = HashSet::new();
    let mut static_rules = Vec::new();
    let mut seen_static: HashSet<(String, String)> = HashSet::new();
    let mut match_rules = Vec::new();
    let mut seen_match: HashSet<(String, String)> = HashSet::new();

    for raw_line in text.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.contains(USERNAME_PLACEHOLDER) {
            return Err(ParseError::UsernamePlaceholderIllegal);
        }
        let (kind, rest) = split_first_token(line);
        match kind {
            "resolve" => {
                let line = parse_resolve(rest)?;
                if seen_resolve.insert(line.clone()) {
                    if resolve.len() >= MAX_RESOLVE_LINES {
                        return Err(ParseError::TooManyResolveLines);
                    }
                    resolve.push(line);
                }
            }
            "static" => {
                let (key, target) = split_key_target(rest)?;
                if key.contains(NAME_PLACEHOLDER) || target.contains(NAME_PLACEHOLDER) {
                    return Err(ParseError::StaticContainsName);
                }
                if key.contains('\\') {
                    return Err(ParseError::BackslashInKey);
                }
                let key_normalized = normalize_dn_key(key);
                if key_normalized.is_empty() {
                    return Err(ParseError::MissingKeyOrTarget);
                }
                let dedup = (key_normalized.clone(), target.to_ascii_lowercase());
                if seen_static.insert(dedup) {
                    static_rules.push(StaticRule {
                        key_normalized,
                        target: target.to_string(),
                    });
                }
            }
            "match" => {
                let (key, target) = split_key_target(rest)?;
                if target != NAME_PLACEHOLDER {
                    return Err(ParseError::InvalidMatchPlaceholder);
                }
                if key.matches(NAME_PLACEHOLDER).count() != 1 {
                    return Err(ParseError::InvalidMatchPlaceholder);
                }
                if key.contains('\\') {
                    return Err(ParseError::BackslashInKey);
                }
                let (prefix, suffix) = key
                    .split_once(NAME_PLACEHOLDER)
                    .ok_or(ParseError::InvalidMatchPlaceholder)?;
                let dedup = (prefix.to_string(), suffix.to_string());
                if seen_match.insert(dedup) {
                    match_rules.push(MatchRule {
                        prefix: prefix.to_string(),
                        suffix: suffix.to_string(),
                    });
                }
            }
            _ => return Err(ParseError::UnknownKind),
        }
    }

    Ok(MappingFile {
        resolve,
        static_rules,
        match_rules,
    })
}

/// Map directory keys to User Group **names** (UUID lookup is the web layer).
///
/// `static` targets are reserved case-insensitively: a `match` whose
/// captured `{name}` equals a reserved target is skipped. `static` does
/// not consume the key -- the same directory key is still scored by
/// `match` lines. A directory key that contains `\` is a defined miss.
#[must_use]
pub fn apply(
    keys: impl IntoIterator<Item = impl AsRef<str>>,
    ast: &MappingFile,
) -> BTreeSet<String> {
    let reserved: HashSet<String> = ast
        .static_rules
        .iter()
        .map(|r| r.target.to_ascii_lowercase())
        .collect();

    // Fold case so "Developers" and "developers" collapse; first spelling wins.
    let mut names: HashMap<String, String> = HashMap::new();

    for key in keys {
        let original = key.as_ref();
        if original.contains('\\') {
            continue;
        }
        let normalized = normalize_dn_key(original);
        if normalized.is_empty() {
            continue;
        }

        for rule in &ast.static_rules {
            if rule.key_normalized == normalized {
                insert_name(&mut names, &rule.target);
            }
        }

        for rule in &ast.match_rules {
            let Some(captured) = capture_name(original, &rule.prefix, &rule.suffix) else {
                continue;
            };
            if reserved.contains(&captured.to_ascii_lowercase()) {
                tracing::warn!(
                    captured = %captured,
                    "ldap_mapping_match_skipped_reserved_target"
                );
                continue;
            }
            insert_name(&mut names, &captured);
        }
    }

    names.into_values().collect()
}

fn insert_name(names: &mut HashMap<String, String>, name: &str) {
    let folded = name.to_ascii_lowercase();
    names.entry(folded).or_insert_with(|| name.to_string());
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

fn split_key_target(rest: &str) -> Result<(&str, &str), ParseError> {
    let rest = rest.trim();
    if rest.is_empty() {
        return Err(ParseError::MissingKeyOrTarget);
    }
    let Some(split) = rest.rfind(|c: char| c.is_ascii_whitespace()) else {
        return Err(ParseError::MissingKeyOrTarget);
    };
    let key = rest[..split].trim();
    let target = rest[split..].trim();
    if key.is_empty() || target.is_empty() {
        return Err(ParseError::MissingKeyOrTarget);
    }
    Ok((key, target))
}

fn parse_resolve(rest: &str) -> Result<ResolveLine, ParseError> {
    let rest = rest.trim();
    if rest.is_empty() {
        return Err(ParseError::MalformedResolve);
    }
    if rest.split_ascii_whitespace().any(|t| t == "compare") {
        return Err(ParseError::CompareUidNotSupported);
    }

    let (kind, after_kind) = split_first_token(rest);
    if kind.is_empty() {
        return Err(ParseError::MalformedResolve);
    }
    let (attr_tok, leftover) = split_first_token(after_kind);
    if attr_tok.is_empty() {
        return Err(ParseError::MalformedResolve);
    }

    match kind {
        "user-attr" => {
            if !leftover.is_empty() {
                return Err(ParseError::UnexpectedBase);
            }
            let attr = canonicalize_attr(attr_tok, USER_ATTRS)?;
            Ok(ResolveLine::UserAttr { attr })
        }
        "group-attr" => {
            if leftover.is_empty() {
                return Err(ParseError::MissingBase);
            }
            let (base, key) = parse_group_attr_tail(leftover)?;
            let attr = canonicalize_attr(attr_tok, GROUP_ATTRS)?;
            Ok(ResolveLine::GroupAttr { attr, base, key })
        }
        _ => Err(ParseError::MalformedResolve),
    }
}

fn split_first_token(s: &str) -> (&str, &str) {
    let s = s.trim();
    match s.find(|c: char| c.is_ascii_whitespace()) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    }
}

fn parse_group_attr_tail(leftover: &str) -> Result<(String, GroupKeyKind), ParseError> {
    let mut parts: Vec<&str> = leftover.split_ascii_whitespace().collect();
    if parts.first().copied() != Some("base") {
        return Err(ParseError::MissingBase);
    }
    parts.remove(0);

    let mut key = GroupKeyKind::Dn;
    if parts.len() >= 2 && parts[parts.len() - 2] == "key" {
        key = match parts[parts.len() - 1] {
            "dn" => GroupKeyKind::Dn,
            "mail" => GroupKeyKind::Mail,
            _ => return Err(ParseError::InvalidKeyKind),
        };
        parts.truncate(parts.len() - 2);
    }

    if parts.is_empty() {
        return Err(ParseError::MissingBase);
    }
    let base = parts.join(" ");
    if base.contains('\\') {
        return Err(ParseError::BackslashInKey);
    }
    if base.contains(NAME_PLACEHOLDER) || base.contains(USERNAME_PLACEHOLDER) {
        return Err(ParseError::PlaceholderInBase);
    }
    Ok((base, key))
}

fn canonicalize_attr(token: &str, allowlist: &[&str]) -> Result<String, ParseError> {
    allowlist
        .iter()
        .find(|a| a.eq_ignore_ascii_case(token))
        .map(|a| (*a).to_string())
        .ok_or(ParseError::UnknownResolveAttr)
}

/// Lowercase, strip whitespace around commas, collapse repeated spaces
/// inside RDN values. Comparison-only -- capture uses the original key.
pub fn normalize_dn_key(s: &str) -> String {
    let lower = s.trim().to_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == ',' {
            while out.ends_with(' ') {
                out.pop();
            }
            out.push(',');
            i += 1;
            while i < chars.len() && chars[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        if c == ' ' {
            if !out.is_empty() && !out.ends_with(' ') && !out.ends_with(',') {
                out.push(' ');
            }
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

fn capture_name(original: &str, prefix: &str, suffix: &str) -> Option<String> {
    let n_prefix = normalize_dn_key(prefix);
    let n_suffix = normalize_dn_key(suffix);
    let (n_key, origins) = normalize_dn_key_mapped(original);
    if !n_key.starts_with(&n_prefix) || !n_key.ends_with(&n_suffix) {
        return None;
    }
    let mid_start = n_prefix.chars().count();
    let mid_end = n_key
        .chars()
        .count()
        .checked_sub(n_suffix.chars().count())?;
    if mid_start > mid_end {
        return None;
    }
    // Empty capture is a miss (`{name}` charset requires length >= 1).
    if mid_start == mid_end {
        return None;
    }
    let orig_start = *origins.get(mid_start)?;
    let orig_end = origins
        .get(mid_end - 1)
        .map(|i| {
            original[*i..]
                .chars()
                .next()
                .map(|c| i + c.len_utf8())
                .unwrap_or(*i)
        })
        .unwrap_or(original.len());
    if orig_start > orig_end || orig_end > original.len() {
        return None;
    }
    let captured = original[orig_start..orig_end].trim();
    if !name_charset_ok(captured) {
        return None;
    }
    Some(captured.to_string())
}

/// Same as [`normalize_dn_key`], plus the original byte index of each
/// emitted character (used to recover `{name}` from the pre-lowercase key).
fn normalize_dn_key_mapped(s: &str) -> (String, Vec<usize>) {
    let trimmed = s.trim();
    let trim_off = s.len() - s.trim_start().len();
    let mut out = String::new();
    let mut origins = Vec::new();
    let mut pending_space: Option<usize> = None;

    for (rel, ch) in trimmed.char_indices() {
        let abs = trim_off + rel;
        let lower = ch.to_ascii_lowercase();
        if lower == ',' {
            while out.ends_with(' ') {
                out.pop();
                origins.pop();
            }
            pending_space = None;
            out.push(',');
            origins.push(abs);
            continue;
        }
        if ch == ' ' {
            if !out.is_empty() && !out.ends_with(' ') && !out.ends_with(',') {
                pending_space = Some(abs);
            }
            continue;
        }
        if ch.is_ascii_whitespace() {
            continue;
        }
        if let Some(space_at) = pending_space.take()
            && !out.ends_with(',')
        {
            out.push(' ');
            origins.push(space_at);
        }
        out.push(lower);
        origins.push(abs);
    }
    while out.ends_with(' ') {
        out.pop();
        origins.pop();
    }
    (out, origins)
}

fn name_charset_ok(name: &str) -> bool {
    let len = name.chars().count();
    if !(1..=MAX_CAPTURE_LEN).contains(&len) {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AD_STATIC: &str = r#"
resolve  user-attr  memberOf
static   CN=Domain Admins,CN=Users,DC=netris,DC=local  Administrators
match    CN={name},OU=UserGroup,OU=Vauban,DC=netris,DC=local  {name}
"#;

    fn parsed(src: &str) -> MappingFile {
        parse(src.as_bytes()).expect("parse")
    }

    #[test]
    fn parse_ad_block_happy_path() {
        let ast = parsed(AD_STATIC);
        assert!(ast.has_resolve());
        assert_eq!(
            ast.resolve_plan().lines,
            vec![ResolveLine::UserAttr {
                attr: "memberOf".into(),
            }]
        );
        let names = apply(
            [
                "CN=Domain Admins,CN=Users,DC=netris,DC=local",
                "CN=Developers,OU=UserGroup,OU=Vauban,DC=netris,DC=local",
            ],
            &ast,
        );
        assert_eq!(
            names,
            BTreeSet::from(["Administrators".into(), "Developers".into()])
        );
    }

    #[test]
    fn comments_only_mapping_parses_without_resolve() {
        let shipped = include_str!("../../config/access/ldaps_mapping.conf");
        let ast = parse(shipped.as_bytes()).expect("shipped catalogue");
        assert!(!ast.has_resolve());
        assert!(ast.resolve_plan().is_empty());
        assert!(apply(["CN=anything,DC=x"], &ast).is_empty());
    }

    #[test]
    fn unknown_resolve_attr_refuses_boot() {
        let err = parse(b"resolve  user-attr  groupMembership\n").unwrap_err();
        assert_eq!(err, ParseError::UnknownResolveAttr);
        let err = parse(b"resolve  group-attr  memberUid  base  OU=groups,DC=x\n").unwrap_err();
        assert_eq!(err, ParseError::UnknownResolveAttr);
    }

    #[test]
    fn compare_uid_refuses_boot() {
        let err =
            parse(b"resolve  group-attr  member  base  OU=groups,DC=x  compare uid\n").unwrap_err();
        assert_eq!(err, ParseError::CompareUidNotSupported);
    }

    #[test]
    fn user_attr_rejects_base() {
        let err = parse(b"resolve  user-attr  memberOf  base  DC=x\n").unwrap_err();
        assert_eq!(err, ParseError::UnexpectedBase);
    }

    #[test]
    fn group_attr_requires_base() {
        let err = parse(b"resolve  group-attr  member\n").unwrap_err();
        assert_eq!(err, ParseError::MissingBase);
    }

    #[test]
    fn group_attr_accepts_key_mail_and_spaced_base() {
        let ast =
            parsed("resolve  group-attr  member  base  OU=User Groups,DC=netris,DC=eu  key mail\n");
        assert_eq!(
            ast.resolve_plan().lines,
            vec![ResolveLine::GroupAttr {
                attr: "member".into(),
                base: "OU=User Groups,DC=netris,DC=eu".into(),
                key: GroupKeyKind::Mail,
            }]
        );
    }

    #[test]
    fn more_than_three_resolve_lines_refuse() {
        let src = "\
resolve user-attr memberOf
resolve user-attr isMemberOf
resolve user-attr isDirectMemberOf
resolve group-attr member base OU=g,DC=x
";
        assert_eq!(
            parse(src.as_bytes()).unwrap_err(),
            ParseError::TooManyResolveLines
        );
    }

    #[test]
    fn duplicate_identical_resolve_is_ignored() {
        let ast = parsed(
            "resolve user-attr memberOf\nresolve user-attr memberOf\nresolve user-attr MEMBEROF\n",
        );
        assert_eq!(ast.resolve_plan().lines.len(), 1);
    }

    #[test]
    fn username_placeholder_refuses_boot() {
        let err = parse(b"static  uid={username},dc=x  Admins\n").unwrap_err();
        assert_eq!(err, ParseError::UsernamePlaceholderIllegal);
    }

    #[test]
    fn backslash_in_file_key_refuses_boot() {
        let err = parse(b"static  CN=Foo\\,Bar,DC=x  Admins\n").unwrap_err();
        assert_eq!(err, ParseError::BackslashInKey);
        let err = parse(b"match  CN={name}\\,OU=g,DC=x  {name}\n").unwrap_err();
        assert_eq!(err, ParseError::BackslashInKey);
        let err = parse(b"resolve group-attr member base OU=g\\,DC=x\n").unwrap_err();
        assert_eq!(err, ParseError::BackslashInKey);
    }

    #[test]
    fn oversized_file_refuses() {
        let mut huge = vec![b'#'; MAX_MAPPING_FILE_BYTES + 1];
        huge[0] = b'\n';
        assert_eq!(parse(&huge).unwrap_err(), ParseError::FileTooLarge);
    }

    #[test]
    fn invalid_utf8_refuses() {
        assert_eq!(parse(&[0xff, 0xfe]).unwrap_err(), ParseError::InvalidUtf8);
    }

    #[test]
    fn match_requires_name_on_both_sides() {
        assert_eq!(
            parse(b"match  CN=Foo,DC=x  Foo\n").unwrap_err(),
            ParseError::InvalidMatchPlaceholder
        );
        assert_eq!(
            parse(b"match  CN={name}{name},DC=x  {name}\n").unwrap_err(),
            ParseError::InvalidMatchPlaceholder
        );
    }

    #[test]
    fn static_rejects_name_placeholder() {
        assert_eq!(
            parse(b"static  CN={name},DC=x  Admins\n").unwrap_err(),
            ParseError::StaticContainsName
        );
    }

    #[test]
    fn apply_table_reserved_or_static_and_charset_miss() {
        let ast = parsed(AD_STATIC);
        // static OR: same key, two targets.
        let or_ast = parsed(
            "\
resolve user-attr memberOf
static  CN=Ops,DC=x  Operators
static  CN=Ops,DC=x  OnCall
",
        );
        assert_eq!(
            apply(["CN=Ops,DC=x"], &or_ast),
            BTreeSet::from(["OnCall".into(), "Operators".into()])
        );

        // charset miss (comma in capture).
        let names = apply(
            ["CN=Bad,Name,OU=UserGroup,OU=Vauban,DC=netris,DC=local"],
            &ast,
        );
        assert!(names.is_empty());

        // directory backslash is a miss, not a parse error.
        let names = apply(
            ["CN=Foo\\,Bar,OU=UserGroup,OU=Vauban,DC=netris,DC=local"],
            &ast,
        );
        assert!(names.is_empty());
    }

    #[test]
    fn apply_normalizes_dn_whitespace_and_case() {
        let ast = parsed(AD_STATIC);
        let names = apply(
            ["cn=Domain  Admins , cn=Users , dc=NETRIS , dc=LOCAL"],
            &ast,
        );
        assert_eq!(names, BTreeSet::from(["Administrators".into()]));
    }

    #[test]
    fn apply_captures_original_spelling() {
        let ast = parsed(AD_STATIC);
        let names = apply(
            ["CN=Help Desk,OU=UserGroup,OU=Vauban,DC=netris,DC=local"],
            &ast,
        );
        assert_eq!(names, BTreeSet::from(["Help Desk".into()]));
    }

    #[test]
    fn apply_mail_match() {
        let ast = parsed(
            "\
resolve group-attr member base DC=netris,DC=eu key mail
static  vauban-admins@netris.eu  Administrators
match   {name}@netris.eu  {name}
",
        );
        let names = apply(["ops@netris.eu", "vauban-admins@netris.eu"], &ast);
        // static does not consume the key: the mail is also scored by match.
        assert_eq!(
            names,
            BTreeSet::from([
                "Administrators".into(),
                "ops".into(),
                "vauban-admins".into()
            ])
        );
    }

    /// A directory admin who creates `CN=Administrators` under the mapped
    /// OU must not obtain the User Group reserved by `static`.
    #[test]
    fn attack_mapping_match_cannot_claim_static_target() {
        let ast = parsed(AD_STATIC);
        let names = apply(
            ["CN=Administrators,OU=UserGroup,OU=Vauban,DC=netris,DC=local"],
            &ast,
        );
        assert!(
            names.is_empty(),
            "reserved target must not be granted via match: {names:?}"
        );
        // Mixed case of the reserved name is also skipped.
        let names = apply(
            ["CN=administrators,OU=UserGroup,OU=Vauban,DC=netris,DC=local"],
            &ast,
        );
        assert!(names.is_empty());
        // The static key still grants the reserved group.
        let names = apply(["CN=Domain Admins,CN=Users,DC=netris,DC=local"], &ast);
        assert_eq!(names, BTreeSet::from(["Administrators".into()]));
    }

    #[test]
    fn file_order_does_not_change_apply() {
        let a = parsed(
            "\
resolve user-attr memberOf
static  CN=A,DC=x  Alpha
match   CN={name},DC=x  {name}
",
        );
        let b = parsed(
            "\
match   CN={name},DC=x  {name}
static  CN=A,DC=x  Alpha
resolve user-attr memberOf
",
        );
        let keys = ["CN=A,DC=x", "CN=Beta,DC=x"];
        assert_eq!(apply(keys, &a), apply(keys, &b));
    }

    #[test]
    fn unknown_kind_refuses() {
        assert_eq!(
            parse(b"pattern  CN={name},DC=x  {name}\n").unwrap_err(),
            ParseError::UnknownKind
        );
    }

    #[test]
    fn placeholder_in_base_refuses() {
        assert_eq!(
            parse(b"resolve group-attr member base OU={name},DC=x\n").unwrap_err(),
            ParseError::PlaceholderInBase
        );
    }

    #[test]
    fn invalid_key_kind_refuses() {
        assert_eq!(
            parse(b"resolve group-attr member base OU=g,DC=x key uid\n").unwrap_err(),
            ParseError::InvalidKeyKind
        );
    }
}
