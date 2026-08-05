//! Patch source expansion.
//!
//! Expands `~/` and `$VAR` / `${VAR}` references in a patch's raw
//! source string against the session's already-resolved variables.
//!
//! # Semantic rules
//!
//! - `~` (alone) or `~/...` → substitute `HOME`. Any other tilde form
//!   (`~user/...`, `~foo`) is passed through literally.
//! - `$NAME` reads greedily as `[A-Za-z0-9_]+`, then validates against
//!   [`StrictVarName`] (`[A-Z_][A-Z0-9_]*`).
//! - `${NAME}` reads everything between the braces, then validates.
//! - `$$` is a literal `$`.
//! - Substituted values are glob-meta escaped using globset's bracket
//!   form (`*` → `[*]`, etc.) so a literal `*` in `$HOME` cannot
//!   accidentally become a wildcard.
//! - Looking up a referenced name that isn't in the resolved-vars set
//!   is a hard error ([`ExpandError::UndefinedVar`]). Substitution
//!   sources its values from the resolved-vars set the caller passes
//!   in via [`VarLookup`].
//!   **One narrow exception:** the *tilde prefix* (`~` / `~/...`)
//!   accepts a `HOME` fallback from process env (threaded through
//!   the `home_fallback` parameter), so `~/foo` works without the
//!   loadout having to declare `HOME = { inherit = true }`. Explicit
//!   `$HOME` and `${HOME}` references stay strict — no fallback.
//! - After substitution the result is **path-normalized**: redundant
//!   slashes and `.` components are dropped. Any `..` component
//!   produces [`ExpandError::PathTraversal`] — silent normalization
//!   of parent-dir would let a malicious pattern escape its declared
//!   prefix and bypass policy. `..` is a hard error everywhere it
//!   appears (raw pattern, substituted value, or any combination).
//! - The final pattern **must be absolute**. A pattern that doesn't
//!   start with `/` after substitution produces
//!   [`ExpandError::NotAbsolute`]. Use `~/foo` or `$HOME/foo` for
//!   home-relative paths — they expand to an absolute form during
//!   substitution.
//!
//! [`StrictVarName`]: crate::core::primitives::StrictVarName

use crate::core::primitives::{FileSet, ResolvedVar};

/// Name → value lookup contract used by [`expand_source`].
///
/// Decouples the expander from any particular session-var carrier.
/// Core implements it for `[ResolvedVar]`; the client wraps its own
/// provenance-bearing var type by implementing this trait separately.
pub trait VarLookup {
    /// Return the value bound to `name`, or `None` if no such var.
    fn lookup(&self, name: &str) -> Option<&str>;
}

impl VarLookup for [ResolvedVar] {
    fn lookup(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|v| v.name() == name)
            .map(ResolvedVar::value)
    }
}

/// Errors produced when expanding a patch source.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ExpandError {
    /// Malformed reference syntax (unterminated `${`, invalid name
    /// character, empty `${}`).
    #[error("malformed expansion syntax at byte {at}: {reason}")]
    MalformedSyntax { at: usize, reason: &'static str },

    /// A reference named a variable not present in the session's
    /// resolved set. No fallback to process env.
    #[error("`${name}` is not a resolved session variable")]
    UndefinedVar { name: String },

    /// The fully-expanded string failed to parse as a glob.
    #[error("expanded source is not a valid glob: {0}")]
    PostExpansionInvalid(#[from] crate::core::primitives::PatchError),

    /// A `..` path component was found anywhere in the (raw or
    /// substituted) pattern. Parent-dir components are rejected
    /// unconditionally — silent normalization would let a malicious
    /// pattern escape its declared prefix and bypass policy checks.
    #[error("path component `..` is not allowed in pattern `{pattern}`")]
    PathTraversal { pattern: String },

    /// The fully-substituted pattern is not absolute (doesn't start
    /// with `/`). Patch sources and policy patterns must resolve to
    /// absolute paths so the gate can drive a filesystem walk and
    /// produce reproducible policy decisions. Relative patterns
    /// would silently depend on the process CWD, which is brittle
    /// and almost never what the user intends.
    ///
    /// Use `~/foo` or `$HOME/foo` for home-relative paths — these
    /// expand to absolute form during substitution.
    #[error(
        "pattern `{pattern}` is not absolute; \
         use `~/...` or an explicit `$HOME` reference for home-relative paths"
    )]
    NotAbsolute { pattern: String },

    /// A leading `~name/...` form (per-user tilde) was used. Only
    /// bare `~` and `~/…` (the current user's home) are expanded;
    /// `~someuser/` would silently be treated as literal, producing
    /// an inert pattern that never matches an absolute path.
    /// Rejecting it up front turns a silent-noop policy rule into a
    /// loud error, since that's almost never what the user intended.
    #[error(
        "pattern `{pattern}` uses `~name/` form; only `~/...` is expanded — \
         use `$HOME/...` or an explicit path"
    )]
    UnsupportedTildeUser { pattern: String },
}

/// Expand `raw` against `resolved_vars` and parse the result as a
/// [`FileSet`] intended as a **patch source pattern** — the input
/// to the walker. The result must be absolute so the walker has a
/// concrete starting point.
///
/// `home_fallback` applies only to the `~` / `~/…` prefix when
/// `HOME` isn't in `resolved_vars`. Explicit `$HOME` / `${HOME}`
/// references stay strict.
///
/// See [`expand_policy_pattern`] for the matcher-side variant that
/// drops the "must be absolute" requirement — policy patterns are
/// used to check paths, not to seed a walk, so a pattern like
/// `**/*.pem` is meaningful there.
///
/// # Errors
///
/// See [`ExpandError`].
///
/// # Panics
///
/// Cannot panic in practice; the loop's bounds guarantee the inner
/// `expect` never fires.
pub fn expand_source(
    raw: &str,
    resolved_vars: &(impl VarLookup + ?Sized),
    home_fallback: Option<&str>,
) -> Result<FileSet, ExpandError> {
    expand_pattern(raw, resolved_vars, home_fallback, RequireAbsolute::Yes)
}

/// Expand `raw` against `resolved_vars` and parse the result as a
/// [`FileSet`] intended as a **policy pattern** — checked against
/// paths that other patches produce.
///
/// Same substitution and normalization as [`expand_source`], but
/// the result does not have to be absolute: a policy pattern like
/// `**/*.pem` is a legitimate matcher for "any `.pem` at any depth"
/// and doesn't need to point at a walk root.
///
/// # Errors
///
/// See [`ExpandError`]. [`ExpandError::NotAbsolute`] cannot be
/// returned from this function.
pub fn expand_policy_pattern(
    raw: &str,
    resolved_vars: &(impl VarLookup + ?Sized),
    home_fallback: Option<&str>,
) -> Result<FileSet, ExpandError> {
    expand_pattern(raw, resolved_vars, home_fallback, RequireAbsolute::No)
}

/// Whether the expander enforces "result must be absolute." Kept
/// internal so the two public entry points expose their intent via
/// their name rather than a caller-visible bool.
#[derive(Copy, Clone, PartialEq, Eq)]
enum RequireAbsolute {
    Yes,
    No,
}

fn expand_pattern(
    raw: &str,
    resolved_vars: &(impl VarLookup + ?Sized),
    home_fallback: Option<&str>,
    require_absolute: RequireAbsolute,
) -> Result<FileSet, ExpandError> {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;

    // Tilde prefix: `~` alone or `~/...`. Any other tilde form is
    // literal.
    if bytes.first() == Some(&b'~') && bytes.get(1).is_none_or(|&c| c == b'/') {
        let home = resolved_vars
            .lookup("HOME")
            .or(home_fallback)
            .ok_or_else(|| ExpandError::UndefinedVar {
                name: "HOME".into(),
            })?;
        escape_glob_metas(home, &mut out);
        i = 1;
    } else if bytes.first() == Some(&b'~') {
        // `~name/...`: we don't support per-user tilde expansion.
        // Left literal, it would be an inert pattern that silently
        // never matches — a footgun. Reject it here so both the
        // walker and policy paths surface the mistake loudly.
        return Err(ExpandError::UnsupportedTildeUser {
            pattern: raw.to_owned(),
        });
    }

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'$' {
            // `$$` → literal `$`.
            if bytes.get(i + 1) == Some(&b'$') {
                out.push('$');
                i += 2;
                continue;
            }
            let (name, consumed) = parse_var_ref(bytes, i)?;
            let value = resolved_vars
                .lookup(name)
                .ok_or_else(|| ExpandError::UndefinedVar {
                    name: name.to_owned(),
                })?;
            escape_glob_metas(value, &mut out);
            i += consumed;
            continue;
        }
        // Literal character — possibly multi-byte UTF-8. Copy the
        // entire character to `out` (pushing one byte at a time would
        // mangle non-ASCII content). Byte-indexed scanning above is
        // still safe because every control character we care about
        // (`$`, `{`, `}`, `~`, `/`) is single-byte ASCII.
        let ch_len = raw[i..]
            .chars()
            .next()
            .expect("non-empty slice has at least one char")
            .len_utf8();
        out.push_str(&raw[i..i + ch_len]);
        i += ch_len;
    }

    let normalized = normalize_path(&out)?;
    if require_absolute == RequireAbsolute::Yes && !normalized.starts_with('/') {
        return Err(ExpandError::NotAbsolute {
            pattern: normalized,
        });
    }
    FileSet::try_new(normalized).map_err(ExpandError::from)
}

/// Drop `.` and empty components, reject any `..` component.
///
/// Preserves a leading `/` (absolute paths) and a trailing `/` (the
/// "this names a directory" affordance some patterns rely on).
/// Glob metacharacters (`**`, `*`, `?`, `[...]`, `{...}`) are
/// path components in their own right and pass through unchanged —
/// only literal `.` and `..` components are touched.
///
/// By the time this runs, `expand_source` has already resolved every
/// `$VAR` / `${VAR}` substitution and consumed the `$$` literal-`$`
/// escape, so this function only sees post-substitution text. It
/// never has to reason about variable syntax — any `$` it encounters
/// is a literal that survived expansion.
fn normalize_path(s: &str) -> Result<String, ExpandError> {
    let is_absolute = s.starts_with('/');
    // A bare `/` is its own thing: absolute root, no trailing slash to
    // restore later.
    let trailing_slash = s.len() > 1 && s.ends_with('/');

    let mut components: Vec<&str> = Vec::new();
    for component in s.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return Err(ExpandError::PathTraversal {
                pattern: s.to_owned(),
            });
        }
        components.push(component);
    }

    let mut out = String::with_capacity(s.len());
    if is_absolute {
        out.push('/');
    }
    out.push_str(&components.join("/"));
    if trailing_slash {
        out.push('/');
    }
    Ok(out)
}

/// Parse a `$VAR` or `${VAR}` reference starting at `bytes[at]` (which
/// is the `$`). Returns `(name, bytes_consumed_including_dollar)`.
fn parse_var_ref(bytes: &[u8], at: usize) -> Result<(&str, usize), ExpandError> {
    debug_assert_eq!(bytes[at], b'$');
    let braced = bytes.get(at + 1) == Some(&b'{');

    let (name_start, name_end, total) = if braced {
        let name_start = at + 2;
        let close = (name_start..bytes.len())
            .find(|&j| bytes[j] == b'}')
            .ok_or(ExpandError::MalformedSyntax {
                at,
                reason: "unterminated `${`",
            })?;
        (name_start, close, close - at + 1)
    } else {
        let name_start = at + 1;
        let mut end = name_start;
        while end < bytes.len() && is_name_byte(bytes[end]) {
            end += 1;
        }
        (name_start, end, end - at)
    };

    if name_end == name_start {
        return Err(ExpandError::MalformedSyntax {
            at,
            reason: if braced {
                "empty `${}` reference"
            } else {
                "`$` not followed by a valid identifier"
            },
        });
    }

    // Safe slice: bytes between name_start and name_end are pure ASCII
    // (validated below) when unbraced; for braced, we accept any UTF-8
    // and validate via chars().
    let name = std::str::from_utf8(&bytes[name_start..name_end]).map_err(|_| {
        ExpandError::MalformedSyntax {
            at,
            reason: "non-UTF8 byte in variable name",
        }
    })?;
    validate_strict_var_name(name).map_err(|reason| ExpandError::MalformedSyntax { at, reason })?;
    Ok((name, total))
}

fn is_name_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Enforce [`crate::core::primitives::StrictVarName`] shape: `[A-Z_][A-Z0-9_]*`.
fn validate_strict_var_name(name: &str) -> Result<(), &'static str> {
    let mut chars = name.chars();
    let first = chars.next().ok_or("empty variable name")?;
    if !(first.is_ascii_uppercase() || first == '_') {
        return Err("variable name must start with uppercase letter or `_`");
    }
    for c in chars {
        if !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            return Err("variable name contains a non-POSIX character");
        }
    }
    Ok(())
}

/// Escape glob metacharacters in `value` so that the substituted
/// content matches as literal path components. Uses globset's bracket
/// form (`*` → `[*]`), which is portable and visible in error output.
///
/// `,` is escaped too even though it's only meaningful inside `{...}`
/// brace groups: if the surrounding pattern contains a brace group and
/// a `$VAR` is substituted *inside* it, the value's commas would
/// otherwise split into extra alternatives. Bracket-escaping `,`
/// preserves the value's intent regardless of context.
/// Turn a literal path into a policy pattern that matches exactly it.
///
/// Policy entries are patterns: they go through variable expansion and
/// then become globs. Anything storing a path a user *chose* — the
/// prompt writing an approved project into `[hooks] allow`, say — has
/// to say so, or the path is reinterpreted. Both directions bite:
/// `/tmp/build*` stored raw matches every sibling `build…` project, and
/// `/home/d/proj[1]` stored raw matches nothing at all, including
/// itself. The first is a consent bypass and the second is a rule that
/// silently never fires.
///
/// Escapes both layers this passes through — `$` for the expander,
/// glob metacharacters for globset. A leading `~` is *not* escapable
/// (the expander has no syntax for it), which is harmless for the
/// callers there are: they store absolute paths, so the character
/// cannot lead.
#[must_use]
pub fn literal_policy_pattern(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    // Split on the expander's one mid-path metacharacter and escape the
    // runs between: `$` doubles to `$$`, everything else is glob-escaped
    // wholesale. The remaining thing the expander reads — a leading `~` —
    // is positional and cannot appear in a run.
    for (i, run) in path.split('$').enumerate() {
        if i > 0 {
            out.push_str("$$");
        }
        escape_glob_metas(run, &mut out);
    }
    out
}

fn escape_glob_metas(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '*' | '?' | '[' | ']' | '{' | '}' | ',' => {
                out.push('[');
                out.push(c);
                out.push(']');
            }
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::primitives::{ResolvedVar, VarValue};

    fn sv(name: &str, value: &str) -> ResolvedVar {
        ResolvedVar::resolve_with(name.into(), VarValue::specified(value), |_| {
            Err(std::env::VarError::NotPresent)
        })
        .unwrap()
    }

    fn expand(raw: &str, vars: &[ResolvedVar]) -> Result<String, ExpandError> {
        // Tests default to no env fallback so existing assertions
        // about "no resolved HOME → error" stay deterministic.
        expand_source(raw, vars, None).map(|fs| fs.pattern().to_owned())
    }

    fn expand_with_env_home(
        raw: &str,
        vars: &[ResolvedVar],
        home_fallback: &str,
    ) -> Result<String, ExpandError> {
        expand_source(raw, vars, Some(home_fallback)).map(|fs| fs.pattern().to_owned())
    }

    // ---- happy paths ----

    #[test]
    fn passes_through_string_with_no_references() {
        let vars = [];
        assert_eq!(
            expand("/plain/path/*.lua", &vars).unwrap(),
            "/plain/path/*.lua"
        );
    }

    /// Regression: literal multi-byte UTF-8 characters in the input
    /// must round-trip byte-for-byte. The byte-indexed scanner must
    /// recognize char boundaries, not push every byte as a `char`.
    #[test]
    fn passes_through_non_ascii_input() {
        let vars = [sv("HOME", "/h")];
        assert_eq!(expand("$HOME/café/é.txt", &vars).unwrap(), "/h/café/é.txt");
    }

    /// Non-ASCII content also round-trips through substituted values,
    /// since the escape step iterates by `char` (not byte).
    #[test]
    fn non_ascii_substitution_value_round_trips() {
        let vars = [sv("DIR", "/mü/sîc")];
        assert_eq!(expand("$DIR/x", &vars).unwrap(), "/mü/sîc/x");
    }

    #[test]
    fn substitutes_unbraced_dollar_var() {
        let vars = [sv("HOME", "/home/u")];
        assert_eq!(expand("$HOME/foo", &vars).unwrap(), "/home/u/foo");
    }

    #[test]
    fn substitutes_braced_dollar_var() {
        let vars = [sv("HOME", "/home/u")];
        assert_eq!(expand("${HOME}foo", &vars).unwrap(), "/home/ufoo");
    }

    #[test]
    fn double_dollar_is_literal() {
        let vars = [];
        assert_eq!(expand("/price$$5", &vars).unwrap(), "/price$5");
    }

    #[test]
    fn tilde_prefix_substitutes_home() {
        let vars = [sv("HOME", "/home/u")];
        assert_eq!(
            expand("~/dotfiles/foo", &vars).unwrap(),
            "/home/u/dotfiles/foo"
        );
    }

    #[test]
    fn bare_tilde_substitutes_home() {
        let vars = [sv("HOME", "/home/u")];
        assert_eq!(expand("~", &vars).unwrap(), "/home/u");
    }

    /// `~foo` isn't `~/`, so it's not tilde-expanded. Left literal,
    /// it would be an inert glob that never matches an absolute
    /// path (the walker's inputs) and never matches a real host
    /// path (a policy's inputs). Reject up front — this is almost
    /// always a user mistake for `~/foo` or an explicit path.
    #[test]
    fn tilde_user_form_is_rejected_up_front() {
        let vars = [];
        let err = expand("~root/x", &vars).unwrap_err();
        assert!(
            matches!(err, ExpandError::UnsupportedTildeUser { ref pattern } if pattern == "~root/x"),
            "got: {err:?}",
        );
    }

    #[test]
    fn dollar_stops_at_non_identifier_byte() {
        let vars = [sv("HOME", "/h")];
        assert_eq!(expand("$HOME/foo", &vars).unwrap(), "/h/foo");
    }

    #[test]
    fn multiple_substitutions_in_one_pattern() {
        let vars = [sv("HOME", "/h"), sv("CFG", "etc")];
        assert_eq!(expand("$HOME/${CFG}/foo", &vars).unwrap(), "/h/etc/foo");
    }

    // ---- glob meta escaping ----

    #[test]
    fn glob_metas_in_substituted_value_are_escaped() {
        // If the user's HOME contains a literal `*`, it must not become
        // a wildcard in the final glob.
        let vars = [sv("HOME", "/home/u-with-*-star")];
        let pat = expand("$HOME/foo", &vars).unwrap();
        assert_eq!(pat, "/home/u-with-[*]-star/foo");
    }

    /// Regression: the `~/...` tilde form must escape glob metas in
    /// HOME just like `$HOME/...` does. A home like `/home/u[1]` must
    /// not have its `[1]` parsed as a glob class, which would cause
    /// `walk_root()` to truncate at the metachar and the patch to
    /// silently match nothing.
    #[test]
    fn tilde_form_escapes_glob_metas_in_home() {
        let vars = [sv("HOME", "/home/u[1]")];
        let pat = expand("~/dotfiles/conf", &vars).unwrap();
        assert_eq!(pat, "/home/u[[]1[]]/dotfiles/conf");
    }

    #[test]
    fn all_glob_metas_get_bracket_escaped() {
        // Build an absolute pattern that holds the value: the
        // substituted value is wrapped in literal `/`s, so the result
        // starts with `/` and passes the absoluteness check.
        let vars = [sv("WEIRD", "*?[]{}\\")];
        let pat = expand("/$WEIRD", &vars).unwrap();
        assert_eq!(pat, "/[*][?][[][]][{][}]\\\\");
    }

    #[test]
    fn glob_metas_outside_substitutions_pass_through() {
        // The user's pattern can legitimately contain `**/*.lua`; only
        // substituted *values* get escaped.
        let vars = [sv("HOME", "/h")];
        assert_eq!(expand("$HOME/**/*.lua", &vars).unwrap(), "/h/**/*.lua");
    }

    /// A `$VAR` substituted *inside* a `{a,b}` brace group must not
    /// split the alternation if the value contains a comma. Without
    /// comma escaping, `prefix{$VAR,fallback}` with `$VAR = "a,b"`
    /// would silently expand to three alternatives (`a`, `b`,
    /// `fallback`) instead of two (`a,b`, `fallback`). The escaped
    /// comma reads to globset as the single-char class `[,]`, which
    /// matches a literal comma without participating in the brace
    /// alternation.
    #[test]
    fn comma_in_value_does_not_break_brace_alternation() {
        let vars = [sv("VAR", "a,b")];
        let pat = expand("/prefix{$VAR,fallback}", &vars).unwrap();
        assert_eq!(pat, "/prefix{a[,]b,fallback}");
    }

    // ---- error cases ----

    #[test]
    fn unterminated_brace_errors() {
        let vars = [];
        let err = expand("${HOME", &vars).unwrap_err();
        assert!(
            matches!(err, ExpandError::MalformedSyntax { reason, .. } if reason.contains("unterminated"))
        );
    }

    #[test]
    fn empty_braced_reference_errors() {
        let vars = [];
        let err = expand("${}", &vars).unwrap_err();
        assert!(matches!(err, ExpandError::MalformedSyntax { .. }));
    }

    #[test]
    fn dollar_without_identifier_errors() {
        let vars = [];
        let err = expand("$/foo", &vars).unwrap_err();
        assert!(matches!(err, ExpandError::MalformedSyntax { .. }));
    }

    #[test]
    fn lowercase_name_rejected_as_non_posix() {
        let vars = [];
        let err = expand("$home/foo", &vars).unwrap_err();
        assert!(matches!(err, ExpandError::MalformedSyntax { .. }));
    }

    #[test]
    fn name_starting_with_digit_rejected() {
        let vars = [];
        let err = expand("${1FOO}", &vars).unwrap_err();
        assert!(matches!(err, ExpandError::MalformedSyntax { .. }));
    }

    #[test]
    fn undefined_var_is_hard_error() {
        let vars = [];
        let err = expand("$AWS_KEY/x", &vars).unwrap_err();
        match err {
            ExpandError::UndefinedVar { name } => assert_eq!(name, "AWS_KEY"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn tilde_without_resolved_home_or_fallback_errors() {
        // No resolved HOME, no fallback — strict error.
        let vars = [];
        let err = expand("~/foo", &vars).unwrap_err();
        match err {
            ExpandError::UndefinedVar { name } => assert_eq!(name, "HOME"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Tilde falls back to the ambient `HOME` when the loadout
    /// doesn't declare one. This makes `~/dotfiles/...` work without
    /// requiring `HOME = { inherit = true }` in every loadout.
    #[test]
    fn tilde_uses_home_fallback_when_no_resolved_home() {
        let vars = [];
        let pat = expand_with_env_home("~/foo", &vars, "/ambient/home").unwrap();
        assert_eq!(pat, "/ambient/home/foo");
    }

    /// Resolved-vars HOME wins over the fallback — the explicit
    /// declaration is authoritative.
    #[test]
    fn resolved_home_wins_over_home_fallback() {
        let vars = [sv("HOME", "/explicit")];
        let pat = expand_with_env_home("~/foo", &vars, "/ambient").unwrap();
        assert_eq!(pat, "/explicit/foo");
    }

    /// `$HOME` (explicit substitution) does NOT consult the fallback.
    /// Only the tilde prefix gets the convenience.
    #[test]
    fn dollar_home_does_not_use_fallback() {
        let vars = [];
        let err = expand_with_env_home("$HOME/foo", &vars, "/ambient").unwrap_err();
        match err {
            ExpandError::UndefinedVar { name } => assert_eq!(name, "HOME"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn expanded_result_must_parse_as_glob() {
        // A `{` left over from an unbalanced literal in the *non-
        // substituted* portion makes the final string a malformed
        // glob. Surface as PostExpansionInvalid.
        let vars = [];
        let err = expand("/foo{", &vars).unwrap_err();
        assert!(
            matches!(err, ExpandError::PostExpansionInvalid(_)),
            "got: {err:?}"
        );
    }

    // ---- path normalization ----

    #[test]
    fn redundant_slashes_are_collapsed() {
        let vars = [];
        assert_eq!(expand("/foo//bar///baz", &vars).unwrap(), "/foo/bar/baz");
    }

    #[test]
    fn dot_components_are_dropped() {
        let vars = [];
        assert_eq!(expand("/foo/./bar/./baz", &vars).unwrap(), "/foo/bar/baz");
    }

    #[test]
    fn dot_files_are_not_dropped() {
        // `.config` is a filename starting with a dot, not a `.`
        // component. Must pass through.
        let vars = [sv("HOME", "/h")];
        assert_eq!(expand("~/.config/nvim", &vars).unwrap(), "/h/.config/nvim");
    }

    #[test]
    fn leading_slash_preserved() {
        let vars = [];
        assert_eq!(expand("/etc/foo", &vars).unwrap(), "/etc/foo");
    }

    #[test]
    fn trailing_slash_preserved() {
        let vars = [];
        assert_eq!(expand("/foo/bar/", &vars).unwrap(), "/foo/bar/");
    }

    #[test]
    fn relative_paths_are_normalized_but_still_rejected() {
        // Even after normalization (dropping `.` and redundant
        // slashes), the result is relative and fails the
        // absoluteness check.
        let vars = [];
        let err = expand("foo//./bar", &vars).unwrap_err();
        // The error carries the *normalized* form, not the raw input.
        assert!(
            matches!(err, ExpandError::NotAbsolute { ref pattern } if pattern == "foo/bar"),
            "got: {err:?}",
        );
    }

    #[test]
    fn glob_metacharacters_survive_normalization() {
        let vars = [];
        assert_eq!(
            expand("/etc//**/./*.conf", &vars).unwrap(),
            "/etc/**/*.conf"
        );
    }

    #[test]
    fn parent_dir_in_raw_pattern_errors() {
        let vars = [];
        let err = expand("/etc/../shadow", &vars).unwrap_err();
        assert!(
            matches!(err, ExpandError::PathTraversal { ref pattern } if pattern.contains("..")),
            "got: {err:?}",
        );
    }

    /// A `..` introduced via substitution is also rejected — the
    /// check runs on the fully-substituted string, so a malicious
    /// `$VAR` value can't smuggle traversal past the pattern check.
    #[test]
    fn parent_dir_introduced_by_substitution_errors() {
        let vars = [sv("SNEAKY", "/etc/..")];
        let err = expand("$SNEAKY/shadow", &vars).unwrap_err();
        assert!(
            matches!(err, ExpandError::PathTraversal { .. }),
            "got: {err:?}"
        );
    }

    // ---- absolute-only ----

    #[test]
    fn relative_pattern_is_rejected() {
        let vars = [];
        let err = expand("foo/bar/*.lua", &vars).unwrap_err();
        assert!(
            matches!(err, ExpandError::NotAbsolute { ref pattern } if pattern == "foo/bar/*.lua"),
            "got: {err:?}"
        );
    }

    /// Substitution that yields a relative result still trips the
    /// absoluteness check — the check runs on the final, expanded
    /// form.
    #[test]
    fn substitution_yielding_relative_pattern_is_rejected() {
        let vars = [sv("REL", "etc")];
        let err = expand("$REL/foo", &vars).unwrap_err();
        assert!(
            matches!(err, ExpandError::NotAbsolute { .. }),
            "got: {err:?}",
        );
    }

    /// Tilde expansion produces an absolute pattern when `HOME` is
    /// absolute (the normal case).
    #[test]
    fn tilde_form_with_absolute_home_passes_absoluteness_check() {
        let vars = [sv("HOME", "/home/u")];
        let pat = expand("~/foo", &vars).unwrap();
        assert_eq!(pat, "/home/u/foo");
    }

    /// Conversely, if `HOME` is relative the tilde expansion produces
    /// a relative pattern and is rejected. This is defensive — the
    /// vars gate should reject non-absolute HOME values upstream,
    /// but the absoluteness check here catches the case.
    #[test]
    fn tilde_with_relative_home_is_rejected() {
        let vars = [sv("HOME", "relative-home")];
        let err = expand("~/foo", &vars).unwrap_err();
        assert!(
            matches!(err, ExpandError::NotAbsolute { .. }),
            "got: {err:?}",
        );
    }

    // ---- expand_policy_pattern ----

    /// `expand_policy_pattern` accepts a non-absolute pattern — the
    /// whole point of the split from `expand_source`. `**/*.pem`
    /// means "any `.pem` at any depth" for matching purposes and
    /// never gets walked, so it doesn't need a root.
    #[test]
    fn policy_pattern_accepts_non_absolute_glob() {
        let vars: [ResolvedVar; 0] = [];
        let fs = expand_policy_pattern("**/*.pem", vars.as_slice(), None).unwrap();
        assert_eq!(fs.pattern(), "**/*.pem");
    }

    /// A `~/…` policy pattern still tilde-expands normally — matching
    /// user-owned paths is the common case.
    #[test]
    fn policy_pattern_expands_tilde() {
        let vars = [sv("HOME", "/home/u")];
        let fs = expand_policy_pattern("~/.ssh/**", vars.as_slice(), None).unwrap();
        assert_eq!(fs.pattern(), "/home/u/.ssh/**");
    }

    /// A path stored through [`literal_policy_pattern`] matches
    /// exactly itself — and, critically, nothing else. The unescaped
    /// forms of these fail in both directions: `/tmp/build*` matches
    /// every sibling, and `/home/d/proj[1]` matches nothing at all.
    #[test]
    fn a_literal_policy_pattern_matches_itself_and_only_itself() {
        let vars: [ResolvedVar; 0] = [];
        let cases: [(&str, &str); 5] = [
            // Wildcards: the over-match direction.
            ("/tmp/build*", "/tmp/build-someone-elses-project"),
            ("/tmp/proj?", "/tmp/projX"),
            // Brackets and braces: the matches-nothing direction.
            ("/home/d/proj[1]", "/home/d/proj1"),
            ("/home/d/{a,b}", "/home/d/a"),
            // The expander's own metacharacter, before globbing runs.
            ("/home/d/$HOME/proj", "/home/d//home/u/proj"),
        ];
        for (literal, sibling) in cases {
            let fs = expand_policy_pattern(&literal_policy_pattern(literal), vars.as_slice(), None)
                .unwrap_or_else(|e| panic!("{literal:?} should expand: {e:?}"));
            assert!(
                fs.is_match(literal),
                "{literal:?} should match itself (stored as {:?})",
                fs.pattern(),
            );
            assert!(
                !fs.is_match(sibling),
                "{literal:?} should not match {sibling:?} (stored as {:?})",
                fs.pattern(),
            );
        }
    }

    /// What storing the path raw would do, pinned so the reason for
    /// [`literal_policy_pattern`] is visible rather than folklore: one
    /// project's approval reaches another project entirely.
    #[test]
    fn an_unescaped_path_is_read_as_a_pattern_and_over_matches() {
        let vars: [ResolvedVar; 0] = [];
        let fs = expand_policy_pattern("/tmp/build*", vars.as_slice(), None).unwrap();
        assert!(
            fs.is_match("/tmp/build-someone-elses-project"),
            "this is the behaviour `literal_policy_pattern` exists to prevent",
        );
    }

    /// An ordinary path is stored unchanged, so escaping costs nothing
    /// in readability for the paths people actually have.
    #[test]
    fn a_literal_policy_pattern_leaves_an_ordinary_path_alone() {
        assert_eq!(
            literal_policy_pattern("/home/dev/my-project"),
            "/home/dev/my-project",
        );
    }

    /// Substitution and `..` normalization still apply — dropping
    /// the absoluteness check is the only relaxation.
    #[test]
    fn policy_pattern_still_rejects_parent_traversal() {
        let vars: [ResolvedVar; 0] = [];
        let err = expand_policy_pattern("a/../b/*.pem", vars.as_slice(), None).unwrap_err();
        assert!(
            matches!(err, ExpandError::PathTraversal { .. }),
            "got: {err:?}",
        );
    }
}
