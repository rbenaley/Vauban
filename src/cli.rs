//! Portal binary CLI helpers (`vcp --help`, `vcp seed-data`, `vcp migration`, version).
//!
//! Help layout and ANSI styles mirror clap's default `Styles::styled()`:
//! - section headers (`Usage:`, `Commands:`, `Options:`) — bold + underline
//! - literals (bin name, commands, flags) — bold
//! - placeholders (`<COMMAND>`, `<PATH>`, …) — underline

use std::io::{self, IsTerminal};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const BOLD_UNDERLINE: &str = "\x1b[1;4m";
const UNDERLINE: &str = "\x1b[4m";

/// True when the invocation asked for help (`-h`, `--help`, or `help`).
pub fn wants_help(args: &[String]) -> bool {
    args.iter()
        .any(|a| matches!(a.as_str(), "-h" | "--help" | "help"))
}

/// True when the invocation asked for version (`-V` or `--version`).
pub fn wants_version(args: &[String]) -> bool {
    args.iter()
        .any(|a| matches!(a.as_str(), "-V" | "--version"))
}

/// `vcp 0.1.3`-style line (crate version).
pub fn version_line(bin: &str) -> String {
    format!("{bin} {}", env!("CARGO_PKG_VERSION"))
}

/// Whether help/version styling should emit ANSI (TTY / `CLICOLOR_FORCE`).
pub fn stdout_wants_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var_os("CLICOLOR_FORCE")
        .map(|v| v != "0")
        .unwrap_or(false)
    {
        return true;
    }
    io::stdout().is_terminal()
}

/// Clap-like help painter.
#[derive(Debug, Clone, Copy)]
pub struct HelpStyle {
    color: bool,
}

impl HelpStyle {
    pub fn auto() -> Self {
        Self {
            color: stdout_wants_color(),
        }
    }

    pub fn plain() -> Self {
        Self { color: false }
    }

    pub fn always() -> Self {
        Self { color: true }
    }

    /// Section heading (`Usage:`, `Commands:`, `Options:`) — bold + underline.
    pub fn header(self, s: &str) -> String {
        self.paint(BOLD_UNDERLINE, s)
    }

    /// Literal syntax (`vcp`, `seed-data`, `-h, --help`) — bold.
    pub fn literal(self, s: &str) -> String {
        self.paint(BOLD, s)
    }

    /// Placeholder (`<COMMAND>`, `<PATH>`) — underline.
    pub fn placeholder(self, s: &str) -> String {
        self.paint(UNDERLINE, s)
    }

    fn paint(self, code: &str, s: &str) -> String {
        if self.color {
            format!("{code}{s}{RESET}")
        } else {
            s.to_owned()
        }
    }
}

/// Pad `token` to `width`, then apply literal (bold) styling.
pub fn styled_literal_col(style: HelpStyle, token: &str, width: usize) -> String {
    style.literal(&format!("{token:<width$}"))
}

/// Full CLI usage for the HTTPS server and lab / migration commands.
pub fn cli_usage() -> String {
    cli_usage_with(HelpStyle::auto())
}

/// Same as [`cli_usage`] with an explicit style (tests / non-TTY).
pub fn cli_usage_with(style: HelpStyle) -> String {
    let usage = style.header("Usage:");
    let commands = style.header("Commands:");
    let options = style.header("Options:");
    let bin = style.literal("vcp");
    let cmd = style.placeholder("<COMMAND>");
    let seed = styled_literal_col(style, "seed-data", 18);
    let docs_export = styled_literal_col(style, "docs export", 18);
    let docs_import = styled_literal_col(style, "docs import", 18);
    let migration = styled_literal_col(style, "migration", 18);
    let help_cmd = styled_literal_col(style, "help", 18);
    let dir = style.placeholder("<DIR>");
    let opt_help = styled_literal_col(style, "-h, --help", 14);
    let opt_ver = styled_literal_col(style, "-V, --version", 14);
    format!(
        "\
Vauban Customer Portal - HTTPS server and lab commands

{usage} {bin} {cmd}

When no command is given, load config, minimally seed an empty DB, and serve HTTPS.

{commands}
  {seed}  Seed the database with test data (docs, builds, issues)
  {docs_export} {dir}  Export DocArticle rows as Markdown + frontmatter
  {docs_import} {dir}  Import Markdown bundle (upsert by slug+version)
  {migration}  Database migrations (apply, generate, …)
  {help_cmd}  Print this message

{options}
  {opt_help}  Print help
  {opt_ver}  Print version
"
    )
}

/// First non-flag positional argument, if any.
pub fn first_command(args: &[String]) -> Option<&str> {
    args.iter()
        .map(String::as_str)
        .find(|a| !a.starts_with('-'))
}

/// Positional args after the first command (skips leading flags before command).
pub fn command_tail(args: &[String]) -> Vec<&str> {
    let Some(idx) = args.iter().position(|a| !a.starts_with('-')) else {
        return Vec::new();
    };
    args[idx + 1..]
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wants_help_recognizes_flags() {
        assert!(wants_help(&[String::from("--help")]));
        assert!(wants_help(&[String::from("-h")]));
        assert!(wants_help(&[String::from("help")]));
        assert!(wants_help(&[
            String::from("seed-data"),
            String::from("--help")
        ]));
        assert!(!wants_help(&[String::from("seed-data")]));
        assert!(!wants_help(&[]));
    }

    #[test]
    fn wants_version_recognizes_flags() {
        assert!(wants_version(&[String::from("-V")]));
        assert!(wants_version(&[String::from("--version")]));
        assert!(!wants_version(&[String::from("--help")]));
        assert!(!wants_version(&[]));
    }

    #[test]
    fn version_line_uses_pkg_version() {
        let line = version_line("vcp");
        assert!(line.starts_with("vcp "));
        assert!(line.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn command_tail_skips_command_and_flags() {
        let args = vec!["docs".to_owned(), "export".to_owned(), "./out".to_owned()];
        assert_eq!(command_tail(&args), vec!["export", "./out"]);
    }

    #[test]
    fn cli_usage_plain_matches_clap_layout() {
        let u = cli_usage_with(HelpStyle::plain());
        assert!(u.starts_with("Vauban Customer Portal"));
        assert!(u.contains("Usage: vcp"));
        assert!(u.contains("<COMMAND>"));
        assert!(!u.contains("usage:"));
        assert!(u.contains("Commands:"));
        assert!(u.contains("docs export"));
        assert!(u.contains("docs import"));
        assert!(u.contains("Options:"));
        assert!(u.contains("seed-data"));
        assert!(u.contains("migration"));
        assert!(!u.contains("import-pkgs"));
        assert!(!u.contains("vcp-cli"));
        assert!(u.contains("HTTPS"));
        assert!(u.contains("-h, --help"));
        assert!(u.contains("-V, --version"));
        assert!(!u.contains("Help: -h"));
        assert!(!u.contains('\u{1b}'));
    }

    #[test]
    fn cli_usage_color_applies_bold_and_underline() {
        let u = cli_usage_with(HelpStyle::always());
        assert!(u.contains(BOLD_UNDERLINE), "headers must be bold+underline");
        assert!(u.contains(BOLD), "literals must be bold");
        assert!(u.contains(UNDERLINE), "placeholders must be underline");
        assert!(u.contains(RESET));
        assert!(u.contains("-V, --version"));
    }

    #[test]
    fn first_command_skips_flags() {
        assert_eq!(first_command(&[]), None);
        assert_eq!(
            first_command(&[String::from("seed-data")]),
            Some("seed-data")
        );
        assert_eq!(
            first_command(&[String::from("migration")]),
            Some("migration")
        );
        assert_eq!(
            first_command(&[String::from("--verbose"), String::from("seed-data")]),
            Some("seed-data")
        );
    }
}
