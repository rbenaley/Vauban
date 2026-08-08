//! Portal binary CLI helpers (`vcp --help`, `vcp seed-data`).

/// True when the invocation asked for help (`-h`, `--help`, or `help`).
pub fn wants_help(args: &[String]) -> bool {
    args.iter()
        .any(|a| matches!(a.as_str(), "-h" | "--help" | "help"))
}

/// Full CLI usage for the HTTPS server and the `seed-data` command.
pub fn cli_usage() -> &'static str {
    "usage: vcp [options] | vcp <command>\n\
     \n\
     Server (default): load config, minimal empty-DB seed, serve HTTPS.\n\
     \n\
     Commands:\n\
       seed-data    Seed the database with test data (docs, builds, issues)\n\
     \n\
     Help: -h, --help, help\n"
}

/// First non-flag positional argument, if any.
pub fn first_command(args: &[String]) -> Option<&str> {
    args.iter()
        .map(String::as_str)
        .find(|a| !a.starts_with('-'))
}

#[cfg(test)]
mod tests {
    use super::{cli_usage, first_command, wants_help};

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
    fn cli_usage_mentions_seed_data_and_server() {
        let u = cli_usage();
        assert!(u.contains("seed-data"));
        assert!(!u.contains("import-pkgs"));
        assert!(u.contains("HTTPS"));
        assert!(u.contains("--help"));
    }

    #[test]
    fn first_command_skips_flags() {
        assert_eq!(first_command(&[]), None);
        assert_eq!(
            first_command(&[String::from("seed-data")]),
            Some("seed-data")
        );
        assert_eq!(
            first_command(&[String::from("--verbose"), String::from("seed-data")]),
            Some("seed-data")
        );
    }
}
