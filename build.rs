use std::env;

fn main() {
    let mut config = topcoat::tailwind::BuildConfig::new().input("styles.css");

    if let Some(path) = env::var_os("TAILWIND_CLI") {
        config = config.executable(path);
    } else {
        #[cfg(target_os = "freebsd")]
        {
            config = config.executable(resolve_freebsd_tailwind_cli());
        }
    }

    config.render().unwrap();
}

/// FreeBSD has no GitHub standalone Tailwind asset. Prefer the `tailwindcss4`
/// pkg path, then `PATH`, then fail with an install hint.
#[cfg(target_os = "freebsd")]
fn resolve_freebsd_tailwind_cli() -> std::path::PathBuf {
    use std::path::{Path, PathBuf};

    const PKG_PATH: &str = "/usr/local/bin/tailwindcss";
    if Path::new(PKG_PATH).is_file() {
        return PathBuf::from(PKG_PATH);
    }
    for name in ["tailwindcss", "tailwind"] {
        if let Some(path) = find_on_path(name) {
            return path;
        }
    }
    panic!(
        "Tailwind CLI not found on FreeBSD. Install with `pkg install \
         tailwindcss4` (provides {PKG_PATH}), or set TAILWIND_CLI to the \
         executable path."
    );
}

#[cfg(target_os = "freebsd")]
fn find_on_path(name: &str) -> Option<std::path::PathBuf> {
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
