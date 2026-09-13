use std::env;
use std::process::Command;

fn main() {
    emit_git_hash();

    let mut config = topcoat::tailwind::BuildConfig::new().input("styles.css");

    if let Some(path) = env::var_os("TAILWIND_CLI") {
        config = config.executable(path);
    } else {
        #[cfg(target_os = "freebsd")]
        {
            config = config.executable(resolve_freebsd_tailwind_cli());
        }
    }

    // FreeBSD's pkg CLI is Node-based (not the GitHub standalone bundle), so
    // `@import "tailwindcss"` must resolve under the package root.
    #[cfg(target_os = "freebsd")]
    ensure_freebsd_tailwind_package();

    config.render().unwrap();
}

/// Short SHA for account / ops identity (`VCP — v0.1.1 [2745693a]`).
fn emit_git_hash() {
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=VCP_GIT_HASH={git_hash}");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/");
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

/// The FreeBSD port installs `tailwindcss` under `/usr/local/lib/node_modules`.
/// The Node CLI resolves `@import "tailwindcss"` from the Cargo package root,
/// so expose that package via a gitignored symlink.
#[cfg(target_os = "freebsd")]
fn ensure_freebsd_tailwind_package() {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    const SYSTEM_PKG: &str = "/usr/local/lib/node_modules/tailwindcss";

    if !Path::new(SYSTEM_PKG).is_dir() {
        panic!(
            "FreeBSD pkg tailwindcss4 is incomplete: missing {SYSTEM_PKG}. \
             Reinstall with `pkg install tailwindcss4`."
        );
    }

    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR must be set when running as a build script"),
    );
    let nm = manifest.join("node_modules");
    let link = nm.join("tailwindcss");

    if link.exists() {
        return;
    }
    if fs::symlink_metadata(&link).is_ok() {
        let _ = fs::remove_file(&link);
    }

    fs::create_dir_all(&nm).unwrap_or_else(|err| {
        panic!("failed to create {}: {err}", nm.display());
    });
    symlink(SYSTEM_PKG, &link).unwrap_or_else(|err| {
        panic!(
            "failed to symlink {} -> {SYSTEM_PKG}: {err}",
            link.display()
        );
    });
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
