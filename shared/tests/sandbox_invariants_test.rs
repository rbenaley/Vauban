//! Source-grep invariant pins for the multi-OS sandbox abstraction.
//!
//! These run via `cargo test` on every platform (they only read source
//! text, no syscalls), so they hold on the FreeBSD integration server and
//! on developer machines alike. A standalone bash mirror lives at
//! `shared/scripts/check_no_new_objects_after_sandbox.sh`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// ---- service entrypoints ----
const AUTH: &str = include_str!("../../vauban-auth/src/main.rs");
const VAULT: &str = include_str!("../../vauban-vault/src/main.rs");
const ACCESS: &str = include_str!("../../vauban-access/src/main.rs");
const AUDIT: &str = include_str!("../../vauban-audit/src/main.rs");
const PROXY_SSH: &str = include_str!("../../vauban-proxy-ssh/src/main.rs");
const PROXY_IACS: &str = include_str!("../../vauban-proxy-iacs/src/main.rs");
const PROXY_RDP: &str = include_str!("../../vauban-proxy-rdp/src/main.rs");
const WEB: &str = include_str!("../../vauban-web/src/main.rs");

// ---- sandbox backends ----
const SB_MOD: &str = include_str!("../src/sandbox/mod.rs");
const SB_CAPSICUM: &str = include_str!("../src/sandbox/capsicum.rs");
const SB_LINUX: &str = include_str!("../src/sandbox/linux.rs");
const SB_OPENBSD: &str = include_str!("../src/sandbox/openbsd.rs");
const SB_NOOP: &str = include_str!("../src/sandbox/noop.rs");

/// The 7 IPC/proxy services that build their sandbox from the raw-fd
/// `setup_service_sandbox*` helpers.
const RAW_FD_SERVICES: &[(&str, &str)] = &[
    ("vauban-auth", AUTH),
    ("vauban-vault", VAULT),
    ("vauban-access", ACCESS),
    ("vauban-audit", AUDIT),
    ("vauban-proxy-ssh", PROXY_SSH),
    ("vauban-proxy-iacs", PROXY_IACS),
    ("vauban-proxy-rdp", PROXY_RDP),
];

const ALL_SERVICES: &[(&str, &str)] = &[
    ("vauban-auth", AUTH),
    ("vauban-vault", VAULT),
    ("vauban-access", ACCESS),
    ("vauban-audit", AUDIT),
    ("vauban-proxy-ssh", PROXY_SSH),
    ("vauban-proxy-iacs", PROXY_IACS),
    ("vauban-proxy-rdp", PROXY_RDP),
    ("vauban-web", WEB),
];

/// PORTE UNIQUE: the OS-specific sandbox primitives must live ONLY under
/// `shared/src/sandbox/`. No service may reach for `pledge`/`unveil`/
/// `landlock`/`seccompiler`/`restrict_self` directly -- everything goes
/// through `enter_sandbox` / `setup_service_sandbox*`.
#[test]
fn sandbox_primitives_only_under_sandbox_module() {
    const PRIMITIVES: &[&str] = &[
        "pledge(",
        "unveil(",
        "landlock::",
        "seccompiler::",
        "restrict_self(",
        "enter_capability_mode(",
    ];
    for (name, src) in ALL_SERVICES {
        for prim in PRIMITIVES {
            assert!(
                !src.contains(prim),
                "{name}/src/main.rs must NOT call the sandbox primitive `{prim}` \
                 directly -- route it through shared::sandbox. The OS gate is \
                 the single source of truth (defense in depth + auditability)."
            );
        }
    }
    // Sanity: the gate primitives DO live in their backend.
    assert!(SB_OPENBSD.contains("pledge(") && SB_OPENBSD.contains("unveil("));
    assert!(SB_LINUX.contains("landlock::") && SB_LINUX.contains("seccompiler::"));
    assert!(SB_CAPSICUM.contains("capsicum::enter("));
}

/// EXHAUSTIVENESS: each backend matches `Resource` exhaustively (no `_ =>`
/// wildcard). Adding a `Resource` variant must fail to compile until every
/// backend handles it -- a wildcard arm would silently skip the new
/// resource and weaken (or break) the sandbox.
#[test]
fn backends_have_no_wildcard_match_arm() {
    for (name, src) in [
        ("capsicum.rs", SB_CAPSICUM),
        ("linux.rs", SB_LINUX),
        ("openbsd.rs", SB_OPENBSD),
        ("noop.rs", SB_NOOP),
    ] {
        for line in src.lines() {
            let code = line.trim_start();
            // Ignore doc/line comments (they legitimately mention `_ =>`).
            if code.starts_with("//") || code.starts_with('*') {
                continue;
            }
            assert!(
                !line.contains("_ =>"),
                "shared/src/sandbox/{name} must not use a `_ =>` wildcard arm: \
                 the Resource match must stay exhaustive so a new variant is a \
                 compile error until handled.\nOffending line: {}",
                line.trim()
            );
        }
    }
}

/// The "without sandbox" operator log line may be emitted ONLY by the noop
/// (development) backend. A service or a real backend logging it would mean
/// the process is running unconfined in production.
#[test]
fn without_sandbox_log_only_in_noop() {
    // The exact operator log literal emitted by the noop backend.
    const LOG: &str = "Running without sandbox";
    assert!(SB_NOOP.contains(LOG));
    for src in [SB_MOD, SB_CAPSICUM, SB_LINUX, SB_OPENBSD] {
        assert!(!src.contains(LOG), "only noop.rs may log \"{LOG}\"");
    }
    for (name, src) in ALL_SERVICES {
        assert!(
            !src.contains(LOG),
            "{name}/src/main.rs must not log \"{LOG}\" -- that signal belongs \
             to the dev-only noop backend."
        );
    }
}

/// SINGLE GATE: each raw-fd service calls a `setup_service_sandbox*` helper
/// EXACTLY once; web calls `shared::sandbox::enter_sandbox` exactly once.
#[test]
fn single_sandbox_gate_per_service() {
    for (name, src) in RAW_FD_SERVICES {
        // Count actual call sites by the contiguous `fn-name + '('` token,
        // which rustfmt never splits across lines (unlike a leading `=`,
        // which it may wrap onto its own line). Self-test string mentions
        // (`.find("capsicum::setup_service_sandbox")`, doc literals) are
        // followed by `"` or `.`, never `(`, so they are excluded.
        let count = src.matches("capsicum::setup_service_sandbox(").count()
            + src
                .matches("capsicum::setup_service_sandbox_extended(")
                .count()
            + src
                .matches("capsicum::setup_service_sandbox_with_listeners(")
                .count();
        assert_eq!(
            count, 1,
            "{name}/src/main.rs must call setup_service_sandbox* EXACTLY once \
             (found {count}); a second post-sandbox call is a red flag."
        );
    }
    let web_count = WEB.matches("shared::sandbox::enter_sandbox(").count();
    assert_eq!(
        web_count, 1,
        "vauban-web/src/main.rs must call shared::sandbox::enter_sandbox EXACTLY once"
    );
}

/// TYPESTATE: the `Entered` witness is threaded into the service main loop /
/// server, so running the loop without entering the sandbox is a compile
/// error. The raw-fd services thread `_sealed: ...Entered` into `main_loop`;
/// web binds the witness and holds it across `serve`.
#[test]
fn entered_witness_is_threaded() {
    for (name, src) in RAW_FD_SERVICES {
        assert!(
            src.contains("capsicum::Entered"),
            "{name}/src/main.rs must thread the sandbox `Entered` witness into \
             its main_loop (typestate gate)."
        );
    }
    assert!(
        WEB.contains("let _sealed = enter_sandbox("),
        "vauban-web must bind the Entered witness returned by enter_sandbox \
         and hold it across serve()."
    );
}

/// NO NEW SOCKETS AFTER THE GATE: no raw `TcpStream::connect` /
/// `TcpListener::bind` may appear AFTER the sandbox call in a service
/// `main.rs` (the supervisor brokers every upstream fd via SCM_RIGHTS).
/// A legitimate exception must be annotated `// allow-post-sandbox: <reason>`.
#[test]
fn no_direct_tcp_after_sandbox_gate() {
    const FORBIDDEN: &[&str] = &["TcpStream::connect", "TcpListener::bind"];
    for (name, src) in RAW_FD_SERVICES {
        let gate = src
            .find("setup_service_sandbox")
            .unwrap_or_else(|| panic!("{name} must call setup_service_sandbox"));
        let post = &src[gate..];
        for line in post.lines() {
            if line.contains("// allow-post-sandbox") {
                continue;
            }
            for pat in FORBIDDEN {
                assert!(
                    !line.contains(pat),
                    "{name}/src/main.rs: `{pat}` appears AFTER the sandbox gate. \
                     The supervisor must broker every socket via SCM_RIGHTS. \
                     If this is genuinely safe, annotate the line with \
                     `// allow-post-sandbox: <reason>`.\nOffending line: {}",
                    line.trim()
                );
            }
        }
    }
}
