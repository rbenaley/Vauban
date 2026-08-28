//! Privsep filesystem layout catalogue (issue #40).
//!
//! Single source of truth: [`CATALOGUE_SRC`] is `pkg/privsep_fs_layout.list`.
//! `+POST_INSTALL` applies it; the supervisor verifies it (production +
//! privsep only) and never calls `setfacl` / `chmod` / `chown`.

use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tracing::{error, info};

use crate::config::SupervisorConfig;

/// Compile-time catalogue (repo file, not the on-disk package copy).
pub const CATALOGUE_SRC: &str = include_str!("../../pkg/privsep_fs_layout.list");

/// Accounts expanded from `ALL` -- lock-step with `+PRE_INSTALL`.
pub const SVC_USERS: &[&str] = &[
    "vb-audit",
    "vb-vault",
    "vb-access",
    "vb-auth",
    "vb-ssh",
    "vb-rdp",
    "vb-web",
    "vb-iacs",
    "vb-mailer",
];

/// Directory vs regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    File,
}

/// Who receives an access ACE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclWho {
    None,
    All,
    Users(Vec<String>),
}

/// Presence requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryFlags {
    Required,
    IfExists,
}

/// One catalogue row after parse (path still contains `${PREFIX}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutEntry {
    pub kind: EntryKind,
    pub path: String,
    pub owner: String,
    pub group: String,
    pub mode: u32,
    pub acl_who: AclWho,
    pub ace: Option<String>,
    pub inherit_default: bool,
    pub flags: EntryFlags,
}

/// Observed metadata used by the pure evaluator (tests inject this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub exists: bool,
    pub is_dir: bool,
    pub owner: String,
    pub group: String,
    pub mode: u32,
    pub acl_users: BTreeSet<String>,
}

/// A single evaluate mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub path: String,
    pub detail: String,
}

impl LayoutEntry {
    /// Expand `ALL` / named users. Empty when `AclWho::None`.
    #[must_use]
    pub fn acl_users(&self) -> Vec<String> {
        match &self.acl_who {
            AclWho::None => Vec::new(),
            AclWho::All => SVC_USERS.iter().map(|s| (*s).to_string()).collect(),
            AclWho::Users(users) => users.clone(),
        }
    }

    /// Substitute `${PREFIX}` and return a filesystem path.
    #[must_use]
    pub fn resolved_path(&self, prefix: &Path) -> PathBuf {
        PathBuf::from(self.path.replace("${PREFIX}", &prefix.to_string_lossy()))
    }

    /// Serialise back to a catalogue line (tests / proptest round-trip).
    #[cfg(test)]
    #[must_use]
    pub fn to_line(&self) -> String {
        let kind = match self.kind {
            EntryKind::Dir => "dir",
            EntryKind::File => "file",
        };
        let acl_who = match &self.acl_who {
            AclWho::None => "-".to_string(),
            AclWho::All => "ALL".to_string(),
            AclWho::Users(users) => users.join(","),
        };
        let ace = self.ace.as_deref().unwrap_or("-");
        let inherit = if self.inherit_default { "fd:r" } else { "none" };
        let flags = match self.flags {
            EntryFlags::Required => "required",
            EntryFlags::IfExists => "if_exists",
        };
        format!(
            "{kind} {} {} {} {:04o} {acl_who} {ace} {inherit} {flags}",
            self.path, self.owner, self.group, self.mode
        )
    }
}

/// Parse the catalogue text. Blank lines and `#` comments are ignored.
pub fn parse_catalogue(src: &str) -> Result<Vec<LayoutEntry>> {
    let mut entries = Vec::new();
    for (idx, raw) in src.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let entry = parse_line(line).with_context(|| format!("catalogue line {}", idx + 1))?;
        entries.push(entry);
    }
    if entries.is_empty() {
        bail!("privsep layout catalogue is empty");
    }
    Ok(entries)
}

fn parse_line(line: &str) -> Result<LayoutEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() != 9 {
        bail!("expected 9 fields, got {}: {line}", fields.len());
    }
    let kind = match fields[0] {
        "dir" => EntryKind::Dir,
        "file" => EntryKind::File,
        other => bail!("unknown kind {other}"),
    };
    let mode = u32::from_str_radix(fields[4].trim_start_matches("0o"), 8)
        .or_else(|_| u32::from_str_radix(fields[4], 8))
        .with_context(|| format!("invalid mode {}", fields[4]))?;
    let acl_who = match fields[5] {
        "-" => AclWho::None,
        "ALL" => AclWho::All,
        names => AclWho::Users(names.split(',').map(str::to_string).collect()),
    };
    let ace = match fields[6] {
        "-" => None,
        perm => Some(perm.to_string()),
    };
    let inherit_default = match fields[7] {
        "none" => false,
        "fd:r" => true,
        other => bail!("unknown inherit {other}"),
    };
    let flags = match fields[8] {
        "required" => EntryFlags::Required,
        "if_exists" => EntryFlags::IfExists,
        other => bail!("unknown flags {other}"),
    };
    if ace.is_none() && !matches!(acl_who, AclWho::None) {
        bail!("acl_who set but ace is -");
    }
    if ace.is_some() && matches!(acl_who, AclWho::None) {
        bail!("ace set but acl_who is -");
    }
    Ok(LayoutEntry {
        kind,
        path: fields[1].to_string(),
        owner: fields[2].to_string(),
        group: fields[3].to_string(),
        mode,
        acl_who,
        ace,
        inherit_default,
        flags,
    })
}

/// Compare one entry to an observation. Pure: no I/O.
#[must_use]
pub fn evaluate(entry: &LayoutEntry, path: &str, observed: &Observed) -> Vec<Violation> {
    let mut out = Vec::new();
    if !observed.exists {
        if entry.flags == EntryFlags::IfExists {
            return out;
        }
        out.push(Violation {
            path: path.to_string(),
            detail: "required path is missing".to_string(),
        });
        return out;
    }
    let expect_dir = matches!(entry.kind, EntryKind::Dir);
    if observed.is_dir != expect_dir {
        out.push(Violation {
            path: path.to_string(),
            detail: format!(
                "kind mismatch: expected {} got {}",
                if expect_dir { "dir" } else { "file" },
                if observed.is_dir { "dir" } else { "file" }
            ),
        });
    }
    if observed.owner != entry.owner {
        out.push(Violation {
            path: path.to_string(),
            detail: format!("owner: expected {} got {}", entry.owner, observed.owner),
        });
    }
    if observed.group != entry.group {
        out.push(Violation {
            path: path.to_string(),
            detail: format!("group: expected {} got {}", entry.group, observed.group),
        });
    }
    if observed.mode & 0o777 != entry.mode & 0o777 {
        out.push(Violation {
            path: path.to_string(),
            detail: format!(
                "mode: expected {:04o} got {:04o}",
                entry.mode & 0o777,
                observed.mode & 0o777
            ),
        });
    }
    for user in entry.acl_users() {
        if !observed.acl_users.contains(&user) {
            out.push(Violation {
                path: path.to_string(),
                detail: format!("missing ACL for user:{user}"),
            });
        }
    }
    out
}

/// Whether the boot gate runs (production AND privsep).
#[must_use]
pub fn should_check_layout(is_production: bool, privsep: bool) -> bool {
    is_production && privsep
}

/// Fail-closed boot check. Verify-only: never chmod / chown / setfacl.
pub fn check_privsep_fs_layout(config: &SupervisorConfig) -> Result<()> {
    if !should_check_layout(
        config.environment.is_production(),
        config.supervisor.privsep,
    ) {
        info!("Skipping privsep FS layout check (not production+privsep)");
        return Ok(());
    }

    let config_dir = SupervisorConfig::find_config_dir()?;
    let prefix = prefix_from_config_dir(&config_dir);
    let entries = parse_catalogue(CATALOGUE_SRC)?;
    let mut violations = Vec::new();
    for entry in &entries {
        let path = entry.resolved_path(&prefix);
        let observed = observe_path(&path);
        violations.extend(evaluate(entry, &path.display().to_string(), &observed));
    }

    if violations.is_empty() {
        info!(
            prefix = %prefix.display(),
            entries = entries.len(),
            "Privsep filesystem layout matches the catalogue"
        );
        return Ok(());
    }

    for v in &violations {
        error!(path = %v.path, detail = %v.detail, "privsep filesystem layout mismatch");
    }
    bail!(
        "refusing to start: privsep filesystem layout does not match \
         pkg/privsep_fs_layout.list ({} mismatch(es)). Do not cp/sed-i \
         vauban.conf (that drops NFSv4 ACEs). Re-apply the catalogue: \
         . /usr/local/share/vauban/privsep_fs_apply.sh && \
         apply_privsep_layout /usr/local /usr/local/share/vauban/privsep_fs_layout.list \
         (or pkg reinstall). First mismatch: {} -- {}",
        violations.len(),
        violations[0].path,
        violations[0].detail
    )
}

fn prefix_from_config_dir(config_dir: &Path) -> PathBuf {
    if config_dir.ends_with("etc/vauban")
        && let Some(etc) = config_dir.parent()
        && let Some(prefix) = etc.parent()
    {
        return prefix.to_path_buf();
    }
    PathBuf::from("/usr/local")
}

fn observe_path(path: &Path) -> Observed {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => {
            return Observed {
                exists: false,
                is_dir: false,
                owner: String::new(),
                group: String::new(),
                mode: 0,
                acl_users: BTreeSet::new(),
            };
        }
    };
    #[cfg(unix)]
    let (owner, group, mode) = {
        use std::os::unix::fs::MetadataExt;
        let uid = meta.uid();
        let gid = meta.gid();
        let owner = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| uid.to_string());
        let group = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
            .ok()
            .flatten()
            .map(|g| g.name)
            .unwrap_or_else(|| gid.to_string());
        (owner, group, meta.mode() & 0o777)
    };
    #[cfg(not(unix))]
    let (owner, group, mode) = (String::new(), String::new(), 0);

    Observed {
        exists: true,
        is_dir: meta.is_dir(),
        owner,
        group,
        mode,
        acl_users: observe_acl_users(path),
    }
}

fn observe_acl_users(path: &Path) -> BTreeSet<String> {
    let output = std::process::Command::new("getfacl").arg(path).output();
    let Ok(out) = output else {
        return BTreeSet::new();
    };
    if !out.status.success() {
        return BTreeSet::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_getfacl_users(&text)
}

fn parse_getfacl_users(text: &str) -> BTreeSet<String> {
    let mut users = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("user:") {
            let name = rest.split(':').next().unwrap_or("");
            if !name.is_empty() && name != "owner@" {
                users.insert(name.to_string());
            }
        }
    }
    users
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn shipped() -> Vec<LayoutEntry> {
        parse_catalogue(CATALOGUE_SRC).expect("shipped catalogue")
    }

    #[test]
    fn parse_shipped_catalogue() {
        let entries = shipped();
        assert_eq!(entries.len(), 8);
        assert!(
            entries
                .iter()
                .any(|e| e.path.ends_with("vauban.conf") && e.mode == 0o600)
        );
        let conf = entries
            .iter()
            .find(|e| e.path.ends_with("vauban.conf"))
            .expect("conf");
        assert_eq!(conf.acl_users().len(), SVC_USERS.len());
        assert_eq!(conf.flags, EntryFlags::Required);
    }

    #[test]
    fn parse_rejects_malformed_line() {
        let err = parse_catalogue("dir too few\n").unwrap_err();
        let full = format!("{err:#}");
        assert!(full.contains("expected 9 fields"), "{full}");
    }

    #[test]
    fn prefix_substitution() {
        let e =
            parse_line("file ${PREFIX}/etc/vauban/vauban.conf root wheel 0600 ALL r none required")
                .expect("line");
        assert_eq!(
            e.resolved_path(Path::new("/usr/local")),
            PathBuf::from("/usr/local/etc/vauban/vauban.conf")
        );
    }

    #[test]
    fn all_expands_to_svc_users() {
        let e = parse_line("file ${PREFIX}/x root wheel 0600 ALL r none required").expect("line");
        assert_eq!(
            e.acl_users(),
            SVC_USERS
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn if_exists_missing_is_ok() {
        let e = parse_line("file /tmp/nope root wheel 0440 - - none if_exists").expect("line");
        let observed = Observed {
            exists: false,
            is_dir: false,
            owner: String::new(),
            group: String::new(),
            mode: 0,
            acl_users: BTreeSet::new(),
        };
        assert!(evaluate(&e, "/tmp/nope", &observed).is_empty());
    }

    #[test]
    fn required_missing_is_err() {
        let e = parse_line("file /tmp/nope root wheel 0600 ALL r none required").expect("line");
        let observed = Observed {
            exists: false,
            is_dir: false,
            owner: String::new(),
            group: String::new(),
            mode: 0,
            acl_users: BTreeSet::new(),
        };
        assert!(!evaluate(&e, "/tmp/nope", &observed).is_empty());
    }

    #[test]
    fn evaluate_rejects_wrong_mode_owner_ace() {
        let e = parse_line("file /x root wheel 0600 vb-web r none required").expect("line");
        let observed = Observed {
            exists: true,
            is_dir: false,
            owner: "root".into(),
            group: "wheel".into(),
            mode: 0o644,
            acl_users: BTreeSet::new(),
        };
        let v = evaluate(&e, "/x", &observed);
        assert!(v.iter().any(|x| x.detail.contains("mode")));
        assert!(v.iter().any(|x| x.detail.contains("missing ACL")));
    }

    #[test]
    fn evaluate_ok_matching() {
        let e = parse_line("file /x root wheel 0600 vb-web r none required").expect("line");
        let observed = Observed {
            exists: true,
            is_dir: false,
            owner: "root".into(),
            group: "wheel".into(),
            mode: 0o600,
            acl_users: BTreeSet::from(["vb-web".into()]),
        };
        assert!(evaluate(&e, "/x", &observed).is_empty());
    }

    #[test]
    fn should_check_only_production_and_privsep() {
        assert!(should_check_layout(true, true));
        assert!(!should_check_layout(true, false));
        assert!(!should_check_layout(false, true));
        assert!(!should_check_layout(false, false));
    }

    #[test]
    fn parse_getfacl_users_nfsv4_and_posix() {
        let nfs = "\
# file: vauban.conf
owner@:rw-p--aARWcCos:-------:allow
user:vb-web:r-------------:-------:allow
user:vb-ssh:r-------------:-------:allow
";
        let users = parse_getfacl_users(nfs);
        assert!(users.contains("vb-web"));
        assert!(users.contains("vb-ssh"));
        assert!(!users.contains("owner@"));

        let posix = "user:vb-access:r--\n";
        assert!(parse_getfacl_users(posix).contains("vb-access"));
    }

    #[test]
    fn to_line_round_trips_shipped() {
        for e in shipped() {
            let again = parse_line(&e.to_line()).expect("round-trip");
            assert_eq!(again, e);
        }
    }

    #[test]
    fn prefix_from_standard_config_dir() {
        assert_eq!(
            prefix_from_config_dir(Path::new("/usr/local/etc/vauban")),
            PathBuf::from("/usr/local")
        );
    }

    #[test]
    fn battle_parse_and_evaluate_are_deterministic() {
        let n = 8;
        let barrier = Arc::new(Barrier::new(n));
        let mut handles = Vec::new();
        for _ in 0..n {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let entries = parse_catalogue(CATALOGUE_SRC).expect("parse");
                let e = &entries[3];
                let observed = Observed {
                    exists: true,
                    is_dir: false,
                    owner: e.owner.clone(),
                    group: e.group.clone(),
                    mode: e.mode,
                    acl_users: e.acl_users().into_iter().collect(),
                };
                evaluate(e, "p", &observed)
            }));
        }
        let first = handles.pop().expect("one").join().expect("thread");
        for h in handles {
            assert_eq!(h.join().expect("thread"), first);
        }
        assert!(first.is_empty());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn to_line_round_trips_constructed(
            is_dir in proptest::bool::ANY,
            mode in 0u32..=0o777,
        ) {
            let kind = if is_dir { "dir" } else { "file" };
            let line = format!(
                "{kind} ${{PREFIX}}/x root wheel {mode:04o} ALL r none required"
            );
            let parsed = parse_line(&line).expect("parse");
            let again = parse_line(&parsed.to_line()).expect("round-trip");
            prop_assert_eq!(parsed, again);
        }

        #[test]
        fn evaluate_refuses_iff_observed_differs(
            mode_ok in proptest::bool::ANY,
            owner_ok in proptest::bool::ANY,
            ace_ok in proptest::bool::ANY,
        ) {
            let e = parse_line("file /x root wheel 0600 vb-web r none required").expect("line");
            let observed = Observed {
                exists: true,
                is_dir: false,
                owner: if owner_ok { "root" } else { "nobody" }.into(),
                group: "wheel".into(),
                mode: if mode_ok { 0o600 } else { 0o644 },
                acl_users: if ace_ok {
                    BTreeSet::from(["vb-web".into()])
                } else {
                    BTreeSet::new()
                },
            };
            let v = evaluate(&e, "/x", &observed);
            let expect_err = !mode_ok || !owner_ok || !ace_ok;
            prop_assert_eq!(!v.is_empty(), expect_err);
        }
    }
}
