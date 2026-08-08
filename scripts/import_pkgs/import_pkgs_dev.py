#!/usr/bin/env python3
"""Dev/testing-only FreeBSD .pkg + notes MD importer for VCP.

Writes Postgres (`releases`, `storage_objects`), blob files under
`{blob_path}/releases/{id}.pkg`, and helper SoT rows in
`{blob_path}/meta.sqlite`. Does **not** call `vcp`, `cargo`, or
`vcp-store` IPC.

Stop the portal (`just run`) before importing so `meta.sqlite` is not
open concurrently.

Usage (from repo root)::

    python3 scripts/import_pkgs/import_pkgs_dev.py
    python3 scripts/import_pkgs/import_pkgs_dev.py --pkgs-dir ~/Downloads \\
        --notes scripts/import_pkgs/vauban_release_notes_from_git_2026-08-08.md

Deps: Python 3.11+ (tomllib), psycopg or psycopg2, zstandard.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import lzma
import os
import sqlite3
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, List, Optional, Tuple

try:
    import tomllib
except ImportError:  # pragma: no cover
    print("error: Python 3.11+ required (tomllib)", file=sys.stderr)
    sys.exit(2)


def _require_zstd():
    try:
        import zstandard as zstd  # type: ignore
    except ImportError:  # pragma: no cover
        die("install zstandard (`pip install zstandard`)")
    return zstd


def connect_pg(url: str):
    try:
        import psycopg

        return psycopg.connect(url)
    except ImportError:
        pass
    try:
        import psycopg2  # type: ignore

        return psycopg2.connect(url)
    except ImportError:  # pragma: no cover
        die("install psycopg or psycopg2 (`pip install psycopg[binary]`)")

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_NOTES = SCRIPT_DIR / "vauban_release_notes_from_git_2026-08-08.md"
DEFAULT_CONFIG = REPO_ROOT / "config" / "development.toml"
DEFAULT_PKGS_DIR = Path.home() / "Downloads"
DEFAULT_DB_URL = "postgresql://postgres@localhost/vcp"
DEFAULT_BLOB = "vcp-storage"
DEFAULT_PID = "/tmp/vcp.pid"

RELEASE_STATUS_PUBLISHED = "PUBLISHED"
RELEASE_GA_ORG_ID = 0
STORAGE_SCOPE_RELEASE = "release"
STORAGE_ORG_NONE = 0

META_OBJECTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
    scope TEXT NOT NULL,
    object_key TEXT NOT NULL,
    org_id TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    ext TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (scope, object_key)
);
"""


@dataclass(frozen=True)
class NotesSection:
    version: str
    released_on: str
    notes: str


@dataclass(frozen=True)
class SortFields:
    v_major: int
    v_minor: int
    v_patch: int
    has_client_suffix: int
    client_suffix: str


@dataclass(frozen=True)
class LabConfig:
    environment: str
    database_url: str
    blob_path: Path
    pid_file: Path


def die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def load_toml(path: Path) -> Dict[str, Any]:
    with path.open("rb") as f:
        return tomllib.load(f)


def resolve_config(config_path: Path, pid_override: Optional[Path]) -> LabConfig:
    data: Dict[str, Any] = {}
    if config_path.is_file():
        data = load_toml(config_path)
    env = str(
        os.environ.get("VCP_ENVIRONMENT")
        or data.get("environment")
        or "development"
    ).strip()
    database = data.get("database") or {}
    storage = data.get("storage") or {}
    server = data.get("server") or {}
    db_url = str(database.get("url") or DEFAULT_DB_URL).strip()
    blob_raw = str(storage.get("blob_path") or DEFAULT_BLOB).strip()
    pid_raw = str(
        pid_override
        or server.get("pid_file")
        or DEFAULT_PID
    ).strip()
    blob_path = Path(blob_raw)
    if not blob_path.is_absolute():
        blob_path = (REPO_ROOT / blob_path).resolve()
    return LabConfig(
        environment=env,
        database_url=db_url,
        blob_path=blob_path,
        pid_file=Path(pid_raw),
    )


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def process_comm(pid: int) -> Optional[str]:
    try:
        out = subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "comm="],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return out or None


def held_by_vcp(pid_file: Path) -> Optional[int]:
    if not pid_file.is_file():
        return None
    raw = pid_file.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return None
    try:
        pid = int(raw)
    except ValueError:
        return None
    if pid <= 0:
        return None
    alive = process_alive(pid)
    if not alive:
        return None
    comm = process_comm(pid)
    if comm is None:
        return pid  # fail closed
    base = Path(comm).name
    if base == "vcp":
        return pid
    return None


def guard_lab(cfg: LabConfig) -> None:
    if cfg.environment.lower() == "production":
        die("refusing to run in production (environment=production)")
    if not str(cfg.blob_path).strip():
        die("storage.blob_path is empty (prod-shaped portal config)")
    holder = held_by_vcp(cfg.pid_file)
    if holder is not None:
        die(
            f"portal is running (pid {holder}, {cfg.pid_file}); "
            "stop `just run` before import so meta.sqlite is not open concurrently"
        )


def version_for_package(version: str) -> str:
    if version.startswith("v") or version.startswith("V"):
        return version[1:]
    return version


def has_lts_marker(version: str) -> bool:
    ver = version_for_package(version)
    return len(ver) >= 4 and ver[-4:].lower() == "+lts"


def strip_lts_marker(version: str) -> str:
    ver = version_for_package(version)
    if has_lts_marker(ver):
        return ver[:-4]
    return ver


def ensure_lts_marker(version: str) -> str:
    if has_lts_marker(version):
        return version
    trimmed = version.strip()
    if not trimmed:
        return "+LTS"
    return f"{trimmed}+LTS"


def derive_release_identity(pkg_version: str) -> Optional[Tuple[str, str]]:
    raw = pkg_version.strip()
    if not raw:
        return None
    is_lts = has_lts_marker(raw)
    core = strip_lts_marker(raw).strip()
    if not core:
        return None
    if core.startswith("v") or core.startswith("V"):
        version = core
    else:
        version = f"v{core}"
    if is_lts:
        version = ensure_lts_marker(version)
    return version, ("LTS" if is_lts else "Stable")


def import_channel(portal_version: str, derived_channel: str) -> str:
    if derived_channel == "LTS":
        return "LTS"
    core = version_for_package(portal_version)
    parts = core.split(".")
    try:
        major = int(parts[0]) if parts else 0
    except ValueError:
        major = 0
    try:
        minor = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        minor = 0
    if major == 0 and minor < 9:
        return "EOL"
    return "Stable"


def version_sort_fields(version: str) -> SortFields:
    ver = strip_lts_marker(version)
    if "-" in ver:
        core, suffix = ver.split("-", 1)
    else:
        core, suffix = ver, ""
    nums: List[int] = []
    for part in core.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        nums.append(int(digits) if digits else 0)
    while len(nums) < 3:
        nums.append(0)
    nums = nums[:3]
    return SortFields(
        v_major=nums[0],
        v_minor=nums[1],
        v_patch=nums[2],
        has_client_suffix=1 if suffix else 0,
        client_suffix=suffix,
    )


def jj_mm_yyyy_to_iso(raw: str) -> str:
    parts = raw.strip().split("-")
    if len(parts) != 3:
        raise ValueError(f"expected JJ-MM-YYYY, got `{raw}`")
    day, month, year = int(parts[0]), int(parts[1]), int(parts[2])
    return f"{year:04d}-{month:02d}-{day:02d}"


def parse_heading(rest: str) -> Optional[Tuple[str, str]]:
    rest = rest.strip()
    if "(" not in rest:
        return None
    ver_raw, date_part = rest.split("(", 1)
    ver_raw = ver_raw.strip()
    if not (ver_raw.startswith("v") or ver_raw.startswith("V")):
        return None
    date_raw = date_part.strip().rstrip(")").strip()
    released_on = jj_mm_yyyy_to_iso(date_raw)
    version = f"v{version_for_package(ver_raw)}"
    return version, released_on


def parse_release_notes_md(raw: str) -> Dict[str, NotesSection]:
    out: Dict[str, NotesSection] = {}
    current: Optional[Tuple[str, str, List[str]]] = None
    for line in raw.splitlines():
        if line.startswith("### "):
            parsed = parse_heading(line[4:])
            if parsed is not None:
                if current is not None:
                    ver, date, lines = current
                    out[ver] = NotesSection(ver, date, "\n".join(lines))
                current = (parsed[0], parsed[1], [])
                continue
        if current is None:
            continue
        t = line.strip()
        if not t:
            continue
        if ":" in t and not t.startswith("#") and not t.startswith("Source:"):
            current[2].append(t)
    if current is not None:
        ver, date, lines = current
        out[ver] = NotesSection(ver, date, "\n".join(lines))
    if not out:
        raise ValueError("no ### vX.Y.Z (JJ-MM-YYYY) sections found in notes markdown")
    return out


def sniff_open(path: Path) -> BinaryIO:
    raw = path.read_bytes()
    if len(raw) >= 4 and raw[:4] == b"\x28\xb5\x2f\xfd":
        zstd = _require_zstd()
        dctx = zstd.ZstdDecompressor()
        return io.BufferedReader(dctx.stream_reader(io.BytesIO(raw)))
    if len(raw) >= 6 and raw[:6] == b"\xfd7zXZ\x00":
        return io.BytesIO(lzma.decompress(raw))
    if len(raw) >= 2 and raw[:2] == b"\x1f\x8b":
        return io.BytesIO(gzip.decompress(raw))
    return io.BytesIO(raw)


def inspect_pkg_version(path: Path) -> str:
    stream = sniff_open(path)
    with tarfile.open(fileobj=stream, mode="r|") as tf:
        full: Optional[bytes] = None
        compact: Optional[bytes] = None
        for member in tf:
            name = member.name.lstrip("./")
            if "/" in name or ".." in name:
                continue
            if name == "+MANIFEST" and full is None:
                f = tf.extractfile(member)
                if f is not None:
                    full = f.read()
            elif name == "+COMPACT_MANIFEST" and compact is None:
                f = tf.extractfile(member)
                if f is not None:
                    compact = f.read()
            if full is not None:
                break
            # Stop after leaving + metadata prefix when we already have compact.
            if not name.startswith("+") and (full is not None or compact is not None):
                break
        body = full or compact
        if body is None:
            raise ValueError("manifeste missing")
        data = json.loads(body.decode("utf-8"))
        version = str(data.get("version") or "").strip()
        if not version:
            raise ValueError("manifeste version empty")
        return version


def list_vauban_pkgs(pkgs_dir: Path) -> List[Path]:
    if not pkgs_dir.is_dir():
        die(f"pkgs dir not found: {pkgs_dir}")
    out = sorted(
        p
        for p in pkgs_dir.iterdir()
        if p.is_file() and p.name.startswith("vauban-") and p.name.endswith(".pkg")
    )
    return out


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def upsert_release(
    cur: Any,
    version: str,
    channel: str,
    section: NotesSection,
    sort: SortFields,
) -> int:
    cur.execute("SELECT id FROM releases WHERE version = %s", (version,))
    row = cur.fetchone()
    if row:
        release_id = int(row[0])
        cur.execute(
            """
            UPDATE releases SET
                channel = %s,
                released_on = %s,
                status = %s,
                notes = %s,
                organization_id = %s,
                v_major = %s,
                v_minor = %s,
                v_patch = %s,
                has_client_suffix = %s,
                client_suffix = %s
            WHERE id = %s
            """,
            (
                channel,
                section.released_on,
                RELEASE_STATUS_PUBLISHED,
                section.notes,
                RELEASE_GA_ORG_ID,
                sort.v_major,
                sort.v_minor,
                sort.v_patch,
                sort.has_client_suffix,
                sort.client_suffix,
                release_id,
            ),
        )
        return release_id
    cur.execute(
        """
        INSERT INTO releases (
            version, channel, released_on, status, notes, organization_id,
            v_major, v_minor, v_patch, has_client_suffix, client_suffix
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            version,
            channel,
            section.released_on,
            RELEASE_STATUS_PUBLISHED,
            section.notes,
            RELEASE_GA_ORG_ID,
            sort.v_major,
            sort.v_minor,
            sort.v_patch,
            sort.has_client_suffix,
            sort.client_suffix,
        ),
    )
    return int(cur.fetchone()[0])


def upsert_storage_object(
    cur: Any, release_id: int, sha256: str, size_bytes: int
) -> None:
    key = str(release_id)
    ts = int(time.time())
    cur.execute(
        """
        SELECT id FROM storage_objects
        WHERE scope = %s AND object_key = %s
        """,
        (STORAGE_SCOPE_RELEASE, key),
    )
    row = cur.fetchone()
    if row:
        cur.execute(
            """
            UPDATE storage_objects SET
                sha256 = %s,
                size_bytes = %s,
                updated_at = %s
            WHERE id = %s
            """,
            (sha256, size_bytes, ts, int(row[0])),
        )
        return
    cur.execute(
        """
        INSERT INTO storage_objects (
            scope, object_key, organization_id, sha256, size_bytes,
            content_type, created_at, updated_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            STORAGE_SCOPE_RELEASE,
            key,
            STORAGE_ORG_NONE,
            sha256,
            size_bytes,
            "",
            ts,
            ts,
        ),
    )


def upsert_meta_sqlite(
    blob_path: Path, release_id: int, sha256: str, size_bytes: int
) -> None:
    meta_path = blob_path / "meta.sqlite"
    conn = sqlite3.connect(str(meta_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.executescript(META_OBJECTS_SCHEMA)
        ts = int(time.time())
        conn.execute(
            """
            INSERT INTO objects (
                scope, object_key, org_id, sha256, size_bytes,
                content_type, ext, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope, object_key) DO UPDATE SET
                org_id = excluded.org_id,
                sha256 = excluded.sha256,
                size_bytes = excluded.size_bytes,
                content_type = excluded.content_type,
                ext = excluded.ext,
                updated_at = excluded.updated_at
            """,
            (
                STORAGE_SCOPE_RELEASE,
                str(release_id),
                "",
                sha256,
                size_bytes,
                "",
                "",
                ts,
                ts,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def run(args: argparse.Namespace) -> None:
    cfg = resolve_config(Path(args.config), Path(args.pid_file) if args.pid_file else None)
    guard_lab(cfg)

    notes_path = Path(args.notes).expanduser()
    pkgs_dir = Path(args.pkgs_dir).expanduser()
    notes_raw = notes_path.read_text(encoding="utf-8")
    notes_map = parse_release_notes_md(notes_raw)
    pkgs = list_vauban_pkgs(pkgs_dir)
    if not pkgs:
        die(f"no vauban-*.pkg under {pkgs_dir}")

    cfg.blob_path.mkdir(parents=True, exist_ok=True)
    (cfg.blob_path / "releases").mkdir(parents=True, exist_ok=True)

    imported = 0
    skipped = 0
    with connect_pg(cfg.database_url) as conn:
        with conn.cursor() as cur:
            for pkg_path in pkgs:
                try:
                    pkg_ver = inspect_pkg_version(pkg_path)
                except Exception as exc:  # noqa: BLE001 — lab script
                    print(f"skip {pkg_path}: inspect failed: {exc}", file=sys.stderr)
                    skipped += 1
                    continue
                identity = derive_release_identity(pkg_ver)
                if identity is None:
                    print(
                        f"skip {pkg_path}: manifeste Version empty/unusable",
                        file=sys.stderr,
                    )
                    skipped += 1
                    continue
                version, derived_channel = identity
                section = notes_map.get(version)
                if section is None:
                    print(
                        f"skip {pkg_path}: no notes section for {version}",
                        file=sys.stderr,
                    )
                    skipped += 1
                    continue

                channel = import_channel(version, derived_channel)
                sort = version_sort_fields(version)
                release_id = upsert_release(cur, version, channel, section, sort)

                data = pkg_path.read_bytes()
                digest = sha256_hex(data)
                size_bytes = len(data)
                dest = cfg.blob_path / "releases" / f"{release_id}.pkg"
                dest.write_bytes(data)

                upsert_storage_object(cur, release_id, digest, size_bytes)
                upsert_meta_sqlite(cfg.blob_path, release_id, digest, size_bytes)

                print(
                    f"imported {version} -> id={release_id} channel={channel} "
                    f"date={section.released_on} sha={digest[:12]}… size={size_bytes}"
                )
                imported += 1
        conn.commit()

    print(
        f"import-pkgs complete: imported={imported} skipped={skipped} "
        f"blob={cfg.blob_path}"
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Dev/testing-only importer: FreeBSD .pkg + notes MD → "
            "Postgres + blob + meta.sqlite (no vcp / vcp-store IPC)."
        )
    )
    p.add_argument(
        "--pkgs-dir",
        default=str(DEFAULT_PKGS_DIR),
        help=f"directory of vauban-*.pkg (default: {DEFAULT_PKGS_DIR})",
    )
    p.add_argument(
        "--notes",
        default=str(DEFAULT_NOTES),
        help=f"release notes markdown (default: {DEFAULT_NOTES})",
    )
    p.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help=f"portal TOML for database/storage/pid (default: {DEFAULT_CONFIG})",
    )
    p.add_argument(
        "--pid-file",
        default=None,
        help=f"override PID file (default: from config or {DEFAULT_PID})",
    )
    return p


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    run(args)


if __name__ == "__main__":
    main()
