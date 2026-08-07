# Auto version/channel from FreeBSD package

## Goal

Remove Version and Channel from the publish form. Derive both from the
FreeBSD package manifeste. On edit, allow only LTS↔EOL or Stable↔EOL.

## Rules

1. **Create**: no `version` / `channel` fields. After `inspect`, call
   `release_pkg::derive_release_identity(&pkg_info.version)`:
   - Manifeste `Version` ends with `+LTS` (case-insensitive) → channel
     `LTS`, store portal version with leading `v` and keep `+LTS`.
   - Otherwise → channel `Stable` (never EOL at create).
2. **Edit**: Version is read-only (no form field). Channel select is
   track-scoped: LTS track → `{LTS, EOL}`; Stable track → `{Stable, EOL}`.
   Track = `channel == LTS` OR version has `+LTS` marker (so EOL that was
   LTS can return to LTS). Saving LTS→EOL stamps `+LTS` on the version.
3. **`package_file_name`**: LTS basename when channel is LTS **or** the
   version carries `+LTS` (EOL LTS builds keep `vauban-X.Y.Z+LTS.pkg`).

## Pyramid

- Unit: derive / track / package_file_name / sort with `+LTS`
- Invariants + `check_admin_releases.sh`
- Proptest / battle / E2E / smoke runbook updates
