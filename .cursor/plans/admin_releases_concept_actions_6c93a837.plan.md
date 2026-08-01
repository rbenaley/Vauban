---
name: Admin releases Concept actions
overview: "Align `/admin/releases` STATUS/ACTIONS with Concept: green PUBLISHED / gray HIDDEN badges, Edit + Publish|Unpublish + Delete (hard delete with confirm), hide HIDDEN releases from customer builds, and extend the full admin_releases pyramid."
todos:
  - id: constants-css
    content: RELEASE_STATUS_* + release_status_badge_class + CSS status-published/hidden
    status: completed
  - id: list-actions
    content: "Admin list: badges, vb-row-actions Edit/Publish|Unpublish/Delete + confirm overlay"
    status: completed
  - id: routes-edit
    content: POST publish/unpublish/delete + GET/POST edit by id
    status: completed
  - id: builds-visibility
    content: Filter HIDDEN from customer builds; reserved vauban sees all
    status: completed
  - id: pyramid
    content: Full admin_releases pyramid + builds visibility pin + runbook
    status: completed
  - id: validate
    content: just fmt-check, clippy, check script, focused tests
    status: completed
isProject: false
---

# Admin releases Concept STATUS and ACTIONS

## Decisions (locked)

- **STATUS labels:** `PUBLISHED` (green) / `HIDDEN` (gray) — Concept, not docs’ `DRAFT`.
- **Delete:** hard delete with confirmation overlay (same pattern as admin docs: `?delete={id}` + type `delete` + POST).
- **Edit:** real edit-by-id (`GET`/`POST /admin/releases/{id}`), not the current link to `/new`.
- **Visibility:** customer builds list only shows `PUBLISHED`; staff reserved org `vauban` still sees all (including HIDDEN) for ops.
- **Keep TARGET column** (product extension beyond Concept).

## Reference patterns

Mirror admin docs list actions in [`src/app/admin/docs.rs`](src/app/admin/docs.rs) / [`src/app/admin/docs/doc.rs`](src/app/admin/docs/doc.rs):

- `vb-row-actions` + POST forms for Publish / Unpublish
- Delete confirm panel when `?delete=` is set
- Gate every mutation with `require_staff` + `releases_manage`

Concept badge colors (from mockup HTML):

- Published: `#2f7d52` / `#e8f1ea` / border `#cfe2d6`
- Hidden: `#8a8f96` / `#eef0ed` / border `#dfe2de`

## Implementation

### 1. Model constants + helpers

In [`src/models/mod.rs`](src/models/mod.rs):

- `RELEASE_STATUS_PUBLISHED = "PUBLISHED"`
- `RELEASE_STATUS_HIDDEN = "HIDDEN"`

In [`src/ui.rs`](src/ui.rs) (next to `channel_badge_class`):

- `release_status_badge_class(status) -> "vb-badge status-published" | "status-hidden" | soft fallback`

CSS in [`styles.css`](styles.css): `.vb-badge.status-published` / `.status-hidden` with Concept colors.

### 2. List UI — [`src/app/admin/releases.rs`](src/app/admin/releases.rs)

- STATUS cell: `<span class=(release_status_badge_class(...))>(status)</span>`
- ACTIONS cell: `vb-row-actions` with:
  - **Edit** → `/admin/releases/{id}`
  - **Unpublish** or **Publish** POST (toggle by current status)
  - **Delete** → `?delete={id}` (preserve `page` where practical; drop sticky delete on pager like docs)
- Delete confirm overlay when query has `delete` (type `delete`, POST `/admin/releases/{id}/delete`)
- CTA copy: `+ New release` (Concept); keep lead short
- Include TARGET typography fix already started (`(target)` without smaller `vb-mono` span) if still dirty

### 3. Mutation + edit routes

New module e.g. [`src/app/admin/releases/release_id.rs`](src/app/admin/releases/release_id.rs) (wired from `releases.rs` / `mod`):

| Route | Behavior |
|-------|----------|
| `POST /admin/releases/{id}/publish` | set `PUBLISHED`, PRG list |
| `POST /admin/releases/{id}/unpublish` | set `HIDDEN`, PRG list |
| `POST /admin/releases/{id}/delete` | hard delete after confirm field, PRG list |
| `GET /admin/releases/{id}` | edit form (reuse compose fields from [`new.rs`](src/app/admin/releases/new.rs)) |
| `POST /admin/releases/{id}` | update row, PRG list or detail |

Reuse `releases_manage` + `capability_denied` / soft-deny 404. Create path in `new.rs` keeps creating as `PUBLISHED`.

### 4. Builds visibility

In [`src/app/org/builds.rs`](src/app/org/builds.rs) `release_visible_to_org` / `load_releases_for_org`:

- Require `status == PUBLISHED` for non-reserved orgs (and for GA/private targeting as today).
- Reserved `vauban` continues to see every release including `HIDDEN`.

Dashboard latest-build on [`src/app/org.rs`](src/app/org.rs) must use the same visibility rule if it loads releases.

### 5. Pyramid (surface: `admin_releases`)

| Layer | Work |
|-------|------|
| **Unit** | `release_status_badge_class`; visibility helper cases PUBLISHED/HIDDEN × org/reserved |
| **Invariants** | Extend [`scripts/check_admin_releases.sh`](scripts/check_admin_releases.sh) + [`admin_releases_invariants_test.rs`](tests/integration_tests/admin_releases_invariants_test.rs): badge classes, `vb-row-actions`, publish/unpublish/delete routes, no STATUS plain text only, confirm delete pin |
| **Proptest** | Status ∈ {PUBLISHED, HIDDEN}; badge class mapping |
| **Battle** | Parallel publish/unpublish or list GETs under contention still OK |
| **E2E** | Create → Unpublish → absent from client builds → Publish → visible again; Delete confirm removes row; member 404 on mutation routes |
| **Smoke** | Extend [`docs/runbooks/admin_releases_smoke_test.md`](docs/runbooks/admin_releases_smoke_test.md): STATUS badges + Publish/Unpublish/Delete + client builds hide HIDDEN |

Also extend [`builds_entitlement`](tests/integration_tests/builds_entitlement_e2e_test.rs) or unit on `release_visible_to_org` so HIDDEN GA does not appear for client org.

### 6. Validation

```text
just fmt && just fmt-check
just clippy
bash scripts/check_admin_releases.sh
just test admin_releases_
just test builds_entitlement_   # visibility touch
```

## Out of scope

- Binary upload / signing workflow
- Removing TARGET column
- Soft-delete / trash bin
- Changing ephemeral download tokens for unpublished builds beyond list visibility
