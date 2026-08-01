---
name: Admin docs status badges
overview: "Align `/admin/docs` STATUS badges with the releases pattern: green PUBLISHED and a striking unpublished badge, while keeping the existing DRAFT label and storage (no DB rename to HIDDEN)."
todos:
  - id: doc-badge-helper
    content: Add doc_status_badge_class + unit tests in ui.rs
    status: completed
  - id: docs-list-badge
    content: Wire status badge into admin/docs.rs list
    status: completed
  - id: docs-pyramid-pins
    content: Extend check_admin_docs + invariants (+ light e2e/runbook if present)
    status: completed
  - id: validate-docs-status
    content: fmt-check, clippy, check script, focused tests
    status: completed
isProject: false
---

# Admin docs status badges (releases-inspired)

## Decision

Keep **`DRAFT`** as the docs unpublished label (DB + UI + Unpublish target). Only improve **visual parity** with releases: green `PUBLISHED`, amber unpublished badge (same palette as `.status-hidden`). Renaming `DRAFT` → `HIDDEN` is out of scope.

## Current gap

[`src/app/admin/docs.rs`](src/app/admin/docs.rs) renders every status as soft teal:

```138:138:src/app/admin/docs.rs
<span class="vb-badge soft">(article.status.clone())</span>
```

Releases already maps status → class via [`release_status_badge_class`](src/ui.rs) + [`.status-published` / `.status-hidden`](styles.css).

## Implementation

### 1. Shared helper in [`src/ui.rs`](src/ui.rs)

Add `doc_status_badge_class(status)`:

- `PUBLISHED` → `vb-badge status-published`
- `DRAFT` → `vb-badge status-hidden` (reuse amber “unpublished” look)
- else → `vb-badge soft`

Unit tests next to `release_status_badge_classes`.

Optionally thin-wrap releases/docs behind a tiny shared private matcher later; not required — two small public helpers stay clear.

### 2. List UI — [`src/app/admin/docs.rs`](src/app/admin/docs.rs)

Same pattern as releases:

```rust
let status_badge = doc_status_badge_class(&article.status).to_owned();
// ...
<span class=(status_badge)>(article.status.clone())</span>
```

No change to Publish/Unpublish/Delete or `DOC_STATUS_*` constants.

### 3. Pyramid / pins (light)

- Extend [`scripts/check_admin_docs.sh`](scripts/check_admin_docs.sh) + [`admin_docs_invariants_test.rs`](tests/integration_tests/admin_docs_invariants_test.rs): list uses `doc_status_badge_class`, not hardcoded `vb-badge soft` on status.
- Optional E2E assert: list HTML contains `status-published` / `status-hidden` when both statuses exist (mirror releases UI pin).
- Smoke note in [`docs/runbooks/admin_docs_smoke_test.md`](docs/runbooks/admin_docs_smoke_test.md) if present: STATUS badges green/amber.

### 4. Validation

```text
just fmt && just fmt-check
just clippy
bash scripts/check_admin_docs.sh
just test admin_docs_
just test doc_status_badge
just bundle   # CSS already has classes; no color change required unless smoke mentions update
```

## Out of scope

- Renaming `DRAFT` → `HIDDEN` in models / unpublish / client filters
- Docs category/version typography refactor
- Changing Publish/Unpublish behavior or versioning rules
