---
name: source-repository
description: >-
  Git workflow, branching strategy, Conventional Commits, and PR hygiene for
  VCP. Use when creating branches, commits, or PRs.
---

# Source Repository Guidelines

## Branching (simplified Git Flow)

```
main (production)
  │
  ├── develop (integration, if used)
  │     ├── feature/xxx
  │     ├── bugfix/yyy
  │     └── …
  ├── release/vX.Y
  └── hotfix/urgent-fix
```

| Prefix | Usage | Example |
|--------|-------|---------|
| `feature/` | New features | `feature/org-onboarding` |
| `bugfix/` | Bug fixes | `bugfix/session-expiry` |
| `hotfix/` | Urgent production fixes | `hotfix/csrf-cookie` |
| `refactor/` | No functional change | `refactor/auth-service` |
| `docs/` | Documentation only | `docs/api-reference` |
| `test/` | Tests only | `test/entitlement-matrix` |
| `chore/` | Maintenance / deps | `chore/update-deps` |

Rules: lowercase, hyphens, ≤50 chars, descriptive (not bare ticket IDs).

## Commits

**Never commit or push without explicit user authorization**
(see `.cursor/rules/git-workflow.mdc`).

### Conventional Commits

```
<type>(<scope>): <description>

[optional body]
```

| Type | Meaning |
|------|---------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation |
| `refactor` | Refactor without behavior change |
| `test` | Tests |
| `chore` | Tooling / deps / housekeeping |
| `perf` | Performance |
| `ci` | CI configuration |
| `security` | Security fix |

Recommended scopes (adjust as the tree grows):

```
auth, org, members, licenses, billing, support, session,
api, db, ui, assets, config, tests, docs
```

- ASCII only in commit messages (no accents, no fancy Unicode arrows).
- Prefer **English** commit messages.
- Imperative mood: `add license download`, not `added` / `adds`.
- Subject ≤72 chars; no trailing period.
- Body explains **why**, not a file list.

## Pull requests

- Title in Conventional Commits form when practical.
- One concern per PR when practical.
- Summary: why + what changed; link plans under `.cursor/plans/` if any.
- Test plan checklist in the PR body (include denial paths for
  auth / tenancy / entitlements).
- Do not force-push `main` / `master`.

| Size | Lines | Guidance |
|------|-------|----------|
| XS | < 50 | Ideal |
| S | 50–200 | Good |
| M | 200–500 | Acceptable |
| L | 500–1000 | Prefer split |
| XL | > 1000 | Split |

Suggested PR checklist:

- [ ] Tests added/updated (pyramid layers when behavioral)
- [ ] Docs / plans updated if contracts changed
- [ ] Clippy / fmt clean locally
- [ ] No secrets or customer PII

## Secrets

Never commit `.env` with real credentials, private keys, or customer
data dumps. Warn if the user asks to commit such files.
