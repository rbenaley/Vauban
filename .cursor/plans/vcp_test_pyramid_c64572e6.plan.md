---
name: VCP test pyramid
overview: Mettre en place l’infra Postgres `vcp_test` (style Vauban), documenter la pyramide ASCII, puis livrer une première surface comportementale complète (auth / session / tenant + modèles) sur les six couches.
todos:
  - id: docs-ascii
    content: ASCII pyramid + mnemonic in quality-assurance skill and vcp-test-pyramid rule; README test DB notes
    status: completed
  - id: infra-vcp-test
    content: scripts/setup_test_db.sh, Justfile db-create-test/db-reset-test, align testing.toml URL
    status: completed
  - id: lib-harness
    content: src/lib.rs split + tests/common harness (connect, cleanup, fixtures)
    status: completed
  - id: unit-models-auth
    content: "Unit/tokio tests: models CRUD+uniqueness, session expiry, auth helpers"
    status: completed
  - id: invariants
    content: scripts/check_auth_tenant.sh + Rust source pins for tenant/Casbin gates
    status: completed
  - id: proptest-battle
    content: auth_tenant proptest + battle (Barrier on sessions/membership)
    status: completed
  - id: e2e-router
    content: "E2E via production app::router: login, wrong-org 404, admin 403, expired session"
    status: completed
  - id: smoke-runbook
    content: docs/runbooks/auth_tenant_smoke_test.md (Vauban template)
    status: completed
  - id: validate
    content: Run fmt/clippy/check script/full cargo test --test-threads=1
    status: completed
isProject: false
---

# VCP behavioral test pyramid + `vcp_test`

## Constat

- Couverture actuelle ≈ **unitaires TLS/config/Casbin/argon2** dans `src/` ; **aucun** `#[tokio::test]`, pas de `tests/`, pas de `scripts/check_*.sh`, pas de `docs/runbooks/`.
- [`config/testing.toml`](config/testing.toml) pointe déjà vers `postgresql://localhost/vcp_test`, mais **aucun** recipe Just / script ne crée cette DB ; [`Justfile`](Justfile) ne gère que `vcp`.
- Modèles Toasty ([`src/models/mod.rs`](src/models/mod.rs)) et seams auth/tenant ([`src/auth.rs`](src/auth.rs), [`src/app/login.rs`](src/app/login.rs), [`src/db.rs`](src/db.rs)) **sans** tests persistence.
- La rule [`vcp-test-pyramid.mdc`](.cursor/rules/vcp-test-pyramid.mdc) décrit les couches mais **sans** l’ASCII présent dans Vauban ([`../Vauban/.cursor/skills/quality-assurance/SKILL.md`](../Vauban/.cursor/skills/quality-assurance/SKILL.md) §1).

## Surface prioritaire (premier lot)

**Auth / session / membership / isolation org** (+ CRUD modèles associés). TLS/ACME reste couvert en unit existant ; sa pyramide complète est hors de ce lot.

```mermaid
flowchart TB
  subgraph harness [Harness]
    setup["scripts/setup_test_db.sh"]
    testingToml["config/testing.toml"]
    common["tests/common"]
  end
  subgraph layers [Pyramid auth_tenant]
    unit["Unit src/"]
    inv["Invariants check_*.sh + pins"]
    prop["Proptest"]
    battle["Battle Barrier"]
    e2e["E2E RouterService + DB"]
    smoke["docs/runbooks/..._smoke_test.md"]
  end
  setup --> testingToml --> common
  common --> unit
  common --> e2e
  common --> battle
```

## 1. Docs / rules (ASCII + wiring)

- Ajouter la pyramide ASCII Vauban et le mnemonic dans [`.cursor/skills/quality-assurance/SKILL.md`](.cursor/skills/quality-assurance/SKILL.md) §1.
- Référencer l’ASCII (ou le pointer) depuis [`.cursor/rules/vcp-test-pyramid.mdc`](.cursor/rules/vcp-test-pyramid.mdc).
- Documenter dans [`README.md`](README.md) : `just db-create-test` / `scripts/setup_test_db.sh`, URL `vcp_test`, `VCP_ENVIRONMENT=testing`, `--test-threads=1`.

## 2. Infra DB de test (strict Vauban-like)

Aligner sur [`../Vauban/vauban-web/scripts/setup_test_db.sh`](../Vauban/vauban-web/scripts/setup_test_db.sh) :

| Élément | Valeur |
|---------|--------|
| DB / user / password | `vcp_test` / `vcp_test` / `vcp_test` |
| URL | `postgresql://vcp_test:vcp_test@localhost/vcp_test` |

Livrables :

- [`scripts/setup_test_db.sh`](scripts/setup_test_db.sh) — `createdb` + role + `GRANT` ; **pas** Diesel : schéma via `db::connect` → `push_schema` (tolérance « already exists » déjà dans [`src/db.rs`](src/db.rs)).
- Justfile : `db-create-test`, `db-reset-test` ; optionnellement `test` documenté comme dépendant de `vcp_test`.
- Mettre à jour [`config/testing.toml`](config/testing.toml) avec l’URL authentifiée ci-dessus (credentials locaux de test uniquement, comme Vauban).

## 3. Fondation crate pour `tests/`

Le crate est aujourd’hui **binaire seul** → les integration tests ne peuvent pas `use vcp::…`.

- Extraire [`src/lib.rs`](src/lib.rs) exposant `acme`, `app`, `auth`, `config`, `db`, `models`, `perms`, `tls` (et helpers layout si besoin).
- Garder [`src/main.rs`](src/main.rs) mince (`vcp::…` / `main` actuel).
- Harness unique : [`tests/common/mod.rs`](tests/common/mod.rs) + binary d’intégration style Vauban (`tests/integration_tests.rs` qui `mod` les suites), ou fichiers `tests/*_e2e_test.rs` indépendants qui partagent `tests/common` — **choix retenu** : un binary `integration_tests` + modules nommés par couche/surface (filtre `cargo test --test integration_tests -- auth_tenant`).

Helpers (portés depuis l’esprit Vauban, sans Diesel) :

- `test_db()` — `Config::load_with_environment(…, Testing)` + `db::connect`
- `cleanup()` — `DELETE` ordonné des lignes préfixées `test_%` / `test-` (users, sessions, memberships, orgs, issues…)
- `unique_name` / fixtures : `create_test_user`, `create_org_with_membership`, `persist_test_session`

## 4. Pyramide complète — surface `auth_tenant`

Naming calqué Vauban : `auth_tenant_{invariants,proptest,battle,e2e}_*` + unit à côté du code.

| Couche | Artefacts | Contenu minimal |
|--------|-----------|-----------------|
| **Unit** | `src/db.rs`, `src/auth.rs`, `src/models` (tests ou helpers purs) | Argon2 (existant) ; expiry session (`expires_at <= now` → None) ; `token_hash_hex` ; role admin vs member sur helper pur ; unicité email/slug via Toasty sur DB si besoin en tokio unit |
| **Invariants** | `scripts/check_auth_tenant.sh` (+ pins Rust) | Pas de gates `is_admin` / role string compares hors Casbin ; catalogue CSV ↔ `TRACKED_PERMS` (étendre drift existant) ; `require_org` mappe non-membre → `not_found` (pin source) ; Origin/session trust présent dans `app::router` |
| **Proptest** | `tests/…/auth_tenant_proptest.rs` + dep `proptest` | Propriétés : `verify_password` roundtrip ; slugs/emails générés restent isolés par préfixe test ; roles hors `{member,admin}` n’obtiennent pas `admin_view` |
| **Battle** | `*_battle_test.rs`, `Barrier` | N writers concurrents sur `AuthSession` (insert/delete même user) ; lectures membership parallèles sans panic / corruption |
| **E2E** | `*_e2e_test.rs` via **production** `app::router` | Drive `RouterService` en HTTP in-process (sans TLS — le seam product est pages+session+DB ; TLS reste unit) : login OK → cookie ; GET `/{org}/` membre ; wrong slug → **404** ; member sur `/{org}/admin/*` → **403** ; session expirée → redirect/unauthorized |
| **Smoke runbook** | [`docs/runbooks/auth_tenant_smoke_test.md`](docs/runbooks/auth_tenant_smoke_test.md) | Template Vauban (audience, severity, automated prerequisites `rtk cargo…` + `check_*.sh`, scénarios A/B/C Pass/Fail, Related links) ; cibles README déjà listées (login, wrong org, non-admin) |

### Refactors ciblés (pour tester le seam de prod, pas un double chemin)

- Extraire de [`src/auth.rs`](src/auth.rs) les parties DB-pures testables (`load_user_by_token_hash` / expiry) tout en gardant les `require_*` comme unique API pages.
- Fixtures E2E appellent `hash_password` / `persist_session` de prod, pas un faux store.
- Ne **pas** importer le harness Axum/Diesel/IPC de Vauban.

## 5. Modèles de données

Tests DB réels sur `vcp_test` (pas SQLite) :

- Create/get `User`, `Organization`, `Membership`, `AuthSession` (happy).
- Unicité `email` / `slug` (sad).
- Session expirée ignorée au load.
- `Issue.organization_id` lié à une org fixture (isolation logique pour E2E wrong-org).
- Stubs `DocArticle` / `Release` : create/list minimal (scaffold) sans élargir le scope produit.

## 6. Validation (DoD)

Après implémentation :

```bash
bash scripts/setup_test_db.sh   # or just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_auth_tenant.sh
rtk cargo test -- --test-threads=1
```

Just `validate` doit rester vert une fois `vcp_test` provisionné.

## Hors scope (ce lot)

- Pyramide complète TLS/ACME (invariants/proptest/battle/E2E/runbook dédiés).
- CI GitHub / Docker Compose (comme Vauban : setup local scripté).
- Migrations Diesel ; rester sur `push_schema` jusqu’à une story migrations explicite.
