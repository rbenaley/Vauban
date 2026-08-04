---
name: Storage arch 1.2 review
overview: Créer l’architecture storage 1.2 qui intègre toute la review 1.1 (consentement C1, fingerprint E2, UV, sign_count configurable, delete lié au digest, purge, guardrails prod, breakglass), superséder 1.1, et figer les arbitrages déjà tranchés / évolutifs en ADR.
todos:
  - id: write-12
    content: Create EN(1.2).md from 1.1 + all review amendments (UV, sign_count knobs, fingerprint, summary/pending/audit, delete digest bind, purge, prod guard, breakglass)
    status: completed
  - id: adrs-002-004
    content: Add ADR 002 C1/C2, 003 enrol/revoke asymmetry, 004 sign_count policy; update docs/adr/README.md
    status: completed
  - id: retarget-supersede
    content: Mark 1.1 superseded; retarget pointers; annotate review audit as addressed
    status: completed
isProject: false
---

# Plan: Storage architecture 1.2 + ADRs (post-review)

## Decisions figées (cette itération)

| Sujet | Choix |
|-------|--------|
| Doc | Nouveau [`docs/technical/VCP_Storage_Helper_Architecture_EN(1.2).md`](docs/technical/VCP_Storage_Helper_Architecture_EN(1.2).md) ; 1.1 marqué superseded |
| Passkeys / `sign_count` | Synced OK (compteur souvent 0 : iCloud, GPM, Touch ID…). Conf helper **`webauthn_strict_sign_count = false`** (défaut) ; si `true`, régression de compteur → refuse + alerte (YubiKey / compteurs qui montent) |
| Delete binding (review §3.8) | **Adopté** : challenge `delete` lié au `sha256` SoT courant si l’objet existe ; à l’exécution, digest changé → erreur explicite (recommencer) |
| Canal cérémonie | **C1 conservé** ; C2 documenté comme évolution (ADR) |
| Enrol/revoke | Asymétrie D12 conservée (ADR) |

## Mapping review → livrable

| # Review | Traitement |
|----------|------------|
| **3.1** Presence vs consent | **1.2** : résumé canonique renvoyé avec chaque challenge ; UI doit l’afficher ; CLI `vcp-store ctap2 pending` ; audit log helper sous `blob_path` ; alerte ops sur `delete_org` / rafales de revoke. Residual C1 + piste C2 → **ADR** |
| **3.4** Substitution E1→E2 | **1.2** : fingerprint obligatoire (`H(credential_id \|\| public_key_cose)`), affiché à E1, recalculé à `ctap2 approve`, approve seulement si match OOB |
| **3.3** `userVerification` | **1.2** : `webauthn_user_verification = "required"` dans `vcp-store.conf` ; check flag UV dans `authenticatorData` |
| **3.6** Bypass prod | **1.2** : boot helper refuse `webauthn_required=false` en production ; pin invariant / test pyramid |
| **3.2** `sign_count` | **1.2** : politique ci-dessus + knobs conf ; détail trade-off synced vs strict → **ADR** court |
| **3.7** Backup / breakglass | **1.2** § ops : backup `meta.sqlite` (creds irremplaçables) ; breakglass = re-enrol CLI sur hôte helper, **journalisé**. Runbook pointer (ops MD peut rester léger, détail dans 1.2) |
| **3.5** Purge challenges | **1.2** : purge TTL `webauthn_challenges` (job ou opportuniste sur `challenge_begin` / `put_prepare`) |
| **3.8** Delete ↔ digest | **1.2** : binding + erreur `object_modified` (ou nom closed-set équivalent) |

## ADRs à ajouter (Accepted)

Suivre le format de [`docs/adr/001-login-rate-limit-multi-instance.md`](docs/adr/001-login-rate-limit-multi-instance.md) ; index dans [`docs/adr/README.md`](docs/adr/README.md).

1. **`002-storage-webauthn-ceremony-channel-c1.md`** — C1 accepté pour MVP ; residual presence≠consent ; mitigations 1.2 (summary, `ctap2 pending`, audit log) ; **C2 deferred** (pas d’implémentation maintenant).
2. **`003-ctap2-enrol-revoke-asymmetry.md`** — ACTIVE seulement via CLI helper ; révocation dashboard sans CLI ; menace revoke-DoS acceptée.
3. **`004-webauthn-sign-count-policy.md`** — défaut permissif (synced / compteur 0) ; `webauthn_strict_sign_count` opt-in pour refuse+alerte sur régression.

(Pas d’ADR séparé pour 3.8 : décision produit « on n’accepte pas le risque » → normative dans 1.2.)

## Contenu concret de EN(1.2)

Partir de [`docs/technical/VCP_Storage_Helper_Architecture_EN(1.1).md`](docs/technical/VCP_Storage_Helper_Architecture_EN(1.1).md) :

- Header version **1.2**, status design, changelog depuis 1.1 (table des 8 points review).
- Conf helper étendue :

```toml
webauthn_required = true
webauthn_user_verification = "required"
webauthn_strict_sign_count = false   # true => reject+alert on counter regression
webauthn_challenge_ttl_secs = 300
# rp_id / origin unchanged
```

- § WebAuthn : UV check ; politique `sign_count` ; résumé canonique + audit log path ; `ctap2 pending` ; fingerprint E1/E2.
- § delete : binding digest quand objet présent ; code d’erreur dédié.
- § ops : purge challenges ; backup/breakglass.
- Threat model : ligne « deceived consent (C1) » + mitigations ; lien ADR 002.
- Pointer review : [`.cursor/audits/vcp_storage_1.1_architecture_review_2026-08-04.md`](.cursor/audits/vcp_storage_1.1_architecture_review_2026-08-04.md).

## Mises à jour satellites (doc only, pas d’implémentation code)

- [`EN(1.1).md`](docs/technical/VCP_Storage_Helper_Architecture_EN(1.1).md) : superseded → 1.2.
- Runbooks / audit Capsicum / `src/storage/mod.rs` comment : pointer 1.2.
- Review audit : courte note en tête « addressed in architecture 1.2 + ADR 002–004 » (pas réécrire toute la review).

## Hors scope

- Implémentation Rust / UI CTAP2 / crates WebAuthn (phases A–F de 1.1 restent post-doc).
- Déploiement C2.
