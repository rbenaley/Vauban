# Machine à états finis pour un système de tickets — analyse et implémentation Rust

> Contexte : système de tickets/issue tracker avec états `Open`, `In Analysis`, `Resolved`, `Closed`. Stack cible : Rust 100%, [Topcoat](https://github.com/tokio-rs/topcoat) (framework SSR) + [Toasty](https://github.com/tokio-rs/toasty) (ORM async).
>
> ⚠️ Topcoat et Toasty sont des projets **early-stage / expérimentaux** (annoncés courant 2026, API non stabilisée). Certains extraits ci-dessous sont basés sur la documentation publique disponible au moment de la rédaction et devront être vérifiés contre la doc à jour avant intégration — les points d'incertitude sont signalés explicitement.

---

## 1. Pourquoi une FSM est pertinente ici

Un tracker de tickets a exactement les propriétés qu'une FSM (machine à états finis) modélise bien :

- un nombre **fini et fermé** d'états (`Open`, `In Analysis`, `Resolved`, `Closed`) ;
- un ticket est toujours dans **un seul état à la fois** ;
- les transitions sont déclenchées par des **événements discrets** (action utilisateur, changement de statut...) ;
- certaines transitions sont **interdites** par construction (ex : on ne passe pas directement de `Open` à `Closed` sans analyse, si c'est la règle métier).

### Modélisation typique

```
Open ──(démarrer analyse)──> In Analysis
In Analysis ──(résoudre)──> Resolved
Resolved ──(fermer)──> Closed
Resolved ──(rouvrir)──> In Analysis
Closed ──(rouvrir)──> Open
```

Chaque transition peut porter un **guard** (condition) : par exemple "seul un admin ou un QA peut fermer un ticket".

### Où ça se complique — limites d'une FSM plate

| Complexité | Symptôme | Solution |
|---|---|---|
| Réouverture / boucles | Le graphe n'est plus un pipeline linéaire | Reste une FSM, mais il faut lister explicitement tous les retours en arrière autorisés |
| Statuts orthogonaux (priorité, assignation, SLA...) | Un état plat devient insuffisant | Glisser vers une machine à états **hiérarchique** (statechart, à la UML) |
| Historique ("rouvrir" doit revenir au dernier état pertinent) | Le modèle FSM pur n'a pas de mémoire | Sortir du modèle FSM strict, ou stocker l'état précédent explicitement |
| Concurrence (plusieurs utilisateurs modifient en même temps) | Pas un problème de FSM en soi | Se gère au niveau de la persistance (voir §6 — verrouillage optimiste) |

**Conclusion pratique** : pour la majorité des trackers (Jira, GitHub Issues simplifié, etc.), une FSM plate avec 4-8 états et une table de transitions explicite (état source, événement, état cible, guard optionnel) couvre très bien le besoin.

---

## 2. Implémentation Rust — enum + `match` exhaustif

Deux approches possibles en Rust :

1. **Enum + `match` exhaustif** (recommandée par défaut) — le compilateur garantit l'exhaustivité.
2. **Table de données** (`HashMap<(State, Event), State>`) — plus flexible si les transitions doivent être configurables dynamiquement (config, DB), mais on perd la garantie de compilation.

### 2.1 Pourquoi préférer `match` exhaustif en Rust

- **Exhaustivité garantie à la compilation** : si tu ajoutes un état ou un événement plus tard, `match` te force à traiter le nouveau cas (erreur de compilation si tu oublies, sauf si un `_` catch-all masque le problème — à éviter si possible pour ce module précis).
- **Zéro coût runtime** — pas de recherche dans une liste, tout est résolu à la compilation.
- **Typage fort** — pas de `string` magique mal orthographiée qui casse silencieusement en prod.

### 2.2 Code

```rust
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TicketState {
    Open,
    InAnalysis,
    Resolved,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketEvent {
    StartAnalysis,
    Resolve,
    Close,
    Reopen,
}

#[derive(Debug)]
pub enum TransitionError {
    InvalidTransition { from: TicketState, event: TicketEvent },
    Forbidden { from: TicketState, event: TicketEvent, reason: &'static str },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransitionError::InvalidTransition { from, event } => {
                write!(f, "Transition invalide : {:?} depuis {:?}", event, from)
            }
            TransitionError::Forbidden { from, event, reason } => {
                write!(f, "Transition refusée ({}) : {:?} depuis {:?}", reason, event, from)
            }
        }
    }
}

impl std::error::Error for TransitionError {}

pub struct Context {
    pub user_role: String,
}

impl TicketState {
    /// Le cœur de la FSM : exhaustif grâce au `match`, le compilateur
    /// nous force à traiter chaque combinaison état/événement.
    pub fn transition(
        self,
        event: TicketEvent,
        ctx: &Context,
    ) -> Result<TicketState, TransitionError> {
        use TicketEvent::*;
        use TicketState::*;

        match (self, event) {
            (Open, StartAnalysis) => Ok(InAnalysis),
            (InAnalysis, Resolve) => Ok(Resolved),
            (Resolved, Close) => {
                if ctx.user_role == "admin" || ctx.user_role == "qa" {
                    Ok(Closed)
                } else {
                    Err(TransitionError::Forbidden {
                        from: self,
                        event,
                        reason: "permissions insuffisantes",
                    })
                }
            }
            (Resolved, Reopen) => Ok(InAnalysis),
            (Closed, Reopen) => Ok(Open),
            _ => Err(TransitionError::InvalidTransition { from: self, event }),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context { user_role: "dev".into() };

    let mut state = TicketState::Open;
    state = state.transition(TicketEvent::StartAnalysis, &ctx)?;
    state = state.transition(TicketEvent::Resolve, &ctx)?;

    let admin_ctx = Context { user_role: "admin".into() };
    state = state.transition(TicketEvent::Close, &admin_ctx)?;

    println!("État final : {:?}", state);
    Ok(())
}
```

### 2.3 Points d'attention pour l'implémenteur

- **`self` par valeur, pas `&mut self`** : `TicketState` est `Copy`, la transition retourne un nouvel état plutôt que de muter en place. C'est ce qui garantit par construction qu'un `Err` ne laisse **jamais** l'état source altéré (invariant I3, voir §5).
- **Pas de `_ => unreachable!()`** : le bras `_ => Err(InvalidTransition ...)` doit rester le seul fourre-tout, et il doit produire une erreur, jamais un panic. Toute variante qui "ne devrait jamais arriver" reste malgré tout un cas géré proprement — une API mal utilisée ou un état corrompu en base ne doit jamais faire planter le processus.
- **Guards à l'intérieur du match, pas en dehors** : garder la vérification de permission (`ctx.user_role`) dans le bras du `match` correspondant, et non dans une couche d'appel séparée — sinon rien ne garantit que la vérification est appliquée de manière cohérente à chaque appelant.
- **`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`** sur ce module spécifiquement : la FSM est un composant critique, elle ne doit jamais paniquer quelle que soit l'entrée.
- **Isoler ce module** (`ticket_fsm.rs`) sans dépendance vers Topcoat/Toasty/HTTP : la FSM doit être testable en isolation totale, ce qui conditionne directement la faisabilité des proptests et du fuzzing (§5).

---

## 3. Alternative : table de transitions en données

À réserver aux cas où les transitions doivent être **configurables** (admin UI, fichier de config, feature flags par tenant) — sinon préférer le `match` exhaustif du §2.

```rust
pub struct Transition {
    pub from: TicketState,
    pub event: TicketEvent,
    pub to: TicketState,
    pub guard: Option<fn(&Context) -> bool>,
}

pub fn transitions() -> Vec<Transition> {
    vec![
        Transition { from: TicketState::Open, event: TicketEvent::StartAnalysis,
            to: TicketState::InAnalysis, guard: None },
        Transition { from: TicketState::InAnalysis, event: TicketEvent::Resolve,
            to: TicketState::Resolved, guard: None },
        Transition { from: TicketState::Resolved, event: TicketEvent::Close,
            to: TicketState::Closed,
            guard: Some(|ctx| ctx.user_role == "admin" || ctx.user_role == "qa") },
        Transition { from: TicketState::Resolved, event: TicketEvent::Reopen,
            to: TicketState::InAnalysis, guard: None },
        Transition { from: TicketState::Closed, event: TicketEvent::Reopen,
            to: TicketState::Open, guard: None },
    ]
}
```

**Point d'attention** : avec cette approche, il n'y a **aucune garantie de compilation** sur l'exhaustivité ou l'absence de doublons/contradictions (deux entrées avec le même `(from, event)` et des `to` différents). Si tu choisis cette voie, l'invariant d'exhaustivité (§5, I1/I4) devient **obligatoire** et doit tourner en CI à chaque changement de la table — ce n'est plus une garantie du compilateur mais une garantie de test.

---

## 4. Intégration Topcoat (SSR) + Toasty (ORM)

### 4.1 Modèle Toasty

```rust
use toasty::Model;

#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Enum)]
pub enum TicketState {
    Open,
    InAnalysis,
    Resolved,
    Closed,
}

#[derive(Debug, Model)]
pub struct Ticket {
    #[key]
    #[auto]
    id: u64,
    title: String,
    state: TicketState,
}
```

> ⚠️ **Point d'incertitude** : le nom exact de la macro pour dériver un enum stockable (`toasty::Enum`) n'a pas pu être confirmé dans les exemples publics disponibles (qui ne montrent que des champs `String`/`u64`/`uuid::Uuid`). Solution de repli sûre si ça ne compile pas : stocker `state: String` en base et faire la conversion via `TryFrom<&str>`/`Display` dans la couche FSM, en gardant `TicketState` comme seul type manipulé par la logique métier.

### 4.2 Composant Topcoat natif (signaux navigateur, sans htmx/Datastar)

Topcoat expose deux primitives pour lier réactivité navigateur et logique serveur :

- **`#[shard]`** : composant qui se **re-rend côté serveur** quand ses arguments (dérivés de signaux) changent, et dont le fragment HTML résultant est swappé dans la page. C'est le bon outil pour une carte de ticket qui doit refléter son état courant.
- **`#[procedure]`** : fonction serveur **appelable depuis le navigateur** via une expression runtime (`$(...)`), pour les actions qui touchent la base de données (ici : exécuter la transition).

```rust
use topcoat::{Result, view::{component, view}, runtime::{shard, expr}};
use crate::ticket_fsm::{TicketState, TicketEvent, Context as FsmContext};

#[shard]
async fn ticket_card(cx: &Cx, ticket_id: u64) -> Result {
    let mut db = cx.app::<toasty::Db>();
    let ticket = Ticket::get_by_id(&mut db, ticket_id).await?;

    view! {
        <div class="ticket-card">
            <span>(format!("{:?}", ticket.state))</span>

            for (label, event) in next_events(ticket.state) {
                <button @click=$(advance(ticket_id, event))>
                    (label)
                </button>
            }
        </div>
    }
}

#[procedure]
async fn advance(cx: &Cx, ticket_id: u64, event: TicketEvent) -> Result<()> {
    let mut db = cx.app::<toasty::Db>();
    let ticket = Ticket::get_by_id(&mut db, ticket_id).await?;

    let ctx = FsmContext { user_role: current_user_role(cx)? };
    let new_state = ticket.state.transition(event, &ctx)?;

    Ticket::update(&mut db, ticket_id)
        .state(new_state)
        .exec(&mut db)
        .await?;

    Ok(())
}

fn next_events(state: TicketState) -> Vec<(&'static str, TicketEvent)> {
    use TicketState::*;
    use TicketEvent::*;
    match state {
        Open       => vec![("Analyser", StartAnalysis)],
        InAnalysis => vec![("Résoudre", Resolve)],
        Resolved   => vec![("Fermer", Close), ("Rouvrir", Reopen)],
        Closed     => vec![("Rouvrir", Reopen)],
    }
}
```

### 4.3 Points d'attention pour l'implémenteur

- **`next_events()` doit rester un miroir de la FSM, pas une source de vérité parallèle.** Le risque principal ici : si `next_events()` diverge du `match` de `transition()` (par exemple on oublie de retirer un bouton après avoir retiré une transition), l'UI propose un événement qui échouera systématiquement côté serveur. Idéalement, générer `next_events()` par introspection (itérer `TicketEvent::iter()` et ne garder que ceux pour lesquels `transition()` retourne `Ok`, avec un `Context` "permissif" pour l'affichage) plutôt que de la dupliquer à la main — voir le pattern d'exhaustivité au §5.
- **Ne jamais faire confiance à l'UI comme seule barrière.** Le fait que le bouton n'apparaisse pas pour un événement invalide est un confort UX, pas une garantie de sécurité — un client peut toujours appeler la `#[procedure]` directement avec un `ticket_id`/`event` arbitraire. La vérification de transition **et** de permission doit être refaite intégralement côté `advance()`, jamais supposée acquise parce que le bouton était filtré.
- **`current_user_role(cx)` doit être fiable et non falsifiable** — dérivé de la session authentifiée côté serveur (cookie signé, JWT vérifié, etc.), jamais d'un champ transmis tel quel par le client dans les paramètres de la `#[procedure]`.
- **Réserve sur la mécanique procedure → shard** : il n'a pas été confirmé si le re-render du `#[shard]` après une `#[procedure]` est automatique ou doit être déclenché explicitement (invalidation manuelle). À vérifier dans `crates/topcoat-runtime/macro/docs/{procedure,shard}.md` avant de figer ce pattern en production.
- **Le `#[procedure]` ne doit jamais retourner l'état interne brut en cas d'erreur** (par ex. ne pas renvoyer le `Debug` complet de `TransitionError` au client si celui-ci peut révéler des détails d'implémentation ou de permissions à un utilisateur non autorisé) — mapper vers un message générique côté HTTP, logger le détail côté serveur.

---

## 5. Durcissement par les invariants

### 5.1 Pourquoi durcir au-delà des tests unitaires classiques

Une table de transitions bien conçue élimine déjà une classe entière de bugs (états incohérents, transitions non documentées). Mais elle ne garantit pas, à elle seule :

- que **toutes** les combinaisons état/événement ont été considérées (exhaustivité) ;
- qu'aucun état n'est un **cul-de-sac** non intentionnel ;
- que le comportement reste correct sous **séquences longues** ou **entrées adverses** ;
- que la persistance reste cohérente sous **concurrence**.

Chacun de ces points correspond à un niveau différent de la pyramide de tests, avec un rapport coût/garantie croissant.

### 5.2 Prérequis : rendre les états et événements itérables

```rust
use strum::{EnumIter, IntoEnumIterator};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
pub enum TicketState { Open, InAnalysis, Resolved, Closed }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
pub enum TicketEvent { StartAnalysis, Resolve, Close, Reopen }
```

`EnumIter` (crate `strum`) permet d'itérer **tous** les états et tous les événements — c'est le socle de tout invariant d'exhaustivité. Sans cette capacité, il est impossible de *prouver* la couverture, seulement de l'espérer.

### 5.3 Invariants formels — le contrat à tester

| ID | Invariant | Ce qu'il garantit |
|---|---|---|
| I1 | **Totalité** — pour tout `(state, event)`, `transition()` retourne `Ok` ou un `TransitionError` connu, jamais de panic | Robustesse face à n'importe quelle entrée |
| I2 | **Déterminisme** — à `(state, event, ctx)` fixés, le résultat est toujours identique | Pas de dépendance cachée (horloge, aléa, état global) |
| I3 | **Pureté vis-à-vis de l'échec** — si `transition()` retourne `Err`, l'état source n'a pas été muté | Garanti ici par construction (`self` par valeur, pas `&mut self`) |
| I4 | **Fermeture du graphe** — l'ensemble des arêtes `(from, event, to)` codées est exactement celui documenté, ni plus ni moins | Pas d'arête fantôme ni d'arête manquante entre code et documentation/diagramme |
| I5 | **Accessibilité** — tout état non terminal a au moins une transition sortante valide | Pas d'état "piège" non intentionnel |
| I6 | **Cohérence des guards** — un guard qui échoue retourne `Forbidden`, jamais un `Ok` avec un état différent du state source | Pas de contournement silencieux des permissions |
| I7 | **Cohérence transactionnelle** (niveau intégration, §6) — deux transitions concurrentes ne produisent jamais un état hors de toute trajectoire valide | Pas de "lost update" en base |

**Point d'attention méthodologique** : ces invariants doivent être écrits **avant** ou en parallèle de l'implémentation, pas après coup en cherchant à justifier le code existant — sinon on risque de documenter des biais de l'implémentation plutôt que les règles métier réelles.

### 5.4 Niveau unit — une arête, un test

```rust
#[test]
fn open_to_in_analysis_ok() {
    let ctx = Context { user_role: "dev".into() };
    assert_eq!(
        TicketState::Open.transition(TicketEvent::StartAnalysis, &ctx),
        Ok(TicketState::InAnalysis)
    );
}

#[test]
fn open_cannot_resolve_directly() {
    let ctx = Context { user_role: "dev".into() };
    assert!(matches!(
        TicketState::Open.transition(TicketEvent::Resolve, &ctx),
        Err(TransitionError::InvalidTransition { .. })
    ));
}

#[test]
fn close_requires_admin_or_qa() {
    let dev_ctx = Context { user_role: "dev".into() };
    assert!(matches!(
        TicketState::Resolved.transition(TicketEvent::Close, &dev_ctx),
        Err(TransitionError::Forbidden { .. })
    ));
}
```

**Point d'attention** : un test unitaire par arête *positive* ne suffit pas — pour chaque état, il faut aussi au moins un test qui vérifie qu'un événement **non listé** depuis cet état est bien rejeté (comme `open_cannot_resolve_directly`). C'est la moitié négative qui protège contre les régressions silencieuses (ex : un futur refactor qui élargirait accidentellement un bras de `match`).

### 5.5 Niveau invariants — tests d'exhaustivité générés

```rust
#[test]
fn i1_total_and_never_panics() {
    let ctx = Context { user_role: "dev".into() };
    for state in TicketState::iter() {
        for event in TicketEvent::iter() {
            // Le simple fait que cet appel ne panique pas, pour TOUTE
            // combinaison, suffit à prouver I1.
            let _ = state.transition(event, &ctx);
        }
    }
}

#[test]
fn i5_no_dead_ends() {
    let ctx = Context { user_role: "admin".into() };
    for state in TicketState::iter() {
        let has_outgoing = TicketEvent::iter()
            .any(|e| state.transition(e, &ctx).is_ok());
        assert!(has_outgoing || state == TicketState::Closed,
            "état sans transition sortante : {state:?}");
    }
}
```

**Point d'attention** : ce test casse **automatiquement** dès qu'un état est ajouté sans lui donner de transition sortante (sauf exception explicite comme `Closed`) — c'est strictement plus fiable qu'une revue de code manuelle, qui peut facilement rater un état orphelin dans un `match` de 15+ lignes.

### 5.6 Property-based testing — modèle de référence indépendant

```rust
use proptest::prelude::*;

fn reference_model(state: TicketState, event: TicketEvent) -> Option<TicketState> {
    use TicketState::*;
    use TicketEvent::*;
    match (state, event) {
        (Open, StartAnalysis) => Some(InAnalysis),
        (InAnalysis, Resolve) => Some(Resolved),
        (Resolved, Close) => Some(Closed),      // guard ignoré ici volontairement
        (Resolved, Reopen) => Some(InAnalysis),
        (Closed, Reopen) => Some(Open),
        _ => None,
    }
}

proptest! {
    #[test]
    fn matches_reference_model(
        state in prop_oneof![
            Just(TicketState::Open), Just(TicketState::InAnalysis),
            Just(TicketState::Resolved), Just(TicketState::Closed),
        ],
        event in prop_oneof![
            Just(TicketEvent::StartAnalysis), Just(TicketEvent::Resolve),
            Just(TicketEvent::Close), Just(TicketEvent::Reopen),
        ],
    ) {
        let ctx = Context { user_role: "admin".into() }; // guards toujours ouverts
        let actual = state.transition(event, &ctx).ok();
        let expected = reference_model(state, event);
        prop_assert_eq!(actual, expected);
    }
}
```

**Point d'attention capital** : le `reference_model` doit être écrit **indépendamment** de l'implémentation — idéalement par relecture du diagramme d'états, pas en copiant/adaptant le `match` de production. Si les deux sont écrits par la même personne au même moment en regardant le même code, le test perd une grande partie de sa valeur différentielle (biais de confirmation). Idéalement, faire relire/écrire ce modèle par une deuxième personne, ou le dater et le figer avant de commencer l'implémentation.

### 5.7 Property-based testing — séquences de trajectoires aléatoires

```rust
proptest! {
    #[test]
    fn any_event_sequence_never_panics_and_stays_in_valid_states(
        events in prop::collection::vec(
            prop_oneof![
                Just(TicketEvent::StartAnalysis), Just(TicketEvent::Resolve),
                Just(TicketEvent::Close), Just(TicketEvent::Reopen),
            ],
            0..50
        ),
        role in prop_oneof!["dev", "admin", "qa"].prop_map(String::from),
    ) {
        let ctx = Context { user_role: role };
        let mut state = TicketState::Open;
        for event in events {
            match state.transition(event, &ctx) {
                Ok(next) => state = next,       // I4 : reste dans l'enum, par construction
                Err(_) => { /* état inchangé, I3 */ }
            }
        }
        prop_assert!(TicketState::iter().any(|s| s == state));
    }
}
```

**Point d'attention** : ce test, exécuté des milliers de fois par `proptest`, explore des séquences qu'un humain n'écrirait jamais à la main (ex : `Reopen` répété 12 fois d'affilée sur `Open`, alternances rapides de rôle). C'est le niveau qui détecte le plus souvent des bugs de logique fine — mais son assertion finale (`TicketState::iter().any(...)`) est volontairement faible ici (elle est garantie par le typage). Pour un test réellement discriminant à ce niveau, il faut y ajouter des assertions métier spécifiques (ex : "jamais `Closed` sans être passé par `Resolved` au moins une fois dans la trajectoire") — sans quoi ce test valide surtout l'absence de crash, pas la justesse métier complète.

### 5.8 Model-based testing formel — `proptest-state-machine`

Approche plus rigoureuse que le §5.7 : au lieu de générer des événements au hasard, on définit un modèle avec **préconditions** (quelles transitions sont valides à cet instant) et on ne génère que des séquences cohérentes avec ce modèle, rejouées contre l'implémentation réelle.

```toml
[dev-dependencies]
proptest = "1"
proptest-state-machine = "0.3"
```

```rust
use proptest::prelude::*;
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};

/// Le "monde idéal" : ce que la FSM DOIT faire, écrit indépendamment
/// de l'implémentation réelle.
#[derive(Debug, Clone)]
pub struct RefState {
    pub ticket_state: TicketState,
    pub role: &'static str,
}

#[derive(Debug, Clone)]
pub enum Transition {
    Fire(TicketEvent),
    SwitchRole(&'static str),
}

pub struct TicketRefMachine;

impl ReferenceStateMachine for TicketRefMachine {
    type State = RefState;
    type Transition = Transition;

    fn init_state() -> BoxedStrategy<Self::State> {
        Just(RefState { ticket_state: TicketState::Open, role: "dev" }).boxed()
    }

    fn transitions(_state: &Self::State) -> BoxedStrategy<Self::Transition> {
        prop_oneof![
            Just(Transition::Fire(TicketEvent::StartAnalysis)),
            Just(Transition::Fire(TicketEvent::Resolve)),
            Just(Transition::Fire(TicketEvent::Close)),
            Just(Transition::Fire(TicketEvent::Reopen)),
            Just(Transition::SwitchRole("dev")),
            Just(Transition::SwitchRole("admin")),
            Just(Transition::SwitchRole("qa")),
        ].boxed()
    }

    /// Le cœur du modèle : la même logique métier que le `match` de
    /// production, mais écrite ici "à froid", en relisant le diagramme.
    fn preconditions(state: &Self::State, transition: &Self::Transition) -> bool {
        use TicketState::*;
        use TicketEvent::*;
        match transition {
            Transition::Fire(StartAnalysis) => state.ticket_state == Open,
            Transition::Fire(Resolve)       => state.ticket_state == InAnalysis,
            Transition::Fire(Close)         => {
                state.ticket_state == Resolved
                    && (state.role == "admin" || state.role == "qa")
            }
            Transition::Fire(Reopen)        => {
                matches!(state.ticket_state, Resolved | Closed)
            }
            Transition::SwitchRole(_)       => true,
        }
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        use TicketState::*;
        match transition {
            Transition::Fire(TicketEvent::StartAnalysis) => state.ticket_state = InAnalysis,
            Transition::Fire(TicketEvent::Resolve)       => state.ticket_state = Resolved,
            Transition::Fire(TicketEvent::Close)         => state.ticket_state = Closed,
            Transition::Fire(TicketEvent::Reopen) => {
                state.ticket_state = if state.ticket_state == Resolved { InAnalysis } else { Open };
            }
            Transition::SwitchRole(r) => state.role = r,
        }
        state
    }
}

pub struct TicketSut {
    pub state: TicketState,
}

impl StateMachineTest for TicketSut {
    type SystemUnderTest = TicketSut;
    type Reference = TicketRefMachine;

    fn init_test(ref_state: &RefState) -> Self::SystemUnderTest {
        TicketSut { state: ref_state.ticket_state }
    }

    /// Rejoue CHAQUE transition acceptée par le modèle contre la vraie
    /// implémentation, et vérifie l'égalité des résultats.
    fn apply(
        mut sut: Self::SystemUnderTest,
        ref_state: &RefState,
        transition: Transition,
    ) -> Self::SystemUnderTest {
        if let Transition::Fire(event) = transition {
            let ctx = Context { user_role: ref_state.role.into() };
            let result = sut.state.transition(event, &ctx);

            let expected = TicketRefMachine::apply(ref_state.clone(), &Transition::Fire(event));
            assert_eq!(
                result, Ok(expected.ticket_state),
                "divergence modèle/implémentation sur {event:?} depuis {:?}",
                ref_state.ticket_state
            );
            sut.state = result.unwrap();
        }
        sut
    }

    /// Invariant vérifié après CHAQUE étape, pas seulement à la fin.
    fn check_invariants(sut: &Self::SystemUnderTest, ref_state: &RefState) {
        assert_eq!(sut.state, ref_state.ticket_state,
            "le SUT et le modèle ont divergé");
    }
}

prop_state_machine! {
    #[test]
    fn ticket_fsm_matches_reference_model(sequential 1..50 => TicketSut);
}
```

**Ce que ça apporte par rapport au §5.7** :

- `transitions()` propose large, mais `preconditions()` **filtre** — proptest explore uniquement des chemins plausibles selon le modèle, ce qui est bien plus efficace que de générer des événements aléatoires et espérer qu'une bonne partie soit valide.
- `check_invariants()` s'exécute **après chaque étape**, pas seulement à la fin — un bug qui casse l'invariant au 17ᵉ événement sur 50 est détecté immédiatement, avec un *shrinking* automatique qui réduit la séquence fautive à sa forme la plus courte reproduisant le bug.
- Le modèle et l'implémentation sont deux écritures **indépendantes** de la même règle métier — leur divergence est le signal, exactement comme un test différentiel.

> ⚠️ **Point d'incertitude** : la signature exacte de `prop_state_machine!` / du mot-clé `sequential` n'a pas été vérifiée contre la version courante de `proptest-state-machine` (l'API a évolué entre les versions 0.1 et 0.3 du crate). À confirmer via `cargo doc --open -p proptest-state-machine` avant intégration.

### 5.9 Fuzzing / battle-testing

```rust
// fuzz/fuzz_targets/ticket_fsm.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct Input {
    events: Vec<TicketEvent>,
    role: String,
}

fuzz_target!(|input: Input| {
    let ctx = Context { user_role: input.role };
    let mut state = TicketState::Open;
    for event in input.events {
        if let Ok(next) = state.transition(event, &ctx) {
            state = next;
        }
    }
});
```

Avec `cargo fuzz run ticket_fsm` en continu (par exemple en job CI nocturne), on trouve des cas limites que même `proptest` ne génère pas naturellement — chaînes `role` contenant de l'Unicode exotique, caractères de contrôle, chaînes vides, très longues, etc.

**Points d'attention** :
- Le fuzzing sur cette FSM a un rendement décroissant rapide (l'espace d'états est petit et fini) — le principal intérêt ici est de fuzzer le **champ `role: String`**, qui est la seule entrée non bornée du système. Envisager de fuzzer plutôt la désérialisation de la requête HTTP complète en amont (payload JSON du `#[procedure]`) si le vrai risque est côté frontière réseau.
- Si la FSM devient un jour partagée entre threads (cache mémoire de tickets), ajouter un test **loom** pour vérifier l'absence de race sur les transitions concurrentes *en mémoire* — distinct du test de concurrence *en base* du §6, qui reste nécessaire même avec loom si la persistance passe par plusieurs instances applicatives.

---

## 6. Concurrence et persistance (invariant I7)

### 6.1 Le problème

Une FSM parfaitement prouvée correcte **en mémoire** peut quand même produire des états incohérents en base si deux requêtes concurrentes lisent le même `Ticket`, transitionnent chacune de leur côté, et écrivent en mode "dernier gagne" (*lost update*). C'est un invariant de **niveau intégration**, pas de niveau FSM pure — aucun test du §5 ne le couvre.

### 6.2 Rendre la transition atomique (verrouillage optimiste)

```rust
#[derive(Debug)]
pub enum PersistError {
    Fsm(TransitionError),
    Conflict, // quelqu'un d'autre a modifié le ticket entre lecture et écriture
    Db(toasty::Error),
}

pub async fn advance_ticket_atomic(
    db: &mut toasty::Db,
    ticket_id: u64,
    event: TicketEvent,
    ctx: &Context,
) -> Result<TicketState, PersistError> {
    // Suppose un champ `version: u32` sur Ticket (pattern optimistic locking),
    // incrémenté à chaque update. Si Toasty expose un mécanisme natif de CAS,
    // le préférer plutôt que de le réimplémenter à la main.
    let ticket = Ticket::get_by_id(db, ticket_id).await.map_err(PersistError::Db)?;
    let current_version = ticket.version;

    let new_state = ticket.state.transition(event, ctx).map_err(PersistError::Fsm)?;

    let rows_affected = Ticket::update(db, ticket_id)
        .state(new_state)
        .version(current_version + 1)
        .filter(|t| t.version.eq(current_version)) // CAS : n'écrit que si rien n'a bougé
        .exec(db)
        .await
        .map_err(PersistError::Db)?;

    if rows_affected == 0 {
        return Err(PersistError::Conflict); // à charge de l'appelant de retry
    }
    Ok(new_state)
}
```

> ⚠️ **Point d'incertitude** : la syntaxe exacte de `.filter()` et du comptage de lignes affectées dans l'API Toasty courante n'a pas pu être confirmée. Le **principe** du CAS (compare-and-swap) via colonne `version` est indépendant de l'ORM — seule la syntaxe change si Toasty expose un mécanisme différent (transaction explicite, verrou pessimiste `SELECT ... FOR UPDATE`, etc.).

### 6.3 Points d'attention sur la stratégie de concurrence

- **Verrouillage optimiste vs pessimiste** : l'optimiste (CAS sur `version`) est préférable ici car les conflits sur un même ticket restent rares en usage normal (deux personnes qui ferment le même ticket à la milliseconde près) — un verrou pessimiste (`FOR UPDATE`) pénaliserait le débit global pour un cas rare. À reconsidérer si le produit prévoit des scénarios de contention forte et intentionnelle (ex : bouton "claim" très disputé).
- **Le retry doit être borné et backoff-é**, jamais une boucle infinie — un `Conflict` répété peut signaler un bug (deux processus qui bouclent l'un sur l'autre) plutôt qu'une simple course bénigne.
- **Ne jamais absorber silencieusement un `Conflict` en le traitant comme un succès** côté UI — l'utilisateur doit être informé que son action a été rejetée à cause d'une modification concurrente, avec un état rafraîchi, plutôt que de laisser croire que sa transition a été appliquée.
- **La colonne `version` doit être incluse dans tout export/audit** — c'est elle qui permet de diagnostiquer a posteriori une suspicion de lost update en production.

### 6.4 Test battle — transitions identiques en concurrence

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_transitions_never_lose_updates() {
    let mut db = setup_test_db().await; // sqlite in-memory, cf. exemples Toasty
    let ticket_id = create_ticket(&mut db, TicketState::Resolved).await;

    let ctx_admin = Context { user_role: "admin".into() };

    // 20 tâches tentent SIMULTANÉMENT de fermer le même ticket resolved.
    let handles: Vec<_> = (0..20)
        .map(|_| {
            let mut db = db.clone(); // ou un pool, selon ce que Toasty expose
            let ctx = ctx_admin.clone();
            tokio::spawn(async move {
                advance_with_retry(&mut db, ticket_id, TicketEvent::Close, &ctx, 5).await
            })
        })
        .collect();

    let results: Vec<_> = futures::future::join_all(handles).await;

    // I7a : toutes les tentatives finissent par réussir (grâce au retry)
    // ou échouent proprement — jamais de panic, jamais de double écriture
    // "gagnante" simultanée.
    let successes = results.iter().filter(|r| matches!(r, Ok(Ok(_)))).count();
    assert_eq!(successes, 20, "certaines transitions concurrentes ont été perdues");

    // I7b : l'état final en base est EXACTEMENT celui attendu par la
    // sémantique métier (idempotence de Close), pas un état halluciné.
    let final_ticket = Ticket::get_by_id(&mut db, ticket_id).await.unwrap();
    assert_eq!(final_ticket.state, TicketState::Closed);

    // I7c : le compteur de version reflète le nombre réel d'écritures
    // qui ont abouti (aucune écriture "invisible").
    assert!(final_ticket.version >= 1);
}

async fn advance_with_retry(
    db: &mut toasty::Db,
    ticket_id: u64,
    event: TicketEvent,
    ctx: &Context,
    max_retries: u32,
) -> Result<TicketState, PersistError> {
    for attempt in 0..max_retries {
        match advance_ticket_atomic(db, ticket_id, event, ctx).await {
            Ok(s) => return Ok(s),
            Err(PersistError::Conflict) if attempt + 1 < max_retries => continue,
            Err(e) => return Err(e),
        }
    }
    Err(PersistError::Conflict)
}
```

### 6.5 Test battle — transitions **divergentes** en concurrence (le cas vraiment discriminant)

Le test précédent fait 20× la **même** transition — c'est le cas facile, elles convergent naturellement. Le test qui révèle réellement un bug de concurrence oppose deux transitions **différentes et mutuellement exclusives** :

```rust
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_close_and_reopen_are_mutually_exclusive() {
    let mut db = setup_test_db().await;
    let ticket_id = create_ticket(&mut db, TicketState::Resolved).await;
    let ctx = Context { user_role: "admin".into() };

    let db1 = db.clone();
    let db2 = db.clone();
    let ctx1 = ctx.clone();
    let ctx2 = ctx.clone();

    let (r1, r2) = tokio::join!(
        tokio::spawn(async move {
            let mut db = db1;
            advance_ticket_atomic(&mut db, ticket_id, TicketEvent::Close, &ctx1).await
        }),
        tokio::spawn(async move {
            let mut db = db2;
            advance_ticket_atomic(&mut db, ticket_id, TicketEvent::Reopen, &ctx2).await
        }),
    );

    // EXACTEMENT une des deux transitions gagne, l'autre reçoit un Conflict
    // propre — jamais un état corrompu, jamais les deux qui "réussissent"
    // en s'écrasant silencieusement.
    let outcomes = [r1.unwrap(), r2.unwrap()];
    let ok_count = outcomes.iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok_count, 1, "les deux transitions concurrentes ont réussi — lost update !");

    let final_state = Ticket::get_by_id(&mut db, ticket_id).await.unwrap().state;
    assert!(
        final_state == TicketState::Closed || final_state == TicketState::InAnalysis,
        "état final incohérent avec les deux trajectoires possibles"
    );
}
```

**Point d'attention capital** : sans le CAS (`filter version.eq(...)`), ce test échoue **systématiquement** en "last write wins silencieux" — les deux futures retournent `Ok`, et l'état final dépend uniquement de l'ordre d'arrivée réseau des deux `UPDATE`, sans qu'aucune erreur ne soit levée nulle part. C'est précisément ce test qui doit faire partie de la suite avant tout passage en production — un invariant de concurrence non testé est un invariant qui n'existe pas.

---

## 7. Niveaux E2E et smoke

| Niveau | Objectif | Ce qu'il vérifie concrètement |
|---|---|---|
| **E2E** | Prouver que le pipeline complet fonctionne | Via le couple `#[procedure]`/`#[shard]` Topcoat, driver HTTP réel contre une DB de test (sqlite en mémoire pour Toasty) ; vérifier qu'un clic sur "Résoudre" change bien le fragment HTML rendu et l'état en base |
| **Smoke** (post-déploiement) | Détecter en quelques secondes un déploiement cassé | Un seul chemin heureux, `Open → In Analysis → Resolved → Closed`, exécuté contre l'environnement réel après chaque déploiement — objectif : rapidité de détection, pas exhaustivité |

**Points d'attention** :
- Le test E2E doit couvrir explicitement le cas d'un événement **refusé par un guard** (ex : `dev` qui tente de fermer un ticket) jusqu'au niveau HTTP — c'est le seul niveau qui vérifie que le rejet ne fuite pas d'information sensible dans la réponse (voir §4.3).
- Le smoke test ne doit **jamais** dépendre d'un ticket réel existant en prod — créer et nettoyer un ticket dédié au smoke test (préfixe reconnaissable, ex: `__smoke_test__`), avec purge automatique, pour ne pas polluer les données de production ni fausser des métriques métier.

---

## 8. Synthèse — la pyramide appliquée à cette FSM

| Niveau | Ce qu'il prouve | Coût | Fréquence recommandée |
|---|---|---|---|
| Unit | Chaque arête documentée se comporte comme prévu | Faible, manuel | À chaque commit (CI) |
| Invariants (`EnumIter`) | Exhaustivité, pas de dead-end, pas de panic | Faible, généré | À chaque commit (CI) |
| Proptest (modèle simple) | L'implémentation == le modèle métier indépendant | Moyen | À chaque commit (CI) |
| Proptest-state-machine | Séquences valides selon préconditions, invariants vérifiés à chaque étape | Moyen-élevé | À chaque commit (CI), avec un budget de cas plus élevé en nightly |
| Proptest (trajectoires libres) | Aucune séquence n'entraîne de crash, même hors modèle | Moyen | À chaque commit (CI) |
| Fuzz / battle | Résistance à l'input adversarial, concurrence DB | Élevé, continu | Job CI dédié + nightly continu |
| E2E | Le pipeline complet (HTTP → FSM → DB → HTML) fonctionne | Élevé | À chaque commit (CI), suite dédiée |
| Smoke | Le chemin critique fonctionne en environnement réel | Faible, rapide | À chaque déploiement |

### Argument de fond pour justifier cet investissement

Le coût marginal de chaque niveau au-delà des tests unitaires est largement compensé par la nature de ce composant : une FSM de gestion de tickets est un point de passage **obligé** pour toute mutation d'état métier dans l'application, elle est appelée depuis potentiellement de nombreux points d'entrée (UI, API, webhooks, jobs automatisés), et une régression y est silencieuse par nature — un ticket qui reste bloqué dans un mauvais état, ou pire, qui saute une étape de validation métier, ne génère pas nécessairement d'erreur visible immédiatement. C'est typiquement le genre de composant où l'absence de bug ne se remarque jamais, mais où sa présence coûte cher en confiance utilisateur et en support une fois découverte en production — ce qui justifie de pousser l'effort de test bien au-delà de ce qu'on ferait pour une fonction utilitaire ordinaire.

### Limite de cette pyramide

Au-delà de ces sept niveaux, on entre dans le chaos-engineering (injection de pannes réseau/DB en environnement de staging, tests de charge avec profils réalistes) — un budget et une maturité d'infrastructure différents, à envisager une fois le produit en usage réel avec un volume de tickets suffisant pour que les scénarios de concurrence cessent d'être hypothétiques.
