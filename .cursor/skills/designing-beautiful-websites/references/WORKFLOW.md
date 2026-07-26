# UX/UI Workflow for Websites

> Use this when you need an end-to-end plan, deliverables, or a repeatable way to go from vague intent → shippable design.

## Table of contents
- [Operating principles](#operating-principles)
- [Phase 0: Define the problem](#phase-0-define-the-problem)
- [Phase 1: Users and goals](#phase-1-users-and-goals)
- [Phase 2: Scope and requirements](#phase-2-scope-and-requirements)
- [Phase 3: Information architecture and navigation](#phase-3-information-architecture-and-navigation)
- [Phase 4: Interaction model](#phase-4-interaction-model)
- [Phase 5: Skeleton (wireframes and layout)](#phase-5-skeleton-wireframes-and-layout)
- [Phase 6: Surface (visual system and comps)](#phase-6-surface-visual-system-and-comps)
- [Phase 7: Validate and iterate](#phase-7-validate-and-iterate)
- [Phase 8: Handoff](#phase-8-handoff)
- [Templates](#templates)

## Operating principles
- **Build from intent to pixels**: decisions about colour and layout are constrained by goals, content, and flows.
- **Work iteratively, not sequentially**: higher-level design can reveal missing lower-level decisions. Expect to revisit.
- **Optimise the key paths first**: a site that nails the primary journeys beats a site with 40 mediocre pages.
- **Design for scanning**: on the web, users skim and select; structure and hierarchy are the design.
- **System > screens**: design tokens + components prevent "one-off UI" and accelerate implementation.

## Phase 0: Define the problem
Output: **one-page design brief**.

Checklist:
- Who is the product/site for?
- What is the #1 outcome the user must achieve?
- What is the #1 business outcome?
- What constraints exist (tech, brand, legal, accessibility, time)?
- What is the current baseline (what works, what fails)?

Rules:
- If details are missing, write assumptions explicitly.
- Tie design decisions to outcomes (conversion, retention, comprehension, task completion).

## Phase 1: Users and goals
Pick a lightweight method based on time.

### Option A: Persona-lite (fast)
Create 1–2 persona-lites that capture:
- goals (why they're here),
- context (device, environment, time pressure),
- anxieties/risks (what makes them hesitate),
- capabilities (experience level, accessibility needs).

### Option B: Job story (fastest)
Format:
- **When** [situation]
- **I want** [motivation]
- **So I can** [expected outcome]

### Option C: Full persona + scenario (when high stakes)
Write a short narrative of an ideal experience that emphasises goals and context.

Rules:
- **Goals before tasks**: tasks are symptoms; goals drive prioritisation.
- Prefer a small "cast" with clear priority:
  - primary persona (design target),
  - secondary personas (supported, but not driving the UI).

## Phase 2: Scope and requirements
Output: **scope list + key paths**.

Steps:
1. List pages/screens and major features.
2. Do a content inventory (what copy, images, data exist?).
3. Define 1–3 **key paths**.

Key path examples:
- Landing → pricing → signup
- Search → filter → item detail → checkout
- Dashboard → create report → export/share

Rules:
- If everything is a priority, nothing is. Pick the journeys that matter.
- Delay "nice to have" features until the key paths are frictionless.

## Phase 3: Information architecture and navigation
Output: **IA diagram + navigation model + labels**.

Checklist:
- Global nav: top-level sections (5–7 is usually enough).
- Local nav: within a section, how do users move laterally?
- Search: if discovery matters, define where search lives and how results work.
- Page naming: every page needs a clear name that matches the user's mental model.

Rules:
- Labels must be obvious. Avoid internal jargon and clever marketing names.
- Prefer recognition over recall: show choices; don't force memory.
- Keep navigation consistent across pages.

## Phase 4: Interaction model
Output: **flows + interaction rules + state model**.

Steps:
1. For each key path, write the step-by-step flow.
2. Define interaction patterns:
  - forms,
  - filtering/sorting,
  - selection,
  - editing,
  - confirmations/destructive actions.
3. Define states for each key screen:
  - loading,
  - empty,
  - error,
  - success,
  - partial data,
  - permissions.

Rules:
- Prefer preventing errors (smart defaults, constraints) over showing errors.
- Prefer modeless feedback (inline status, previews) over disruptive dialogs.

## Phase 5: Skeleton (wireframes and layout)
Output: **wireframes + component inventory**.

Steps:
1. Start with a real feature/content block (not a nav bar).
2. Place information in priority order.
3. Establish page regions:
  - site ID,
  - navigation,
  - primary content,
  - secondary content,
  - calls to action.
4. Define responsive layout constraints:
  - max content width,
  - breakpoints,
  - column strategy.

Rules:
- A page should be parsable at a glance into clearly defined areas.
- Make click targets and interactive affordances obvious.

## Phase 6: Surface (visual system and comps)
Output: **tokens + component library + page comps**.

Steps:
1. Create tokens:
  - spacing/sizing,
  - type scale,
  - colours (with shades),
  - radius,
  - elevation.
2. Define components and variants.
3. Apply to key pages first.

Rules:
- Constrain choices. Systems beat arbitrary numbers.
- Use spacing to clarify grouping.
- Use colour sparingly for meaning (actions and status), not decoration.

## Phase 7: Validate and iterate
Output: **issues + fixes + updated design**.

Use quick, repeatable tests:
- **Glance test**: in 10 seconds, can someone tell what it is and what to do?
- **Key-path walkthrough**: can a first-time user complete the journey?
- **Edge case sweep**: long text, missing data, errors, empty.
- **Accessibility sweep**: contrast, focus, keyboard, semantics.

Iteration rule:
- Make the smallest set of changes that remove the largest confusion.

## Phase 8: Handoff
Output: **build-ready package**.

Include:
- tokens (CSS variables or JSON),
- component specs (including states),
- responsive rules,
- accessibility notes,
- content rules (copy lengths, truncation),
- and acceptance criteria for key paths.

## Templates

### Template: Design brief (one page)
- **Product/site:**
- **Primary user:**
- **Primary user goal:**
- **Business goal:**
- **Success metrics:**
- **Constraints:**
- **Key pages:**
- **Key paths:**
- **Brand traits (3–5 adjectives):**
- **Risks/unknowns:**

### Template: Key path flow
- **Goal:**
- **Entry points:**
- **Steps:**
  1.
  2.
  3.
- **Decisions/branches:**
- **Failure states:**
- **Success confirmation:**

### Template: Component inventory
For each component:
- name,
- purpose,
- variants,
- states,
- dependencies (tokens, subcomponents).

### Template: State model (per page)
- Loading:
- Empty:
- Error:
- Success:
- Partial data:
- Permissions:
