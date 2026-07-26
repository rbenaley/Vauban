# UX/UI Design Audit Playbook

> Use this when the user asks to critique, review, modernise, or improve an existing website/app UI.

## Table of contents
- [What to collect](#what-to-collect)
- [Audit workflow](#audit-workflow)
- [Heuristic review rubric](#heuristic-review-rubric)
- [Common root causes](#common-root-causes)
- [How to present results](#how-to-present-results)

## What to collect
- Screens: home, key pages, key flows, states (error/empty/loading)
- Known constraints: brand, tech stack, accessibility target
- Success metrics: conversion, task completion, retention, support tickets
- Primary users: who they are and what they want to do

If you don't have data, state assumptions.

## Audit workflow
1. **Define success**
  - What should users be able to do?
  - What does the business care about?

2. **Map 1–3 key paths**
  - Write the flows step-by-step.
  - Note every moment of uncertainty or friction.

3. **Run a "trunk test" on internal pages**
  Check whether a first-time user can tell:
  - what site this is,
  - what page this is,
  - where they are in the structure,
  - where to go next.

4. **Heuristic review (fast rubric below)**
  Capture issues as:
  - **Symptom** (what the user experiences)
  - **Cause** (why it happens)
  - **Fix** (concrete change)

5. **Systemise fixes**
  Look for repeating causes:
  - inconsistent spacing,
  - unclear clickability,
  - weak hierarchy,
  - inconsistent component styles.

6. **Propose an iteration plan**
  - quick wins (1–2 days)
  - medium changes (1–2 weeks)
  - bigger redesign (multi-week)

## Heuristic review rubric
Score each area: ✅ good / ⚠️ needs work / ❌ broken.

### Clarity
- Can users tell what the page is for in 10 seconds?
- Is the primary action obvious?
- Are labels self-explanatory?

### Hierarchy
- Is there a clear primary/secondary/tertiary structure?
- Does spacing communicate grouping?
- Do headings match content and boundaries?

### Navigation and findability
- Is location clear (active states, page titles)?
- Are section labels consistent?
- Is search available where needed?

### Interaction quality
- Do controls behave as expected?
- Is feedback immediate and non-disruptive?
- Are errors prevented where possible?

### Visual quality
- Is typography consistent and readable?
- Is colour used with restraint and meaning?
- Is depth/border usage calm (not busy)?

### Accessibility
- Contrast targets met?
- Keyboard usable?
- Focus visible?
- Labels and errors accessible?

## Common root causes
- No defined token system → inconsistent spacing/colours/typography.
- Too many competing CTAs → unclear priority.
- Clever labels → hesitation and misclicks.
- Weak affordances → "is this clickable?" confusion.
- Overuse of borders → busy and cluttered look.
- Missing states → broken first impressions (empty/loading/error).

## How to present results
Recommended structure:
1. **Executive summary**: 5–10 bullets
2. **Top issues by severity**
  - Critical (blocks key path)
  - Major (causes hesitation)
  - Minor (polish)
3. **Screens/flows reviewed**
4. **Recommendations**
  - system fixes (tokens/components)
  - page fixes
5. **Next iteration plan**
  - quick wins
  - medium
  - long term
