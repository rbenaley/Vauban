# UX/UI Checklists and Templates

> Use this for fast QA and consistent outputs.

## Table of contents
- [Design brief checklist](#design-brief-checklist)
- [IA and navigation checklist](#ia-and-navigation-checklist)
- [Wireframe checklist](#wireframe-checklist)
- [Visual system checklist](#visual-system-checklist)
- [Interaction and forms checklist](#interaction-and-forms-checklist)
- [Accessibility checklist](#accessibility-checklist)
- [Content checklist](#content-checklist)
- [Responsive checklist](#responsive-checklist)
- [Pre-launch QA checklist](#pre-launch-qa-checklist)
- [Component state matrix template](#component-state-matrix-template)

## Design brief checklist
- [ ] Primary user(s) defined
- [ ] Primary user goal and business goal stated
- [ ] Success metrics listed
- [ ] Constraints (tech, time, brand, legal, accessibility) captured
- [ ] Key pages listed
- [ ] Key paths listed
- [ ] Assumptions clearly marked

## IA and navigation checklist
- [ ] Top-level nav is short and stable
- [ ] Labels are obvious and consistent
- [ ] Current location is visible (active state / breadcrumbs)
- [ ] Every page has a clear title that matches nav labels
- [ ] Search exists where discovery matters

## Wireframe checklist
- [ ] Page has a single primary action (or an explicit reason it doesn't)
- [ ] Regions are clear (nav, main, secondary)
- [ ] Key path steps are unambiguous
- [ ] Clickable elements are clearly signified
- [ ] Spacing communicates grouping (inside < between)

## Visual system checklist
- [ ] Spacing scale defined and used
- [ ] Type scale defined and used
- [ ] Colour palette defined (neutrals, primary, semantic accents)
- [ ] Contrast targets met
- [ ] Radius and elevation systems defined
- [ ] Borders used sparingly

## Interaction and forms checklist
- [ ] Inputs have labels
- [ ] Inline validation behaviour defined
- [ ] Errors are actionable, not blaming
- [ ] Destructive actions are reversible or confirmed
- [ ] Feedback is modeless when possible

## Accessibility checklist
- [ ] Keyboard navigation works and focus is visible
- [ ] Contrast targets met
- [ ] Not colour-only communication
- [ ] Semantic elements used appropriately
- [ ] Forms announce errors appropriately

## Content checklist
- [ ] Headings describe the section
- [ ] Copy is scannable (bullets, short paragraphs)
- [ ] Button labels describe outcomes
- [ ] Jargon and clever labels removed
- [ ] Empty states explain and guide

## Responsive checklist
- [ ] Mobile-first layout is viable
- [ ] Primary action remains prominent at all sizes
- [ ] Text doesn't become too wide to read
- [ ] Tables/toolbars have responsive strategies
- [ ] Touch targets are comfortable

## Pre-launch QA checklist
- [ ] Key paths tested end-to-end
- [ ] Loading/empty/error states handled
- [ ] Long text and localisation expansion tested
- [ ] Images have safe fallbacks
- [ ] Performance basics: avoid heavy assets above the fold
- [ ] Cross-browser smoke test

## Component state matrix template
For each component:
- Variants:
- States:
  - Default
  - Hover
  - Focus
  - Active
  - Disabled
  - Loading
  - Error
  - Success
  - Empty (if relevant)
- Keyboard behaviour:
- Screen reader notes:
