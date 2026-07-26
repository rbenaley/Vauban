# Responsive Layout Rules

> Use this when you need mobile-first layouts, breakpoint decisions, and component behaviour across screen sizes.

## Table of contents
- [Core rules](#core-rules)
- [Mobile-first workflow](#mobile-first-workflow)
- [Containers, columns, and reading width](#containers-columns-and-reading-width)
- [Independent scaling](#independent-scaling)
- [Component responsivity](#component-responsivity)
- [Responsive navigation](#responsive-navigation)
- [Testing checklist](#testing-checklist)

## Core rules
- Design for constraints first; expand later.
- Prioritise content and primary actions at every breakpoint.
- Don't squeeze desktop UI onto mobile; reflow it.

## Mobile-first workflow
1. Start at ~360–420px width.
2. Design key pages and key paths.
3. Expand to tablet and desktop and fix what felt like a compromise.

If you're stuck designing a "small" UI on a wide canvas, shrink the canvas.

## Containers, columns, and reading width
Rules:
- Reading-heavy sections need a max width; wide text is hard to scan.
- Don't make everything full-width just because the header is full-width.
- If a layout feels too wide, split into columns instead of stretching content.

## Independent scaling
Avoid purely proportional scaling.
As screens shrink:
- large elements should shrink faster than small elements,
- spacing should compress, but not uniformly,
- component padding often needs to tighten more than font size.

Rule:
- fine-tune properties independently; don't treat the UI as a zoomed image.

## Component responsivity
For each component, define:
- how it reflows (stack vs inline),
- how it truncates or wraps text,
- how density changes,
- touch target rules,
- and what happens to secondary actions.

Examples:
- tables → switch to cards, stacked rows, or horizontal scrolling with clear affordance.
- toolbars → move secondary actions into an overflow menu.

## Responsive navigation
Rules:
- keep primary navigation discoverable;
- avoid hiding essential sections behind deep menus on desktop;
- on mobile, use patterns users recognise (tabs, bottom nav, hamburger) based on app type.

## Testing checklist
- breakpoints: small phone, large phone, tablet, desktop, wide desktop
- text expansion: +30% length (localisation)
- touch: tap targets and spacing
- keyboard: focus order and visible focus
- content extremes: long titles, empty lists, huge numbers
