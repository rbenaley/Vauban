# Accessibility Essentials for Web UX/UI

> Use this when designing, auditing, or specifying UI. Accessibility is a quality baseline, not a nice-to-have.

## Table of contents
- [Non-negotiables](#non-negotiables)
- [Colour and contrast](#colour-and-contrast)
- [Keyboard and focus](#keyboard-and-focus)
- [Semantic HTML](#semantic-html)
- [Forms and errors](#forms-and-errors)
- [Motion and animation](#motion-and-animation)

## Non-negotiables
- All interactive elements are reachable via keyboard.
- Focus is visible and logical.
- Text has sufficient contrast.
- Controls have programmatic labels.
- Errors are understandable and recoverable.

## Colour and contrast
Targets:
- normal text: ≥ 4.5:1
- large text: ≥ 3:1

Rules:
- don't rely on colour alone to communicate state (also use icons, text, or patterns).
- if white text forces a coloured background to become too dark and visually dominant, use dark text on a light tint.

## Keyboard and focus
Rules:
- focus order follows visual order.
- focus styles are obvious (don't remove outlines without replacing them).
- modals trap focus and restore it on close.

## Semantic HTML
Prefer native elements:
- `<button>` for actions, `<a>` for navigation.
- headings are hierarchical.
- lists are real lists.
- inputs have `<label>`.

ARIA rule:
- don't add ARIA when native semantics already solve it.

## Forms and errors
Rules:
- label every input.
- indicate required fields.
- validate clearly and near the field.
- on submit errors, focus the first invalid field.
- error messages must be announced (aria-live / describedby patterns).

## Motion and animation
Rules:
- motion should communicate meaning (state change), not just decorate.
- respect reduced motion preferences.
