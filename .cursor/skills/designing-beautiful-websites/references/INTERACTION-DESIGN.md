# Interaction Design for Websites

> Use this when you need behaviour rules, form patterns, error handling, and clear feedback.

## Table of contents
- [Interaction principles](#interaction-principles)
- [Affordances and signifiers](#affordances-and-signifiers)
- [Direct manipulation and feedback](#direct-manipulation-and-feedback)
- [Preventing errors](#preventing-errors)
- [Dialogs, confirmations, and destructive actions](#dialogs-confirmations-and-destructive-actions)
- [Forms](#forms)
- [States and edge cases](#states-and-edge-cases)

## Interaction principles
- **Make expectations explicit**: the UI "promises" behaviour through its visuals; always deliver on that promise.
- **Prefer recognition over recall**: show options and context; don't make people memorise.
- **Feedback is part of the interaction**: users should always know what happened and what happens next.
- **Prevent errors**: the best error message is the one you never need.
- **Keep users in flow**: avoid interruptive patterns unless risk is truly high.

## Affordances and signifiers
Affordances are what a control *appears* to do.

Rules:
- controls must look like controls (buttons, links, inputs); don't rely on hover to reveal affordance;
- interactive areas must have clear hover/focus/active states;
- don't use the same visual style for interactive and non-interactive elements.

Common traps:
- decorative icons that look clickable,
- cards that are clickable with no signifier,
- "link-like" coloured text that isn't a link.

## Direct manipulation and feedback
When possible, let users act directly on visible objects and see results immediately.

Patterns:
- inline editing (instead of separate edit screens),
- previewing outcomes before committing,
- drag/drop reordering with clear drop targets,
- immediate visual confirmation for actions.

### Modeless feedback (preferred)
Use persistent, inline feedback that doesn't stop the user:
- status badges,
- inline validation,
- progress indicators,
- subtle toasts (with undo when appropriate).

Avoid:
- frequent blocking dialogs,
- errors that appear only after submission,
- vague spinners with no context.

## Preventing errors
Three levels of defence (use in order):
1. **Make errors impossible**: constrain inputs, use pickers, infer values.
2. **Make errors unlikely**: smart defaults, suggestions, previews.
3. **Make recovery easy**: undo, clear explanations, safe fallbacks.

Examples:
- auto-format phone numbers and dates;
- look up postcode from address (when feasible);
- disable impossible actions and explain why.

## Dialogs, confirmations, and destructive actions
Principle: don't make users confirm things they don't understand.

Use confirmations when:
- the action is destructive *and* not easily reversible,
- the user might trigger it accidentally,
- the impact is significant.

Confirmation copy should:
- name the thing being affected,
- state the impact,
- offer a safe escape.

Prefer:
- **undo** (best),
- **soft delete**,
- **preview**,
- **two-step** destructive actions (e.g., "type DELETE").

## Forms
### Anatomy
For each field:
- label (required),
- input,
- help text (optional),
- validation message (conditional).

### Layout and grouping
Rules:
- group related fields; separate groups with extra spacing;
- labels should feel attached to inputs (tight spacing);
- align fields and controls on a clear grid;
- keep forms as short as possible.

### Validation
Preferred:
- validate inline after interaction (blur) and on submit;
- show errors near the field;
- keep messages human and actionable.

Avoid:
- error summaries with no field mapping,
- clearing user input after an error,
- blaming the user.

### Defaults and choice architecture
Rules:
- pick sensible defaults based on likely user intent;
- for long lists, provide search or typeahead;
- don't force a choice when "none" is valid.

### Accessibility essentials
- every input has a label associated with it;
- errors are announced to assistive tech;
- focus moves to the first error on submit;
- keyboard navigation works logically.

## States and edge cases
Every screen/component should define:
- **Loading**: what is loading? how long? skeleton or spinner?
- **Empty**: why empty? what next? hide irrelevant controls?
- **Error**: what happened? retry? alternative path?
- **Success**: what changed? next action?
- **Disabled**: why disabled? what enables it?

Edge cases checklist:
- long labels, long values, localisation (text expansion),
- missing avatars/images,
- permissions and read-only modes,
- offline/slow network,
- partial data.
