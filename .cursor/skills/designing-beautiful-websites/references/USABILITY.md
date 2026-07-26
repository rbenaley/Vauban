# Usability for Websites

> Use this when you need to diagnose confusion, improve navigation, or make an interface feel effortless.

## Table of contents
- [Usability mindset](#usability-mindset)
- [Design for scanning](#design-for-scanning)
- [Make choices mindless](#make-choices-mindless)
- [Navigation that users trust](#navigation-that-users-trust)
- [Make clickability obvious](#make-clickability-obvious)
- [Reduce noise and distractions](#reduce-noise-and-distractions)
- [Microcopy and naming](#microcopy-and-naming)
- [Quick tests](#quick-tests)
- [Common failure patterns](#common-failure-patterns)

## Usability mindset
Users rarely read; they **skim**, then pick the first option that seems good enough.
Your job is to make the "good enough" option the right one.

Rules of thumb:
- prefer **clarity over persuasion**;
- remove uncertainty;
- don't punish users for mistakes;
- don't surprise users with non-standard behaviour.

## Design for scanning
Treat pages like signage.
Help users understand the page quickly by:
- using conventions,
- creating strong visual hierarchy,
- dividing pages into clear regions,
- formatting content for scanning.

### Visual hierarchy checklist
Every key page should be legible as:
1. page name/purpose,
2. primary action,
3. primary content,
4. secondary actions,
5. supporting info.

Common fixes:
- make the primary CTA the most visually prominent interactive element;
- ensure headings describe the content underneath them;
- use consistent heading sizes and spacing rules;
- avoid placing headings so they "span" unrelated content.

### Clear regions checklist
At a glance, a user should be able to point and say:
- "navigation",
- "main content",
- "things I can do",
- "supporting info",
- "promotions/ads (if any)".

If the page can't be chunked, simplify the layout and reduce competing elements.

## Make choices mindless
"Fewer clicks" is less important than "easier clicks".
Multiple easy, confident selections beat one confusing choice.

### Information scent
Links and buttons should describe the result of clicking.
Users should feel they are moving closer to the goal at every step.

Checklist:
- link text is descriptive, not "Click here";
- button labels describe outcomes ("Create invoice", not "Submit");
- navigation labels match user language;
- the current location is visible (active states, breadcrumbs where needed).

## Navigation that users trust
Navigation should answer:
- where am I?
- what's here?
- where can I go next?

### Global navigation
Rules:
- keep top-level sections stable across the site;
- use familiar placement (header/top bar or left nav);
- avoid hiding primary nav behind multiple clicks on desktop.

### Page naming
Every page needs a clear name.
It should:
- be near the top of the main content region,
- match what the user clicked,
- use plain language.

### Search
If users can arrive with vague intent, search is not optional.
Rules:
- put search where users expect it;
- support forgiving input (typos, partial matches);
- show results that are easy to scan.

## Make clickability obvious
Users should never have to think:
- "is this clickable?"

Rules:
- interactive elements must look interactive:
  - buttons look like buttons,
  - links look like links,
  - tabs look like tabs.
- don't make plain text look like a link.
- keep click targets comfortably large.

Common pitfalls:
- entire cards being clickable with no signifier;
- "ghost" buttons that look like secondary text;
- icons with unclear meaning.

## Reduce noise and distractions
Noise forces thinking.

Checklist:
- remove decorative elements that compete with primary content;
- avoid too many colours, weights, and border styles;
- reduce repeated CTAs;
- limit animation to meaning (status/feedback).

## Microcopy and naming
Words are UI.

Rules:
- choose "obvious" names over cute/clever names;
- use labels users already know;
- keep instructions short and close to the control;
- remove needless words.

Error copy:
- explain what happened,
- why it matters,
- what to do next.
Never scold the user.

## Quick tests
### Glance test (10 seconds)
Show a screen for 10 seconds. Ask:
- what is this?
- who is it for?
- what can you do here?
- what is the primary action?
- where is the navigation?

If answers vary, fix hierarchy and labels.

### "Trunk test" (first-time comprehension)
Give someone a random internal page (not the home page). Ask them to identify:
- what site is this?
- what page is this?
- what are the main sections?
- where are they in the structure?
- how can they search?

If they can't answer quickly, fix:
- site ID/branding placement,
- page naming,
- nav structure,
- and visual hierarchy.

### Five-minute usability test (DIY)
1. Give a realistic task (from a key path).
2. Ask the participant to narrate what they expect will happen.
3. Stay silent; observe confusion.
4. After, ask:
  - what was hardest?
  - what surprised you?
  - what did you expect instead?

You'll learn enough from 3–5 participants to make meaningful improvements.

## Common failure patterns
- **Everything is "important"** → nothing stands out; fix hierarchy.
- **Too many words** → users skip; tighten copy and use bullets.
- **Clever labels** → users hesitate; rename.
- **Hidden primary action** → make the next step obvious.
- **Unclear grouping** → adjust spacing; add separators only if needed.
- **Weak click signifiers** → use conventional styling.
