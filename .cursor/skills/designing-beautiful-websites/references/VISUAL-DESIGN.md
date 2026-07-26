# Visual Design Systems for Websites

> Use this when you need to make a UI feel polished and coherent (spacing, typography, colour, depth, imagery).

## Table of contents
- [Start with a system](#start-with-a-system)
- [Layout and spacing](#layout-and-spacing)
- [Typography](#typography)
- [Colour](#colour)
- [Depth, borders, and elevation](#depth-borders-and-elevation)
- [Working with images](#working-with-images)
- [Finishing touches](#finishing-touches)
- [Reference token starter (CSS)](#reference-token-starter-css)

## Start with a system
Beautiful interfaces look "effortless" because decisions are **constrained**.

Rules:
- choose a spacing scale, type scale, and colour palette *before* polishing screens;
- use tokens in implementation (CSS variables / design tokens), not one-off values;
- if you add a new token, it must have a reason and a usage rule.

## Layout and spacing

### Start with too much whitespace
A reliable way to reach "clean" is:
1. give elements *more* room than you think they need,
2. then remove whitespace until the layout feels tight *without* feeling cramped.

Dense layouts are sometimes correct (dashboards, data-heavy tools), but density should be a deliberate choice.

### Establish a spacing and sizing scale
Avoid pixel-by-pixel tweaking.
Pick a non-linear scale where adjacent values are meaningfully different.

Suggested scale (px):
`0, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128`

Rules:
- no new spacing values without a strong reason;
- "try next value up/down" should usually be the right adjustment;
- prefer padding and whitespace over borders.

### Avoid ambiguous spacing
If spacing is the only grouping cue:
- keep **inside-group spacing smaller** than **between-group spacing**.

Common examples:
- form labels must feel attached to their inputs;
- headings must feel attached to the section they introduce;
- list items need separation that doesn't look like line-height.

### You don't have to fill the whole screen
Wide content is harder to read and parse.

Rules:
- choose a sensible max width for reading-heavy sections;
- don't expand components just because there is empty space;
- when a section needs more visual weight, use hierarchy (type/spacing), not width.

Mobile-first technique:
- design on a narrow canvas first (~360–420px), then expand.

### Alignment and rhythm
- Align to a small set of vertical anchors (grid lines, baseline rhythm).
- Prefer consistent edge alignment over "centering everything".
- Use repeated spacing patterns so the page feels calm.

## Typography

### Establish a type scale
Most UIs use too many font sizes.

Recommended: 6–8 sizes, named.
Example (px):
- `12` caption
- `14` small
- `16` base
- `20` lg
- `24` xl
- `30` 2xl
- `40` 3xl

Rules:
- use weight, colour, and spacing before adding sizes;
- define line-height per category (body vs headings);
- keep reading line length ~45–80 characters.

### Weight and contrast
- Body text needs enough contrast against the background.
- Use heavier weight or larger size instead of pure colour changes for hierarchy.

### Fonts (pragmatic defaults)
- Use 1 font family for most UI.
- If using a second font, reserve it for display/brand moments.
- Avoid ultra-thin weights for text.

## Colour

### Build palettes with shades
Define shades up front so you don't end up with dozens of near-identical colours.

Rules:
- define a **neutral** scale for backgrounds and text;
- define one primary brand colour with shades;
- define semantic accents (success/warn/danger/info) with shades;
- avoid algorithmic lightening/darkening for production tokens.

A practical shade naming scheme:
`100, 200, 300, 400, 500, 600, 700, 800, 900`

Typical usage:
- `900–700` for text
- `600–400` for borders/icons/active states
- `300–100` for subtle backgrounds

### Greys have temperature
True grey is rare; "greys" often lean warm or cool.
Pick a temperature and keep it consistent.

Rule:
- slightly increase saturation in very light and very dark neutrals so they don't feel washed out.

### Don't let lightness kill saturation
Very light or very dark colours can look dull if saturation isn't adjusted.

Practical approach:
- for lighter shades: raise saturation slightly as lightness rises;
- for darker shades: raise saturation slightly as lightness falls.

### Adjust perceived brightness with small hue rotation
Different hues feel inherently brighter.
To create lighter/darker shades without "washing out" a colour:
- rotate hue slightly (small changes only; keep within ~20–30°).

### Accessible contrast without ugly UI
Targets:
- normal text: ≥ 4.5:1
- large text: ≥ 3:1

If white text on a coloured background forces the background to become too dark and dominant:
- **flip the contrast**: use dark coloured text on a light tinted background.

For coloured text on coloured backgrounds:
- consider shifting the text hue towards a brighter hue while meeting contrast.

## Depth, borders, and elevation

### Emulate a light source
To make elevation feel real:
- top edges are slightly lighter;
- shadows fall below the element;
- keep blur modest; sharp-ish edges feel more natural.

### Use shadows to convey meaning
Shadows are not decoration; they indicate z-position and focus.

Guidelines:
- subtle shadows for cards/buttons,
- stronger shadows for popovers,
- strongest for modals.

Define a small elevation system (3–5 shadows) and reuse them.

### Use fewer borders
Borders can make a UI feel busy.
Try, in this order:
1. more spacing,
2. slight background difference,
3. subtle shadow,
4. border (last resort).

## Working with images

Rules:
- use genuinely good images; low-quality images poison an otherwise clean UI;
- ensure text on images has consistent contrast (overlay, gradient, or avoid);
- beware user-uploaded images: plan for weird crops, bad lighting, and clashing colours.

Practical strategies:
- enforce aspect ratios;
- use object-fit with focal point hints;
- add subtle background or border radius consistency.

## Finishing touches

### Empty states
Don't ship a feature without its empty state.
An empty state should:
- explain what this section is for,
- show an example,
- and highlight the next action.

Also consider hiding irrelevant controls (filters/tabs) until there is data.

### Accent borders
To make UI feel "designed" without adding noise:
- use a thin accent border on cards/alerts;
- keep contrast subtle;
- tie accent use to meaning (status, category).

### Decorated backgrounds (subtle)
Background patterns and shapes can add polish.
Rules:
- keep contrast low;
- keep decoration out of the reading path;
- use it to frame sections, not compete with content.

## Reference token starter (CSS)

```css
:root {
  /* Spacing */
  --space-0: 0px;
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 24px;
  --space-6: 32px;
  --space-7: 48px;
  --space-8: 64px;
  --space-9: 96px;
  --space-10: 128px;

  /* Type scale */
  --font-0: 12px;
  --font-1: 14px;
  --font-2: 16px;
  --font-3: 20px;
  --font-4: 24px;
  --font-5: 30px;
  --font-6: 40px;

  /* Radius */
  --radius-1: 6px;
  --radius-2: 10px;
  --radius-3: 16px;

  /* Elevation (examples, tune to palette) */
  --shadow-1: 0 1px 2px rgba(0,0,0,0.08);
  --shadow-2: 0 4px 10px rgba(0,0,0,0.10);
  --shadow-3: 0 10px 25px rgba(0,0,0,0.12);
  --shadow-4: 0 20px 50px rgba(0,0,0,0.16);

  /* Neutral palette (example placeholders) */
  --neutral-0: #ffffff;
  --neutral-50: #f8fafc;
  --neutral-100: #f1f5f9;
  --neutral-200: #e2e8f0;
  --neutral-300: #cbd5e1;
  --neutral-600: #475569;
  --neutral-800: #1f2937;
  --neutral-900: #0f172a;
}
```

Use a real palette for your project; don't ship placeholder colours.
