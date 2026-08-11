# Vauban Customer Portal — transactional email templates

Three send-ready HTML emails for the Vauban Customer Portal, plus the
design tokens they were built from.

## Contents

| File | Event | Subject line |
|---|---|---|
| `user-join.html`  | User added — invitation | Invitation to {org} — Vauban Customer Portal |
| `user-login.html` | User login — magic link | Sign in to Vauban Customer Portal |
| `user-leave.html` | User removed — access revoked | Access removed — {org} |
| `design-tokens.json`    | Colors, type, spacing, component values | — |
| `vauban-logo.png`       | Star-fort logo, 384px (rendered at 48px) | — |

## Build notes

- Nested `<table role="presentation">` layout, 600px wrapper, single column.
- Every style is inline. No `<style>` block, no JavaScript, no external
  stylesheet, no web fonts.
- Email-safe font stacks: Arial/Helvetica for body, Courier New for the
  wordmark and raw URLs (substitutes for IBM Plex Sans / IBM Plex Mono).
- Bulletproof buttons: padded `<td>` with `bgcolor`, `<a>` set to
  `display:block`.
- Hidden preheader span (~85 chars) as the first element in `<body>`.
- `mso-line-height-rule:exactly` on every text cell for the Outlook Word
  engine.

## VCP wiring

Templates are embedded at compile time via `include_str!` from
`src/mail_templates.rs`. Placeholders substituted before send:

| Placeholder | Meaning |
|---|---|
| `__ORG_NAME__` | Organization display name (HTML-escaped in HTML body) |
| `__MAGIC_URL__` | Absolute magic-link URL (join + login; button, fallback href, visible URL) |
| `__FROM_ADDRESS__` | `magic_links.from_address` |
| `__TTL_MINUTES__` | `ceil(token_ttl_secs / 60)` as a decimal string |

Logo uses `src="cid:vauban-logo"` with `Attachment::inline` from
`vauban-logo.png` (Gmail/Outlook do not render base64 `data:` images).

Plain-text alternatives keep the historic copy from `src/mailer.rs`.
