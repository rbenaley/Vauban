# Third-Party Licenses

This file lists third-party assets bundled inside the Vauban binary that ship
under their own license, separately from the project license in `LICENSE`.

> Rust crate dependencies are not listed here: their licenses are tracked
> automatically via `cargo` and `Cargo.lock`.  This file covers **vendored
> binary assets** (fonts, prebuilt JavaScript, CSS) that live under
> `vauban-web/static/`.

---

## text-security-disc.woff2

- **File:** `vauban-web/static/fonts/text-security-disc.woff2`
- **Upstream:** <https://github.com/noppa/text-security>
- **Copyright:** Copyright 2020 Oskari Noppa
- **License:** SIL Open Font License, Version 1.1 (OFL-1.1)

The full license text follows.  It must remain bundled with the font per
clause 2 of OFL-1.1.

```
This Font Software is licensed under the SIL Open Font License,
Version 1.1.

This license is copied below, and is also available with a FAQ at:
http://scripts.sil.org/OFL

-----------------------------------------------------------
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font
creation efforts of academic and linguistic communities, and to
provide a free and open framework in which fonts may be shared and
improved in partnership with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply to
any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software
components as distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to,
deleting, or substituting -- in part or in whole -- any of the
components of the Original Version, by changing formats or by porting
the Font Software to a new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed,
modify, redistribute, and sell modified and unmodified copies of the
Font Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components, in
Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the
corresponding Copyright Holder. This restriction only applies to the
primary font name as presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created using
the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```

---

## Self-hosted front-end libraries (MIT)

These JavaScript/CSS libraries used to be loaded from public CDNs
(`cdn.tailwindcss.com`, `unpkg.com`, `cdn.jsdelivr.net`). They are now
vendored verbatim (pinned versions, no source change) under
`vauban-web/static/js/vendor/` and `vauban-web/static/css/vendor/` so the
browser never reaches a third-party origin at runtime. Refresh them with
`vauban-web/scripts/vendor_assets.sh`.

| Library | Version | File(s) | Upstream |
|---|---|---|---|
| Tailwind CSS (JIT Play CDN bundle) | 3.4.17 | `js/vendor/tailwindcss.js` | <https://github.com/tailwindlabs/tailwindcss> |
| htmx | 1.9.12 | `js/vendor/htmx.min.js`, `js/vendor/htmx-ext-ws.js`, `js/vendor/htmx-ext-json-enc.js` | <https://github.com/bigskysoftware/htmx> |
| Alpine.js (standard build) | 3.14.0 | `js/vendor/alpine.min.js` | <https://github.com/alpinejs/alpine> |
| @xterm/xterm | 5.5.0 | `js/vendor/xterm.min.js`, `css/vendor/xterm.min.css` | <https://github.com/xtermjs/xterm.js> |
| @xterm/addon-fit | 0.10.0 | `js/vendor/xterm-addon-fit.min.js` | <https://github.com/xtermjs/xterm.js> |
| @xterm/addon-web-links | 0.11.0 | `js/vendor/xterm-addon-web-links.min.js` | <https://github.com/xtermjs/xterm.js> |

All of the above are distributed under the MIT License. Copyright belongs to
their respective authors:

- Tailwind CSS: Copyright (c) Tailwind Labs, Inc.
- htmx: Copyright (c) Big Sky Software
- Alpine.js: Copyright (c) Caleb Porzio and contributors
- xterm.js and addons: Copyright (c) The xterm.js authors

The MIT License text (common to all of the above):

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
