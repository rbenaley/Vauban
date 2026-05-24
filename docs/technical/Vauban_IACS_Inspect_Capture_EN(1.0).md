# Vauban IACS Inspect Capture

**Version:** 1.0
**Date:** 25 May 2026
**Author:** Richard Ben Aleya

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [Position in the Vauban architecture](#2-position-in-the-vauban-architecture)
3. [Authorization gates](#3-authorization-gates)
4. [Surface and routes](#4-surface-and-routes)
5. [Pipeline](#5-pipeline)
6. [Dissectors](#6-dissectors)
7. [UI / UX contract](#7-ui--ux-contract)
8. [Battle-tested invariants](#8-battle-tested-invariants)
9. [Threat model](#9-threat-model)
10. [Test coverage](#10-test-coverage)
11. [Source of truth](#11-source-of-truth)

---

## 1. Purpose

The IACS recording feature (cf. `Vauban_Recording_Architecture_EN(1.5).md`)
captures every TCP segment of an Engineering-Workstation-to-asset tunnel as a
`channels/<n>.pcap.gz` file under the session's recording directory. The
file is suitable for offline forensic analysis with Wireshark, but two
operational shortcomings remain:

1. **Wireshark is offline.** The investigator has to download the
   recording, run Wireshark on a workstation, mount the right key
   material, and find the segment of interest. The audit feedback loop
   is measured in minutes, not seconds.
2. **Wireshark is generic.** It does not know what the operator's
   intent is, what the EWS endpoint is, what role each peer plays in
   the channel, what the asset's industrial protocol is, or how the
   `meta.json` integrity hash binds the capture to the audit trail.

`Inspect Capture` ("ICA") closes both gaps by rendering the same PCAP
inline, in the operator's browser, with industrial-protocol awareness:
Modbus FC and exception classification, IEC-104 ASDU type and Cause of
Transmission, with packet-level direction inferred from the recording's
canonical client/server tuple. The view is **read-only**, **server-rendered**
(HTMX + Tailwind + a tiny declarative Alpine `x-data`), and intentionally
narrower than Wireshark: no decryption, no replay, no decoder for every
exotic protocol -- just the dimensions Vauban ops actually pivot on.

The investigator workflow becomes a single click: from the recording
detail page, "Inspect Capture" opens the analyzer; the analyst filters
by direction / kind, free-text searches across the dissector summaries
(e.g. `FC06`, `ASDU C_SC_NA_1`), and clicks a row to see the dissection
tree linked, byte-by-byte, to the raw hex dump.

## 2. Position in the Vauban architecture

```
EWS  --SSH+direct-tcpip-->  vauban-proxy-iacs
                                 |
                                 +-> vauban-audit (PCAP gz)
                                 +-> vauban-access (re-check)

vauban-web  --IPC--> vauban-supervisor --SCM_RIGHTS--> meta.json
vauban-web  --IPC--> vauban-supervisor --SCM_RIGHTS--> channels/<n>.pcap.gz
            (Capsicum: vauban-web cannot open files directly)

vauban-web ::services::iacs_packet_analyzer
            +-- parser.rs        // PCAP global+record parser, etherparse
            +-- flow.rs          // canonical client/server inference
            +-- dissectors/      // modbus, iec104, passthrough
            +-- mod.rs           // analyze_channel + page_summaries

vauban-web ::handlers::web::sessions::inspect_capture*
            (3 handlers, route_layer require_admin_view + Casbin gate)
            -> Askama templates  (templates/sessions/inspect/*.html)
```

The analyzer lives entirely inside `vauban-web`, at the same trust
boundary as the rest of the audit-replay surface. The Capsicum-sandboxed
service never opens files directly: `meta.json` and each
`channels/<n>.pcap.gz` are fetched through the supervisor's
`SCM_RIGHTS`-brokered file-descriptor read path, exactly like the SSH /
RDP replay viewers (cf. `Vauban_Privsep_Architecture_EN(1.2).md` § FD
broker).

## 3. Authorization gates

Inspect Capture is gated by **`admin:view`** -- the same Casbin
permission that protects the supervisor dashboard. Three layers compose:

1. **`require_admin_view` route layer** on the
   `/sessions/recordings/{uuid}/inspect*` sub-tree. A non-admin gets a
   403 *before* any handler runs. Defence-in-depth pinned by
   `inspect_capture_test::routes_are_mounted_under_admin_layer`.
2. **`PermissionContext.admin_view`** re-checked in every handler body
   after the layer. A misconfiguration of either layer is caught by the
   other.
3. **Anti-enumeration response shaping**. Every "not found / not IACS /
   not finalized / channel index out of range / frame index out of
   range" condition collapses to the same generic
   `AppError::NotFound("Not found")`. A non-admin who somehow bypassed
   the layer (or an admin probing for an unknown UUID) cannot use the
   URL space as an oracle for session existence. Pinned by
   `inspect_capture_test::handlers_funnel_through_resolve_inspect_target`.

Inspect Capture is read-only and never spawns a session, never connects
RDP/SSH, never submits an access request. The handlers carry no
session-creation surface and no WebSocket. This is enforced by the same
asset-zone split rule (`/assets/manage/*` is structurally session-free
-- the inspect surface follows the same convention).

## 4. Surface and routes

| Method | Path                                                                            | Handler                          | Purpose |
|--------|---------------------------------------------------------------------------------|----------------------------------|---------|
| GET    | `/sessions/recordings/{uuid}/inspect`                                           | `inspect_capture`                | Initial full-page paint |
| GET    | `/sessions/recordings/{uuid}/inspect/channels/{n}/packets`                      | `inspect_capture_packet_list`    | HTMX fragment: filtered, paginated packet list |
| GET    | `/sessions/recordings/{uuid}/inspect/channels/{n}/packets/{idx}`                | `inspect_capture_packet_detail`  | HTMX fragment: dissection tree + hex dump |

Channel index `n` and frame index `idx` are 1-based. `idx == 0` is
rejected with the generic 404 (anti-enumeration). The shell page
auto-loads the first frame of the first channel via HTMX
`hx-trigger="load delay:50ms"` so the operator lands on a populated
view without a second click.

Query parameters on the list endpoint:

| Name        | Type   | Default | Notes |
|-------------|--------|---------|-------|
| `direction` | enum   | --      | `ews_to_asset` / `asset_to_ews` |
| `kind`      | enum   | --      | `tcp` / `read` / `cmd` / `exception` |
| `q`         | string | --      | free-text, case-insensitive, matched against the dissector summary |
| `page`      | int    | 1       | 1-based |
| `page_size` | int    | 100     | clamped to `[1, MAX_PAGE_SIZE]` |

Channel switch is implemented as a `<a>` tab grid (no `<select>`) so
HTMX can `hx-include` the active filter chips without JavaScript. URL
state is pushed via `hx-push-url` -- the back button restores the
previous filter combination.

## 5. Pipeline

```
PCAP.gz bytes (from supervisor FD broker)
    |
    v
parser::parse_pcap_gz                   -- gunzip, libpcap global header,
                                           per-record header, etherparse
                                           IPv4/IPv6 + TCP, payload slice
    |
    v  Vec<RawPacket>
flow::ChannelEndpoints::infer_from_first_packets
                                         -- canonical client/server tuple
                                            from the first SYN (fall back
                                            to first record on truncation)
    |
    v
dissectors::dissect(profile, payload, direction)
                                         -- Modbus / IEC-104 / Passthrough
                                         -- returns Dissection { kind,
                                            summary, tree: Vec<FieldNode> }
    |
    v
PacketSummary { frame_idx, ts, direction, kind, summary, ... }
    |
    +------> page_summaries(filter) -> PacketListPage  (list view)
    |
    v
analyze_packet(idx) -> PacketDetail { summary, tree, hex_rows,
                                       byte_field_ids }
                                          (detail view, with the
                                           tree<->hex byte map)
```

The pipeline is **stateless**. Each handler call re-parses the channel
PCAP from scratch; there is no in-memory cache and no on-disk side
state. The capture is therefore always rendered from the same byte
artifact that the integrity hash in `meta.json` covers -- the operator
cannot see a stale or de-synchronised view.

Hard limits, applied at parse time, prevent a malicious or
mis-truncated PCAP from exhausting memory:

| Constant                  | Value | Purpose |
|---------------------------|-------|---------|
| `MAX_RECORD_LEN`          | 64 KB | reject pcap records claiming more than 64 KB on the wire |
| `MAX_RECORDS_PER_CHANNEL` | 200_000 | hard ceiling on the number of frames the analyzer will materialise |
| `MAX_DECOMPRESSED_BYTES`  | 256 MB | gunzip output cap |

Beyond these caps the parser returns `ParserError::TooLarge` and the
handler collapses to the generic 404. The recording itself is not
corrupted -- the operator falls back to the offline Wireshark workflow
for these (rare) edge cases.

## 6. Dissectors

Three dissectors ship in v1.0; the dispatcher in
`services::iacs_packet_analyzer::dissectors::dissect` chooses based on
the `industrial_protocol` column on the `proxy_sessions` row (mapped to
`shared::iacs_protocol::ExpectedProfile`).

### 6.1 Modbus/TCP

Parses the MBAP header (Transaction ID, Protocol ID, Length, Unit ID)
and the function code. Function-code classification:

| FC                   | PacketKind  |
|----------------------|-------------|
| 1, 2, 3, 4 (reads)   | `Read`      |
| 5, 6, 15, 16, 22, 23 | `Cmd`       |
| FC with 0x80 bit set | `Exception` (with mapped exception label) |

Request and response framings differ; the dissector renders the
appropriate sub-tree for each leg using the canonical
`ChannelEndpoints::direction_of` decision. This is what gives the
operator a one-line "Write Single Register addr=0x10 val=0x4242" or
"Read Holding Registers addr=0x00 qty=10" instead of "FC06 = some bytes".

### 6.2 IEC 60870-5-104

Parses the APCI start byte, length, and frame format (I-frame /
S-frame / U-frame). For I-frames the dissector reads the ASDU Type ID
and Cause of Transmission and classifies:

| ASDU type / COT                             | PacketKind   |
|---------------------------------------------|--------------|
| Monitoring direction (M_*) / spontaneous COT| `Read`       |
| Control direction (C_*) / activation COT    | `Cmd`        |
| Negative COT (deactivation / activation NACK) / unknown type | `Exception` |

U-frames (STARTDT/STOPDT/TESTFR) and S-frames are classified `Tcp` --
they carry no application payload.

### 6.3 Passthrough

Fallback for OPC-UA, PROFINET, BACnet/SC, MQTT/TLS, DNP3 and any
unrecognised industrial protocol. The MVP does NOT decode these; it
surfaces:

- Total payload byte count.
- ASCII preview of the first ~32 bytes.
- A single `tcp.payload` field in the tree.

`PacketKind` is **always** `Read` -- a safe default that never
mis-attributes a write to an asset for a protocol the analyzer cannot
parse. The "Cmd" filter therefore returns 0 results on a Passthrough
capture; Wireshark remains the right tool for those flows.

## 7. UI / UX contract

The page is server-rendered Askama. Three areas:

1. **Header strip**: breadcrumbs, recording metadata (asset, EWS, channel
   count, total bytes), and a persistent **replay-safety banner** ("This
   is a read-only forensic view; no traffic is replayed to the asset").
2. **Channel selector + filter chips**: tabs for each channel (HTMX
   `hx-get` with `hx-include="#inspect-filters"`); direction / kind
   radio chips; debounced search box (300 ms).
3. **3-pane responsive grid** (`grid-cols-1` mobile, `lg:grid-cols-12`
   desktop): packet list (5 cols), dissection tree + hex dump (7 cols).
   On mobile the panes stack; the detail pane scrolls into view when a
   row is tapped.

Color coding (Tailwind):

| Class                                   | Meaning                          |
|-----------------------------------------|----------------------------------|
| `bg-amber-50 text-amber-900` (row)      | `Cmd` packets                    |
| `bg-rose-50 text-rose-900` (row)        | `Exception` packets              |
| `bg-blue-50 text-blue-900` (row)        | `Read` packets                   |
| `bg-gray-50 text-gray-700` (row)        | `Tcp` (control) packets          |
| `bg-emerald-100 text-emerald-900` (chip)| highlighted (Alpine `x-data`)    |

### 7.1 No JavaScript except a 12-line Alpine `x-data`

The hard rule: no inline `<script>` tag anywhere under
`templates/sessions/inspect/`. The interactivity ladder is:

- **HTMX** for filter changes, pagination, channel switch, packet
  selection, and the auto-load-on-shell.
- **Alpine.js** declarative bindings only. The dissection tree and the
  hex dump share a single `x-data="{ highlight: null }"` scope; each
  tree node carries `data-field="<id>"` and emits
  `@mouseenter="highlight='<id>'"`, the matching hex byte gets a
  conditional class. Bidirectional. ~10 lines of Alpine, declarative,
  no `eval()`, CSP-compatible.
- **Server-rendered tree**. The `FieldNode` is recursive in Rust but
  flattened to a `TreeRowViewModel { depth, indent_px, ... }` list
  before reaching the template, because Askama refuses unbounded
  template recursion (`#include` + `with` does not converge -- it
  triggers a `SIGBUS` at template-expansion time).

This is enforced by the lint
`scripts/check_inspect_capture_no_inline_script.sh` and the
template-test `templates_carry_no_inline_script_tag`.

### 7.2 Responsive

Mobile-first: every top-level container in the inspect partials carries
at least one Tailwind breakpoint class (`sm:`, `md:`, `lg:`, `xl:`).
Pinned by `scripts/check_inspect_capture_responsive.sh`.

### 7.3 Tree<->hex contract

The bidirectional highlight binds tree nodes and hex bytes by the
shared `field_id` string. The dissectors emit `field_id`s; the
view-model carries them; both partials reference them dynamically (no
literal `data-field="..."` hardcoded in templates). Pinned by
`scripts/check_inspect_capture_field_offsets.sh` and the template-tests
`packet_detail_carries_data_field_attributes_*`.

## 8. Battle-tested invariants

The analyzer is a forensic surface; mis-rendering is worse than no
rendering. Five invariants are pinned by tests and CI:

1. **The dissector dispatch is exhaustive on `ExpectedProfile`.** Any
   new variant in `shared::iacs_protocol::ExpectedProfile` must be
   classified -- the `match` is non-`_` and the build fails on a
   missing arm.
2. **Frame indexing is dense and 1-based.** `analyze_channel_bytes`
   returns one summary per record; the indexer cannot skip frames.
   Pinned by
   `inspect_capture_pipeline_e2e_test::analyze_channel_emits_one_summary_per_record`.
3. **Byte-to-field map is a partition.** Every dissection-tree leaf's
   `[offset, offset+length)` range maps to its `field_id` in
   `byte_field_ids`; ranges never overlap. Pinned by
   `analyze_packet_bytes_byte_field_ids_partitions_payload`.
4. **Passthrough never returns `PacketKind::Cmd`.** A protocol the
   analyzer cannot parse must not be misclassified. Pinned by
   `passthrough::tests::passthrough_never_returns_cmd`.
5. **Anti-enumeration funnels through `resolve_inspect_target`.** All
   three handlers go through the same DB lookup + IACS-only +
   finalized-only check; out-of-band conditions return the same generic
   404. Pinned by `handlers_funnel_through_resolve_inspect_target`.

## 9. Threat model

| Threat                                                                | Mitigation |
|-----------------------------------------------------------------------|------------|
| Non-admin enumerates session UUIDs via `/inspect`                     | Casbin `admin:view` + generic 404 on every "not eligible" path |
| Malicious PCAP with 4 GB record claim                                 | `MAX_RECORD_LEN` (64 KB), `MAX_RECORDS_PER_CHANNEL` (200_000), `MAX_DECOMPRESSED_BYTES` (256 MB) |
| Truncated / corrupt PCAP                                              | Parser returns `ParserError::Truncated`; handler returns generic 404 (never crashes the worker) |
| Direction inference fooled by an asymmetric channel                   | First-SYN priority + canonical (`client`, `server`) tuple from `meta.json`; fallback heuristic only for late-joining frames |
| Operator clicks "Inspect" on a still-recording session                | `recording_finalized_at IS NULL` -> generic 404. Avoids reading a partially-written file. |
| XSS / inline script injection                                         | Lint forbids `<script>` under `templates/sessions/inspect/`; CSP `script-src` does not allow `'unsafe-inline'` |
| FD exhaustion on the supervisor by a poll-storm                       | Each handler call performs ONE `meta.json` fetch + ONE channel PCAP fetch + drops both FDs synchronously |
| Tree<->hex desynchronisation (highlight points at the wrong byte)     | Dissector emits `field_id` + absolute offset; analyzer constructs `byte_field_ids` from the same offset; pinned by partition test |

## 10. Test coverage

Service / parser / dissector layer (inline `mod tests` in each module,
fixtures generated by `vauban-audit::iacs_pcap_synth`):

- `parser.rs`: round-trip through synthetic Modbus + IEC-104 captures,
  IPv6 support, payload-offset, TCP flag labels, truncated-record and
  corrupt-magic rejections, oversize-record rejection.
- `flow.rs`: SYN-priority endpoint inference, fallback on missing SYN,
  direction classification on subsequent records.
- `dissectors/modbus.rs`: FC1-FC23 classification, exception bit,
  request vs response framing, summary string format, field-offset
  accuracy.
- `dissectors/iec104.rs`: I-frame vs S-frame vs U-frame, Type ID and
  COT label, classify-as-`Cmd` on activation COT, classify-as-`Exception`
  on negative COT.
- `dissectors/passthrough.rs`: never-`Cmd`, ASCII preview, panic-free on
  arbitrary bytes.
- `iacs_packet_analyzer/mod.rs::tests`: `analyze_channel_bytes`,
  `page_summaries` filter (direction, kind, search) and pagination,
  `analyze_packet_bytes` detail view, `build_byte_field_map` partition.

Handler / template layer
(`vauban-web/tests/web/inspect_capture*_test.rs`):

- Pin tests on `inspect_capture`, `inspect_capture_packet_list`,
  `inspect_capture_packet_detail`: admin gate, anti-enumeration funnel,
  filter wiring, `frame_idx == 0` rejection, route mounting in
  `main.rs`.
- Template tests: HTMX wiring (`hx-get`/`-target`/`-swap`/`-include`/
  `-push-url`/debounce), color classes, replay-safety banner, no
  inline `<script>`, responsive grid, tree<->hex `data-field`
  contract, Alpine `x-data` highlight.
- Recording detail / list visibility: button visible for IACS sessions,
  hidden for SSH / RDP, hidden for non-finalized recordings.

Pipeline E2E (`inspect_capture_pipeline_e2e_test.rs`):

- Generate a real Modbus + IEC-104 PCAP via `iacs_pcap_synth`, feed it
  through `analyze_channel_bytes` + `analyze_packet_bytes`, assert
  packet count, classification, direction, dense indexing, and the
  byte-to-field partition.

CI lint scripts:

- `scripts/check_inspect_capture_no_inline_script.sh`
- `scripts/check_inspect_capture_responsive.sh`
- `scripts/check_inspect_capture_field_offsets.sh`

## 11. Source of truth

- Service: `vauban-web/src/services/iacs_packet_analyzer/` (parser,
  flow, dissectors, mod).
- Handlers: `vauban-web/src/handlers/web/sessions.rs`
  (`resolve_inspect_target`, `inspect_capture*`).
- Routes: `vauban-web/src/main.rs`
  (`/sessions/recordings/{uuid}/inspect*`, behind
  `require_admin_view`).
- View-models: `vauban-web/src/templates/sessions/inspect_capture.rs`
  (`InspectCaptureViewModel`, `PacketListViewModel`,
  `PacketDetailViewModel`, `flatten_tree`).
- Templates: `vauban-web/templates/sessions/inspect/*.html` (shell,
  channel selector, filter chips, packet list, packet detail, hex
  dump).
- Fixtures: `vauban-audit::iacs_pcap_synth` (the inverse of this
  analyzer; same byte format).
- Companion docs:
  - `Vauban_Recording_Architecture_EN(1.5).md` -- PCAP file format,
    `meta.json`, integrity hash, FD broker contract.
  - `Vauban_IACS_Proxy_Architecture_EN(1.0).md` -- upstream proxy
    that produced the PCAP.
  - `Vauban_Privsep_Architecture_EN(1.2).md` -- supervisor FD broker.
