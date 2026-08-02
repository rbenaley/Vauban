# VCP capacity audit — gisco (FreeBSD)

**Date:** 2026-08-02  
**Scope:** Customer portal (`vcp`) capacity on host `gisco`, derived from a
real Safari browsing session log (DEBUG) and the current SSR + Postgres
architecture.  
**Audience:** operators sizing a first production / staging box.  
**Status:** engineering estimate (not a load-test report).

---

## 1. Executive summary

| Question | Answer |
|----------|--------|
| Can gisco host VCP for many LTS customers? | **Yes** for intermittent B2B use. |
| Comfortable concurrent *active* users | **~80–200** (release build, `INFO` logs). |
| **1000** users active at once (clicking) | **Not realistic** on this box; p95 latency collapses into multi-second queues. |
| First bottleneck | **CPU** (TLS + SSR), then **Postgres query fan-out**, not RAM or ZFS. |
| FreeBSD vs Linux | FreeBSD is a **good fit** (kqueue, native ZFS); it does **not** multiply capacity by 2× for this workload. |

**Rule of thumb:** hundreds to ~1–2k *registered* client orgs is fine; size the
box for *concurrent active sessions*, not for license count.

---

## 2. Target host

| Item | Value |
|------|--------|
| Hostname | `gisco` |
| OS | FreeBSD |
| CPU | AMD Ryzen 5 PRO 3600 — 6 cores / 12 threads |
| RAM | 32 GiB |
| Storage | ZFS pool `zroot`, mirror of two NVMe (`nda0p4` / `nda1p4`), ~944G, ~3% used |
| Assumed deploy | `vcp` **release** binary, log filter **`info`**, Postgres on the **same** host |

Production default log filter in-tree is already `info`
(`Environment::Production.default_log_filter()` in `src/config.rs`). Development
defaults to `debug`, which is what inflated the observed terminal noise.

---

## 3. Observed traffic profile (Safari session)

### 3.1 What one HTML navigation costs

A typical authenticated page hit (docs / builds / issues) issues:

1. `AuthSession` by token hash  
2. `User` by id  
3. `Organization` by slug (or full scan for some admin lists)  
4. `Membership` for `(user_id, org_id)`  
5. Domain query (`DocArticle`, `Release`, `Issue`, `EphemeralDownload`, …)

Measured SQL durations in the DEBUG log were usually **0.2–1.0 ms** per
statement on a warm local Postgres. That means **database round-trip time is
not the primary limiter** for a single user; **request fan-out and CPU** are.

### 3.2 Duplicate queries (amplification)

**Update (request SQL dedup):** list page + embedded search shard COUNTs /
company card hydrates are now request-memoized (`#[memoize]` on domain
loaders — see `scripts/check_request_sql_dedup.sh`). A list GET should show
**one** matching COUNT (or one `company_cards_page` hydrate) per filter key
in DEBUG, not two. Shard-only POSTs remain separate requests (re-auth +
query).

Historical Safari DEBUG still showed identical statements twice inside one
request window (before that wave), for example:

- `DocArticle` filtered by `(PUBLISHED, category)` executed twice  
- `DocArticle` `status = PUBLISHED` executed twice on list/detail paths  
- Admin issues/companies page+shard recount / rehydrate  

Auth lookups were already request-memoized (`require_org`, session helpers in
`src/auth.rs`). **Update (dashboard issue stats):** org home no longer runs
four issue `COUNT(*)` + latest `LIMIT 1` — one org-scoped `Issue` load
(capped) + Rust `summarize_issue_stats` / `latest_issue_by_updated_at`
(`src/dashboard_stats.rs`, `scripts/check_dashboard_stats.sh`). Docs tile
still uses a published-docs `COUNT(*)`. Remaining open: any non-list
component duplication outside the memoized helpers.

### 3.3 TLS / HTTP/2 vs “session reopen”

Pattern after many HTML responses:

1. One (or few) HTTP/2 streams carry the document — auth + SQL + SSR.  
2. Shortly after, **~6–8** `rustls` handshake lines appear (`TLS13_AES_256_GCM_SHA384`, ALPN `h2`).

Interpretation:

- The portal **session cookie** is *not* torn down per click.  
- Safari opens **additional TCP+TLS connections** for parallel assets (CSS/JS,
  fonts, favicons) and connection pooling behavior.  
- Multiplexed streams on an existing h2 connection are cheap; **new handshakes
  are the expensive part of the post-click noise**.

`ProtocolName(6832)` in logs is ASCII `"h2"` encoded as hex bytes.

### 3.4 Rough per-active-user rates (browsing)

| Mode | Pages / user | HTTP streams (HTML+local assets) | SQL / page (today) |
|------|--------------|----------------------------------|--------------------|
| Calm browsing | ~1 / 5–15 s | ~2–10 / page | ~4–10 (often ×2) |
| Clicking filters / chips | ~1 / 0.3–2 s | same | same |
| Burst (open many tabs) | higher | higher | higher |

For capacity math below we use a **design active user** as:

> ~1 HTML navigation every **3 s**, ~8 SQL statements/page (including
> duplication), plus ~7 TLS handshakes amortized across navigations (Safari).

That is intentionally somewhat pessimistic for B2B portals (many users idle).

---

## 4. Cost model (where CPU and RAM go)

### 4.1 Relative cost of one click (release + INFO)

| Layer | Relative cost | Notes |
|-------|---------------|--------|
| Application SQL | Medium | Many small queries; cheap each, costly in aggregate under concurrency |
| SSR HTML (Topcoat) | Medium–high | Dominates once SQL is sub-ms |
| TLS handshakes (new conns) | Medium | Safari multiplies connections; TLS 1.3 is CPU-bound |
| Asset bytes | Low–medium | Served once warm; CPU for crypto on new conns |
| Logging at `INFO` | Low | DEBUG would add material I/O and formatting cost |
| Disk (ZFS SSD) | Low | Working set fits RAM; ZFS ARC helps Postgres |

### 4.2 Memory

| Component | Idle | Under load (order of magnitude) |
|-----------|------|----------------------------------|
| `vcp` process | ~50–150 MiB | ~150–800 MiB |
| Postgres + caches | ~200–800 MiB | ~1–3 GiB (same host) |
| FreeBSD + ZFS ARC | remainder of RAM | Prefer leaving **several GiB** for ARC |

**32 GiB is comfortable.** Memory is unlikely to be the first limit before CPU
and Postgres latency.

### 4.3 FreeBSD-specific notes

Strengths for this workload:

- Mature network stack and `kqueue` for many short-lived connections  
- First-class ZFS (already used on `gisco`)  
- Stable long-running services  

Limits of the “FreeBSD is more powerful than Linux” claim for *this* app:

- Tokio + rustls + Postgres behave similarly on both kernels for SSR portals.  
- Linux has closed most networking gaps for this class of service.  
- Expect FreeBSD to be **comparable or slightly nicer** for connection churn,
  not a 2× capacity multiplier.

---

## 5. Capacity estimates

### 5.1 Definitions

| Term | Meaning |
|------|---------|
| **Registered client** | One customer org with ≥1 LTS subscription (mostly idle) |
| **Active user** | Authenticated browser actively navigating (clicks every few seconds) |
| **Concurrent actives** | Active users overlapping in the same minute |

License count ≠ load. One thousand registered orgs with 2% active is ~20 actives.

### 5.2 Recommended operating points on gisco

| Concurrent actives | Expected UX | CPU (order) | Host RAM use (order) |
|--------------------|-------------|-------------|----------------------|
| 0–20 | Instant | &lt; 1 core | &lt; 2 GiB |
| 50–100 | Smooth | ~0.5–1.5 cores | ~2–4 GiB |
| **80–200** | **Comfort zone** | ~1–3 cores | ~3–6 GiB |
| 300–500 | Degraded at peaks | ~3–5 cores | ~4–8 GiB |
| **1000** | **Overloaded** | all cores pegged | RAM still OK; latency not |

### 5.3 Registered clients (intermittent B2B)

Assuming classic customer-portal duty cycle (most orgs silent most of the day):

| Registered LTS clients | Feasibility on gisco |
|------------------------|----------------------|
| 100–300 | Easy |
| 500–1000 | Comfortable if concurrent actives stay in the rows above |
| 1000–2000 | Plausible with low concurrent activity; watch peaks (support spikes, Monday mornings) |

---

## 6. Latency under concurrency (including 1000 actives)

Assumptions: release build, `INFO`, Postgres colocated, current query fan-out,
Safari-like clients, no CDN for origin assets.

| Concurrent actives | p50 page latency | p95 page latency | User experience |
|--------------------|------------------|------------------|-----------------|
| 50–100 | ~20–80 ms | ~100–250 ms | Fluid |
| 200–300 | ~50–150 ms | ~300–800 ms | Acceptable |
| 500 | ~150–400 ms | ~1–3 s | Noticeably slow at peaks |
| **1000** | **~0.5–2 s** | **~3–10+ s** / errors | Queue collapse |

### 6.1 Why latency is non-linear

```text
latency
  ^
  |                            /
  |                          /
  |                       /
  |                  ___/
  |           ______/
  |__________/
  +---------------------------------> concurrent actives
        100    300    500    1000
```

Up to a few hundred actives, latency grows slowly (headroom on 12 threads).
Past ~500, wait time in the run queue and Postgres dominate — **p95 explodes**
even if average CPU is “only” high, not quite 100% sampled.

### 6.2 Worked sketch for 1000 actives

If each active averages one HTML page every 3 s:

- HTML RPS ≈ 1000 / 3 ≈ **330 pages/s**  
- SQL RPS ≈ 330 × 8 ≈ **~2600 statements/s** (with today’s duplication)  
- TLS: if even a fraction open new connections, handshake CPU stacks on top  

A 6-core Ryzen can sustain high RPS for *trivial* handlers; VCP handlers are
**SSR + auth + multi-query**. 1000 simultaneous browsers is a **small-fleet**
problem, not a single mid-range workstation problem.

---

## 7. Sensitivity (what moves the numbers most)

| Change | Effect on capacity |
|--------|--------------------|
| Fix duplicate SQL (docs/issues) | **+20–40%** effective headroom (list page+shard COUNT/hydrate dedup + dashboard single-load issue stats landed) |
| Request-scoped cache for session/user/org (already partial) | Helps every page |
| Long-cache / CDN for `/_topcoat` assets | Cuts TLS churn from Safari |
| `DEBUG` logs in production | **Avoid** — burns CPU/I/O |
| Postgres on a second host | Helps past ~300–500 actives |
| Second `vcp` instance + load balancer | Primary scale-out path toward 1000 actives |
| HTTP/2 connection reuse (client-side) | Outside our control; Safari remains chatty |

---

## 8. Recommendations

### 8.1 For gisco as first production box

1. Run **release** + **`INFO`** (or stricter).  
2. Size for **peak concurrent actives**, not seat count.  
3. Keep ZFS ARC healthy (do not over-allocate Postgres `shared_buffers` to starve ARC).  
4. Add simple SLOs: p95 HTML &lt; 500 ms; alert when CPU &gt; ~70% sustained.  
5. Treat **1000 concurrent actives** as a **scale-out** milestone, not a single-node goal.

### 8.2 Before chasing 1000 concurrent actives

1. Eliminate duplicate domain queries visible in DEBUG traces.  
2. Confirm asset caching headers for static Topcoat bundles.  
3. Load-test with a tool that models SSR+cookie sessions (not only static GETs).  
4. Split Postgres when SQL wait exceeds SSR time under load.  
5. Add a second app instance when one box’s p95 exceeds SLO at target concurrency.

### 8.3 Monitoring signals that matter more than handshake DEBUG lines

- `vcp` process CPU and RSS  
- Postgres: connections, `pg_stat_activity`, slow queries  
- HTTP p50/p95 (access log already exists in-tree)  
- TLS handshake failure coalescer (already implemented for noisy failures)

---

## 9. Method and confidence

| Input | Source |
|-------|--------|
| Per-click SQL shape | Safari DEBUG session on `/vauban/*` (docs, builds, issues) |
| SQL timings | `toasty` / `tokio_postgres` DEBUG durations in that log |
| TLS behavior | Repeated `rustls::server::hs` after HTML responses |
| Hardware | Operator-provided `gisco` inventory |
| Code defaults | `src/config.rs` log filters; `src/auth.rs` memoization |

**Confidence:** medium for the **comfort zone (≤200 actives)**; lower for exact
p95 at 500–1000 without a synthetic load test. Absolute numbers should be
validated with a short k6/vegeta/gatling (or similar) campaign against a
release binary before promising SLAs.

---

## 10. Bottom line

On **FreeBSD + Ryzen 5 PRO 3600 + 32 GiB + ZFS SSD**, VCP as currently built is
a good fit for a **customer portal with hundreds of LTS clients** and
**tens to low hundreds of simultaneous active users**.

It is **not** sized for **1000 concurrent active browsers** without scale-out
and query hygiene. FreeBSD helps networking and ops; it does not rewrite that
conclusion.
