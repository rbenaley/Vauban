# Runbook -- HTTPS edge (access log + security headers)

> Manual validation after shipping **Apache CLF access logging**, dynamic
> `Cache-Control: no-store`, browser hardening headers
> (`X-Content-Type-Options`, CSP `frame-ancestors`, `Permissions-Policy`),
> or **trailing-slash `redirect_permanent` (308) canonical redirects**.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for edge/header changes. Do not ship without A–E.

Related:

- [README](../../README.md)
- Lint: `scripts/check_http_edge.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- http_edge -- --test-threads=1`

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
just fmt-check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_http_edge.sh
rtk cargo test --test integration_tests -- http_edge -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- `curl -k` (accept local self-signed cert).
- Terminal showing process logs (`vcp=debug` or default development filter).

## A -- Security headers on a dynamic page

```bash
curl -k -sI https://127.0.0.1:3000/login
```

Expect response headers (names case-insensitive):

| Header | Value |
|--------|--------|
| `Cache-Control` | `no-store` |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | `frame-ancestors 'none'` |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=()` |

Pass: all four present with the values above.

## B -- Access log file (Apache CLF)

Path comes from `server.access_log_path`:

| Environment | Default path |
|-------------|--------------|
| development / testing | `logs/vcp-access.log` (crate root; gitignored) |
| production | `/var/log/vcp-access.log` |

1. With `just run` in one terminal, run:
   ```bash
   curl -k -s -o /dev/null -w "%{http_code}\n" https://127.0.0.1:3000/login
   ```
2. Tail the access log file (not the process stderr tracing stream):
   ```bash
   tail -n 5 logs/vcp-access.log
   ```
   Expect a bare Apache Common Log Format line, e.g.:
   ```text
   127.0.0.1 - - [26/Jul/2026:23:00:00 +0200] "GET /login HTTP/1.1" 200 -
   ```

Pass: one CLF-shaped line appended per request. Startup tracing should show a
separate `INFO vcp::tls::access_log:` line with `access_log=…` (not mixed into
the listening line); CLF request content lives only in the file.

## C -- Static assets keep long-cache (regression)

```bash
# After loading /login in a browser, pick a hashed asset URL from the HTML,
# or list target/assets and hit a known /_topcoat/assets/... URL.
curl -k -sI "https://127.0.0.1:3000/_topcoat/assets/<hashed-file>"
```

Expect `Cache-Control` containing `immutable` / long `max-age` (Topcoat asset
pipeline), **not** `no-store`.

Pass: dynamic pages are `no-store`; hashed assets remain cacheable.

## D -- Coalesced TLS handshake failures

With `VCP_ENVIRONMENT=development` and default filter (`info,vcp=debug`), flood
incompatible TLS clients (TLS 1.2-only or empty cipher suite), e.g.:

```bash
for i in $(seq 1 20); do
  openssl s_client -connect 127.0.0.1:3000 -tls1_2 </dev/null >/dev/null 2>&1 || true
done
sleep 0.3
```

With default filter (`vcp=debug`), these lines are hidden. With `vcp=trace`,
expect **one** (or few) `TRACE vcp::tls::serve:` line shaped like:

```text
TLS handshake failed error=… count=N
```

with `N > 1` after the idle window (~150 ms quiet), **not** one line per failed
handshake.

Pass: coalesced `count=N` appears under `vcp=trace`; no DEBUG flood under the
default filter.

## E -- Trailing-slash canonical `redirect_permanent` (308)

```bash
curl -k -sI https://127.0.0.1:3000/login/
curl -k -sI "https://127.0.0.1:3000/login/?next=1"
curl -k -sI https://127.0.0.1:3000/
```

Expect:

| Request | Status | `Location` |
|---------|--------|------------|
| `/login/` | **308** | `/login` |
| `/login/?next=1` | **308** | `/login?next=1` |
| `/` | **303** (or other non-308 redirect to login) | `/login` |

Also confirm security headers (`no-store`, `nosniff`, CSP) remain on the 308.

Pass: trailing slashes canonicalize via Topcoat `redirect_permanent`; root `/` is unchanged.
