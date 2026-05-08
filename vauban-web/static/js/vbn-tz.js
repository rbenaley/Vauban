// VAUBAN - browser timezone bootstrap.
//
// Posts the browser-resolved IANA timezone identifier into the
// `vbn_tz` cookie so the server can format every date/time the
// templates render in the operator's local timezone (DB / logs /
// IPC remain UTC -- see docs/runbooks/timezone_localization.md).
//
// CSP note: this file is intentionally external because the global
// security middleware enforces `script-src 'self'` (no
// `'unsafe-inline'`). It MUST be loaded synchronously in <head>
// BEFORE the main content paints so the optional reload happens
// before the user sees a UTC-formatted page.
//
// First hit (no cookie): posts the cookie and forces a reload via
// `location.replace()`. The reload happens before paint because
// the script is loaded synchronously.
//
// Subsequent hits: posts the cookie ONLY if the resolved timezone
// changed since the last visit (laptop crossing time zones, OS
// setting flipped). No reload.
(function () {
    var tz;
    try {
        tz = (Intl && Intl.DateTimeFormat && Intl.DateTimeFormat().resolvedOptions().timeZone) || 'UTC';
    } catch (_e) {
        tz = 'UTC';
    }
    if (typeof tz !== 'string' || tz.length === 0 || tz.length > 64) {
        tz = 'UTC';
    }
    var match = document.cookie.match(/(?:^|;\s*)vbn_tz=([^;]+)/);
    var current = match ? decodeURIComponent(match[1]) : null;
    if (current === tz) {
        return;
    }
    var attrs = '; Path=/; SameSite=Lax; Max-Age=31536000';
    if (location.protocol === 'https:') {
        attrs += '; Secure';
    }
    document.cookie = 'vbn_tz=' + encodeURIComponent(tz) + attrs;
    if (current === null) {
        location.replace(location.href);
    }
})();
