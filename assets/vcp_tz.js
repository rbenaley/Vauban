/*! Set first-party vcp_tz from the browser IANA zone so SSR can localize times. */
(function () {
  try {
    var tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (!tz) return;
    var match = document.cookie.match(/(?:^|; )vcp_tz=([^;]*)/);
    var cur = match ? decodeURIComponent(match[1]) : "";
    if (cur === tz) return;
    var secure = location.protocol === "https:" ? "; Secure" : "";
    document.cookie =
      "vcp_tz=" +
      encodeURIComponent(tz) +
      "; Path=/; Max-Age=31536000; SameSite=Lax" +
      secure;
    var key = "vcp_tz_reloaded";
    if (sessionStorage.getItem(key) === tz) return;
    sessionStorage.setItem(key, tz);
    location.reload();
  } catch (_e) {
    /* ignore */
  }
})();
