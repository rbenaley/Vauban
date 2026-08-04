/*! VCP WebAuthn ceremony helper (C1). Expects data-* on #vcp-webauthn-root. */
(function () {
  function b64urlToBuf(s) {
    var pad = "=".repeat((4 - (s.length % 4)) % 4);
    var b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
    var str = atob(b64);
    var buf = new ArrayBuffer(str.length);
    var view = new Uint8Array(buf);
    for (var i = 0; i < str.length; i++) view[i] = str.charCodeAt(i);
    return buf;
  }
  function bufToB64url(buf) {
    var view = new Uint8Array(buf);
    var s = "";
    for (var i = 0; i < view.length; i++) s += String.fromCharCode(view[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function parseAllow(raw) {
    if (!raw) return [];
    try {
      var arr = JSON.parse(raw);
      return arr.map(function (id) {
        return { type: "public-key", id: b64urlToBuf(id) };
      });
    } catch (_e) {
      return [];
    }
  }
  /** WebAuthn RP IDs must be DNS names; IP literals (e.g. 127.0.0.1) are rejected. */
  function isIpHostname(host) {
    if (!host) return false;
    if (host === "::1" || host.indexOf(":") >= 0) return true;
    var parts = host.split(".");
    if (parts.length !== 4) return false;
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(parts[i])) return false;
      var n = Number(parts[i]);
      if (n > 255) return false;
    }
    return true;
  }
  function assertWebauthnHost(rpId) {
    var host = location.hostname;
    if (isIpHostname(host)) {
      var port = location.port ? ":" + location.port : "";
      throw new Error(
        "WebAuthn cannot run on an IP address (" +
          host +
          "). Open https://localhost" +
          port +
          location.pathname +
          location.search +
          " instead (dev rp_id is localhost)."
      );
    }
    if (rpId && rpId !== host && !host.endsWith("." + rpId)) {
      throw new Error(
        "WebAuthn rpId \"" +
          rpId +
          "\" does not match this page host \"" +
          host +
          "\". Use the origin configured in storage.webauthn_origin."
      );
    }
  }
  async function runGet(root) {
    var challenge = root.getAttribute("data-challenge") || "";
    var rpId = root.getAttribute("data-rp-id") || location.hostname;
    assertWebauthnHost(rpId);
    var allow = parseAllow(root.getAttribute("data-allow") || "[]");
    var assertion = await navigator.credentials.get({
      publicKey: {
        challenge: b64urlToBuf(challenge),
        rpId: rpId,
        allowCredentials: allow,
        userVerification: "required",
        timeout: 120000,
      },
    });
    if (!assertion) throw new Error("no assertion");
    var response = assertion.response;
    return JSON.stringify({
      id: assertion.id,
      rawId: bufToB64url(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: bufToB64url(response.clientDataJSON),
        authenticatorData: bufToB64url(response.authenticatorData),
        signature: bufToB64url(response.signature),
        userHandle: response.userHandle
          ? bufToB64url(response.userHandle)
          : null,
      },
    });
  }
  async function runCreate(root) {
    var challenge = root.getAttribute("data-challenge") || "";
    var rpId = root.getAttribute("data-rp-id") || location.hostname;
    assertWebauthnHost(rpId);
    var userId = root.getAttribute("data-user-id") || "admin";
    var userName = root.getAttribute("data-user-name") || "admin";
    var cred = await navigator.credentials.create({
      publicKey: {
        challenge: b64urlToBuf(challenge),
        rp: { name: "VCP Storage", id: rpId },
        user: {
          id: new TextEncoder().encode(userId),
          name: userName,
          displayName: userName,
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          userVerification: "required",
          residentKey: "preferred",
        },
        timeout: 120000,
        attestation: "none",
      },
    });
    if (!cred) throw new Error("no credential");
    var response = cred.response;
    return JSON.stringify({
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(response.clientDataJSON),
        attestationObject: bufToB64url(response.attestationObject),
      },
    });
  }
  function bind() {
    var root = document.getElementById("vcp-webauthn-root");
    if (!root) return;
    var mode = root.getAttribute("data-mode") || "get";
    var btn = document.getElementById("vcp-webauthn-btn");
    var input = document.getElementById("vcp-webauthn-assertion");
    var form = document.getElementById("vcp-webauthn-form");
    if (!btn || !input || !form) return;
    btn.addEventListener("click", function (ev) {
      ev.preventDefault();
      // form.submit() skips HTML5 constraints; enforce label for create (E1).
      if (mode === "create") {
        var labelEl = form.querySelector("#admin_label") || form.querySelector("[name=admin_label]");
        var label = labelEl && labelEl.value ? labelEl.value.trim() : "";
        if (!label) {
          if (labelEl && typeof labelEl.reportValidity === "function") {
            labelEl.setCustomValidity("Key label is required");
            labelEl.reportValidity();
            labelEl.setCustomValidity("");
          } else {
            alert("Key label is required");
          }
          return;
        }
      }
      btn.disabled = true;
      var p = mode === "create" ? runCreate(root) : runGet(root);
      p.then(function (json) {
        input.value = json;
        form.submit();
      }).catch(function (err) {
        btn.disabled = false;
        alert("WebAuthn failed: " + (err && err.message ? err.message : err));
      });
    });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();
