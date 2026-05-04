// VAUBAN Alpine.js components and HTMX event handlers
//
// This file is loaded as an external script to avoid 'unsafe-inline' in CSP.
// Alpine.js components are registered via Alpine.data() before Alpine initializes.

document.addEventListener('alpine:init', function () {
    // Global store for JIT access request modal (issue #34).
    //
    // Per-asset data flows through this store: the per-row "Request"
    // button on /assets calls `open(uuid, type, requireMfa)`, the
    // modal's hidden form fields read `:value="$store.accessModal.*"`,
    // and the TOTP block is conditionally rendered with
    // `<template x-if="$store.accessModal.require_mfa">`. Issue #34
    // moved the modal off the now-removed `/assets/{uuid}` detail
    // page so non-approved users no longer fetch description / dates
    // / ssh-host-key fingerprint just to submit a request.
    Alpine.store('accessModal', {
        show: false,
        asset_uuid: '',
        asset_type: '',
        require_mfa: false,
        open: function (uuid, type, requireMfa) {
            this.asset_uuid = String(uuid || '');
            this.asset_type = String(type || '');
            this.require_mfa = !!requireMfa;
            this.show = true;
        },
    });

    // Global store for connection justification modal (SEC-03 + issue #34).
    //
    // Per-asset data flows through this store: the per-row "Connect"
    // button (when `require_justification` is on) calls
    // `open(uuid, type)`. The form submit uses
    // `htmx.ajax('POST', $store.justificationModal.connectUrl(), {source: $el, swap: 'none'})`
    // because Alpine `:hx-post` bindings don't compose reliably with
    // the HTMX form submit handler that's already cached at
    // template scan time. The programmatic `htmx.ajax()` path keeps
    // the full htmx-request lifecycle (HX-Redirect, HX-Trigger,
    // hx-indicator, htmx:after-request) so behaviour is identical
    // to a static `hx-post` form.
    Alpine.store('justificationModal', {
        show: false,
        asset_uuid: '',
        asset_type: '',
        open: function (uuid, type) {
            this.asset_uuid = String(uuid || '');
            this.asset_type = String(type || '');
            this.show = true;
        },
        // Single source of truth for the SSH/RDP endpoint switch.
        // Mirrors the static `hx-post` form on rows that don't
        // require justification (asset_list.html).
        connectUrl: function () {
            var path = this.asset_type === 'rdp' ? 'connect-rdp' : 'connect';
            return '/assets/' + encodeURIComponent(this.asset_uuid) + '/' + path;
        },
    });

    // Global store for the styled delete-confirmation modal (BUG-12 / issue #19).
    //
    // Why a store and not a `Alpine.data` component?
    //   The modal is a singleton rendered ONCE in base.html, but every
    //   destructive form scattered across the templates needs to open it.
    //   A store gives us one instance + global access via `$store`.
    //
    // How it integrates with HTMX:
    //   Each destructive form attaches `@htmx:confirm.prevent` that calls
    //   `$store.deleteConfirm.openWith({ title, message, sourceEvent: $event })`.
    //   `htmx:confirm` is the official HTMX hook for async confirmation flows
    //   (https://htmx.org/events/#htmx:confirm). Calling preventDefault on the
    //   listener stops HTMX's default `window.confirm()` action; calling
    //   `event.detail.issueRequest(true)` later (from `confirm()` below)
    //   tells HTMX to proceed *without* re-firing the confirmation chain.
    //
    // The `true` argument is critical (BUG-12 follow-up). HTMX's
    // `issueRequest(skipConfirmation)` checks `skipConfirmation !== true &&
    // question` before sending the request — if `hx-confirm` is set on the
    // form (it is, as our defense-in-depth fallback) and we call
    // `issueRequest()` with no arg, HTMX re-prompts via `window.confirm()`.
    // The user then sees BOTH the styled Alpine modal *and* a native
    // browser dialog. Passing `true` skips that second prompt while keeping
    // the `hx-confirm` attribute available for the JS-off / Alpine-broken
    // fallback path.
    //
    // Fallback when this store fails to register (Alpine asset 404, JS off,
    // or a CSP that strips inline event handlers): the form still carries
    // a plain `hx-confirm` attribute, so HTMX falls back to a native
    // `window.confirm()` dialog instead of silently destroying data.
    Alpine.store('deleteConfirm', {
        open: false,
        title: '',
        message: '',
        confirmLabel: 'Delete',
        sourceEvent: null,
        openWith: function (opts) {
            this.title = (opts && opts.title) || 'Confirm';
            this.message = (opts && opts.message) || 'Are you sure?';
            this.confirmLabel = (opts && opts.confirmLabel) || 'Delete';
            this.sourceEvent = (opts && opts.sourceEvent) || null;
            this.open = true;
        },
        confirm: function () {
            // Snapshot the source event before clearing state so a stray
            // re-render can't null it out mid-flight.
            var ev = this.sourceEvent;
            this.open = false;
            this.sourceEvent = null;
            if (ev && ev.detail && typeof ev.detail.issueRequest === 'function') {
                // `true` = skipConfirmation: bypass HTMX's `hx-confirm`
                // re-prompt. See block comment above.
                ev.detail.issueRequest(true);
            }
        },
        cancel: function () {
            this.open = false;
            this.sourceEvent = null;
        }
    });

    // CSRF helper: reads token from cookie and keeps inputs synced
    Alpine.data('csrf', function () {
        return {
            token: '',
            init: function () {
                this.refreshToken();
            },
            refreshToken: function () {
                var match = document.cookie.match(/(?:^|;\s*)__vauban_csrf=([^;]*)/);
                this.token = match ? match[1] : '';
            }
        };
    });

    // SSH Terminal component (requires xterm.js loaded)
    Alpine.data('sshTerminal', function (sessionId) {
        return {
            sessionId: sessionId,
            status: 'disconnected',
            statusText: 'Disconnected',
            term: null,
            ws: null,
            fitAddon: null,
            reconnectAttempts: 0,
            maxReconnectAttempts: 5,

            init: function () {
                var self = this;
                this.$nextTick(function () { self.initTerminal(); });
            },

            initTerminal: function () {
                if (typeof Terminal === 'undefined') {
                    console.error('Terminal not loaded');
                    return;
                }
                if (!this.$refs.terminal) {
                    console.error('Terminal ref not found');
                    return;
                }

                this.term = new Terminal({
                    cursorBlink: true,
                    fontSize: 14,
                    fontFamily: '"Fira Code", "Monaco", "Menlo", "Ubuntu Mono", monospace',
                    theme: {
                        background: '#1e1e1e',
                        foreground: '#d4d4d4',
                        cursor: '#d4d4d4',
                        cursorAccent: '#1e1e1e',
                        selectionBackground: '#264f78',
                        black: '#000000',
                        red: '#cd3131',
                        green: '#0dbc79',
                        yellow: '#e5e510',
                        blue: '#2472c8',
                        magenta: '#bc3fbc',
                        cyan: '#11a8cd',
                        white: '#e5e5e5',
                        brightBlack: '#666666',
                        brightRed: '#f14c4c',
                        brightGreen: '#23d18b',
                        brightYellow: '#f5f543',
                        brightBlue: '#3b8eea',
                        brightMagenta: '#d670d6',
                        brightCyan: '#29b8db',
                        brightWhite: '#e5e5e5'
                    },
                    allowProposedApi: true
                });

                this.fitAddon = new FitAddon.FitAddon();
                this.term.loadAddon(this.fitAddon);
                this.term.loadAddon(new WebLinksAddon.WebLinksAddon());
                this.term.open(this.$refs.terminal);

                var self = this;
                setTimeout(function () {
                    self.fitAddon.fit();
                    self.sendResize();
                }, 50);

                this.term.onData(function (data) {
                    if (self.ws && self.ws.readyState === WebSocket.OPEN) {
                        self.ws.send(data);
                    }
                });

                this._resizeHandler = function () { self.handleResize(); };
                this._fullscreenHandler = function () {
                    setTimeout(function () { self.handleResize(); }, 100);
                };
                window.addEventListener('resize', this._resizeHandler);
                document.addEventListener('fullscreenchange', this._fullscreenHandler);

                this.connect(this.sessionId);
            },

            destroy: function () {
                if (this._resizeHandler) window.removeEventListener('resize', this._resizeHandler);
                if (this._fullscreenHandler) document.removeEventListener('fullscreenchange', this._fullscreenHandler);
                if (this.ws) this.ws.close(1000, 'Component destroyed');
                if (this.term) this.term.dispose();
            },

            setStatus: function (status, text) {
                this.status = status;
                this.statusText = text;
            },

            connect: function (sessionId) {
                var self = this;
                var protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                var wsUrl = protocol + '//' + window.location.host + '/ws/terminal/' + sessionId;

                this.setStatus('connecting', 'Connecting...');
                this.term.write('\r\n\x1b[33mConnecting to SSH session...\x1b[0m\r\n');

                this.ws = new WebSocket(wsUrl);
                this.ws.binaryType = 'arraybuffer';

                this.ws.onopen = function () {
                    self.setStatus('connected', 'Connected');
                    self.term.write('\x1b[32mConnected!\x1b[0m\r\n\r\n');
                    self.reconnectAttempts = 0;
                    self.sendResize();
                };

                this.ws.onmessage = function (event) {
                    if (event.data instanceof ArrayBuffer) {
                        self.term.write(new Uint8Array(event.data));
                    } else {
                        try {
                            var msg = JSON.parse(event.data);
                            if (msg.error) {
                                self.term.write('\r\n\x1b[31mError: ' + msg.error + '\x1b[0m\r\n');
                            }
                        } catch (e) {
                            self.term.write(event.data);
                        }
                    }
                };

                this.ws.onclose = function (event) {
                    self.setStatus('disconnected', 'Disconnected');
                    self.term.write('\r\n\x1b[31mConnection closed.\x1b[0m\r\n');

                    if (self.reconnectAttempts < self.maxReconnectAttempts && event.code !== 1000) {
                        self.reconnectAttempts++;
                        var delay = Math.min(1000 * Math.pow(2, self.reconnectAttempts), 30000);
                        self.term.write('\x1b[33mReconnecting in ' + (delay / 1000) + 's... (attempt ' + self.reconnectAttempts + '/' + self.maxReconnectAttempts + ')\x1b[0m\r\n');
                        setTimeout(function () { self.connect(sessionId); }, delay);
                    }
                };

                this.ws.onerror = function () {
                    self.term.write('\r\n\x1b[31mConnection error.\x1b[0m\r\n');
                };
            },

            sendResize: function () {
                if (this.ws && this.ws.readyState === WebSocket.OPEN && this.fitAddon) {
                    var dims = this.fitAddon.proposeDimensions();
                    if (dims) {
                        this.ws.send(JSON.stringify({ type: 'resize', cols: dims.cols, rows: dims.rows }));
                    }
                }
            },

            handleResize: function () {
                if (this.fitAddon) {
                    this.fitAddon.fit();
                    this.sendResize();
                }
            },

            toggleFullscreen: function () {
                var self = this;
                if (document.fullscreenElement) {
                    document.exitFullscreen();
                } else {
                    this.$refs.container.requestFullscreen().then(function () {
                        setTimeout(function () { self.handleResize(); }, 100);
                    });
                }
            },

            disconnect: function () {
                this.reconnectAttempts = this.maxReconnectAttempts;
                if (this.ws) this.ws.close(1000, 'User disconnected');
                window.location.href = '/assets';
            }
        };
    });

    // RDP Viewer component (canvas-based remote desktop)
    Alpine.data('rdpViewer', function (sessionId) {
        return {
            sessionId: sessionId,
            connected: false,
            error: null,
            ws: null,
            ctx: null,
            decoder: null,
            videoMode: false,
            desktopWidth: 1280,
            desktopHeight: 720,
            _lastMouseSend: 0,
            _pendingMouseMove: null,
            _mouseThrottleMs: 33,

            init: function () {
                var self = this;
                this._fullscreenHandler = function () {
                    self.$nextTick(function () {
                        if (document.fullscreenElement) {
                            var w = screen.width;
                            var h = screen.height;
                            w = Math.max(200, w - (w % 2));
                            h = Math.max(200, h - (h % 2));
                            self.sendInput({ type: 'resize', width: w, height: h });
                        } else {
                            self.sendInput({ type: 'resize', width: 1280, height: 720 });
                        }
                        self._updateCanvasLayout();
                        self.$refs.canvas.focus();
                    });
                };
                document.addEventListener('fullscreenchange', this._fullscreenHandler);
                this.$nextTick(function () { self.connectWs(); });
            },

            destroy: function () {
                if (this._fullscreenHandler) document.removeEventListener('fullscreenchange', this._fullscreenHandler);
                if (this._pendingMouseMove) clearTimeout(this._pendingMouseMove);
                if (this.decoder) { try { this.decoder.close(); } catch (e) { /* ignore */ } }
                if (this.ws) this.ws.close(1000, 'Component destroyed');
            },

            _initVideoDecoder: function () {
                var self = this;
                if (typeof VideoDecoder === 'undefined') {
                    console.log('[RDP] WebCodecs not available, using PNG fallback');
                    return;
                }
                try {
                    this.decoder = new VideoDecoder({
                        output: function (frame) {
                            if (self.ctx) {
                                self.ctx.drawImage(frame, 0, 0, self.desktopWidth, self.desktopHeight);
                            }
                            frame.close();
                        },
                        error: function (e) {
                            console.error('[RDP] VideoDecoder error:', e);
                        }
                    });
                    this.decoder.configure({
                        codec: 'avc1.42001f',
                        optimizeForLatency: true
                    });
                    console.log('[RDP] WebCodecs VideoDecoder initialized');
                } catch (e) {
                    console.warn('[RDP] Failed to init VideoDecoder:', e);
                    this.decoder = null;
                }
            },

            connectWs: function () {
                var self = this;
                var protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                var wsUrl = protocol + '//' + window.location.host + '/ws/rdp/' + this.sessionId;

                this.ws = new WebSocket(wsUrl);
                this.ws.binaryType = 'arraybuffer';

                this.ws.onopen = function () {
                    self.connected = true;
                    self.error = null;
                    self.ctx = self.$refs.canvas.getContext('2d');
                    self.$refs.canvas.focus();

                    self._initVideoDecoder();
                    if (self.decoder) {
                        self.sendInput({ type: 'capabilities', video_codecs: ['avc1.42001f'] });
                        console.log('[RDP] Sent H.264 capabilities');
                    }
                };

                this._msgCount = 0;
                this._binaryCount = 0;
                this._videoFrameCount = 0;
                this.ws.onmessage = function (event) {
                    self._msgCount++;
                    if (typeof event.data === 'string') {
                        console.log('[RDP] text msg #' + self._msgCount + ':', event.data.substring(0, 200));
                        try {
                            var msg = JSON.parse(event.data);
                            if (msg.type === 'desktop_size' || msg.type === 'desktop_resize') {
                                self.desktopWidth = msg.width;
                                self.desktopHeight = msg.height;
                                self._updateCanvasLayout();
                                console.log('[RDP] desktop ' + msg.type + ': ' + msg.width + 'x' + msg.height);
                            } else if (msg.type === 'mode' && msg.video) {
                                self.videoMode = true;
                                console.log('[RDP] Server confirmed H.264 video mode');
                            } else if (msg.error) {
                                self.error = msg.error;
                            }
                        } catch (e) { /* ignore */ }
                        return;
                    }
                    self._binaryCount++;
                    var buf = new Uint8Array(event.data);
                    if (buf.length < 8) {
                        console.warn('[RDP] binary too short:', buf.length);
                        return;
                    }

                    // Discriminate: byte 0 == 0x01 => H.264 video frame, otherwise PNG region
                    if (buf[0] === 0x01 && self.decoder && self.videoMode) {
                        self._handleVideoFrame(event.data, buf);
                    } else {
                        self._handlePngRegion(event.data, buf);
                    }
                };

                this.ws.onclose = function () {
                    self.connected = false;
                };

                this.ws.onerror = function () {
                    self.error = 'Connection error';
                    self.connected = false;
                };
            },

            _handleVideoFrame: function (arrayBuf, buf) {
                // Header (10 bytes): type(1) + flags(1) + timestamp_ms(4 LE) + width(2 LE) + height(2 LE)
                if (buf.length < 10) return;
                var dv = new DataView(arrayBuf);
                var flags = buf[1];
                var isKeyframe = (flags & 0x01) !== 0;
                var timestampMs = dv.getUint32(2, true);
                var width = dv.getUint16(6, true);
                var height = dv.getUint16(8, true);
                var nalData = buf.slice(10);

                if (width !== this.desktopWidth || height !== this.desktopHeight) {
                    this.desktopWidth = width;
                    this.desktopHeight = height;
                    this._updateCanvasLayout();
                    if (this.decoder) {
                        this.decoder.configure({
                            codec: 'avc1.42001f',
                            codedWidth: width,
                            codedHeight: height,
                            optimizeForLatency: true
                        });
                    }
                }

                this._videoFrameCount++;
                if (this._videoFrameCount <= 10 || this._videoFrameCount % 60 === 0) {
                    console.log('[RDP] H.264 frame #' + this._videoFrameCount +
                        ' key=' + isKeyframe + ' ' + width + 'x' + height +
                        ' ' + nalData.length + 'B ts=' + timestampMs + 'ms');
                }

                try {
                    var chunk = new EncodedVideoChunk({
                        type: isKeyframe ? 'key' : 'delta',
                        timestamp: timestampMs * 1000,
                        data: nalData
                    });
                    this.decoder.decode(chunk);
                } catch (e) {
                    console.error('[RDP] decode error:', e);
                }
            },

            _handlePngRegion: function (arrayBuf, buf) {
                var dv = new DataView(arrayBuf);
                var x = dv.getUint16(0, true);
                var y = dv.getUint16(2, true);
                var w = dv.getUint16(4, true);
                var h = dv.getUint16(6, true);
                var pngSize = buf.length - 8;

                if (this._binaryCount <= 30 || this._binaryCount % 50 === 0) {
                    console.log('[RDP] PNG #' + this._binaryCount +
                        ' x=' + x + ' y=' + y + ' w=' + w + ' h=' + h +
                        ' png=' + pngSize + 'B');
                }

                var self = this;
                var blob = new Blob([buf.slice(8)], { type: 'image/png' });
                var img = new Image();
                var blobUrl = URL.createObjectURL(blob);
                img.onload = function () {
                    if (self.ctx) {
                        self.ctx.drawImage(img, x, y);
                    }
                    URL.revokeObjectURL(blobUrl);
                };
                img.onerror = function () {
                    console.error('[RDP] PNG decode FAILED #' + self._binaryCount +
                        ' size=' + pngSize + 'B');
                    URL.revokeObjectURL(blobUrl);
                };
                img.src = blobUrl;
            },

            _updateCanvasLayout: function () {
                var canvas = this.$refs.canvas;
                if (!canvas) return;
                if (document.fullscreenElement) {
                    var vw = window.innerWidth;
                    var vh = window.innerHeight;
                    var dw = this.desktopWidth;
                    var dh = this.desktopHeight;
                    if (dw > 0 && dh > 0) {
                        var scale = Math.min(vw / dw, vh / dh);
                        canvas.style.width = Math.floor(dw * scale) + 'px';
                        canvas.style.height = Math.floor(dh * scale) + 'px';
                    }
                } else {
                    canvas.style.width = '';
                    canvas.style.height = '';
                }
            },

            sendInput: function (input) {
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify(input));
                }
            },

            onMouseMove: function (e) {
                var self = this;
                var now = Date.now();
                var rect = this.$refs.canvas.getBoundingClientRect();
                var scaleX = this.desktopWidth / rect.width;
                var scaleY = this.desktopHeight / rect.height;
                var payload = {
                    type: 'mouse_move',
                    x: Math.round((e.clientX - rect.left) * scaleX),
                    y: Math.round((e.clientY - rect.top) * scaleY)
                };
                if (this._pendingMouseMove) clearTimeout(this._pendingMouseMove);
                if (now - this._lastMouseSend >= this._mouseThrottleMs) {
                    this._lastMouseSend = now;
                    this.sendInput(payload);
                } else {
                    this._pendingMouseMove = setTimeout(function () {
                        self._lastMouseSend = Date.now();
                        self._pendingMouseMove = null;
                        self.sendInput(payload);
                    }, this._mouseThrottleMs - (now - this._lastMouseSend));
                }
            },

            onMouseDown: function (e) {
                var rect = this.$refs.canvas.getBoundingClientRect();
                var scaleX = this.desktopWidth / rect.width;
                var scaleY = this.desktopHeight / rect.height;
                this.sendInput({
                    type: 'mouse_button',
                    button: e.button,
                    pressed: true,
                    x: Math.round((e.clientX - rect.left) * scaleX),
                    y: Math.round((e.clientY - rect.top) * scaleY)
                });
            },

            onMouseUp: function (e) {
                var rect = this.$refs.canvas.getBoundingClientRect();
                var scaleX = this.desktopWidth / rect.width;
                var scaleY = this.desktopHeight / rect.height;
                this.sendInput({
                    type: 'mouse_button',
                    button: e.button,
                    pressed: false,
                    x: Math.round((e.clientX - rect.left) * scaleX),
                    y: Math.round((e.clientY - rect.top) * scaleY)
                });
            },

            onWheel: function (e) {
                this.sendInput({
                    type: 'mouse_wheel',
                    delta_x: Math.round(e.deltaX),
                    delta_y: Math.round(e.deltaY)
                });
            },

            onKeyDown: function (e) {
                this.sendInput({
                    type: 'key',
                    code: e.code,
                    key: e.key,
                    pressed: true,
                    shift: e.shiftKey,
                    ctrl: e.ctrlKey,
                    alt: e.altKey,
                    meta: e.metaKey
                });
            },

            onKeyUp: function (e) {
                this.sendInput({
                    type: 'key',
                    code: e.code,
                    key: e.key,
                    pressed: false,
                    shift: e.shiftKey,
                    ctrl: e.ctrlKey,
                    alt: e.altKey,
                    meta: e.metaKey
                });
            },

            toggleFullscreen: function () {
                var self = this;
                if (document.fullscreenElement) {
                    document.exitFullscreen();
                } else {
                    this.$refs.container.requestFullscreen().then(function () {
                        self.$nextTick(function () { self.$refs.canvas.focus(); });
                    });
                }
            },

            disconnect: function () {
                if (this.ws) this.ws.close(1000, 'User disconnected');
                window.location.href = '/assets';
            }
        };
    });
});

// ── HTMX event handlers ──────────────────────────────────────────────────────
// Wrapped in DOMContentLoaded because this script is loaded in <head>,
// before <body> exists.  Without the wrapper, document.body is null
// and addEventListener would throw.

document.addEventListener('DOMContentLoaded', function () {
    // Toast notification handler
    document.body.addEventListener('showToast', function (evt) {
        var detail = evt.detail || {};
        var alpineData = Alpine.$data(document.body);
        if (alpineData && alpineData.addNotification) {
            alpineData.addNotification({
                title: detail.type === 'error' ? 'Error' : (detail.type === 'success' ? 'Success' : 'Info'),
                message: detail.message || 'An error occurred',
                level: detail.type || 'error'
            });
        }
    });

    // Redirect handler for HTMX responses
    document.body.addEventListener('redirectTo', function (evt) {
        var detail = evt.detail || {};
        if (detail.url) {
            window.location.href = detail.url;
        }
    });

    // JIT access modal trigger from SSH/RDP handlers
    // (HX-Trigger: show-access-request-modal).
    //
    // Issue #34 - the legacy `HX-Redirect` to
    // `/assets/{uuid}#request-access` was replaced by the SSH/RDP
    // handlers emitting an `HX-Trigger` whose payload carries the
    // asset_uuid, asset_type, require_mfa fields the modal needs.
    // This avoids the page-load detour through the now-removed
    // `/assets/{uuid}` detail page (information leak surface).
    //
    // Backward compatibility: if `event.detail` is empty (legacy
    // payload-less trigger), the modal still opens but with empty
    // store fields -- the form will then fail validation rather
    // than submit with stale data.
    document.body.addEventListener('show-access-request-modal', function (evt) {
        if (typeof Alpine === 'undefined' || !Alpine.store('accessModal')) {
            return;
        }
        var store = Alpine.store('accessModal');
        var detail = evt.detail || {};
        if (typeof store.open === 'function' && detail.asset_uuid) {
            store.open(detail.asset_uuid, detail.asset_type || '', !!detail.require_mfa);
        } else {
            store.show = true;
        }
    });

    // Issue #34 -- the legacy hash-router has been removed along
    // with the `/assets/{uuid}` detail page. The two modaux are
    // now driven entirely by per-row buttons on `/assets` (no
    // nav, no hash, no client-side policy data island). Any old
    // bookmark pointing at the legacy URL lands on a 410 Gone
    // served by `gone_asset_user_view` and the user is invited
    // to go back to `/assets`.
});
