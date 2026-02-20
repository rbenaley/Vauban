// VAUBAN Alpine.js components and HTMX event handlers
//
// This file is loaded as an external script to avoid 'unsafe-inline' in CSP.
// Alpine.js components are registered via Alpine.data() before Alpine initializes.

document.addEventListener('alpine:init', function () {
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
                            // Request server-side resize to match screen;
                            // canvas dimensions update when the server confirms
                            // via a desktop_size message.
                            var w = screen.width;
                            var h = screen.height;
                            // RDP spec: width must be even, min 200
                            w = Math.max(200, w - (w % 2));
                            h = Math.max(200, h);
                            self.sendInput({ type: 'resize', width: w, height: h });
                        } else {
                            self.sendInput({ type: 'resize', width: 1280, height: 720 });
                        }
                        self.$refs.canvas.focus();
                    });
                };
                document.addEventListener('fullscreenchange', this._fullscreenHandler);
                this.$nextTick(function () { self.connectWs(); });
            },

            destroy: function () {
                if (this._fullscreenHandler) document.removeEventListener('fullscreenchange', this._fullscreenHandler);
                if (this._pendingMouseMove) clearTimeout(this._pendingMouseMove);
                if (this.ws) this.ws.close(1000, 'Component destroyed');
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
                };

                this._msgCount = 0;
                this._binaryCount = 0;
                this.ws.onmessage = function (event) {
                    self._msgCount++;
                    if (typeof event.data === 'string') {
                        console.log('[RDP] text msg #' + self._msgCount + ':', event.data.substring(0, 200));
                        try {
                            var msg = JSON.parse(event.data);
                            if (msg.type === 'desktop_size' || msg.type === 'desktop_resize') {
                                self.desktopWidth = msg.width;
                                self.desktopHeight = msg.height;
                                console.log('[RDP] desktop ' + msg.type + ': ' + msg.width + 'x' + msg.height);
                            } else if (msg.error) {
                                self.error = msg.error;
                            }
                        } catch (e) { /* ignore */ }
                        return;
                    }
                    self._binaryCount++;
                    // Binary: header (8 bytes: x u16 LE, y u16 LE, w u16 LE, h u16 LE) + PNG data
                    var buf = new Uint8Array(event.data);
                    if (buf.length < 8) {
                        console.warn('[RDP] binary too short:', buf.length);
                        return;
                    }
                    var dv = new DataView(event.data);
                    var x = dv.getUint16(0, true);
                    var y = dv.getUint16(2, true);
                    var w = dv.getUint16(4, true);
                    var h = dv.getUint16(6, true);
                    var pngSize = buf.length - 8;

                    if (self._binaryCount <= 30 || self._binaryCount % 50 === 0) {
                        console.log('[RDP] binary #' + self._binaryCount +
                            ' x=' + x + ' y=' + y + ' w=' + w + ' h=' + h +
                            ' png=' + pngSize + 'B canvas=' + (self.ctx ? 'ok' : 'null'));
                    }

                    var blob = new Blob([buf.slice(8)], { type: 'image/png' });
                    var img = new Image();
                    var blobUrl = URL.createObjectURL(blob);
                    img.onload = function () {
                        if (self.ctx) {
                            self.ctx.drawImage(img, x, y);
                            if (self._binaryCount <= 5) {
                                console.log('[RDP] drawn #' + self._binaryCount +
                                    ' at (' + x + ',' + y + ') img=' + img.naturalWidth + 'x' + img.naturalHeight);
                            }
                        } else {
                            console.warn('[RDP] ctx is null, cannot draw');
                        }
                        URL.revokeObjectURL(blobUrl);
                    };
                    img.onerror = function (e) {
                        console.error('[RDP] PNG decode FAILED #' + self._binaryCount +
                            ' size=' + pngSize + 'B header bytes:', buf[8], buf[9], buf[10], buf[11]);
                        URL.revokeObjectURL(blobUrl);
                    };
                    img.src = blobUrl;
                };

                this.ws.onclose = function () {
                    self.connected = false;
                };

                this.ws.onerror = function () {
                    self.error = 'Connection error';
                    self.connected = false;
                };
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
});
