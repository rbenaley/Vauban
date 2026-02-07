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
