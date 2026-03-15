# Vauban

**A fortified bastion for privileged access management, built in Rust.**

Vauban is an open-source security bastion, developed in Rust, designed to protect and control access to critical infrastructure across enterprise, industrial, and defense environments. Its architecture leverages proven, cutting-edge technologies: privilege separation inspired by OpenSSH and Capsicum sandboxing, a confinement mechanism developed with funding from DARPA (U.S. Department of Defense). The solution includes multi-factor authentication (MFA), role-based access control (RBAC), full session recording, and real-time monitoring of SSH and RDP connections. Free and sovereignty-friendly, Vauban meets the traceability and audit requirements of sensitive environments while offering an open-source alternative to proprietary solutions.

## Project Structure

```
vauban-supervisor/    # Process orchestrator, watchdog, signal handling
vauban-web/           # HTTPS server, REST API, WebSocket handlers, frontend
vauban-auth/          # Authentication, MFA, SSO, LDAP integration
vauban-access/        # Access control, groups, and instance-level authorization (Casbin)
vauban-vault/         # Secrets management, encryption/decryption service
vauban-audit/         # Audit logging, session recording
vauban-proxy-ssh/     # SSH protocol proxy (russh)
vauban-proxy-rdp/     # RDP protocol proxy (IronRDP, H.264 encoding)
shared/               # IPC protocol, message types, common utilities
config/               # TOML configuration files
docs/                 # Technical architecture documentation
```

## Building

### Prerequisites

- Rust 1.89+ (edition 2024)
- [just](https://github.com/casey/just) command runner
- NASM (for OpenH264 assembly compilation)
- PostgreSQL
- FreeBSD (for Capsicum sandbox; builds on macOS/Linux without sandboxing)

### Build

```bash
# Build all crates (debug)
just build

# Build release binaries (optimized, LTO, stripped)
just build --release

# Run all tests
just test

# Run clippy lints
just clippy
```

### Run

```bash
# Start all services via the supervisor
cargo run
```

The supervisor reads `config/default.toml`, forks all 7 child processes, sets up IPC pipes, drops privileges, and enters the watchdog loop.

## Documentation

Detailed technical architecture documents are available in [`docs/technical/`](docs/technical/):

| Document | Description |
|----------|-------------|
| [Privilege Separation Architecture](docs/technical/Vauban_Privsep_Architecture_EN(1.2).md) | Process model, IPC protocol, Capsicum sandboxing, supervisor design |
| [Vault Architecture](docs/technical/Vauban_Vault_Architecture_EN(1.0).md) | Cryptographic design, key management, threat model |
| [RDP Session Architecture](docs/technical/Vauban_RDP_Architecture_EN(1.0).md) | H.264 encoding, WebCodecs decoding, dynamic resolution, input pipeline |
| [OpenH264 AVX2 Optimizations](docs/technical/Vauban_OpenH264_AVX2_Optimizations_EN(1.0).md) | Custom AVX2 assembly for SAD and intra prediction (~50% CPU reduction) |
| [ACME TLS Certificate Architecture](docs/technical/Vauban_ACME_TLS_Architecture_EN(1.0).md) | Automatic certificate renewal, TLS-ALPN-01, zero-downtime rotation |
| [Session Recording Architecture](docs/technical/Vauban_Recording_Architecture_EN(1.1).md) | Segmented fMP4 recording, DASH multi-Period playback, BLAKE3 integrity, Shaka Player |

## Security Model

Vauban's security is built on defense in depth:

1. **Process isolation**: Each service runs under a dedicated UID with no shared memory
2. **Capsicum confinement**: After initialization, processes cannot open files, create sockets, or access the filesystem
3. **Credential isolation**: Encryption keys are confined to `vauban-vault`; secrets are encrypted at rest in PostgreSQL and only decrypted transiently for session establishment, wrapped in zeroize-on-drop memory
4. **Network brokering**: Sandboxed proxies cannot establish TCP connections directly; the supervisor brokers all outbound connections via `SCM_RIGHTS` file descriptor passing
5. **Memory safety**: Rust's ownership model prevents buffer overflows, use-after-free, and data races
6. **Secret hygiene**: Environment variables destroyed after reading, `SensitiveString` zeroized on drop

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.

## Author

Richard Ben Aleya
