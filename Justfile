# Vauban build recipes
#
# vauban-proxy-rdp is excluded from the Cargo workspace due to irreconcilable
# pre-release dependency conflicts in the RustCrypto ecosystem (ironrdp/picky/sspi
# vs russh/ssh-key). These recipes ensure it is always built alongside the workspace.
#
# --target-dir target ensures vauban-proxy-rdp outputs binaries into the shared
# target/ directory where the supervisor expects them (bin_path = "./target/debug").

rdp_manifest := "--manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target"

# Build all crates (workspace + vauban-proxy-rdp)
build *ARGS:
    cargo build --workspace {{ARGS}}
    cargo build {{rdp_manifest}} {{ARGS}}

# Check all crates without producing binaries
check *ARGS:
    cargo check --workspace {{ARGS}}
    cargo check {{rdp_manifest}} {{ARGS}}

# Run all tests
test *ARGS:
    cargo test --workspace {{ARGS}}
    cargo test {{rdp_manifest}} {{ARGS}}

# Run clippy on all crates
clippy *ARGS:
    cargo clippy --workspace {{ARGS}}
    cargo clippy {{rdp_manifest}} {{ARGS}}

# Build release binaries
release:
    cargo build --workspace --release
    cargo build {{rdp_manifest}} --release

# Clean all build artifacts
clean:
    cargo clean
