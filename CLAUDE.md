# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Rauha is an isolation-first container runtime. Zones are the core concept — a first-class isolation boundary that unifies cgroups, namespaces, and eBPF enforcement under one API. Linux uses eBPF LSM hooks for per-syscall enforcement; macOS will use Virtualization.framework VMs.

## Build & Test Commands

```bash
cargo build                          # Build all workspace crates
cargo test                           # Run all unit tests
cargo test -p rauha-oci              # Test a single crate
cargo test test_name                 # Run a single test by name
cargo build --bin rauhad             # Build just the daemon
cargo build --bin rauha              # Build just the CLI
cargo build --bin rauha-shim         # Build the per-zone shim

# eBPF programs (separate build, requires nightly Rust)
cargo xtask build-ebpf               # Debug build
cargo xtask build-ebpf --release     # Release build

# Run the daemon (development, listens on [::1]:9876)
RUST_LOG=rauhad=debug cargo run --bin rauhad

# Use the CLI (connects to RAUHA_ADDR or http://[::1]:9876)
cargo run --bin rauha -- zone create --name test
cargo run --bin rauha -- zone list

# Integration tests (Linux only, require root + running rauhad)
bash tests/integration/test-image-pull.sh
bash tests/integration/test-container-lifecycle.sh
bash tests/integration/test-zone-isolation.sh
```

Proto files are in `proto/` (zone.proto, container.proto, image.proto). They compile automatically via `build.rs` in rauhad and rauha-cli.

## Core Principles

1. **Easy to understand** — no clever abstractions, no indirection for its own sake.
2. **Easy to use** — `rauha zone create`, `rauha run`. No 50-flag commands.
3. **Easy to fix** — small files, clear boundaries, minimal dependencies.
4. **Reliable as bedrock** — every code path tested, every error handled with context.

**Non-negotiables:** No YAML (TOML only). No premature abstractions. No "design for the future."

## Architecture

### Key Abstraction: `IsolationBackend` trait (`rauha-common/src/backend.rs`)

Both platform backends implement this trait. rauhad is platform-agnostic — it calls trait methods and doesn't know which OS it's on.

### Async/Sync Boundary

- **rauhad** is async (tokio) — gRPC server, concurrent zone management
- **rauha-shim** is deliberately sync — `fork()` in a multithreaded async runtime is UB. The shim is single-threaded so it can safely fork, setns, pivot_root, and run the container process
- IPC between daemon and shim: length-prefixed postcard over Unix socket (`rauha-common/src/shim.rs`)

### One Shim Per Zone (Not Per Container)

This diverges from containerd's one-shim-per-container model. Zones are the isolation boundary, not containers. Multiple containers in a zone share namespaces. rauhad spawns one `rauha-shim` per zone; the shim forks additional container processes on request.

### Container Fork Flow (Linux)

The sync pipe pattern in `rauha-shim/src/container.rs` prevents a TOCTOU race: the child must be in the zone's cgroup **before** it runs, otherwise eBPF enforcement doesn't apply. Parent writes child PID to cgroup, then signals the pipe; child blocks until confirmed.

### Data Stores

- **redb** (`/var/lib/rauha/metadata/rauha.redb`) — persisted zone/container metadata. Source of truth on crash recovery.
- **BPF maps** (pinned at `/sys/fs/bpf/rauha/`) — in-kernel enforcement state. Reconciled from redb on daemon startup.
- **Content store** (`/var/lib/rauha/content/blobs/sha256/`) — content-addressable OCI blob storage.

### eBPF Programs (`rauha-ebpf/src/`)

Five LSM hooks enforce zone boundaries at the kernel level: `file_open`, `bprm_check_security`, `ptrace_access_check`, `task_kill`, `cgroup_attach_task`. Programs use hardcoded struct offsets (not CO-RE yet). Shared kernel/userspace types live in `rauha-ebpf-common`.

Built separately via `cargo xtask build-ebpf` targeting `bpfel-unknown-none`. Not part of the normal workspace build.

## Code Conventions

- Error messages include what went wrong AND what to do about it. Many error variants have a `hint` field.
- Linux-only code uses `#[cfg(target_os = "linux")]` with stub implementations for other platforms.
- Policies are TOML. See `policies/standard.toml` for the canonical example.
- Tests go in `#[cfg(test)]` modules within source files, not in separate test files.
- The macOS backend (`rauhad/src/backend/macos/`) is a stub — it logs operations and returns Ok.

## Workspace Crates

| Crate | Purpose |
|-------|---------|
| `rauha-common` | Shared types, `IsolationBackend` trait, error types, policy parsing, shim IPC protocol |
| `rauhad` | Daemon — gRPC server, zone registry, metadata (redb), Linux/macOS backends |
| `rauha-cli` | CLI binary — connects to rauhad via gRPC |
| `rauha-shim` | Per-zone sync process — fork/run containers (Linux only) |
| `rauha-oci` | OCI image pull, content store, rootfs preparation, runtime spec generation |
| `rauha-ebpf` | eBPF LSM programs (kernel-side, not in workspace, separate build) |
| `rauha-ebpf-common` | Shared `#[repr(C)]` types between eBPF programs and userspace |
| `xtask` | Build helper for eBPF compilation |

## Linux Kernel Requirements (for eBPF enforcement)

- Linux 6.1+ with `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Boot parameter: `lsm=lockdown,capability,bpf`
- BTF at `/sys/kernel/btf/vmlinux`
