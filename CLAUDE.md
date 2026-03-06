# Rauha — Development Guidelines

## Core Principles

1. **Easy to understand** — a new contributor should be able to read any file and know what it does. No clever abstractions. No indirection for indirection's sake. If you need a comment to explain what code does, the code is too complicated.

2. **Easy to use** — `rauha zone create`, `rauha run`. That's it. No 50-flag commands, no YAML manifests to get started, no implicit behavior that surprises people.

3. **Easy to fix and maintain** — small files, clear boundaries, minimal dependencies. When something breaks, you should find the bug in minutes, not hours. No magic, no codegen you can't read, no framework lock-in.

4. **Reliable as bedrock** — this is infrastructure. People put their production workloads on it. Every code path must be tested. Every error must be handled, not swallowed. No "we'll fix it later", no "shouldn't happen" comments hiding panics. If it can fail, it has a test that proves it handles failure. If it can't fail, prove it with types.

## Non-Negotiables

- No YAML. TOML for config, that's it.
- No premature interfaces or plugin systems. Build what works, extract abstractions only when forced to by real use cases.
- No "design for the future" — solve today's problem correctly. Tomorrow's problem gets solved tomorrow.

## Architecture Decisions

- **Rust, not Go** — no GC, predictable performance, single static binaries
- **Zones, not namespace soup** — one isolation concept instead of duct-taped mechanisms
- **Own the full stack** — no dependency on Docker, containerd, or Cilium. Learn from them, don't wrap them
- **Native on every platform** — eBPF on Linux, Virtualization.framework on macOS. No VMs pretending to be native
- **Simple networking** — one bridge, eBPF policy on it. No iptables chains, no CNI plugins, no kube-proxy

## Code Style

- Small functions, small files
- No premature abstraction — three similar lines are better than a generic helper used once
- Error messages should tell you what went wrong AND what to do about it
- Tests should be obvious — if a test needs explanation, simplify it
- Minimize dependencies — every crate we add is code we maintain

## Project Structure

- `rauha-common` — shared types, traits, policy parsing
- `rauhad` — daemon (zone registry, metadata, gRPC server, backends)
- `rauha-cli` — CLI binary
- `rauha-shim` — per-zone shim (Linux)
- `rauha-oci` — OCI spec compliance
- `rauha-ebpf` — eBPF programs (Linux kernel-side)
