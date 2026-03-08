# Rauha

**Isolation-first container runtime for Linux and macOS.**

Linux containers bolt isolation onto a kernel that wasn't designed for it — namespaces, cgroups, and seccomp are independent mechanisms duct-taped together. Solaris got this right in 2005 with Zones: isolation was a first-class kernel concept, not an afterthought.

Rauha brings that philosophy to modern systems. One runtime, two native backends: eBPF on Linux, Virtualization.framework on macOS. Container UX, zones security model, Rust performance.

> *Rauha* (Finnish) — peace, calm. What your production systems should be.

---

## Why

Every container runtime today works the same way: create a namespace, attach a cgroup, bolt on a seccomp filter, hope nothing falls through the cracks. The isolation primitives don't know about each other. A process in container A can't *see* container B's processes (PID namespace), but the kernel has no concept of "these two things are isolated from each other" — it's enforced by separate, uncoordinated mechanisms.

This creates real problems:

- **Escape vectors** live in the gaps between mechanisms. A process that manipulates its cgroup can sidestep namespace restrictions. A mount namespace escape can bypass seccomp filters. Each mechanism is secure in isolation; the composition is where things break.

- **Cross-container visibility** requires explicit, per-mechanism blocking. Want to prevent container A from signaling container B? That's a seccomp rule. From accessing B's files? That's a mount namespace + MAC policy. From seeing B's network traffic? That's a network namespace. Miss one mechanism and you have a hole.

- **macOS doesn't have any of this.** Docker Desktop runs a hidden Linux VM. Every file access goes through virtio-fs. Every network packet crosses a VM boundary. Debugging is painful. Performance suffers. It's a Linux runtime pretending to be native.

Rauha introduces the **zone** — a first-class isolation boundary that unifies all these mechanisms under one concept.

---

## The Zone Model

A zone is not a namespace. It's not a cgroup. It's the *concept* that ties them together.

```
                     ┌──────────────────────────────────────────────────┐
                     │               Global Zone (Host)                │
                     │                                                 │
                     │  rauhad                   system processes       │
                     │                                                 │
                     │  ┌───────────────────┐  ┌───────────────────┐   │
                     │  │      Zone A       │  │      Zone B       │   │
                     │  │                   │  │                   │   │
                     │  │  nginx            │  │  postgres         │   │
                     │  │  app-server       │  │  redis            │   │
                     │  │                   │  │                   │   │
                     │  │  own cgroup       │  │  own cgroup       │   │
                     │  │  own netns        │  │  own netns        │   │
                     │  │  own rootfs       │  │  own rootfs       │   │
                     │  └───────────────────┘  └───────────────────┘   │
                     │            ╳ denied by default ╳                │
                     └──────────────────────────────────────────────────┘
```

Every container belongs to exactly one zone. Zones are the unit of:

| Property | Meaning |
|----------|---------|
| **Visibility** | Processes in Zone A cannot see Zone B's processes |
| **Access** | Files, IPC, and signals cannot cross zone boundaries |
| **Networking** | Cross-zone traffic is denied by default |
| **Resources** | Each zone has its own CPU, memory, I/O, and PID limits |

Cross-zone communication is never implicit. It requires an explicit policy rule — allow-list, not deny-list.

---

## How It Works

### Linux: eBPF makes the kernel zone-aware

On Linux, Rauha loads eBPF programs into kernel hook points that enforce zone boundaries at the syscall level. Every `open()`, `kill()`, `connect()`, and `ptrace()` checks zone membership before proceeding.

```
Process in Zone A calls open("/data/file.txt")
  -> kernel reaches file_open LSM hook
  -> rauha_file_open eBPF program fires
  -> looks up process cgroup -> zone_id = A
  -> looks up file inode -> file_zone = B
  -> A != B -> returns -EACCES
  -> process gets "Permission denied"
```

This isn't a userspace check. It's enforced in the kernel, on every access, with no daemon round-trip. The eBPF programs read from shared BPF maps that `rauhad` populates — policy changes are a map update, not a process restart.

**eBPF enforcement programs (implemented):**

| Program | LSM Hook | What it blocks |
|---------|----------|---------------|
| `rauha_file_open` | `file_open` | Cross-zone file access |
| `rauha_bprm_check` | `bprm_check_security` | Cross-zone binary execution |
| `rauha_ptrace_check` | `ptrace_access_check` | Cross-zone debugging/tracing |
| `rauha_task_kill` | `task_kill` | Cross-zone signals |
| `rauha_cgroup_attach` | `cgroup_attach_task` | Zone escape via cgroup manipulation |

**Planned:** `sb_mount` (mount guard), `ipc_permission` (IPC guard), cgroup skb/sock (network policy), `getdents64` (/proc filtering).

Requires Linux 6.1+ with `CONFIG_BPF_LSM=y`.

### macOS: truly native, no Linux VM

On macOS, each zone is a lightweight VM via Apple's Virtualization.framework. Not a hidden Linux VM like Docker Desktop — a native Apple Silicon hypervisor VM that boots in under a second.

Same `rauha zone create` command. Same policy format. Same isolation guarantees. Native filesystem performance. No virtio-fs overhead.

---

## Architecture

```
                          ┌────────────────────────┐
                          │       rauha CLI         │
                          │  (one binary, all OS)   │
                          └───────────┬────────────┘
                                      │ gRPC (TCP :9876)
                          ┌───────────▼────────────┐
                          │         rauhad          │
                          │   (zone manager daemon) │
                          │                         │
                          │  ┌───────────────────┐  │
                          │  │   Zone Registry    │  │
                          │  │                    │  │
                          │  │  zones + containers│  │
                          │  │  policy engine     │  │
                          │  └────────┬──────────┘  │
                          │           │              │
                          │  ┌────────▼──────────┐  │
                          │  │  IsolationBackend  │  │  ◄── trait object
                          │  └────────┬──────────┘  │
                          │           │              │
                          │  ┌────────▼──────────┐  │     ┌──────────────────────┐
                          │  │   Image Service    │──│────>│  Content Store        │
                          │  │  (pull/unpack OCI) │  │     │  /var/lib/rauha/     │
                          │  └───────────────────┘  │     │   content/blobs/     │
                          │                         │     │   content/manifests/ │
                          │  ┌───────────────────┐  │     └──────────────────────┘
                          │  │  Metadata (redb)   │  │
                          │  │  /var/lib/rauha/   │  │
                          │  │   metadata/rauha.  │  │
                          │  │   redb             │  │
                          │  └───────────────────┘  │
                          └───────────┬────────────┘
                                      │
                   ┌──────────────────┴──────────────────┐
                   │                                     │
          ┌────────▼─────────┐                ┌─────────▼────────┐
          │   Linux Backend   │                │  macOS Backend    │
          │                   │                │  (Phase 5)        │
          │  eBPF LSM hooks   │                │                   │
          │  cgroups v2       │                │  Virt.framework   │
          │  network ns       │                │  sandbox profiles │
          │  shim management  │                │  pf firewall      │
          └────────┬─────────┘                └───────────────────┘
                   │
                   │ spawns one per zone
                   │
          ┌────────▼──────────────────────────────────────────┐
          │                    rauha-shim                      │
          │              (sync, single-threaded)               │
          │                                                    │
          │  Unix socket: /run/rauha/shim-{zone}.sock          │
          │  IPC: length-prefixed postcard                     │
          │                                                    │
          │  For each container:                               │
          │    fork() ──> write PID to zone cgroup             │
          │           ──> signal sync pipe                     │
          │           ──> child: pivot_root + exec             │
          │                                                    │
          │  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
          │  │ nginx   │  │ app     │  │ worker  │           │
          │  │ PID 42  │  │ PID 87  │  │ PID 91  │           │
          │  └─────────┘  └─────────┘  └─────────┘           │
          └───────────────────┬───────────────────────────────┘
                              │
           ┌──────────────────▼───────────────────────────┐
           │              Linux Kernel                     │
           │                                               │
           │  BPF maps (pinned at /sys/fs/bpf/rauha/)     │
           │    ZONE_MEMBERSHIP   cgroup_id -> zone_id    │
           │    ZONE_POLICY       zone_id -> policy       │
           │    INODE_ZONE_MAP    inode -> zone_id        │
           │    ZONE_ALLOWED_COMMS  (src,dst) -> allowed  │
           │                                               │
           │  LSM hooks                                    │
           │    file_open ──> rauha_file_open              │
           │    bprm_check ──> rauha_bprm_check            │
           │    ptrace ──> rauha_ptrace_check              │
           │    task_kill ──> rauha_task_kill               │
           │    cgroup_attach ──> rauha_cgroup_attach       │
           │                                               │
           │  cgroups v2                                   │
           │    /sys/fs/cgroup/rauha.slice/zone-{name}/   │
           └───────────────────────────────────────────────┘
```

### The `IsolationBackend` trait

The key abstraction. Both backends implement the same interface — `rauhad` doesn't know or care which platform it's running on.

```rust
trait IsolationBackend: Send + Sync {
    // Zone lifecycle
    fn create_zone(&self, config: &ZoneConfig) -> Result<ZoneHandle>;
    fn destroy_zone(&self, zone: &ZoneHandle) -> Result<()>;

    // Policy
    fn enforce_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()>;
    fn hot_reload_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()>;

    // Containers
    fn create_container(&self, zone: &ZoneHandle, spec: &ContainerSpec) -> Result<ContainerHandle>;
    fn start_container(&self, container: &ContainerHandle) -> Result<()>;
    fn stop_container(&self, container: &ContainerHandle) -> Result<()>;

    // Observability
    fn zone_stats(&self, zone: &ZoneHandle) -> Result<ZoneStats>;
    fn verify_isolation(&self, zone: &ZoneHandle) -> Result<IsolationReport>;

    // Crash recovery
    fn recover_zone(&self, zone: &ZoneHandle, zone_type: ZoneType, policy: &ZonePolicy) -> Result<()>;
    fn cleanup_orphans(&self, known_zones: &[ZoneHandle]) -> Result<()>;

    // Platform identity
    fn isolation_model(&self) -> IsolationModel;
    fn name(&self) -> &str;
}
```

### Crate Structure

| Crate | Purpose |
|-------|---------|
| `rauha-common` | Shared types, `IsolationBackend` trait, policy parsing, shim IPC protocol |
| `rauhad` | Daemon — gRPC server, zone registry, metadata store (redb), backends |
| `rauha-cli` | CLI binary |
| `rauha-shim` | Per-zone shim process (sync, single-threaded, Linux only) |
| `rauha-oci` | OCI image pull, content store, rootfs preparation, runtime spec generation |
| `rauha-ebpf` | eBPF LSM programs (kernel-side, separate build target) |
| `rauha-ebpf-common` | Shared `#[repr(C)]` types between eBPF programs and userspace |
| `xtask` | Build helper for eBPF compilation |

### Key Dependencies

| Crate | Why |
|-------|-----|
| `aya` / `aya-ebpf` | eBPF in pure Rust — no libbpf, no C |
| `tonic` / `prost` | gRPC (daemon ↔ CLI, future CRI compatibility) |
| `redb` | Metadata store — pure Rust, ACID, zero C deps |
| `tokio` | Async runtime (daemon and CLI) |
| `postcard` | Binary serialization for shim ↔ daemon IPC |
| `nix` | Linux syscalls (fork, setns, pivot_root, mount) |
| `oci-spec` | OCI runtime spec types |
| `reqwest` | OCI registry HTTP client |

---

## Usage

```bash
# Create zones
rauha zone create --name frontend --policy policies/standard.toml
rauha zone create --name database --policy policies/strict.toml

# Run containers in zones
rauha run --zone frontend nginx:latest
rauha run --zone database postgres:16

# Containers are isolated by default
rauha zone verify frontend    # ISOLATED

# Image management
rauha image pull alpine:latest
rauha image ls
rauha image inspect alpine:latest

# Explicit cross-zone communication
rauha policy apply --zone frontend --allow-zone database

# Observe
rauha ps --zone frontend
rauha top --zone database
rauha trace --zone frontend
rauha events
```

### Zone Policies

Policies are declarative TOML files. Allow-list model — nothing is permitted unless explicitly listed.

```toml
[zone]
name = "production"
type = "non-global"

[capabilities]
allowed = ["CAP_NET_BIND_SERVICE", "CAP_CHOWN"]

[resources]
cpu_shares = 1024
memory_limit = "4Gi"
pids_max = 512

[network]
mode = "isolated"
allowed_zones = ["frontend"]
allowed_egress = ["0.0.0.0/0:443"]

[filesystem]
writable_paths = ["/data", "/tmp", "/var/log"]

[devices]
allowed = ["/dev/null", "/dev/zero", "/dev/urandom"]

[syscalls]
deny = ["mount", "umount2", "pivot_root"]
```

---

## Roadmap

- [x] **Phase 1: Foundation** — workspace, shared types, `IsolationBackend` trait, redb metadata, zone registry, gRPC skeleton, CLI
- [x] **Phase 2: Linux Isolation** — eBPF programs (Aya), BPF map management, LSM enforcement, network namespaces, cgroup hierarchy, crash recovery
- [x] **Phase 3: Container Runtime** — OCI image pull, content store, image service, zone shim, container lifecycle
- [ ] **Phase 4: Integration & Hardening** — end-to-end testing, overlayfs snapshotter, PTY attach, streaming logs
- [ ] **Phase 5: macOS Backend** — Virtualization.framework, sandbox profiles, APFS clone snapshotter, Network.framework + pf
- [ ] **Phase 6: Observability** — `rauha trace` (eBPF/DTrace), `rauha top`, event streaming

---

## Honest Trade-offs

**eBPF is not a kernel primitive.** Zone identity is reconstructed via BPF map lookup on every enforcement call. A process that could manipulate cgroup membership could theoretically escape — defended by the `zone_cgroup_lock` LSM hook, but it's defense-in-depth, not a hardware boundary.

**LSM is additive-only.** eBPF LSM programs can deny access but cannot override SELinux/AppArmor denials. Zone policy must be a subset of existing MAC policy.

**Struct offsets are hardcoded.** eBPF programs use fixed offsets for kernel structs (e.g., `file->f_inode` at +32). Correct for Linux 6.1+ but may break on future kernels until CO-RE BTF support is added.

**macOS backend requires macOS 15+** for the Containers API. Older versions get Virtualization.framework VMs only.

**Covert channels** via shared kernel resources (CPU cache timing, memory pressure) are not addressable by eBPF. Same limitation as all OS-level isolation.

**eBPF verifier complexity ceiling.** Programs accessing deep kernel structs must be carefully bounded to pass the BPF verifier. This constrains how sophisticated individual enforcement programs can be.

See [SECURITY.md](SECURITY.md) for a detailed analysis of the security model and known limitations.

---

## Building

```bash
# Requires: Rust 1.75+, protoc
cargo build
cargo test

# Start the daemon (development)
RUST_LOG=rauhad=debug cargo run --bin rauhad

# Use the CLI
cargo run --bin rauha -- zone create --name test
cargo run --bin rauha -- zone list

# Build eBPF programs (requires nightly Rust)
cargo xtask build-ebpf
cargo xtask build-ebpf --release
```

**Linux eBPF requirements:**
- Linux 6.1+ kernel
- `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Boot parameter: `lsm=lockdown,capability,bpf`

---

## License

Apache-2.0
