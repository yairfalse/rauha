# Rauha

**Isolation-first container runtime for Linux and macOS.**

Containers bolt isolation onto a kernel that wasn't designed for it — namespaces, cgroups, and seccomp are independent mechanisms duct-taped together. Solaris got this right in 2005 with Zones: isolation was a first-class kernel concept, not an afterthought.

Rauha brings that philosophy to modern systems. **Zones** are the core primitive — a unified isolation boundary that ties together cgroups, namespaces, and eBPF enforcement under one API. Two native backends: eBPF LSM hooks on Linux, Virtualization.framework VMs on macOS.

> *Rauha* (Finnish) — peace, calm. What your production systems should be.

## The Zone Model

A zone is not a namespace. It's not a cgroup. It's the *concept* that ties them together.

```
┌─────────────────────────────────────────────────────────┐
│                   Global Zone (Host)                    │
│                                                         │
│   rauhad ─── gRPC :9876 ──── rauha CLI                 │
│                                                         │
│   ┌─────────────────────┐   ┌─────────────────────┐    │
│   │       Zone A        │   │       Zone B         │    │
│   │                     │   │                      │    │
│   │   nginx             │   │   postgres           │    │
│   │   app-server        │   │   redis              │    │
│   │                     │   │                      │    │
│   │   10.89.0.2/16      │   │   10.89.0.3/16       │    │
│   │   own cgroup        │   │   own cgroup          │    │
│   │   own netns         │   │   own netns           │    │
│   │   own rootfs        │   │   own rootfs          │    │
│   └─────────────────────┘   └──────────────────────┘    │
│              ╳ denied by default ╳                       │
└─────────────────────────────────────────────────────────┘
```

Every container belongs to exactly one zone. Zones are the unit of:

| Concern | What it means |
|---------|---------------|
| **Visibility** | Processes in Zone A cannot see Zone B's processes |
| **Access** | Files, IPC, and signals cannot cross zone boundaries |
| **Networking** | Each zone gets its own IP, bridge connectivity, and firewall rules |
| **Resources** | CPU, memory, I/O, and PID limits scoped per zone |
| **Policy** | TOML-based, allow-list only, hot-reloadable without restart |

Cross-zone communication requires an explicit policy rule — allow-list, not deny-list.

## How It Works

### Linux: eBPF makes the kernel zone-aware

Rauha loads eBPF programs into kernel LSM hooks that enforce zone boundaries at the syscall level. Every `open()`, `kill()`, `connect()`, and `ptrace()` checks zone membership before proceeding.

```
Process in Zone A calls open("/data/file.txt")
  │
  ├─ kernel reaches file_open LSM hook
  ├─ rauha eBPF program fires
  ├─ lookup: process cgroup → zone_id = A
  ├─ lookup: file inode → file_zone = B
  ├─ A ≠ B → return -EACCES
  │
  └─ process gets "Permission denied"
```

This isn't a userspace check — it's enforced in the kernel on every access with no daemon round-trip. Policy changes are a BPF map update, not a process restart.

| eBPF Program | LSM Hook | Blocks |
|-------------|----------|--------|
| `rauha_file_open` | `file_open` | Cross-zone file access |
| `rauha_bprm_check` | `bprm_check_security` | Cross-zone binary execution |
| `rauha_ptrace_check` | `ptrace_access_check` | Cross-zone debugging/tracing |
| `rauha_task_kill` | `task_kill` | Cross-zone signals |
| `rauha_cgroup_attach` | `cgroup_attach_task` | Zone escape via cgroup manipulation |

Requires Linux 6.1+ with `CONFIG_BPF_LSM=y`.

### macOS: native VMs via Virtualization.framework

Each zone is a lightweight Linux VM — not a hidden shared VM like Docker Desktop. Each zone gets its own VM with hardware-enforced isolation.

The `rauha-guest-agent` runs inside each VM and manages container processes over virtio-vsock, using the same postcard IPC protocol as the Linux shim. APFS `clonefile()` provides instant, zero-copy rootfs clones. Network isolation uses pf firewall anchors per zone.

Same CLI. Same policy format. Same guarantees.

### Zone Networking

Each zone gets a unique IP from the `10.89.0.0/16` subnet. The `rauha0` bridge acts as gateway. nftables handles NAT masquerade for internet access and per-zone forward chains for traffic filtering.

```
Zone A (10.89.0.2)                    Zone B (10.89.0.3)
    │                                     │
  eth0 ──── veth-a ─┐       ┌── veth-b ── eth0
                    │       │
              ┌─────┴───────┴─────┐
              │     rauha0        │
              │   10.89.0.1/16    │
              │   (bridge+gw)     │
              └────────┬──────────┘
                       │
                 IP forwarding
                       │
                nftables NAT
                (masquerade)
                       │
                 host interface
                       │
                    internet
```

**Enforcement layering:** nftables handles packet filtering (L3/L4). eBPF `ZONE_ALLOWED_COMMS` map provides defense-in-depth for cross-zone socket operations. Network namespaces provide structural isolation. Three independent layers — if one is bypassed, the others still hold.

## Architecture

```
┌──────────────────┐
│    rauha CLI     │
└────────┬─────────┘
         │ gRPC :9876
┌────────▼─────────────────────────────────────────────┐
│                        rauhad                        │
│                                                      │
│  Zone Registry ── Policy Engine ── Metadata (redb)   │
│       │                                              │
│  IsolationBackend (trait)                            │
│       │                                              │
│  Image Service ── Content Store ── IP Allocator      │
└───────┬──────────────────────────────────┬───────────┘
        │                                  │
┌───────▼──────────┐            ┌──────────▼───────────┐
│  Linux Backend   │            │   macOS Backend      │
│                  │            │                      │
│  eBPF LSM hooks  │            │  Virtualization.fw   │
│  cgroups v2      │            │  APFS clonefile      │
│  network ns      │            │  pf firewall         │
│  nftables NAT    │            │  virtio-vsock        │
│  IP allocator    │            │  VM-per-zone         │
└───────┬──────────┘            └──────────┬───────────┘
        │ one per zone                     │ one VM per zone
┌───────▼──────────┐            ┌──────────▼───────────┐
│   rauha-shim     │            │ rauha-guest-agent    │
│ sync, fork-safe  │            │   inside Linux VM    │
│ Unix socket IPC  │            │   vsock port 5123    │
│ postcard codec   │            │   postcard codec     │
└──────────────────┘            └──────────────────────┘
```

### The `IsolationBackend` trait

The key abstraction. Both backends implement the same interface — `rauhad` is platform-agnostic.

```rust
trait IsolationBackend: Send + Sync {
    fn create_zone(&self, config: &ZoneConfig) -> Result<ZoneHandle>;
    fn destroy_zone(&self, zone: &ZoneHandle) -> Result<()>;
    fn enforce_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()>;
    fn hot_reload_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()>;
    fn create_container(&self, zone: &ZoneHandle, spec: &ContainerSpec) -> Result<ContainerHandle>;
    fn start_container(&self, container: &ContainerHandle) -> Result<u32>;
    fn stop_container(&self, container: &ContainerHandle) -> Result<()>;
    fn zone_stats(&self, zone: &ZoneHandle) -> Result<ZoneStats>;
    fn verify_isolation(&self, zone: &ZoneHandle) -> Result<IsolationReport>;
    fn recover_zone(&self, zone: &ZoneHandle, zone_type: ZoneType, policy: &ZonePolicy) -> Result<()>;
    fn cleanup_orphans(&self, known_zones: &[ZoneHandle]) -> Result<()>;
    fn isolation_model(&self) -> IsolationModel; // SyscallPolicy | HardwareBoundary
    fn name(&self) -> &str;
}
```

### Crate Structure

| Crate | Purpose |
|-------|---------|
| `rauha-common` | Shared types, `IsolationBackend` trait, policy parsing, shim IPC protocol |
| `rauhad` | Daemon — gRPC server, zone registry, metadata (redb), networking, backends |
| `rauha-cli` | CLI binary |
| `rauha-shim` | Per-zone sync process — fork/run containers (Linux only) |
| `rauha-guest-agent` | Guest-side daemon inside macOS VMs |
| `rauha-oci` | OCI image pull, content store, rootfs preparation |
| `rauha-ebpf` | eBPF LSM programs (kernel-side, separate build) |
| `rauha-ebpf-common` | Shared `#[repr(C)]` types between eBPF and userspace |
| `xtask` | Build helper for eBPF compilation |

## Usage

```bash
# Create zones with policies
rauha zone create --name frontend --policy policies/standard.toml
rauha zone create --name database --policy policies/strict.toml

# Run containers in zones
rauha run --zone frontend nginx:latest
rauha run --zone database postgres:16

# Verify isolation
rauha zone verify frontend

# Image management
rauha image pull alpine:latest
rauha image ls
rauha image inspect alpine:latest

# Observe
rauha ps --zone frontend
rauha logs <container-id> --follow
rauha exec -it <container-id> /bin/sh
```

### Zone Policies

Declarative TOML. Allow-list model — nothing is permitted unless explicitly listed.

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
mode = "bridged"
allowed_zones = ["frontend"]
allowed_egress = ["0.0.0.0/0:443"]

[filesystem]
writable_paths = ["/data", "/tmp", "/var/log"]

[syscalls]
deny = ["mount", "umount2", "pivot_root"]
```

## Oracle Test Suite

Rauha includes a ground-truth oracle (`eval/oracle/`) — a standalone Rust binary that validates rauhad through its gRPC API. 54 numbered test cases across 11 categories. The oracle never reads source code, never mocks. When a case fails, it means the system's public contract is broken.

```bash
cd eval/oracle
RAUHA_GRPC_ENDPOINT=http://[::1]:9876 cargo test           # all cases
RAUHA_GRPC_ENDPOINT=http://[::1]:9876 cargo test -- case_001  # one case
```

| Range | Category | Cases |
|-------|----------|-------|
| 001-003 | Zone lifecycle | create, list, delete, duplicates |
| 004-006 | Container lifecycle | create, start, stop, exit |
| 007-009 | Image management | pull, inspect, remove |
| 010-012 | Isolation verification | healthy, nonexistent, policy reload |
| 013-015 | Policy enforcement | apply, memory limits, invalid rejection |
| 016-018 | Networking | bridged, host mode, DNS |
| 019-021 | Observability | stats, NotFound paths |
| 022-029 | Resilience | input validation (8 cases) |
| 030-034 | Multi-zone | coexistence, scoping, force-delete |
| 035-039 | Container edge cases | NotFound, invalid UUID |
| 040-054 | Invariants & stress | ID consistency, boundaries, rapid cycles |

## Building

```bash
# Build all workspace crates
cargo build

# Run unit tests
cargo test

# Start the daemon
RUST_LOG=rauhad=debug cargo run --bin rauhad

# macOS: sign after every build
codesign --entitlements rauhad/rauhad.entitlements -s - target/debug/rauhad

# Build eBPF programs (requires nightly)
cargo xtask build-ebpf
```

**Linux:** kernel 6.1+, `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`, boot with `lsm=lockdown,capability,bpf`

**macOS:** macOS 15+ (Sequoia), Apple Silicon or Intel with VT-x, `com.apple.security.virtualization` entitlement

## Trade-offs

**eBPF is not a kernel primitive.** Zone identity is reconstructed via BPF map lookup on every enforcement call. Defended by the `zone_cgroup_lock` LSM hook, but it's defense-in-depth, not a hardware boundary.

**LSM is additive-only.** eBPF LSM programs can deny access but cannot override SELinux/AppArmor denials. Zone policy must be a subset of existing MAC policy.

**Struct offsets are hardcoded.** eBPF programs use fixed offsets for kernel structs (e.g., `file->f_inode` at +32). Correct for Linux 6.1+; CO-RE BTF support is planned.

**Covert channels** via shared kernel resources (CPU cache timing, memory pressure) are not addressable by eBPF. Same limitation as all OS-level isolation.

## License

Apache-2.0
