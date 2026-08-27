# Positioning and Hardening Roadmap

Research snapshot: 2026-08-27. Sources are linked inline; kernel version floors
are stated so features can be runtime-gated rather than raising the 6.1 baseline.

## How Rauha differs from Docker

Docker assumes a semi-trusted image and a human operator. Rauha assumes an
adversarial workload and an operator who needs proof. Every differentiator below
is either shipped, probed on every release, or explicitly marked *planned*.

- **Strict admission** — a requested control is enforced, audited, or the zone is
  refused. Nothing degrades silently. (shipped: `admission = "strict"`)
- **Trusted enrollment** — no image code executes before the process is inside
  its zone's enforcement boundary; init and exec get identical treatment.
  (*milestone* — see "Enrollment" below; the current crun hook does not meet it)
- **Default-deny network** — no host-local services (localhost, link-local, the
  bridge gateway, metadata endpoints), no cross-zone traffic, IPv6 included.
  (shipped for IPv4 via nftables; IPv6 default-off *planned*)
- **Signed execution receipts** — a DSSE/in-toto statement binding image digest,
  policy hash, active hooks and self-test result, deny and drop counts, exit code
  and time window. (*planned* — `obl_receipts`)
- **Adversarial host-impact probes as a release gate** — hostile images, not
  friendly ones, decide whether a build ships. (shipped: `tests/security/`)
- **Crash recovery never drops or un-enforces a running zone** — kill -9 the
  daemon mid-workload; the same PID keeps its cgroup, BPF membership, and inode
  ownership. (shipped: `recovery-probe.sh`)
- **A microVM tier through the same OCI bundle interface** — selection policy
  TBD. (*planned* — `obl_tier`; macOS VM-per-zone is the existing proof point)

Credible "stronger than Docker defaults" milestone: user namespaces + seccomp +
safe image extraction (no symlink/hardlink escapes, no device nodes) +
host-input filtering + device/writable-path enforcement + trusted enrollment.
Until adversarial probes pass, the honest message is *promising architecture,
incomplete containment.*

## Where the market is (2025–2026)

Nobody produces a signed, run-level record of which controls were actually
active. That is the gap.

| Who | Isolation | What they lack |
|---|---|---|
| gVisor (GKE, Cloud Run, Modal, OpenAI, Anthropic) | user-space kernel, systrap | no attestation, denies only in debug logs |
| Firecracker / Kata / Cloud Hypervisor / libkrun | microVM; snapshot-restore is the primitive | CoCo attests boot, not policy activity |
| Docker Sandboxes (Apr 2026), ECI/Sysbox, DHI | per-session microVM; provenance stops at the image | desktop-first; no run evidence |
| E2B, Modal, Daytona, Fly, Cloudflare Sandboxes | Firecracker / gVisor / plain containers | no enforcement evidence |
| Codex sandbox, `@anthropic-ai/sandbox-runtime` | bubblewrap + Landlock/seccomp + egress proxy | "run strace manually" for violations |
| kubernetes-sigs/agent-sandbox | delegates to RuntimeClass (runsc default), warm pools | orchestration only; needs a runtime that reports back |
| Tetragon / Falco / KubeArmor / OCSF / OTel | event schemas | no run-level tamper-evident record; ring drops unreported |

Sources: [gVisor perf](https://gvisor.dev/docs/architecture_guide/performance/),
[microVM survey](https://emirb.github.io/blog/microvm-2026/),
[Docker Sandboxes](https://www.docker.com/blog/why-microvms-the-architecture-behind-docker-sandboxes/),
[sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime/blob/main/README.md),
[Codex sandbox](https://simonwillison.net/2025/Nov/9/codex-sandbox-investigation/),
[agent-sandbox](https://agent-sandbox.sigs.k8s.io/docs/getting_started/overview/),
[CoCo attestation](https://confidentialcontainers.org/docs/features/runtime-attestation/),
[Tetragon events](https://tetragon.io/docs/concepts/events/).

### Eight exploitable gaps, ranked

1. **Signed execution receipt** as an in-toto predicate, so `cosign
   verify-attestation` and Witness policy consume it unchanged.
2. **Enforcement liveness as evidence** — the offset self-test and per-hook
   counters already exist; put them in the receipt.
3. **Denial explainability per task** — `RunSandbox` already returns the zone's
   deny events; add process lineage (Tetragon-style `exec_id`/parent) and paths.
4. **Egress evidence** — domain allowlist UX (proxy) plus every allowed and
   denied connection recorded in the receipt.
5. **Agent RuntimeClass with a contract** — a containerd 2.x sandbox controller
   (one shim per pod = one shim per zone) whose pod status carries the receipt.
6. **Lossless-or-declared telemetry** — `ringbuf.drop`/`pipeline.shed` already
   exist; the receipt states `evidence_complete: bool`.
7. **One policy TOML, two platforms, one receipt schema** — BPF-LSM on Linux, VM
   boundary on macOS.
8. **OCSF/OTel projection** of `rauha-evidence` for free SIEM adoption.

## Enrollment: fixing the crun boundary

Verified against crun `src/libcrun/container.c` (main, 2026-08-27):
`startContainer` hooks are forked by init **after** `pivot_root`, `setresuid`,
capability drop, and seccomp, and `path` resolves in the image rootfs. A hook
there runs the image's `/bin/sh` with workload privileges, so a hostile image
can skip enrollment entirely, and no trusted binary can be placed there either —
the hook has no `CAP_SYS_ADMIN` and may be seccomp-blocked. `startContainer` is
a dead end for enrollment in any runtime (runc sequences it the same way).

What the shim does (`rauha-shim/src/container.rs`): `crun create --pid-file`
(all privileged setup, init parked on `exec.fifo`, outside the zone cgroup) →
`pidfd_open` → write `cgroup.procs`, fail closed on error → `crun start`. No
image code runs before enrollment; the pidfd makes signal/wait immune to PID
reuse.

| Option | Verdict |
|---|---|
| `startContainer` hook | fail-open; untrusted code before enrollment — never |
| Trusted static helper in `startContainer` | cannot work: runs after privilege drop |
| **`crun create` → pidfd → `cgroup.procs` → `crun start`** (current) | enrollment while init is parked; crun setup judged outside the zone; one `cgroup.procs` write, fail closed |
| `createRuntime` hook, host binary, reads state JSON `pid` | spec-blessed (nvidia pattern); equivalent to the current flow if a hook is ever required |
| `--cgroup-manager=cgroupfs` + `"cgroupsPath": "/rauha.slice/zone-X"` | crun passes the zone cgroup dirfd to `clone3(CLONE_INTO_CGROUP)`: zero window and `crun exec` enrolls too — but crun's privileged setup then runs *inside* the zone cgroup, so Syva would need a `bprm_check_security`-keyed phase gate (audit before the workload's first exec, deny after) in `capable`/`file_open` |
| Post-hoc `/proc/pid/cgroup` (or `PIDFD_GET_INFO` cgroupid, 6.13+) | not enforcement; keep as the invariant check |

The `cgroupsPath` variant is the upgrade if exec-path enrollment or a zero-write
sequence is ever needed; it is not required while the create/enroll/start
sequence holds. Any change to the start path must keep enrollment strictly
between `create` and `start`, and a hostile-image probe is the right test.

Crun details to handle: omit `linux.resources` from the spec (Rauha owns limits);
`crun delete` will try to `rmdir` the zone cgroup and get `EBUSY` — verify it is
non-fatal or delete the zone cgroup ourselves; the no-internal-process rule
means nothing may live in `rauha.slice` itself. Set `run.oci.hooks.stdout`/
`stderr`, make the shim `PR_SET_CHILD_SUBREAPER`, own `--console-socket`.

Sources: [runtime-spec hooks](https://github.com/opencontainers/runtime-spec/blob/main/config.md),
[crun man](https://github.com/containers/crun/blob/main/crun.1.md),
[runc changelog](https://github.com/opencontainers/runc/blob/main/CHANGELOG.md).

## Kernel primitives to adopt (with floors)

Today the Linux backend classifies `filesystem.writable_paths`,
`devices.allowed`, and `syscalls.deny` as unsupported, and has no seccomp,
user-namespace, Landlock, or pidfd code. These close those gaps, cheapest first.

1. **cgroup v2 basics** (5.14+, trivial): `cgroup.kill` for atomic zone
   teardown (replaces the shim kill loop), `memory.oom.group=1`, `pids.max`,
   PSI (`memory.pressure`) exposed in `rauha top`.
   [cgroup-v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
2. **Safe rootfs assembly** (5.12+): `OPEN_TREE_CLONE` + `mount_setattr(RDONLY|
   NOSUID|NODEV)` + `move_mount`; resolve all in-container paths with `openat2(
   RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)` or the `pathrs` crate; verify
   `/dev/null` by `st_rdev`, never path. Removes the class behind runc/crun/youki
   CVE-2025-31133/52565/52881 (all mount-path races).
   [CNCF writeup](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/),
   [libpathrs](https://github.com/cyphar/libpathrs)
3. **pidfd lifetime** (5.3+; `PIDFD_GET_INFO` cgroupid 6.13; `PIDFD_INFO_EXIT`
   6.15): hold a pidfd per container, signal via `pidfd_send_signal`, reacquire
   on `recover_zone()` instead of trusting stored PIDs.
   [LWN pidfd info](https://lwn.net/Articles/992991/)
4. **seccomp from policy** (any kernel; OCI `linux.seccomp`): `syscalls.deny` →
   `SCMP_ACT_ERRNO`; default-deny `io_uring_setup`, `userfaultfd`, `bpf`,
   `perf_event_open`, `kexec_*`, `open_by_handle_at`. Later: `SCMP_ACT_NOTIFY`
   with the sync shim as listener (`run.oci.seccomp.receiver`) for FD brokering
   and `zone.syscall.denied` evidence.
   [seccomp_unotify](https://www.mankier.com/2/seccomp_unotify)
5. **User namespaces + idmapped overlay** (5.19+): one userns per zone; Syva
   attaches `userns_create` (6.1, BPF-attachable) to deny nested userns for zone
   tasks unless policy allows. Kubernetes 1.36 made `hostUsers: false` GA.
   [userns GA](https://kubernetes.io/blog/2026/04/23/kubernetes-v1-36-userns-ga/)
6. **Landlock per zone** (ABI-gated: fs 5.13, TCP ports 6.7, signal/abstract-
   socket scoping 6.12, audit 6.15, TSYNC 7.0): closes `writable_paths` in-
   process and irrevocably, independent of BPF-LSM; stacks with `lsm=...,bpf`.
   [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
7. **Devices** via `BPF_PROG_TYPE_CGROUP_DEVICE` per zone cgroup (the only v2
   device controller) → closes `devices.allowed`. `cgroup/connect4|6` for L4
   egress as defense-in-depth beside nftables.
8. **Syva additions**: `bpf_path_d_path` (6.12) so `zone.file.denied` carries a
   path; `uring_allowed` hook (6.15); BPF token (6.9) so the enforcer needs no
   `CAP_BPF`; assert `lsm_list_modules()` (6.8) contains `bpf` and `landlock`.
   [BPF token](https://lwn.net/Articles/959350/),
   [bpf_path_d_path](https://docs.ebpf.io/linux/kfuncs/bpf_path_d_path/)
9. **Per-netns sysctls** from the shim after `setns`: `ip_unprivileged_port_start
   =1024`, `disable_ipv6=1` unless policy allows v6. Host-level in `rauha setup`:
   `kernel.io_uring_disabled=1`, `kernel.unprivileged_bpf_disabled=2`,
   `yama.ptrace_scope=2`.

## Suggested sequencing

1. Land the crun executor (create → pidfd → enroll → start) on `main` with a
   hostile-image probe that proves nothing runs before enrollment — this closes
   `obl_executor` honestly and is the precondition for `obl_hardening`.
2. Items 1–4 above (cgroup basics, safe rootfs, pidfd, seccomp): closes
   `syscalls.deny`; all ≤5.14 so no baseline change.
3. Landlock + userns + cgroup device BPF: closes `writable_paths` and
   `devices.allowed`; `admit_linux_policy` flips them from unsupported to
   enforced, kernel-gated.
4. Receipt as in-toto predicate over what `zone verify --json` already knows;
   then the containerd sandbox controller carrying it.
5. microVM experiment via `run.oci.handler=krun` (libkrun) — the same bundle,
   one annotation, KVM required — the cheapest honest `obl_tier` measurement.
