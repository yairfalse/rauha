# Wasm isolation-tier probe

Measured 2026-08-27 in the locked `syva-dev` Lima gate with
`eval/wasm-tier-probe.sh`:

```text
crun=crun version 1.14.1
available=false
probe_us=2103
error=could not load `libwasmedge.so.0`: `libwasmedge.so.0: cannot open shared object file: No such file or directory`
```

The probe used crun's experimental `run.oci.handler=wasm` path and a minimal
41-byte WebAssembly `_start` module. The same gate measured Rauha's native OCI
create/enroll/start handoff at 13 ms average (`n=5`). crun advertises
`+WASM:wasmedge`, but the locked host cannot execute the module because its
declared handler library is absent.

Decision: do not expose a Wasm tier yet. First package and pin WasmEdge in the
locked gate, then require the Wasm path to preserve Rauha policy admission and
signed receipt semantics. Re-run this probe and promote the tier only if it
works and materially improves on the native handoff. This follows crun's
[experimental handler contract](https://github.com/containers/crun/blob/main/crun.1.md#runocihandlerhandler)
without adding another runtime abstraction to Rauha.
