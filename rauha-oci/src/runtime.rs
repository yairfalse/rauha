use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, MountBuilder, ProcessBuilder,
    RootBuilder, Spec, SpecBuilder,
};
use rauha_common::container::ContainerSpec;
use rauha_common::error::RauhaError;
use rauha_common::zone::ZonePolicy;

use crate::distribution::OciImageConfig;

/// Generate an OCI runtime spec by merging image config, container spec, and zone policy.
pub fn generate_spec(
    image_config: &OciImageConfig,
    container_spec: &ContainerSpec,
    _policy: &ZonePolicy,
    rootfs_path: &str,
) -> Result<Spec, RauhaError> {
    let img = image_config.config.as_ref();

    // Determine command: container spec overrides image defaults.
    let args = if !container_spec.command.is_empty() {
        container_spec.command.clone()
    } else {
        let mut cmd = Vec::new();
        if let Some(ep) = img.and_then(|c| c.entrypoint.as_ref()) {
            cmd.extend(ep.iter().cloned());
        }
        if let Some(c) = img.and_then(|c| c.cmd.as_ref()) {
            cmd.extend(c.iter().cloned());
        }
        if cmd.is_empty() {
            vec!["/bin/sh".to_string()]
        } else {
            cmd
        }
    };

    // Merge environment variables: image defaults + container overrides.
    let mut env: Vec<String> = img
        .and_then(|c| c.env.as_ref())
        .cloned()
        .unwrap_or_default();
    for (k, v) in &container_spec.env {
        // Override existing or add new.
        let key_prefix = format!("{k}=");
        if let Some(pos) = env.iter().position(|e| e.starts_with(&key_prefix)) {
            env[pos] = format!("{k}={v}");
        } else {
            env.push(format!("{k}={v}"));
        }
    }
    // Ensure PATH is set.
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }

    // Working directory.
    let cwd = container_spec
        .working_dir
        .as_deref()
        .or_else(|| img.and_then(|c| c.working_dir.as_deref()))
        .unwrap_or("/")
        .to_string();

    // Build process spec.
    let process = ProcessBuilder::default()
        .args(args)
        .env(env)
        .cwd(cwd)
        .terminal(false)
        .build()
        .map_err(|e| RauhaError::BackendError(format!("failed to build process spec: {e}")))?;

    // Root filesystem.
    let root = RootBuilder::default()
        .path(rootfs_path)
        .readonly(false)
        .build()
        .map_err(|e| RauhaError::BackendError(format!("failed to build root spec: {e}")))?;

    // Standard container mounts.
    let mounts = vec![
        MountBuilder::default()
            .destination("/proc")
            .typ("proc")
            .source("proc")
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/sys")
            .typ("sysfs")
            .source("sysfs")
            .options(vec!["nosuid".into(), "noexec".into(), "nodev".into(), "ro".into()])
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/dev")
            .typ("tmpfs")
            .source("tmpfs")
            .options(vec!["nosuid".into(), "strictatime".into(), "mode=755".into(), "size=65536k".into()])
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/dev/pts")
            .typ("devpts")
            .source("devpts")
            .options(vec![
                "nosuid".into(),
                "noexec".into(),
                "newinstance".into(),
                "ptmxmode=0666".into(),
                "mode=0620".into(),
            ])
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/dev/shm")
            .typ("tmpfs")
            .source("shm")
            .options(vec!["nosuid".into(), "noexec".into(), "nodev".into(), "mode=1777".into(), "size=65536k".into()])
            .build()
            .unwrap(),
    ];

    // Linux namespaces: the zone already has these, the shim enters them via setns.
    let ns_types = [
        LinuxNamespaceType::Pid,
        LinuxNamespaceType::Mount,
        LinuxNamespaceType::Network,
        LinuxNamespaceType::Uts,
        LinuxNamespaceType::Ipc,
    ];
    let namespaces: Vec<_> = ns_types
        .into_iter()
        .map(|typ| {
            LinuxNamespaceBuilder::default()
                .typ(typ)
                .build()
                .unwrap()
        })
        .collect();

    let linux = LinuxBuilder::default()
        .namespaces(namespaces)
        .build()
        .map_err(|e| RauhaError::BackendError(format!("failed to build linux spec: {e}")))?;

    let spec = SpecBuilder::default()
        .version("1.0.2")
        .root(root)
        .process(process)
        .mounts(mounts)
        .linux(linux)
        .hostname(container_spec.name.clone())
        .build()
        .map_err(|e| RauhaError::BackendError(format!("failed to build OCI spec: {e}")))?;

    Ok(spec)
}
