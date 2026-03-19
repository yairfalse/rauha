//! Structured output for human and machine consumers.
//!
//! Every command uses `print()` to emit results. In human mode, the caller
//! provides a closure that prints formatted text. In JSON mode, the value
//! is serialized to stdout as a single JSON object per line.

use serde::Serialize;

/// Output mode selected by the global `--json` flag.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OutputMode {
    Human,
    Json,
}

/// Print a result in the appropriate format.
///
/// - `Human`: calls the closure for free-form text output.
/// - `Json`: serializes `value` as a single-line JSON object to stdout.
pub fn print<T: Serialize>(mode: OutputMode, value: &T, human: impl FnOnce()) {
    match mode {
        OutputMode::Human => human(),
        OutputMode::Json => {
            println!("{}", serde_json::to_string(value).expect("serialize output"));
        }
    }
}

/// Print a JSON error to stdout (for --json mode) and exit with code 1.
pub fn print_error(message: &str) {
    let err = serde_json::json!({
        "ok": false,
        "error": message,
    });
    println!("{err}");
}

// ── Serializable response types ──────────────────────────────────────
//
// These are the CLI's output contract — stable, decoupled from proto types.
// AI agents and scripts can rely on these field names.

#[derive(Serialize)]
pub struct ZoneCreated {
    pub ok: bool,
    pub name: String,
    pub id: String,
}

#[derive(Serialize)]
pub struct ZoneInfo {
    pub name: String,
    pub zone_type: String,
    pub state: String,
    pub container_count: u32,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ZoneList {
    pub ok: bool,
    pub zones: Vec<ZoneInfo>,
}

#[derive(Serialize)]
pub struct ZoneDeleted {
    pub ok: bool,
    pub name: String,
}

#[derive(Serialize)]
pub struct ZoneInspect {
    pub ok: bool,
    pub name: String,
    pub id: String,
    pub zone_type: String,
    pub state: String,
    pub container_count: u32,
    pub created_at: String,
    pub policy_toml: String,
}

#[derive(Serialize)]
pub struct IsolationCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct ZoneVerification {
    pub ok: bool,
    pub zone: String,
    pub isolated: bool,
    pub checks: Vec<IsolationCheck>,
}

#[derive(Serialize)]
pub struct ContainerCreated {
    pub ok: bool,
    pub container_id: String,
    pub name: String,
    pub zone: String,
    pub image: String,
}

#[derive(Serialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub pid: u32,
}

#[derive(Serialize)]
pub struct ContainerList {
    pub ok: bool,
    pub containers: Vec<ContainerInfo>,
}

#[derive(Serialize)]
pub struct ContainerStopped {
    pub ok: bool,
    pub container_id: String,
}

#[derive(Serialize)]
pub struct ContainerDeleted {
    pub ok: bool,
    pub container_id: String,
}

#[derive(Serialize)]
pub struct ImagePulled {
    pub ok: bool,
    pub reference: String,
}

#[derive(Serialize)]
pub struct ImageInfo {
    pub reference: String,
    pub digest: String,
    pub size: u64,
    pub tags: Vec<String>,
}

#[derive(Serialize)]
pub struct ImageList {
    pub ok: bool,
    pub images: Vec<ImageInfo>,
}

#[derive(Serialize)]
pub struct ImageRemoved {
    pub ok: bool,
    pub reference: String,
}

#[derive(Serialize)]
pub struct ImageInspect {
    pub ok: bool,
    pub reference: String,
    pub digest: String,
    pub size: u64,
    pub config: serde_json::Value,
}
