use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum RauhaError {
    #[error("zone not found: {0}")]
    ZoneNotFound(String),

    #[error("zone already exists: {0}")]
    ZoneAlreadyExists(String),

    #[error("container not found: {0}")]
    ContainerNotFound(Uuid),

    #[error("container already exists in zone: {name} in {zone}")]
    ContainerAlreadyExists { name: String, zone: String },

    #[error("zone is not empty, contains {count} container(s)")]
    ZoneNotEmpty { count: usize },

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("isolation backend error: {0}")]
    BackendError(String),

    #[error("image not found: {0}")]
    ImageNotFound(String),

    #[error("metadata store error: {0}")]
    MetadataError(String),

    #[error("image error: {0}")]
    ImageError(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("cross-zone access denied: {src} -> {dst}")]
    CrossZoneAccessDenied { src: String, dst: String },

    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("eBPF error: {message}")]
    EbpfError {
        message: String,
        /// What the user should try to fix this.
        hint: String,
    },

    #[error("cgroup error: {message}")]
    CgroupError {
        message: String,
        hint: String,
    },

    #[error("namespace error: {message}")]
    NamespaceError {
        message: String,
        hint: String,
    },

    #[error("network error: {message}")]
    NetworkError {
        message: String,
        hint: String,
    },

    #[error("image pull error: {reference}: {message}")]
    ImagePullError { reference: String, message: String },

    #[error("content store error: {message}")]
    ContentError { message: String },

    #[error("shim error for zone {zone}: {message}")]
    ShimError { zone: String, message: String },

    #[error("rootfs error: {message}")]
    RootfsError { message: String },

    #[error("container exec error for {container}: {message}")]
    ContainerExecError { container: String, message: String },

    #[error("kernel too old: requires {required}, found {found}")]
    KernelTooOld {
        required: String,
        found: String,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, RauhaError>;
