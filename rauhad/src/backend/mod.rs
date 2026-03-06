// Re-export the trait from common.
pub use rauha_common::backend::IsolationBackend;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

/// Create the platform-appropriate isolation backend.
pub fn create_backend(root: &str) -> rauha_common::error::Result<Box<dyn IsolationBackend>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxBackend::new(root)?))
    }

    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::MacosBackend::new(root)?))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(rauha_common::error::RauhaError::UnsupportedPlatform(
            std::env::consts::OS.into(),
        ))
    }
}
