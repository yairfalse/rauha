use std::collections::HashMap;
use std::sync::Arc;

use crate::content::{ContentStore, Digest};
use crate::reference::ImageReference;
use rauha_common::error::RauhaError;

/// OCI manifest (simplified — we parse what we need).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciManifest {
    pub schema_version: u32,
    #[serde(default)]
    pub media_type: String,
    pub config: OciDescriptor,
    pub layers: Vec<OciDescriptor>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OciDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

/// OCI image config (the parts we need for container creation).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OciImageConfig {
    #[serde(default)]
    pub config: Option<OciImageConfigInner>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OciImageConfigInner {
    #[serde(default, rename = "Cmd")]
    pub cmd: Option<Vec<String>>,
    #[serde(default, rename = "Entrypoint")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default, rename = "Env")]
    pub env: Option<Vec<String>>,
    #[serde(default, rename = "WorkingDir")]
    pub working_dir: Option<String>,
    #[serde(default, rename = "User")]
    pub user: Option<String>,
}

/// OCI Distribution Spec client for pulling images from registries.
pub struct DistributionClient {
    content: Arc<ContentStore>,
    http: reqwest::Client,
    /// Token cache keyed by (registry, scope).
    tokens: tokio::sync::Mutex<HashMap<(String, String), String>>,
}

impl DistributionClient {
    pub fn new(content: Arc<ContentStore>) -> Self {
        Self {
            content,
            http: reqwest::Client::builder()
                .user_agent("rauha/0.1")
                .build()
                .expect("failed to build HTTP client"),
            tokens: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Pull and store a manifest, returning the parsed manifest.
    pub async fn pull_manifest(
        &self,
        reference: &ImageReference,
    ) -> Result<OciManifest, RauhaError> {
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            reference.registry, reference.repository, reference.tag
        );

        let body = self
            .authenticated_get(
                &url,
                &reference.registry,
                &reference.repository,
                &[
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                ],
            )
            .await?;

        // Store raw manifest in content store.
        let canonical = reference.to_string_canonical();
        self.content
            .put_manifest(&canonical, &body)
            .map_err(|e| RauhaError::ContentError {
                message: format!("failed to store manifest: {e}"),
            })?;

        serde_json::from_slice(&body).map_err(|e| RauhaError::ImagePullError {
            reference: canonical,
            message: format!("invalid manifest JSON: {e}"),
        })
    }

    /// Pull and store a blob (layer or config), with progress callback.
    pub async fn pull_blob<F>(
        &self,
        registry: &str,
        repository: &str,
        digest: &Digest,
        mut on_progress: F,
    ) -> Result<(), RauhaError>
    where
        F: FnMut(u64, u64),
    {
        // Skip if already present.
        if self.content.has_blob(digest) {
            return Ok(());
        }

        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            registry,
            repository,
            digest.as_str()
        );

        let resp = self
            .authenticated_get_response(&url, registry, repository)
            .await?;

        let total = resp.content_length().unwrap_or(0);
        let mut downloaded: u64 = 0;

        let bytes = {
            use futures_util::StreamExt;
            let mut body = Vec::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| RauhaError::ImagePullError {
                    reference: digest.to_string(),
                    message: format!("download error: {e}"),
                })?;
                downloaded += chunk.len() as u64;
                body.extend_from_slice(&chunk);
                on_progress(downloaded, total);
            }
            body
        };

        // Verify digest.
        if !digest.validate(&bytes) {
            return Err(RauhaError::ContentError {
                message: format!("digest mismatch for {digest}"),
            });
        }

        self.content
            .put_blob(&bytes)
            .map_err(|e| RauhaError::ContentError {
                message: format!("failed to store blob: {e}"),
            })?;

        Ok(())
    }

    /// GET with OCI auth challenge-response flow.
    async fn authenticated_get(
        &self,
        url: &str,
        registry: &str,
        repository: &str,
        accept: &[&str],
    ) -> Result<Vec<u8>, RauhaError> {
        let scope = format!("repository:{}:pull", repository);

        // Try with cached token first.
        if let Some(token) = self.get_cached_token(registry, &scope).await {
            let resp = self
                .http
                .get(url)
                .header("Accept", accept.join(", "))
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| RauhaError::ImagePullError {
                    reference: url.to_string(),
                    message: format!("request failed: {e}"),
                })?;

            if resp.status().is_success() {
                return resp.bytes().await.map(|b| b.to_vec()).map_err(|e| {
                    RauhaError::ImagePullError {
                        reference: url.to_string(),
                        message: format!("read body failed: {e}"),
                    }
                });
            }
        }

        // Initial request (may get 401).
        let resp = self
            .http
            .get(url)
            .header("Accept", accept.join(", "))
            .send()
            .await
            .map_err(|e| RauhaError::ImagePullError {
                reference: url.to_string(),
                message: format!("request failed: {e}"),
            })?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            let www_auth = resp
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let token = self.fetch_token(&www_auth, &scope).await?;
            self.cache_token(registry, &scope, &token).await;

            // Retry with token.
            let resp = self
                .http
                .get(url)
                .header("Accept", accept.join(", "))
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| RauhaError::ImagePullError {
                    reference: url.to_string(),
                    message: format!("retry request failed: {e}"),
                })?;

            if !resp.status().is_success() {
                return Err(RauhaError::ImagePullError {
                    reference: url.to_string(),
                    message: format!("HTTP {}", resp.status()),
                });
            }

            resp.bytes().await.map(|b| b.to_vec()).map_err(|e| {
                RauhaError::ImagePullError {
                    reference: url.to_string(),
                    message: format!("read body failed: {e}"),
                }
            })
        } else if resp.status().is_success() {
            resp.bytes().await.map(|b| b.to_vec()).map_err(|e| {
                RauhaError::ImagePullError {
                    reference: url.to_string(),
                    message: format!("read body failed: {e}"),
                }
            })
        } else {
            Err(RauhaError::ImagePullError {
                reference: url.to_string(),
                message: format!("HTTP {}", resp.status()),
            })
        }
    }

    /// GET a streaming response with auth.
    async fn authenticated_get_response(
        &self,
        url: &str,
        registry: &str,
        repository: &str,
    ) -> Result<reqwest::Response, RauhaError> {
        let scope = format!("repository:{}:pull", repository);

        // Try with cached token.
        if let Some(token) = self.get_cached_token(registry, &scope).await {
            let resp = self
                .http
                .get(url)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| RauhaError::ImagePullError {
                    reference: url.to_string(),
                    message: format!("request failed: {e}"),
                })?;

            if resp.status().is_success() {
                return Ok(resp);
            }
        }

        // Initial request.
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| RauhaError::ImagePullError {
                reference: url.to_string(),
                message: format!("request failed: {e}"),
            })?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            let www_auth = resp
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let token = self.fetch_token(&www_auth, &scope).await?;
            self.cache_token(registry, &scope, &token).await;

            let resp = self
                .http
                .get(url)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| RauhaError::ImagePullError {
                    reference: url.to_string(),
                    message: format!("retry failed: {e}"),
                })?;

            if !resp.status().is_success() {
                return Err(RauhaError::ImagePullError {
                    reference: url.to_string(),
                    message: format!("HTTP {}", resp.status()),
                });
            }

            Ok(resp)
        } else if resp.status().is_success() {
            Ok(resp)
        } else {
            Err(RauhaError::ImagePullError {
                reference: url.to_string(),
                message: format!("HTTP {}", resp.status()),
            })
        }
    }

    /// Parse `Www-Authenticate: Bearer realm="...",service="...",scope="..."` and fetch a token.
    async fn fetch_token(
        &self,
        www_authenticate: &str,
        scope: &str,
    ) -> Result<String, RauhaError> {
        let realm = extract_param(www_authenticate, "realm").unwrap_or_default();
        let service = extract_param(www_authenticate, "service").unwrap_or_default();

        if realm.is_empty() {
            return Err(RauhaError::ImagePullError {
                reference: String::new(),
                message: "no realm in Www-Authenticate header".into(),
            });
        }

        let url = format!("{realm}?service={service}&scope={scope}");

        let resp: serde_json::Value = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| RauhaError::ImagePullError {
                reference: url.clone(),
                message: format!("token request failed: {e}"),
            })?
            .json()
            .await
            .map_err(|e| RauhaError::ImagePullError {
                reference: url,
                message: format!("invalid token response: {e}"),
            })?;

        // Docker Hub returns "token", some registries return "access_token".
        resp.get("token")
            .or_else(|| resp.get("access_token"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| RauhaError::ImagePullError {
                reference: String::new(),
                message: "no token in auth response".into(),
            })
    }

    async fn get_cached_token(&self, registry: &str, scope: &str) -> Option<String> {
        self.tokens
            .lock()
            .await
            .get(&(registry.to_string(), scope.to_string()))
            .cloned()
    }

    async fn cache_token(&self, registry: &str, scope: &str, token: &str) {
        self.tokens
            .lock()
            .await
            .insert((registry.to_string(), scope.to_string()), token.to_string());
    }
}

/// Extract a parameter from a Bearer challenge header.
/// e.g., `Bearer realm="https://...",service="registry.docker.io"`
fn extract_param<'a>(header: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=\"");
    let start = header.find(&needle)? + needle.len();
    let end = header[start..].find('"')? + start;
    Some(&header[start..end])
}

// We need futures-util for StreamExt on the bytes stream.
// reqwest re-exports it, but we reference it explicitly for the streaming blob download.
mod futures_util {
    pub use tokio_stream::StreamExt;
}
