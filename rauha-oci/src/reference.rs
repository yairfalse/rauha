/// A parsed OCI image reference.
///
/// Examples:
/// - `nginx` → `registry-1.docker.io/library/nginx:latest`
/// - `myrepo/myimage:v2` → `registry-1.docker.io/myrepo/myimage:v2`
/// - `ghcr.io/owner/image@sha256:abc...` → as-is with digest
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub tag: String,
    pub digest: Option<String>,
}

impl ImageReference {
    /// Parse a Docker/OCI image reference string.
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("empty image reference".into());
        }

        // Split off @sha256:... digest if present.
        let (name_tag, digest) = if let Some(at_pos) = input.find('@') {
            let digest = &input[at_pos + 1..];
            if !digest.starts_with("sha256:") {
                return Err(format!("unsupported digest algorithm: {digest}"));
            }
            (&input[..at_pos], Some(digest.to_string()))
        } else {
            (input, None)
        };

        // Split into (registry+repo) and tag.
        let (name, tag) = if let Some(colon_pos) = name_tag.rfind(':') {
            // Only treat as tag if the colon is after the last '/'.
            // This avoids treating port numbers as tags (e.g. localhost:5000/image).
            let last_slash = name_tag.rfind('/').unwrap_or(0);
            if colon_pos > last_slash {
                (
                    &name_tag[..colon_pos],
                    name_tag[colon_pos + 1..].to_string(),
                )
            } else {
                (name_tag, "latest".to_string())
            }
        } else {
            (name_tag, "latest".to_string())
        };

        // Split into registry and repository.
        let (registry, repository) = if let Some(slash_pos) = name.find('/') {
            let first_part = &name[..slash_pos];
            // It's a registry if it contains a dot, colon, or is "localhost".
            if first_part.contains('.') || first_part.contains(':') || first_part == "localhost" {
                (first_part.to_string(), name[slash_pos + 1..].to_string())
            } else {
                // Docker Hub with explicit user/org.
                (
                    "registry-1.docker.io".to_string(),
                    name.to_string(),
                )
            }
        } else {
            // Bare name like "nginx" → docker.io/library/nginx.
            (
                "registry-1.docker.io".to_string(),
                format!("library/{name}"),
            )
        };

        // Normalize docker.io → registry-1.docker.io.
        let registry = match registry.as_str() {
            "docker.io" | "index.docker.io" => "registry-1.docker.io".to_string(),
            _ => registry,
        };

        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// Canonical reference string for display/storage.
    pub fn to_string_canonical(&self) -> String {
        if let Some(ref digest) = self.digest {
            format!("{}/{}@{}", self.registry, self.repository, digest)
        } else {
            format!("{}/{}:{}", self.registry, self.repository, self.tag)
        }
    }
}

impl std::fmt::Display for ImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string_canonical())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_name() {
        let r = ImageReference::parse("nginx").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/nginx");
        assert_eq!(r.tag, "latest");
        assert_eq!(r.digest, None);
    }

    #[test]
    fn parse_with_tag() {
        let r = ImageReference::parse("alpine:3.19").unwrap();
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag, "3.19");
    }

    #[test]
    fn parse_with_namespace() {
        let r = ImageReference::parse("myuser/myimage:v2").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "myuser/myimage");
        assert_eq!(r.tag, "v2");
    }

    #[test]
    fn parse_full_reference() {
        let r = ImageReference::parse("ghcr.io/owner/repo:main").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "owner/repo");
        assert_eq!(r.tag, "main");
    }

    #[test]
    fn parse_with_digest() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let input = format!("nginx@{digest}");
        let r = ImageReference::parse(&input).unwrap();
        assert_eq!(r.digest.unwrap(), digest);
    }

    #[test]
    fn parse_localhost_registry() {
        let r = ImageReference::parse("localhost:5000/myimage:dev").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "myimage");
        assert_eq!(r.tag, "dev");
    }

    #[test]
    fn docker_io_normalization() {
        let r = ImageReference::parse("docker.io/library/nginx:latest").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
    }
}
