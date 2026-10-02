//! Ed25519 node identity, not a tunnel/session cipher.

use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    fmt, fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    str::FromStr,
};
use zeroize::Zeroizing;

const KEY_MAGIC: &[u8; 8] = b"GGBKEY1\n";

/// The complete Ed25519 public key; short display names are never identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NodeId([u8; 32]);

// Byte ordering is identical to NodeId's derived ordering. Lookups return an
// already validated identity, never construct an unchecked key from wire bytes.
impl Borrow<[u8; 32]> for NodeId {
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

impl NodeId {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 public key")?;
        ensure!(!key.is_weak(), "weak Ed25519 public key");
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Control-record signatures are domain-separated. No arbitrary key conversion.
    pub fn verify(&self, context: &str, payload: &[u8], signature: &[u8; 64]) -> Result<()> {
        let digest = blake3::derive_key(context, payload);
        VerifyingKey::from_bytes(&self.0)?
            .verify_strict(&digest, &Signature::from_bytes(signature))
            .context("invalid control-record signature")
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for NodeId {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        ensure!(
            value.len() == 64 && value.is_ascii(),
            "public key must contain 64 hexadecimal characters"
        );
        let mut bytes = [0; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
                .context("public key must be hexadecimal")?;
        }
        Self::from_bytes(bytes)
    }
}

impl TryFrom<String> for NodeId {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}
impl From<NodeId> for String {
    fn from(value: NodeId) -> Self {
        value.to_string()
    }
}

/// Deliberately has no Debug, Clone or Serialize implementation.
pub struct Identity(SigningKey);

impl Identity {
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut())
            .map_err(|error| anyhow::anyhow!("OS randomness: {error}"))?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    pub fn node_id(&self) -> NodeId {
        NodeId(self.0.verifying_key().to_bytes())
    }

    pub fn sign(&self, context: &str, payload: &[u8]) -> [u8; 64] {
        self.0
            .sign(&blake3::derive_key(context, payload))
            .to_bytes()
    }

    /// Atomic, no-clobber publication in a caller-owned directory, with mode 0600.
    pub fn save_new(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(KEY_MAGIC)?;
        file.write_all(self.0.as_bytes())?;
        file.as_file().sync_all()?;
        file.persist_noclobber(path)
            .map_err(|error| error.error)
            .with_context(|| {
                format!(
                    "create identity {} (existing files are preserved)",
                    path.display()
                )
            })?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("open identity {}", path.display()))?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "identity must be a regular file");
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "identity permissions must exclude group and other users (chmod 600)"
        );
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(41).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() == 40 && &bytes[..8] == KEY_MAGIC,
            "invalid identity file format"
        );
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(&bytes[8..]);
        Ok(Self(SigningKey::from_bytes(&seed)))
    }
}

#[cfg(test)]
pub(crate) fn test_id(seed: u8) -> NodeId {
    NodeId(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_roundtrip_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let original = Identity::generate().unwrap();
        original.save_new(&path).unwrap();
        assert_eq!(Identity::load(&path).unwrap().node_id(), original.node_id());
        assert!(Identity::generate().unwrap().save_new(&path).is_err());
        assert_eq!(Identity::load(&path).unwrap().node_id(), original.node_id());
    }

    #[test]
    fn signatures_bind_domain_payload_and_identity() {
        let key = Identity::generate().unwrap();
        let sig = key.sign("nnlan.test.v1", b"record");
        assert!(
            key.node_id()
                .verify("nnlan.test.v1", b"record", &sig)
                .is_ok()
        );
        assert!(key.node_id().verify("other", b"record", &sig).is_err());
        assert!(
            key.node_id()
                .verify("nnlan.test.v1", b"changed", &sig)
                .is_err()
        );
        assert!(
            test_id(42)
                .verify("nnlan.test.v1", b"record", &sig)
                .is_err()
        );
    }

    #[test]
    fn rejects_weak_keys_bad_files_and_symlinks() {
        assert!(NodeId::from_bytes([0; 32]).is_err());
        assert!("zz".repeat(32).parse::<NodeId>().is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let key = Identity::generate().unwrap();
        key.save_new(&path).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(Identity::load(&link).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Identity::load(&path).is_err());
        assert_eq!(
            key.node_id().to_string().parse::<NodeId>().unwrap(),
            key.node_id()
        );
    }
}
