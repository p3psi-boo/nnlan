//! Atomic sequence reservations survive crashes; the identity lock spans daemon life.
use crate::{config::Config, identity::NodeId};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    node: NodeId,
    reserved: u64,
    probe: u32,
}

pub struct State {
    stored: Stored,
    next: u64,
    path: PathBuf,
    _lock: File,
}
impl State {
    /// Exclusivity without reading or reserving sequence state (early boot guard).
    pub fn lock(config: &Config, config_path: &Path) -> Result<File> {
        let identity = config.identity_path(config_path);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(identity.with_extension("lock"))?;
        ensure!(
            lock.metadata()?.is_file(),
            "identity lock is not a regular file"
        );
        lock.try_lock()
            .context("another daemon is using this identity")?;
        Ok(lock)
    }
    pub fn open(config: &Config, config_path: &Path, node: NodeId) -> Result<Self> {
        let lock = Self::lock(config, config_path)?;
        let identity = config.identity_path(config_path);
        let path = identity.with_extension("state.json");
        let stored = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => {
                ensure!(
                    file.metadata()?.is_file() && file.metadata()?.len() <= 4096,
                    "invalid state file"
                );
                let mut bytes = vec![];
                file.take(4097).read_to_end(&mut bytes)?;
                let stored: Stored = serde_json::from_slice(&bytes)
                    .context("invalid state; refusing to reset sequence/probe")?;
                ensure!(stored.node == node, "state belongs to another identity");
                stored
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Stored {
                node,
                reserved: 0,
                probe: 0,
            },
            Err(e) => return Err(e.into()),
        };
        let next = stored
            .reserved
            .checked_add(1)
            .context("sequence exhausted")?;
        let mut result = Self {
            stored,
            next,
            path,
            _lock: lock,
        };
        result.reserve()?;
        Ok(result)
    }
    fn reserve(&mut self) -> Result<()> {
        self.stored.reserved = self
            .stored
            .reserved
            .checked_add(10_000)
            .context("sequence exhausted")?;
        self.persist()
    }
    fn persist(&self) -> Result<()> {
        let parent = self.path.parent().unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&serde_json::to_vec(&self.stored)?)?;
        file.as_file().sync_all()?;
        file.persist(&self.path).map_err(|e| e.error)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
    pub fn sequence(&mut self) -> Result<u64> {
        if self.next >= self.stored.reserved {
            self.reserve()?;
        }
        let next = self.next;
        self.next = self.next.checked_add(1).context("sequence exhausted")?;
        Ok(next)
    }
    pub fn probe(&self) -> u32 {
        self.stored.probe
    }
    pub fn set_probe(&mut self, probe: u32) -> Result<()> {
        self.stored.probe = probe;
        self.persist()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    #[test]
    fn guard_lock_never_reads_or_changes_sequence_state() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("nnlan.toml");
        let config = Config::default();
        let state_path = config
            .identity_path(&config_path)
            .with_extension("state.json");
        std::fs::write(&state_path, b"damaged state").unwrap();
        let lock = State::lock(&config, &config_path).unwrap();
        assert!(State::lock(&config, &config_path).is_err());
        assert!(
            State::open(
                &config,
                &config_path,
                Identity::generate().unwrap().node_id()
            )
            .is_err()
        );
        drop(lock);
        assert!(State::lock(&config, &config_path).is_ok());
        assert_eq!(std::fs::read(state_path).unwrap(), b"damaged state");
    }

    #[test]
    fn restart_skips_reserved_sequences_and_lock_is_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("nnlan.toml");
        let config = Config::default();
        let node = Identity::generate().unwrap().node_id();
        let mut state = State::open(&config, &config_path, node).unwrap();
        assert!(State::open(&config, &config_path, node).is_err());
        let first = state.sequence().unwrap();
        state.set_probe(19).unwrap();
        drop(state);
        let mut resumed = State::open(&config, &config_path, node).unwrap();
        assert!(resumed.sequence().unwrap() >= first + 10_000);
        assert_eq!(resumed.probe(), 19);
    }
}
