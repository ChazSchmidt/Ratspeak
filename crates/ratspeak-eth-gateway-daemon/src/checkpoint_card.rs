//! Native operator tool for producing an untrusted RSETHCF1 checkpoint card.
//!
//! The operator supplies the weak-subjectivity root and epoch out of band.
//! Beacon responses are used only as evidence to verify the bootstrap from
//! that root; they cannot select the root, epoch, or output path.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ratspeak_eth_gateway::{
    BeaconCheckpointCard, BeaconConsensusClient, BeaconHttpPolicy, BeaconOperatorAuthorization,
    HttpEndpointPolicy, ReqwestBeaconHttpTransport, SystemUnixClock,
};
use ratspeak_eth_verifier::MAX_MANUAL_CHECKPOINT_FILE_BYTES;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::DaemonError;

const MAX_AUTHORIZATION_BYTES: u64 = 16 * 1024;
const MAX_BEACON_ENDPOINT_BYTES: usize = 8 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCardConfig {
    pub checkpoint_root: String,
    pub checkpoint_epoch: u64,
    pub beacon_rpc_endpoint: String,
    #[serde(default)]
    pub authorization_path: Option<PathBuf>,
    pub output_path: PathBuf,
}

impl std::fmt::Debug for CheckpointCardConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CheckpointCardConfig")
            .field("checkpoint_epoch", &self.checkpoint_epoch)
            .field("output_path_present", &true)
            .finish_non_exhaustive()
    }
}

/// Runs the card producer from an absolute, private configuration file.
pub fn run(config_path: &Path) -> Result<(), DaemonError> {
    if !config_path.is_absolute() {
        return Err(DaemonError::InvalidConfiguration);
    }
    let config = read_config(config_path)?;
    let root = parse_root(&config.checkpoint_root)?;
    if root == [0; 32] || config.checkpoint_epoch == 0 {
        return Err(DaemonError::InvalidConfiguration);
    }
    if !config.output_path.is_absolute() {
        return Err(DaemonError::InvalidConfiguration);
    }
    validate_beacon_endpoint_length(&config.beacon_rpc_endpoint)?;
    let authorization = config
        .authorization_path
        .as_deref()
        .map(|path| {
            if !path.is_absolute() {
                return Err(DaemonError::InvalidConfiguration);
            }
            read_authorization(path)
        })
        .transpose()?;
    let policy = BeaconHttpPolicy::conservative();
    let transport = ReqwestBeaconHttpTransport::new(
        &config.beacon_rpc_endpoint,
        authorization,
        // Card production never permits cleartext, including loopback. A
        // local TLS terminator can be used for development instead.
        HttpEndpointPolicy::HttpsOnly,
        policy,
    )
    .map_err(|_| DaemonError::ProviderUnavailable)?;
    let mut client = BeaconConsensusClient::new(
        ratspeak_eth_verifier::BeaconCheckpointRoot::sepolia(root),
        transport,
        SystemUnixClock,
        policy,
    )
    .map_err(|_| DaemonError::ProviderUnavailable)?;
    let card = client
        .acquire_checkpoint_card(config.checkpoint_epoch)
        .map_err(|_| DaemonError::ProviderUnavailable)?;
    write_card(&config.output_path, &card)?;
    println!(
        "checkpoint card written: epoch={} root=0x{} bytes={} fingerprint=0x{}",
        card.checkpoint_epoch(),
        hex_string(&card.checkpoint_root()),
        card.bytes().len(),
        hex_string(&card.fingerprint()),
    );
    Ok(())
}

fn read_config(path: &Path) -> Result<CheckpointCardConfig, DaemonError> {
    let bytes = read_private_regular_file(path, 256 * 1024)?;
    serde_json::from_slice(&bytes).map_err(|_| DaemonError::InvalidConfiguration)
}

fn read_authorization(path: &Path) -> Result<BeaconOperatorAuthorization, DaemonError> {
    let bytes = Zeroizing::new(read_private_regular_file(path, MAX_AUTHORIZATION_BYTES)?);
    let value = std::str::from_utf8(&bytes).map_err(|_| DaemonError::ProviderUnavailable)?;
    BeaconOperatorAuthorization::parse(value.trim()).map_err(|_| DaemonError::ProviderUnavailable)
}

fn write_card(path: &Path, card: &BeaconCheckpointCard) -> Result<(), DaemonError> {
    write_card_bytes(path, card.bytes(), || {})
}

fn write_card_bytes(
    path: &Path,
    bytes: &[u8],
    after_sync: impl FnOnce(),
) -> Result<(), DaemonError> {
    if path.parent().is_none() {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    ensure_private_parent(path)?;
    if bytes.is_empty() || bytes.len() > MAX_MANUAL_CHECKPOINT_FILE_BYTES {
        return Err(DaemonError::InvalidConfiguration);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    let opened = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return Err(DaemonError::InvalidFilesystemBoundary),
    };
    let result = file.write_all(bytes).and_then(|_| file.sync_all());
    after_sync();
    let descriptor = file.metadata();
    let entry = std::fs::symlink_metadata(path);
    let valid = result.is_ok()
        && descriptor.as_ref().is_ok_and(|metadata| {
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && metadata.permissions().mode() & 0o7777 == 0o600
                && metadata.len() == bytes.len() as u64
        })
        && entry.as_ref().is_ok_and(|metadata| {
            !metadata.file_type().is_symlink()
                && metadata.is_file()
                && same_file(metadata, &opened)
                && metadata.len() == bytes.len() as u64
        });
    if !valid {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    let parent_sync = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path.parent().unwrap())
        .and_then(|directory| directory.sync_all());
    if parent_sync.is_err() {
        // Leave the failed create_new artifact in place for explicit operator
        // cleanup. Never unlink by pathname after an attacker may have
        // replaced the directory entry.
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    drop(file);
    Ok(())
}

fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
        && left.permissions().mode() & 0o7777 == right.permissions().mode() & 0o7777
}

fn read_private_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, DaemonError> {
    ensure_private_parent(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    let before = validate_private_file(&file)?;
    if before.len() > maximum {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    let after = validate_private_file(&file)?;
    if bytes.len() as u64 > maximum
        || bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    Ok(bytes)
}

fn validate_private_file(file: &File) -> Result<std::fs::Metadata, DaemonError> {
    let metadata = file
        .metadata()
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7177 != 0
    {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    Ok(metadata)
}

fn ensure_private_parent(path: &Path) -> Result<(), DaemonError> {
    let parent = path
        .parent()
        .ok_or(DaemonError::InvalidFilesystemBoundary)?;
    let metadata =
        std::fs::symlink_metadata(parent).map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    if parent
        .canonicalize()
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?
        != parent
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    Ok(())
}

fn parse_root(value: &str) -> Result<[u8; 32], DaemonError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|_| DaemonError::InvalidConfiguration)?;
    bytes
        .try_into()
        .map_err(|_| DaemonError::InvalidConfiguration)
}

fn validate_beacon_endpoint_length(value: &str) -> Result<(), DaemonError> {
    if value.is_empty() || value.len() > MAX_BEACON_ENDPOINT_BYTES {
        return Err(DaemonError::InvalidConfiguration);
    }
    Ok(())
}

fn hex_string(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn output_is_create_new_and_rejects_existing_or_symlink() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("card.bin");
        write_card_bytes(&path, b"card", || {}).unwrap();
        assert!(write_card_bytes(&path, b"again", || {}).is_err());

        let link = directory.path().join("link.bin");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(write_card_bytes(&link, b"card", || {}).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"card");
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn replacement_after_sync_is_rejected_without_deleting_replacement() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("card.bin");
        let replacement = directory.path().join("replacement.bin");
        std::fs::write(&replacement, b"replacement").unwrap();
        let result = write_card_bytes(&path, b"card", || {
            std::fs::rename(&replacement, &path).unwrap();
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    }

    #[test]
    fn private_inputs_reject_all_special_permission_bits() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("private");
        std::fs::write(&path, b"private").unwrap();
        for mode in [0o2600, 0o4600, 0o1600, 0o700] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let file = OpenOptions::new().read(true).open(&path).unwrap();
            assert!(validate_private_file(&file).is_err(), "mode {mode:o}");
        }
    }

    #[test]
    fn private_parent_requires_exact_0700_without_special_bits() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("card.bin");
        for mode in [0o701, 0o755, 0o1700, 0o2700, 0o4700] {
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(mode))
                .unwrap();
            assert!(ensure_private_parent(&path).is_err(), "mode {mode:o}");
        }
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(ensure_private_parent(&path).is_ok());
    }

    #[test]
    fn beacon_endpoint_is_bounded_before_url_parsing() {
        assert!(validate_beacon_endpoint_length("https://beacon.invalid").is_ok());
        assert!(validate_beacon_endpoint_length("").is_err());
        assert!(
            validate_beacon_endpoint_length(&"x".repeat(MAX_BEACON_ENDPOINT_BYTES + 1)).is_err()
        );
    }
}
