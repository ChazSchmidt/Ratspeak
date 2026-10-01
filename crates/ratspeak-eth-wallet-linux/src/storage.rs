use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    os::fd::{AsFd, OwnedFd},
    path::Path,
};

use ring::rand::{SecureRandom, SystemRandom};
use rustix::{
    fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags, fstat, open, openat},
    process::geteuid,
};

use crate::{MAX_VAULT_BYTES, VaultError};

const LOCK_FILE: &str = ".ratspeak-ethereum-wallet.lock";
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

pub(crate) struct ParentDirectory(OwnedFd);
pub(crate) struct VaultLock {
    _fd: OwnedFd,
}

pub(crate) fn ensure_private_parent(path: &Path) -> Result<(), VaultError> {
    match open_private_parent(path) {
        Ok(_) => return Ok(()),
        Err(VaultError::MissingParent) => {}
        Err(error) => return Err(error),
    }
    match fs::mkdir(path, Mode::from_raw_mode(PRIVATE_DIRECTORY_MODE)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(os_error("create vault parent", error)),
    }
    open_private_parent(path).map(|_| ())
}

pub(crate) fn open_private_parent(path: &Path) -> Result<ParentDirectory, VaultError> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| match error {
        rustix::io::Errno::NOENT => VaultError::MissingParent,
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => VaultError::InsecureParent,
        other => os_error("open vault parent", other),
    })?;
    let stat = fstat(&fd).map_err(|error| os_error("inspect vault parent", error))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o077 != 0
    {
        return Err(VaultError::InsecureParent);
    }
    Ok(ParentDirectory(fd))
}

pub(crate) fn lock_shared(parent: &ParentDirectory) -> Result<VaultLock, VaultError> {
    lock(parent, FlockOperation::NonBlockingLockShared)
}

pub(crate) fn lock_exclusive(parent: &ParentDirectory) -> Result<VaultLock, VaultError> {
    lock(parent, FlockOperation::NonBlockingLockExclusive)
}

fn lock(parent: &ParentDirectory, operation: FlockOperation) -> Result<VaultLock, VaultError> {
    let fd = openat(
        &parent.0,
        LOCK_FILE,
        OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::from_raw_mode(PRIVATE_FILE_MODE),
    )
    .map_err(|error| match error {
        rustix::io::Errno::LOOP => VaultError::InsecureFile,
        other => os_error("open vault lock", other),
    })?;
    validate_private_file(&fd)?;
    fs::flock(&fd, operation).map_err(|error| match error {
        rustix::io::Errno::AGAIN => VaultError::Busy,
        other => os_error("lock vault", other),
    })?;
    Ok(VaultLock { _fd: fd })
}

pub(crate) fn read_vault(
    parent: &ParentDirectory,
    file_name: &OsStr,
) -> Result<Vec<u8>, VaultError> {
    let fd = openat(
        &parent.0,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| match error {
        rustix::io::Errno::NOENT => VaultError::NotFound,
        rustix::io::Errno::LOOP => VaultError::InsecureFile,
        other => os_error("open vault", other),
    })?;
    let stat = validate_private_file(&fd)?;
    if stat.st_size < 0 || stat.st_size as u64 > MAX_VAULT_BYTES as u64 {
        return Err(VaultError::OversizedVault);
    }
    let expected_len = stat.st_size as usize;
    let mut file = File::from(fd);
    let mut encoded = Vec::with_capacity(expected_len.min(MAX_VAULT_BYTES));
    Read::by_ref(&mut file)
        .take((MAX_VAULT_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|error| io_error("read vault", error))?;
    if encoded.len() > MAX_VAULT_BYTES {
        return Err(VaultError::OversizedVault);
    }
    if encoded.len() != expected_len {
        return Err(VaultError::InvalidFormat);
    }
    Ok(encoded)
}

pub(crate) fn install_new(
    parent: &ParentDirectory,
    file_name: &OsStr,
    encoded: &[u8],
) -> Result<(), VaultError> {
    atomic_write(parent, file_name, encoded, true)
}

pub(crate) fn replace(
    parent: &ParentDirectory,
    file_name: &OsStr,
    encoded: &[u8],
) -> Result<(), VaultError> {
    atomic_write(parent, file_name, encoded, false)
}

fn atomic_write(
    parent: &ParentDirectory,
    file_name: &OsStr,
    encoded: &[u8],
    no_replace: bool,
) -> Result<(), VaultError> {
    if encoded.len() > MAX_VAULT_BYTES {
        return Err(VaultError::OversizedVault);
    }
    let temp_name = random_temp_name()?;
    let result = (|| {
        let fd = openat(
            &parent.0,
            &temp_name,
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(PRIVATE_FILE_MODE),
        )
        .map_err(|error| os_error("create temporary vault", error))?;
        validate_private_file(&fd)?;
        let mut file = File::from(fd);
        file.write_all(encoded)
            .map_err(|error| io_error("write temporary vault", error))?;
        file.sync_all()
            .map_err(|error| io_error("sync temporary vault", error))?;
        drop(file);

        if no_replace {
            fs::renameat_with(
                &parent.0,
                &temp_name,
                &parent.0,
                file_name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|error| match error {
                rustix::io::Errno::EXIST => VaultError::AlreadyExists,
                other => os_error("install vault", other),
            })?;
        } else {
            fs::renameat(&parent.0, &temp_name, &parent.0, file_name)
                .map_err(|error| os_error("replace vault", error))?;
        }

        fs::fsync(&parent.0).map_err(|_| VaultError::DurabilityUncertain)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::unlinkat(&parent.0, &temp_name, AtFlags::empty());
    }
    result
}

fn validate_private_file(fd: impl AsFd) -> Result<rustix::fs::Stat, VaultError> {
    let stat = fstat(fd).map_err(|error| os_error("inspect private file", error))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != geteuid().as_raw()
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != PRIVATE_FILE_MODE
    {
        return Err(VaultError::InsecureFile);
    }
    Ok(stat)
}

fn random_temp_name() -> Result<OsString, VaultError> {
    let mut random = [0u8; 16];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| VaultError::Randomness)?;
    let mut name = String::with_capacity(14 + random.len() * 2);
    name.push_str(".wallet.tmp.");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(name.into())
}

fn os_error(operation: &'static str, source: rustix::io::Errno) -> VaultError {
    VaultError::Io {
        operation,
        source: source.into(),
    }
}

fn io_error(operation: &'static str, source: std::io::Error) -> VaultError {
    VaultError::Io { operation, source }
}
