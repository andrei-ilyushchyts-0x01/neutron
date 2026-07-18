//! Owned, single-link, mode-private output files.
//!
//! Every path component is opened relative to a directory file descriptor with
//! `O_NOFOLLOW`. Publication then uses `renameat`/`linkat` against that pinned
//! parent descriptor, so a concurrent symlink replacement cannot redirect a
//! root-owned write outside the validated directory.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
use serde::Serialize;

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateFileMode {
    CreateNew,
    Overwrite,
    Append,
    Lock,
}

struct SecureParent {
    directory: File,
    display_path: PathBuf,
    target_name: CString,
}

pub(crate) struct PinnedPrivatePath {
    parent: SecureParent,
    display_path: PathBuf,
}

impl PinnedPrivatePath {
    pub(crate) fn new(path: &Path) -> Result<Self> {
        let parent = secure_parent(path)?;
        let metadata = parent.directory.metadata().with_context(|| {
            format!(
                "inspecting mode-private directory {}",
                parent.display_path.display()
            )
        })?;
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o077 != 0 {
            bail!(
                "private socket directory must have no group/world permissions: {}",
                parent.display_path.display()
            );
        }
        Ok(Self {
            parent,
            display_path: path.to_path_buf(),
        })
    }

    pub(crate) fn proc_path(&self) -> PathBuf {
        let mut path = PathBuf::from("/proc/self/fd");
        path.push(self.parent.directory.as_raw_fd().to_string());
        path.push(OsStr::from_bytes(self.parent.target_name.as_bytes()));
        path
    }

    pub(crate) fn stat(&self) -> Result<Option<libc::stat>> {
        metadata_at(&self.parent)
    }

    pub(crate) fn chmod(&self, mode: libc::mode_t) -> Result<()> {
        let result = unsafe {
            libc::fchmodat(
                self.parent.directory.as_raw_fd(),
                self.parent.target_name.as_ptr(),
                mode,
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
                .with_context(|| format!("chmod {:04o} {}", mode, self.display_path.display()))
        }
    }

    pub(crate) fn unlink(&self) -> Result<()> {
        unlink_at(&self.parent.directory, &self.parent.target_name)
            .with_context(|| format!("removing {}", self.display_path.display()))
    }
}

fn c_string(value: &OsStr, context: &str) -> Result<CString> {
    CString::new(value.as_bytes()).with_context(|| format!("{context} contains a NUL byte"))
}

fn open_starting_directory(absolute: bool) -> Result<File> {
    let path = if absolute { c"/" } else { c"." };
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("opening secure path anchor");
    }
    // SAFETY: `open` returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_directory_at(parent: &File, name: &OsStr, display: &Path) -> Result<File> {
    let name = c_string(name, "secure directory component")?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening secure directory component {}", display.display()));
    }
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn validate_directory(directory: &File, display: &Path) -> Result<()> {
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspecting secure output directory {}", display.display()))?;
    use std::os::unix::fs::MetadataExt as _;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        bail!(
            "secure output directory must be owned and non-writable by group/others: {}",
            display.display()
        );
    }
    Ok(())
}

fn validate_creation_directory(directory: &File, display: &Path) -> Result<()> {
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspecting secure creation directory {}", display.display()))?;
    use std::os::unix::fs::MetadataExt as _;
    let sticky = metadata.mode() & libc::S_ISVTX != 0;
    let writable = metadata.mode() & 0o022 != 0;
    let euid = unsafe { libc::geteuid() };
    let owned_safe = metadata.uid() == euid && (!writable || sticky);
    let root_sticky = metadata.uid() == 0 && sticky;
    if !metadata.is_dir() || (!owned_safe && !root_sticky) {
        bail!(
            "secure creation directory must be owned and protected or root-owned sticky: {}",
            display.display()
        );
    }
    Ok(())
}

fn open_directory_path(path: &Path) -> Result<File> {
    let mut directory = open_starting_directory(path.is_absolute())?;
    let mut walked = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    };
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                walked.push(name);
                directory = open_directory_at(&directory, name, &walked)?;
            }
            Component::ParentDir => {
                bail!(
                    "secure output paths must not contain '..': {}",
                    path.display()
                );
            }
            Component::Prefix(_) => bail!("unsupported secure output path: {}", path.display()),
        }
    }
    Ok(directory)
}

fn parent_parts(path: &Path) -> Result<(PathBuf, CString)> {
    let target = path
        .file_name()
        .context("secure output path must end in a file name")?;
    if target.is_empty() {
        bail!("secure output path must end in a non-empty file name");
    }
    let target_name = c_string(target, "secure output file name")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok((parent.to_path_buf(), target_name))
}

fn secure_parent(path: &Path) -> Result<SecureParent> {
    let (parent, target_name) = parent_parts(path)?;
    let directory = open_directory_path(&parent)?;
    validate_directory(&directory, &parent)?;
    Ok(SecureParent {
        directory,
        display_path: parent,
        target_name,
    })
}

fn metadata_at(parent: &SecureParent) -> Result<Option<libc::stat>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.directory.as_raw_fd(),
            parent.target_name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: successful `fstatat` initialized the structure.
        return Ok(Some(unsafe { stat.assume_init() }));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(error).with_context(|| {
            format!(
                "inspecting secure output target in {}",
                parent.display_path.display()
            )
        })
    }
}

/// Create a new mode-0700 directory without following any path component.
/// The final `mkdirat` is relative to the pinned parent descriptor and never
/// reuses an existing entry.
pub fn create_private_directory(path: &Path) -> Result<()> {
    let (parent_path, target_name) = parent_parts(path)?;
    let parent = open_directory_path(&parent_path)?;
    validate_creation_directory(&parent, &parent_path)?;
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), target_name.as_ptr(), 0o700) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("creating private directory {}", path.display()));
    }
    let mut created = true;
    let finish = (|| -> Result<()> {
        let directory = open_directory_at(
            &parent,
            path.file_name().context("private directory has no name")?,
            path,
        )?;
        if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("chmod 0700 {}", path.display()));
        }
        validate_directory(&directory, path)?;
        directory
            .sync_all()
            .with_context(|| format!("syncing new directory {}", path.display()))?;
        parent
            .sync_all()
            .with_context(|| format!("syncing directory parent {}", parent_path.display()))?;
        Ok(())
    })();
    if finish.is_ok() {
        created = false;
    }
    if created {
        unsafe {
            libc::unlinkat(parent.as_raw_fd(), target_name.as_ptr(), libc::AT_REMOVEDIR);
        }
    }
    finish
}

/// Open one single-link regular artifact beneath a root directory using only
/// descriptor-relative, non-following lookups.
pub fn open_regular_beneath(root: &Path, relative: &Path, maximum: Option<u64>) -> Result<File> {
    if relative.is_absolute() {
        bail!("artifact path must be relative: {}", relative.display());
    }
    let components: Vec<_> = relative.components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("unsafe artifact path: {}", relative.display());
    }
    let mut directory = open_directory_path(root)
        .with_context(|| format!("opening artifact root {}", root.display()))?;
    for component in &components[..components.len() - 1] {
        let Component::Normal(name) = component else {
            unreachable!("components validated above");
        };
        directory = open_directory_at(&directory, name, relative).with_context(|| {
            format!(
                "artifact parent must be a real directory (symlinks are forbidden): {}",
                relative.display()
            )
        })?;
    }
    let Component::Normal(name) = components[components.len() - 1] else {
        unreachable!("components validated above");
    };
    let name = c_string(name, "artifact file name")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening artifact {}", relative.display()));
    }
    // SAFETY: `openat` returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting artifact {}", relative.display()))?;
    use std::os::unix::fs::MetadataExt as _;
    if !metadata.is_file() || metadata.nlink() != 1 {
        bail!(
            "artifact is not a single-link regular file: {}",
            relative.display()
        );
    }
    if maximum.is_some_and(|limit| metadata.len() > limit) {
        bail!(
            "artifact exceeds the {} byte limit: {}",
            maximum.unwrap_or_default(),
            relative.display()
        );
    }
    Ok(file)
}

/// Open a streaming private output relative to a pinned, fully non-following
/// parent directory. This is the streaming counterpart to [`write`].
#[doc(hidden)]
pub fn open_private_file(path: &Path, mode: PrivateFileMode) -> Result<File> {
    let parent = secure_parent(path)?;
    let access = if mode == PrivateFileMode::Lock {
        libc::O_RDWR
    } else {
        libc::O_WRONLY
    };
    let mut flags = access | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    match mode {
        PrivateFileMode::CreateNew => flags |= libc::O_EXCL,
        PrivateFileMode::Overwrite => {}
        PrivateFileMode::Append => flags |= libc::O_APPEND,
        PrivateFileMode::Lock => {}
    }
    let fd = unsafe {
        libc::openat(
            parent.directory.as_raw_fd(),
            parent.target_name.as_ptr(),
            flags,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening private output {}", path.display()));
    }
    // SAFETY: `openat` returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting private output {}", path.display()))?;
    use std::os::unix::fs::MetadataExt as _;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!(
            "private output must be an owned, single-link private regular file: {}",
            path.display()
        );
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("chmod 0600 {}", path.display()));
    }
    if mode == PrivateFileMode::Overwrite {
        file.set_len(0)
            .with_context(|| format!("truncating private output {}", path.display()))?;
    }
    Ok(file)
}

fn validate_existing_target(parent: &SecureParent, path: &Path, overwrite: bool) -> Result<()> {
    let Some(stat) = metadata_at(parent)? else {
        return Ok(());
    };
    if !overwrite {
        bail!("secure output already exists: {}", path.display());
    }
    let kind = stat.st_mode & libc::S_IFMT;
    if kind != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o077 != 0
    {
        bail!(
            "secure overwrite target must be an owned, single-link private regular file: {}",
            path.display()
        );
    }
    Ok(())
}

fn create_staged_file(parent: &SecureParent) -> Result<(CString, File)> {
    for _ in 0..32 {
        let name = CString::new(format!(
            ".neutron.tmp-{}-{}",
            std::process::id(),
            NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("generated temporary name contains no NUL");
        let fd = unsafe {
            libc::openat(
                parent.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd >= 0 {
            // SAFETY: `openat` returned a new owned descriptor.
            let file = unsafe { File::from_raw_fd(fd) };
            let metadata = file.metadata().context("inspecting staged secure output")?;
            use std::os::unix::fs::MetadataExt as _;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                unsafe {
                    libc::unlinkat(parent.directory.as_raw_fd(), name.as_ptr(), 0);
                }
                bail!("new staged secure output failed ownership checks");
            }
            let chmod = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
            if chmod != 0 {
                let error = std::io::Error::last_os_error();
                unsafe {
                    libc::unlinkat(parent.directory.as_raw_fd(), name.as_ptr(), 0);
                }
                return Err(error).context("chmod 0600 staged secure output");
            }
            return Ok((name, file));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error).context("creating staged secure output");
        }
    }
    bail!("unable to allocate a unique staged secure output name")
}

fn unlink_at(directory: &File, name: &CString) -> std::io::Result<()> {
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub fn write(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    let parent = secure_parent(path)?;
    validate_existing_target(&parent, path, overwrite)?;
    let (temporary_name, mut file) = create_staged_file(&parent)?;
    let mut cleanup = TempFile::new(parent.directory.try_clone()?, temporary_name.clone());
    file.write_all(bytes)
        .with_context(|| format!("writing staged output for {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing staged output for {}", path.display()))?;
    drop(file);

    if overwrite {
        let result = unsafe {
            libc::renameat(
                parent.directory.as_raw_fd(),
                temporary_name.as_ptr(),
                parent.directory.as_raw_fd(),
                parent.target_name.as_ptr(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("atomically replacing {}", path.display()));
        }
        cleanup.disarm();
    } else {
        let result = unsafe {
            libc::linkat(
                parent.directory.as_raw_fd(),
                temporary_name.as_ptr(),
                parent.directory.as_raw_fd(),
                parent.target_name.as_ptr(),
                0,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("atomically publishing {}", path.display()));
        }
        if let Err(error) = unlink_at(&parent.directory, &temporary_name) {
            let _ = unlink_at(&parent.directory, &parent.target_name);
            return Err(error)
                .with_context(|| format!("removing staged output for {}", path.display()));
        }
        cleanup.disarm();
    }

    if let Err(error) = parent.directory.sync_all() {
        if !overwrite {
            let _ = unlink_at(&parent.directory, &parent.target_name);
        }
        return Err(error).with_context(|| {
            format!("syncing output directory {}", parent.display_path.display())
        });
    }
    Ok(())
}

struct TempFile {
    directory: File,
    name: CString,
    armed: bool,
}

impl TempFile {
    fn new(directory: File, name: CString) -> Self {
        Self {
            directory,
            name,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlink_at(&self.directory, &self.name);
        }
    }
}

pub fn write_json(path: &Path, value: &impl Serialize, overwrite: bool) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write(path, &bytes, overwrite)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn private_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "neutron-private-output-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn private_parent_accepts_atomic_output() {
        let dir = private_dir("accept");
        let path = dir.join("artifact.json");
        write(&path, b"first\n", true).unwrap();
        write(&path, b"second\n", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn owned_readable_parent_is_accepted_but_writable_or_symlinked_parent_is_rejected() {
        let readable = private_dir("readable");
        std::fs::set_permissions(&readable, std::fs::Permissions::from_mode(0o755)).unwrap();
        write(&readable.join("artifact"), b"yes", false).unwrap();

        let writable = private_dir("writable");
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(write(&writable.join("artifact"), b"no", false).is_err());

        let target = private_dir("target");
        let link = std::env::temp_dir().join(format!(
            "neutron-private-output-link-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&link);
        symlink(&target, &link).unwrap();
        assert!(write(&link.join("artifact"), b"no", false).is_err());

        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_dir_all(target);
        let _ = std::fs::remove_dir_all(writable);
        let _ = std::fs::remove_dir_all(readable);
    }

    #[test]
    fn intermediate_symlink_and_parent_traversal_are_rejected() {
        let base = private_dir("intermediate-base");
        let target = private_dir("intermediate-target");
        let nested = target.join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&target, base.join("redirect")).unwrap();

        assert!(write(&base.join("redirect/nested/artifact"), b"no", false).is_err());
        assert!(write(&base.join("../escape"), b"no", false).is_err());

        let _ = std::fs::remove_dir_all(base);
        let _ = std::fs::remove_dir_all(target);
    }

    #[test]
    fn create_new_refuses_existing_target_and_overwrite_refuses_symlink() {
        let dir = private_dir("targets");
        let artifact = dir.join("artifact");
        write(&artifact, b"first", false).unwrap();
        assert!(write(&artifact, b"second", false).is_err());

        let victim = dir.join("victim");
        std::fs::write(&victim, b"victim").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link");
        symlink(&victim, &link).unwrap();
        assert!(write(&link, b"replaced", true).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn private_directory_creation_and_beneath_open_are_non_following() {
        let base = private_dir("directory-create");
        let run = base.join("run");
        create_private_directory(&run).unwrap();
        assert!(create_private_directory(&run).is_err());
        write(&run.join("artifact"), b"evidence", false).unwrap();

        let mut file = open_regular_beneath(&run, Path::new("artifact"), Some(8)).unwrap();
        let mut bytes = Vec::new();
        use std::io::Read as _;
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"evidence");
        assert!(open_regular_beneath(&run, Path::new("artifact"), Some(7)).is_err());

        let outside = base.join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, run.join("link")).unwrap();
        assert!(open_regular_beneath(&run, Path::new("link"), None).is_err());

        let _ = std::fs::remove_dir_all(base);
    }
}
