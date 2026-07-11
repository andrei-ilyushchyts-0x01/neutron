//! Owned, single-link, mode-private output files.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Serialize;

fn open(path: &Path, overwrite: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    if overwrite {
        options.create(true);
    } else {
        options.create_new(true);
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening {} for secure output", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting secure output {}", path.display()))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!(
            "secure output must be an owned regular file with one link: {}",
            path.display()
        );
    }
    if overwrite {
        file.set_len(0)
            .with_context(|| format!("truncating verified output {}", path.display()))?;
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok(file)
}

pub(crate) fn write(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    let mut file = open(path, overwrite)?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flushing {}", path.display()))
}

pub(crate) fn write_json(path: &Path, value: &impl Serialize, overwrite: bool) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write(path, &bytes, overwrite)
}
