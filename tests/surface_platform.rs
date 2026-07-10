use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use neutron::surface::{FileKind, PlatformReader, RealPlatformReader};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[test]
fn real_platform_reader_projects_filesystem_state_and_stable_time() {
    let path = std::env::temp_dir().join(format!(
        "neutron-surface-platform-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir(&path).unwrap();
    let first = path.join("z-file");
    let second = path.join("a-file");
    let link = path.join("link");
    fs::write(&first, b"surface").unwrap();
    fs::write(&second, b"mapper").unwrap();
    symlink("z-file", &link).unwrap();

    let reader = RealPlatformReader;
    assert_eq!(reader.read(&first).unwrap(), b"surface");
    assert_eq!(
        reader.read_dir(&path).unwrap(),
        vec![second.clone(), link.clone(), first.clone()]
    );
    assert_eq!(reader.read_link(&link).unwrap(), Path::new("z-file"));
    assert_eq!(reader.canonicalize(&link).unwrap(), first);
    assert_eq!(reader.metadata(&path).unwrap().kind, FileKind::Directory);
    assert_eq!(reader.metadata(&second).unwrap().kind, FileKind::File);
    assert_eq!(reader.metadata(&link).unwrap().kind, FileKind::Symlink);

    let null = reader.metadata(Path::new("/dev/null")).unwrap();
    assert_eq!(null.kind, FileKind::CharacterDevice);
    assert!(null.major.is_some() && null.minor.is_some());
    let _ = reader.selinux_context(&second);
    assert_eq!(
        reader
            .selinux_context(Path::new("bad\0path"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    let collected_at = reader.collected_at();
    assert!(collected_at.ends_with('Z') && collected_at.contains('T'));

    fs::remove_dir_all(path).unwrap();
}

#[test]
fn real_platform_reader_uses_only_absolute_allowlisted_android_commands() {
    let reader = RealPlatformReader;
    let error = reader.command_output("shell-from-path", &[]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    if let Err(error) = reader.command_output("lshal", &["-i", "-p"]) {
        assert_ne!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
    if let Err(error) = reader.command_output("vndservice", &["list"]) {
        assert_ne!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
