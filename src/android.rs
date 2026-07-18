//! Android platform helpers used by the tracer CLI.

use std::fs;
use std::io;
use std::process::Output;

use anyhow::{bail, Context, Result};

pub fn run_platform_command(program: &str, args: &[&str]) -> io::Result<Output> {
    crate::surface::platform::run_platform_command_bounded(program, args)
}

fn validate_package_name(package: &str) -> Result<&str> {
    let package = package.trim();
    if package.is_empty() {
        bail!("package name must be non-empty");
    }
    if !package
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
    {
        bail!("invalid Android package name '{package}'");
    }
    Ok(package)
}

fn normalize_provider_authority(authority: &str) -> Result<String> {
    let authority = authority.trim();
    let authority = if authority
        .get(..10)
        .is_some_and(|s| s.eq_ignore_ascii_case("content://"))
    {
        authority[10..]
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
    } else {
        authority
    };
    let authority = authority.trim();
    if authority.is_empty() {
        bail!("Android provider authority must be non-empty");
    }
    if !authority
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("invalid Android provider authority '{authority}'");
    }
    Ok(authority.to_string())
}

fn parse_authority_header(line: &str) -> Option<&str> {
    let rest = line.trim().strip_prefix('[')?;
    let end = rest.find("]:")?;
    Some(&rest[..end])
}

fn parse_provider_component(line: &str) -> Option<String> {
    let rest = line.trim().split_once("Provider{").map(|(_, rest)| rest)?;
    let body = rest.split_once('}').map(|(body, _)| body)?;
    let component = body.split_whitespace().nth(1)?;
    if component.contains('/') {
        Some(component.to_string())
    } else {
        None
    }
}

fn package_from_component(component: &str) -> Option<String> {
    let (package, _) = component.split_once('/')?;
    validate_package_name(package).ok().map(str::to_string)
}

fn parse_application_info_package(line: &str) -> Option<String> {
    let rest = line
        .trim()
        .split_once("ApplicationInfo{")
        .map(|(_, rest)| rest)?;
    let body = rest.split_once('}').map(|(body, _)| body)?;
    let package = body.split_whitespace().last()?;
    validate_package_name(package).ok().map(str::to_string)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderResolution {
    pub authority: String,
    pub package: String,
    pub component: Option<String>,
}

/// Parse `dumpsys package providers` output and return the provider package
/// for an exact authority match. Accepts either a bare authority or a
/// `content://authority/path` URI.
pub fn parse_provider_authority_lines(output: &str, authority: &str) -> Result<ProviderResolution> {
    let authority = normalize_provider_authority(authority)?;
    let lines: Vec<&str> = output.lines().collect();

    for (idx, line) in lines.iter().enumerate() {
        let Some(found_authority) = parse_authority_header(line) else {
            continue;
        };
        if found_authority != authority {
            continue;
        }

        let mut component: Option<String> = None;
        let mut package: Option<String> = None;
        for detail in &lines[idx + 1..] {
            if parse_authority_header(detail).is_some() {
                break;
            }
            if component.is_none() {
                component = parse_provider_component(detail);
                if let Some(component_package) =
                    component.as_deref().and_then(package_from_component)
                {
                    package = Some(component_package);
                }
            }
            if package.is_none() {
                package = parse_application_info_package(detail);
            }
            if package.is_some() && component.is_some() {
                break;
            }
        }

        let package = package.with_context(|| {
            format!("provider authority {authority} found but no package parsed")
        })?;
        return Ok(ProviderResolution {
            authority,
            package,
            component,
        });
    }

    bail!("provider authority {authority} not found in package-manager output")
}

/// Parse output from `cmd package list packages -U <pkg>` or
/// `pm list packages -U <pkg>` and return the exact package UID.
pub fn parse_package_uid_lines(output: &str, package: &str) -> Result<u32> {
    let package = validate_package_name(package)?;
    for line in output.lines() {
        let Some(rest) = line.trim().strip_prefix("package:") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let Some(found_package) = parts.next() else {
            continue;
        };
        if found_package != package {
            continue;
        }
        for part in parts {
            if let Some(uid) = part.strip_prefix("uid:") {
                return uid
                    .parse()
                    .with_context(|| format!("invalid uid '{uid}' for package {package}"));
            }
        }
        bail!("package {package} found but no uid:<N> field was present");
    }
    bail!("package {package} not found in package-manager output");
}

/// Explain the ambiguity introduced when package-scoped matching resolves to
/// an Android platform/shared AID instead of a normal app UID. Runtime events
/// are UID-scoped, so a package name alone cannot isolate one APK under these
/// IDs.
pub fn match_package_uid_warning(package: &str, uid: u32) -> Option<String> {
    if uid >= 10_000 {
        return None;
    }
    Some(format!(
        "--match-package {package} resolved to shared/system UID {uid}; \
         runtime filtering is UID-scoped, so this capture may include other \
         processes using uid {uid}. Add --match-pid/--match-comm, fd filters, \
         or a scenario-specific service capture before drawing package-specific \
         conclusions."
    ))
}

/// Resolve an Android content-provider authority to its declaring package.
/// Intended to run on-device, where `dumpsys package providers` is available.
pub fn resolve_provider_authority(authority: &str) -> Result<ProviderResolution> {
    let authority = normalize_provider_authority(authority)?;
    let output = run_platform_command("dumpsys", &["package", "providers"])
        .context("running dumpsys package providers")?;
    if !output.status.success() {
        bail!("dumpsys package providers exited with {}", output.status);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_provider_authority_lines(&stdout, &authority)
}

fn run_package_query(program: &str, args: &[&str], package: &str) -> Result<Option<u32>> {
    let output = run_platform_command(program, args)
        .with_context(|| format!("running {program} {}", args.join(" ")))?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    match parse_package_uid_lines(&stdout, package) {
        Ok(uid) => Ok(Some(uid)),
        Err(_) => Ok(None),
    }
}

/// Resolve an installed Android package name to its app UID. Intended to
/// run on-device, where `cmd package` or `pm` is available.
pub fn resolve_package_uid(package: &str) -> Result<u32> {
    let package = validate_package_name(package)?;
    let attempts: [(&str, Vec<&str>); 2] = [
        ("cmd", vec!["package", "list", "packages", "-U", package]),
        ("pm", vec!["list", "packages", "-U", package]),
    ];
    for (program, args) in attempts {
        if let Some(uid) = run_package_query(program, &args, package)? {
            return Ok(uid);
        }
    }
    bail!("could not resolve Android package '{package}' to a UID via cmd package or pm")
}

/// Android app process names are either the package itself or
/// `<package>:<isolated-name>`. Only argv[0] is relevant in `/proc/PID/cmdline`.
pub fn is_package_process_cmdline(cmdline: &[u8], package: &str) -> bool {
    let name = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    name == package
        || name
            .strip_prefix(package)
            .is_some_and(|suffix| suffix.starts_with(':'))
}

fn parse_status_uid(status: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        line.strip_prefix("Uid:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

/// Find every live process whose real UID matches `uid`.
pub fn find_uid_processes(uid: u32) -> Result<Vec<u32>> {
    const MAX_PROC_ENTRIES: usize = 32 * 1024;
    const MAX_STATUS_BYTES: usize = 1024 * 1024;
    let mut pids = Vec::new();
    for (index, entry) in fs::read_dir("/proc").context("reading /proc")?.enumerate() {
        if index >= MAX_PROC_ENTRIES {
            bail!("/proc exceeds the {MAX_PROC_ENTRIES}-entry discovery limit");
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("reading /proc directory entry"),
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let status = match crate::surface::platform::read_regular_file_bounded(
            &entry.path().join("status"),
            MAX_STATUS_BYTES,
        ) {
            Ok(status) => String::from_utf8(status)
                .with_context(|| format!("decoding /proc/{pid}/status for UID discovery"))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading /proc/{pid}/status for UID discovery"))
            }
        };
        let process_uid = parse_status_uid(&status)
            .with_context(|| format!("parsing /proc/{pid}/status for UID discovery"))?;
        if process_uid == uid {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

/// Find every live process belonging to the package UID whose cmdline is the
/// package or one of its colon-suffixed Android child process names.
pub fn find_package_processes(package: &str, uid: u32) -> Result<Vec<u32>> {
    const MAX_CMDLINE_BYTES: usize = 64 * 1024;
    let package = validate_package_name(package)?;
    let mut pids = Vec::new();
    for pid in find_uid_processes(uid)? {
        let cmdline = match crate::surface::platform::read_regular_file_bounded(
            std::path::Path::new(&format!("/proc/{pid}/cmdline")),
            MAX_CMDLINE_BYTES,
        ) {
            Ok(cmdline) => cmdline,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading /proc/{pid}/cmdline for package discovery"))
            }
        };
        if is_package_process_cmdline(&cmdline, package) {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cmd_package_uid_output() {
        let output = "\
package:com.android.providers.contacts uid:10094
package:com.example.probe uid:10341
";
        assert_eq!(
            parse_package_uid_lines(output, "com.example.probe").unwrap(),
            10341
        );
    }

    #[test]
    fn exact_package_match_prevents_prefix_collision() {
        let output = "\
package:com.example uid:10100
package:com.example.debug uid:10101
";
        assert_eq!(
            parse_package_uid_lines(output, "com.example.debug").unwrap(),
            10101
        );
    }

    #[test]
    fn rejects_invalid_package_names() {
        let err = parse_package_uid_lines("", "com.example;id").unwrap_err();
        assert!(format!("{err:#}").contains("invalid Android package name"));
    }

    #[test]
    fn parses_dumpsys_provider_authority() {
        let output = "\
Registered ContentProviders:
  [com.google.android.apps.messaging.shared.ui.avatar.AvatarContentProvider]:
    Provider{88ed4af com.google.android.apps.messaging/.shared.ui.avatar.AvatarContentProvider}
      applicationInfo=ApplicationInfo{9e4057 com.google.android.apps.messaging}
  [com.android.contacts]:
    Provider{1259fac com.google.android.providers.contacts/.ContactsProvider2}
      applicationInfo=ApplicationInfo{5a7a23c com.google.android.providers.contacts}
";

        let provider = parse_provider_authority_lines(
            output,
            "com.google.android.apps.messaging.shared.ui.avatar.AvatarContentProvider",
        )
        .unwrap();

        assert_eq!(
            provider.authority,
            "com.google.android.apps.messaging.shared.ui.avatar.AvatarContentProvider"
        );
        assert_eq!(provider.package, "com.google.android.apps.messaging");
        assert_eq!(
            provider.component.as_deref(),
            Some("com.google.android.apps.messaging/.shared.ui.avatar.AvatarContentProvider")
        );
    }

    #[test]
    fn provider_authority_accepts_content_uri() {
        let output = "\
Registered ContentProviders:
  [com.android.contacts]:
    Provider{1259fac com.google.android.providers.contacts/.ContactsProvider2}
";

        let provider =
            parse_provider_authority_lines(output, "content://com.android.contacts/raw_contacts/1")
                .unwrap();

        assert_eq!(provider.authority, "com.android.contacts");
        assert_eq!(provider.package, "com.google.android.providers.contacts");
    }

    #[test]
    fn provider_authority_rejects_invalid_names() {
        let err = parse_provider_authority_lines("", "content://contacts;id").unwrap_err();
        assert!(format!("{err:#}").contains("invalid Android provider authority"));
    }

    #[test]
    fn package_process_cmdline_accepts_main_and_colon_processes_only() {
        assert!(is_package_process_cmdline(
            b"com.example.app\0--flag\0",
            "com.example.app"
        ));
        assert!(is_package_process_cmdline(
            b"com.example.app:camera\0",
            "com.example.app"
        ));
        assert!(!is_package_process_cmdline(
            b"com.example.application\0",
            "com.example.app"
        ));
    }

    #[test]
    fn status_uid_parser_uses_the_real_uid_column() {
        assert_eq!(
            parse_status_uid("Uid:\t10123\t20123\t30123\t40123\n"),
            Some(10123)
        );
        assert_eq!(parse_status_uid("Name:\tapp\nGid:\t10123\n"), None);
    }

    #[test]
    fn uid_process_discovery_includes_self() {
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let uid = parse_status_uid(&status).unwrap();
        assert!(find_uid_processes(uid)
            .unwrap()
            .contains(&std::process::id()));
    }
}
