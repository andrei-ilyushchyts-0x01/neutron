//! Bounded system subjects, shared by capture and host consumers.
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::surface::{Process, SurfaceSnapshot};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SubjectSelector {
    Package(String),
    Uid(u32),
    Pids(Vec<ProcessRoot>),
    Executable(String),
    Service { transport: String, endpoint: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessRoot {
    pub pid: u32,
    pub starttime: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSubject {
    pub schema: String,
    pub selector: SubjectSelector,
    pub roots: Vec<ProcessIdentity>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub boot_id: String,
    pub pid: u32,
    pub starttime: u64,
    pub uid: u32,
    pub gid: u32,
    pub executable: String,
    pub selinux_domain: String,
}

impl FromStr for SubjectSelector {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, String> {
        let (kind, value) = value.split_once(':').ok_or(
            "subject must use pid:, exe:, package:, uid:, binder:, vndbinder:, or hwbinder:",
        )?;
        if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
            return Err("subject must be a bounded printable value".into());
        }
        let subject = match kind {
            "package" => Self::Package(value.into()),
            "uid" => Self::Uid(value.parse().map_err(|_| "invalid UID")?),
            "exe" if value.starts_with('/') => Self::Executable(value.into()),
            "binder" | "vndbinder" | "hwbinder" => Self::Service {
                transport: kind.into(),
                endpoint: value.into(),
            },
            "pid" => {
                let mut roots = Vec::new();
                for root in value.split(',') {
                    let (pid, starttime) = root
                        .split_once('@')
                        .map_or((root, None), |(pid, start)| (pid, Some(start)));
                    let pid = pid
                        .parse::<u32>()
                        .ok()
                        .filter(|pid| *pid > 0)
                        .ok_or("PID must be positive")?;
                    let starttime = starttime
                        .map(|value| {
                            value
                                .parse::<u64>()
                                .ok()
                                .filter(|value| *value > 0)
                                .ok_or("starttime must be positive")
                        })
                        .transpose()?;
                    if roots.iter().any(|root: &ProcessRoot| root.pid == pid) {
                        return Err("duplicate PID root".into());
                    }
                    roots.push(ProcessRoot { pid, starttime });
                    if roots.len() > 1024 {
                        return Err("subject exceeds 1024 roots".into());
                    }
                }
                roots.sort_by_key(|root| root.pid);
                Self::Pids(roots)
            }
            _ => return Err("unknown subject kind or non-absolute executable path".into()),
        };
        Ok(subject)
    }
}

impl SubjectSelector {
    pub fn validate(&self) -> Result<()> {
        let parsed: SubjectSelector = self.id().parse().map_err(anyhow::Error::msg)?;
        if parsed != *self {
            bail!("subject selector is not canonical");
        }
        Ok(())
    }

    pub fn matches_capture(
        &self,
        resolved: Option<&ResolvedSubject>,
        package: Option<&str>,
        uid: Option<u32>,
        pid: Option<u32>,
    ) -> bool {
        if let Some(resolved) = resolved {
            return resolved.selector == *self;
        }
        match self {
            Self::Package(expected) => package == Some(expected.as_str()),
            Self::Uid(expected) => uid == Some(*expected),
            Self::Pids(roots) => {
                roots.len() == 1 && roots[0].starttime.is_none() && pid == Some(roots[0].pid)
            }
            _ => false,
        }
    }

    pub fn id(&self) -> String {
        match self {
            Self::Package(value) => format!("package:{value}"),
            Self::Uid(value) => format!("uid:{value}"),
            Self::Executable(value) => format!("exe:{value}"),
            Self::Service {
                transport,
                endpoint,
            } => format!("{transport}:{endpoint}"),
            Self::Pids(roots) => format!(
                "pid:{}",
                roots
                    .iter()
                    .map(|root| match root.starttime {
                        Some(starttime) => format!("{}@{starttime}", root.pid),
                        None => root.pid.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }

    pub fn resolve(&self, max_roots: usize) -> Result<ResolvedSubject> {
        // ponytail: reuse the bounded inventory; extract a lighter collector if
        // measured refresh cost matters. Never fall back from an unresolved owner.
        self.resolve_snapshot(&crate::surface::collect_snapshot()?, max_roots)
    }

    pub fn resolve_snapshot(
        &self,
        snapshot: &SurfaceSnapshot,
        max_roots: usize,
    ) -> Result<ResolvedSubject> {
        if !(1..=1024).contains(&max_roots) {
            bail!("subject root cap must be 1..=1024");
        }
        let service_pid = if let Self::Service {
            transport,
            endpoint,
        } = self
        {
            let matches: Vec<_> = snapshot
                .services
                .iter()
                .filter(|service| &service.transport == transport && &service.name == endpoint)
                .collect();
            if matches.len() != 1 {
                bail!("service subject is absent or ambiguous: {}", self.id());
            }
            let service = matches[0];
            if service.confidence != "exact" || service.process_id.is_none() {
                bail!("service subject has no exact process owner: {}", self.id());
            }
            let pid = service.pid.context("service owner PID is unresolved")?;
            if !snapshot.processes.iter().any(|process| {
                process.pid == pid && Some(&process.id) == service.process_id.as_ref()
            }) {
                bail!("service owner incarnation is unresolved");
            }
            Some(pid)
        } else {
            None
        };
        let mut roots = Vec::new();
        for process in &snapshot.processes {
            let selected = match self {
                Self::Package(package) => process.cmdline.first().is_some_and(|name| {
                    name == package || name.starts_with(&format!("{package}:"))
                }),
                Self::Uid(uid) => process.uid == Some(*uid),
                Self::Executable(path) => process.executable.as_ref() == Some(path),
                Self::Service { .. } => service_pid == Some(process.pid),
                Self::Pids(pids) => pids.iter().any(|root| {
                    root.pid == process.pid
                        && root
                            .starttime
                            .map_or(true, |starttime| starttime == process.starttime)
                }),
            };
            if selected {
                roots.push(ProcessIdentity::try_from(process)?);
            }
        }
        roots.sort_by_key(|root| (root.pid, root.starttime));
        if roots.is_empty() || roots.len() > max_roots {
            bail!(
                "subject resolved to {} roots (required 1..={max_roots})",
                roots.len()
            );
        }
        if let Self::Pids(requested) = self {
            if requested.len() != roots.len() {
                bail!("PID subject vanished, was reused, or has inaccessible identity");
            }
        }
        let resolved = ResolvedSubject {
            schema: "neutron.subject/v1".into(),
            selector: self.clone(),
            roots,
        };
        resolved.validate()?;
        if resolved
            .roots
            .iter()
            .any(|root| root.boot_id != snapshot.device.boot_id)
        {
            bail!("subject process boot does not match inventory boot");
        }
        Ok(resolved)
    }
}

impl TryFrom<&Process> for ProcessIdentity {
    type Error = anyhow::Error;
    fn try_from(process: &Process) -> Result<Self> {
        Ok(Self {
            boot_id: process.boot_id.clone(),
            pid: process.pid,
            starttime: process.starttime,
            uid: process.uid.context("subject UID is inaccessible")?,
            gid: process.gid,
            executable: process
                .executable
                .clone()
                .context("subject executable is inaccessible")?,
            selinux_domain: process.selinux_domain.clone(),
        })
    }
}

impl ResolvedSubject {
    /// Explicit PIDs expire; only dynamic selectors may admit a replacement.
    pub fn refresh(&self, max_roots: usize) -> Result<Self> {
        let next = self.selector.resolve(max_roots)?;
        self.validate_successor(&next)?;
        Ok(next)
    }

    pub(crate) fn validate_successor(&self, next: &Self) -> Result<()> {
        self.validate()?;
        next.validate()?;
        if self.selector != next.selector || self.roots[0].boot_id != next.roots[0].boot_id {
            bail!("subject admission changed the selector or boot identity");
        }
        if matches!(self.selector, SubjectSelector::Pids(_)) && next.roots != self.roots {
            bail!("explicit PID subject identity changed");
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != "neutron.subject/v1" || self.roots.is_empty() || self.roots.len() > 1024 {
            bail!("invalid subject schema or root count");
        }
        self.selector.validate()?;
        let mut seen = std::collections::BTreeSet::new();
        for root in &self.roots {
            if root.pid == 0
                || root.starttime == 0
                || root.boot_id.len() != 36
                || root.boot_id.bytes().enumerate().any(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b != b'-'
                    } else {
                        !b.is_ascii_hexdigit()
                    }
                })
                || !root.executable.starts_with('/')
                || root.executable.len() > 4096
                || root.executable.chars().any(char::is_control)
                || root.selinux_domain.is_empty()
                || root.selinux_domain.len() > 4096
                || root.selinux_domain.chars().any(char::is_control)
                || root.boot_id != self.roots[0].boot_id
                || !seen.insert(root.pid)
            {
                bail!("subject requires unique, complete boot/PID/starttime/executable/domain identities");
            }
        }
        match &self.selector {
            SubjectSelector::Pids(requested)
                if requested.len() != self.roots.len()
                    || requested.iter().any(|request| {
                        !self.roots.iter().any(|root| {
                            root.pid == request.pid
                                && request.starttime.map_or(true, |s| s == root.starttime)
                        })
                    }) =>
            {
                bail!("resolved roots do not match PID/incarnation selector");
            }
            SubjectSelector::Uid(uid) if self.roots.iter().any(|root| root.uid != *uid) => {
                bail!("resolved roots do not match UID selector");
            }
            SubjectSelector::Executable(path)
                if self.roots.iter().any(|root| root.executable != *path) =>
            {
                bail!("resolved roots do not match executable selector");
            }
            _ => {}
        }
        Ok(())
    }
}
