use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceInventory {
    pub name: String,
    pub descriptor: Option<String>,
    pub pid: Option<u32>,
    pub transport: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VintfDeclaration {
    pub format: String,
    pub package: String,
    pub version: Option<String>,
    pub interface: String,
    pub instance: String,
    pub transport: Option<String>,
}

impl VintfDeclaration {
    pub fn fqname(&self) -> String {
        if self.format == "hidl" {
            match self
                .version
                .as_deref()
                .filter(|version| !version.is_empty())
            {
                Some(version) => format!(
                    "{}@{}::{}/{}",
                    self.package, version, self.interface, self.instance
                ),
                None => format!("{}::{}/{}", self.package, self.interface, self.instance),
            }
        } else {
            format!("{}.{}/{}", self.package, self.interface, self.instance)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessStatus {
    pub uid: u32,
    pub gid: u32,
}

pub fn parse_service_list_inventory(input: &str) -> Vec<ServiceInventory> {
    parse_indexed_services(input, "binder")
}

pub fn parse_vndservice_list(input: &str) -> Vec<ServiceInventory> {
    parse_indexed_services(input, "vndbinder")
}

fn parse_indexed_services(input: &str, transport: &str) -> Vec<ServiceInventory> {
    let mut services = BTreeMap::<String, ServiceInventory>::new();
    for line in input.lines().map(str::trim) {
        if line.is_empty() || line.starts_with("Found ") {
            continue;
        }
        let digit_count = line.bytes().take_while(u8::is_ascii_digit).count();
        let body = line[digit_count..].trim_start();
        let Some(separator) = body.find(":") else {
            continue;
        };
        let name = body[..separator].trim();
        if name.is_empty() {
            continue;
        }
        let descriptor = body[separator + 1..]
            .split_once('[')
            .and_then(|(_, rest)| rest.split_once(']'))
            .map(|(descriptor, _)| descriptor.trim().to_string())
            .filter(|descriptor| !descriptor.is_empty());
        services
            .entry(name.to_string())
            .or_insert_with(|| ServiceInventory {
                name: name.to_string(),
                descriptor,
                pid: None,
                transport: transport.to_string(),
            });
    }
    services.into_values().collect()
}

pub fn parse_lshal_inventory(input: &str) -> Vec<ServiceInventory> {
    let mut services = BTreeMap::<String, ServiceInventory>::new();
    for line in input.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some((index, raw_name)) = tokens.iter().enumerate().find(|(_, token)| {
            (token.contains("::") || (token.contains('/') && token.contains('.')))
                && !token.starts_with('/')
        }) else {
            continue;
        };
        let name = raw_name.trim_matches(|character: char| matches!(character, ',' | '[' | ']'));
        let pid = tokens[index + 1..]
            .iter()
            .map(|token| token.trim_matches(|character: char| !character.is_ascii_digit()))
            .find(|token| !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|token| token.parse::<u32>().ok())
            .filter(|pid| *pid != 0);
        services
            .entry(name.to_string())
            .or_insert_with(|| ServiceInventory {
                name: name.to_string(),
                descriptor: None,
                pid,
                transport: "hwbinder".to_string(),
            });
    }
    services.into_values().collect()
}

pub fn parse_dumpsys_pid(input: &str) -> Option<u32> {
    let mut lines = input.lines().map(str::trim).filter(|line| !line.is_empty());
    let line = lines.next()?;
    if lines.next().is_some() || !line.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    line.parse().ok()
}

#[derive(Default)]
struct HalBuilder {
    format: String,
    package: String,
    versions: Vec<String>,
    transport: Option<String>,
    fqnames: Vec<String>,
    interfaces: Vec<InterfaceBuilder>,
}

#[derive(Default)]
struct InterfaceBuilder {
    name: String,
    instances: Vec<String>,
}

impl HalBuilder {
    fn finish(self) -> Vec<VintfDeclaration> {
        let mut declarations = Vec::new();
        let declared_versions: Vec<Option<String>> = if self.versions.is_empty() {
            vec![None]
        } else {
            self.versions.iter().cloned().map(Some).collect()
        };
        for fqname in self.fqnames {
            if let Some((version, interface, instance)) = split_fqname(&fqname) {
                let versions =
                    version.map_or_else(|| declared_versions.clone(), |value| vec![Some(value)]);
                for version in versions {
                    declarations.push(VintfDeclaration {
                        format: self.format.clone(),
                        package: self.package.clone(),
                        version,
                        interface: interface.clone(),
                        instance: instance.clone(),
                        transport: self.transport.clone(),
                    });
                }
            }
        }
        for interface in self.interfaces {
            for instance in interface.instances {
                for version in &declared_versions {
                    if !self.package.is_empty()
                        && !interface.name.is_empty()
                        && !instance.is_empty()
                    {
                        declarations.push(VintfDeclaration {
                            format: self.format.clone(),
                            package: self.package.clone(),
                            version: version.clone(),
                            interface: interface.name.clone(),
                            instance: instance.clone(),
                            transport: self.transport.clone(),
                        });
                    }
                }
            }
        }
        declarations
    }
}

fn split_fqname(value: &str) -> Option<(Option<String>, String, String)> {
    let (version, interface_instance) = match value.split_once("::") {
        Some((version, rest)) => (
            Some(version.trim().trim_start_matches('@').to_string()),
            rest,
        ),
        None => (None, value),
    };
    let (interface, instance) = interface_instance.split_once('/')?;
    let interface = interface.trim();
    let instance = instance.trim();
    if interface.is_empty() || instance.is_empty() {
        return None;
    }
    Some((version, interface.to_string(), instance.to_string()))
}

fn attribute(start: &BytesStart<'_>, key: &[u8]) -> Result<Option<String>> {
    for attribute in start.attributes() {
        let attribute = attribute.context("reading VINTF XML attribute")?;
        if attribute.key.as_ref() == key {
            return Ok(Some(
                String::from_utf8_lossy(attribute.value.as_ref()).into_owned(),
            ));
        }
    }
    Ok(None)
}

pub fn parse_vintf_manifest(input: &str) -> Result<Vec<VintfDeclaration>> {
    let mut reader = Reader::from_reader(input.as_bytes());
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut stack = Vec::<Vec<u8>>::new();
    let mut hal: Option<HalBuilder> = None;
    let mut interface: Option<InterfaceBuilder> = None;
    let mut declarations = BTreeSet::new();

    loop {
        match reader
            .read_event_into(&mut buffer)
            .context("parsing VINTF XML")?
        {
            Event::Start(start) => {
                let name = start.name().as_ref().to_vec();
                if name.as_slice() == b"hal" {
                    hal = Some(HalBuilder {
                        format: attribute(&start, b"format")?.unwrap_or_default(),
                        ..HalBuilder::default()
                    });
                } else if name.as_slice() == b"interface" && hal.is_some() {
                    interface = Some(InterfaceBuilder::default());
                }
                stack.push(name);
            }
            Event::Empty(start) => {
                if start.name().as_ref() == b"hal" {
                    let builder = HalBuilder {
                        format: attribute(&start, b"format")?.unwrap_or_default(),
                        ..HalBuilder::default()
                    };
                    declarations.extend(builder.finish());
                }
            }
            Event::Text(text) => {
                let Some(tag) = stack.last().map(Vec::as_slice) else {
                    buffer.clear();
                    continue;
                };
                let value = String::from_utf8_lossy(text.as_ref()).trim().to_string();
                if value.is_empty() {
                    buffer.clear();
                    continue;
                }
                if let Some(current_interface) = interface.as_mut() {
                    match tag {
                        b"name" => current_interface.name = value,
                        b"instance" => current_interface.instances.push(value),
                        _ => {}
                    }
                } else if let Some(current_hal) = hal.as_mut() {
                    match tag {
                        b"name" => current_hal.package = value,
                        b"version" => current_hal.versions.push(value),
                        b"transport" => current_hal.transport = Some(value),
                        b"fqname" => current_hal.fqnames.push(value),
                        _ => {}
                    }
                }
            }
            Event::End(end) => {
                let name = end.name().as_ref().to_vec();
                let Some(start_name) = stack.pop() else {
                    bail!("unexpected closing VINTF XML tag");
                };
                if start_name != name {
                    bail!("mismatched VINTF XML tags");
                }
                if name.as_slice() == b"interface" {
                    if let (Some(current_hal), Some(current_interface)) =
                        (hal.as_mut(), interface.take())
                    {
                        current_hal.interfaces.push(current_interface);
                    }
                } else if name.as_slice() == b"hal" {
                    if let Some(current_hal) = hal.take() {
                        declarations.extend(current_hal.finish());
                    }
                }
            }
            Event::Eof => {
                if !stack.is_empty() {
                    bail!("unclosed VINTF XML tag");
                }
                break;
            }
            _ => {}
        }
        buffer.clear();
    }

    Ok(declarations.into_iter().collect())
}

pub fn parse_process_status(input: &str) -> Result<ProcessStatus> {
    let mut uid = None;
    let mut gid = None;
    for line in input.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            uid = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
        } else if let Some(value) = line.strip_prefix("Gid:") {
            gid = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
        }
    }
    Ok(ProcessStatus {
        uid: uid.context("process status has no valid Uid")?,
        gid: gid.context("process status has no valid Gid")?,
    })
}

pub fn parse_process_starttime(input: &str) -> Result<u64> {
    let opening_comm = input
        .find('(')
        .context("process stat has no opening comm parenthesis")?;
    let closing_comm = input
        .rfind(')')
        .context("process stat has no closing comm parenthesis")?;
    if closing_comm <= opening_comm {
        bail!("process stat has invalid comm parentheses");
    }
    input[closing_comm + 1..]
        .split_whitespace()
        .nth(19)
        .context("process stat has no starttime field")?
        .parse()
        .context("invalid process starttime")
}

pub fn parse_module_names(input: &str) -> Vec<String> {
    input
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            fields.next()?.parse::<u64>().ok()?;
            (fields.count() >= 4).then(|| name.to_string())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn ioctl_label(cmd: u32) -> String {
    crate::decode::decode_ioctl(cmd, &[], 0, None)
        .name
        .unwrap_or_else(|| format!("cmd=0x{cmd:08x}"))
}
