use std::fs;
use std::path::PathBuf;

use clap::Parser;
use neutron::cli::{Cli, Command, IoctlCommand};
use neutron::ioctl_schema::{generate, GenerateArgs, RuntimeIdentity, SchemaPack, SchemaRegistry};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "neutron-{name}-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn cli_accepts_generate_and_repeatable_schema_packs() {
    let cli = Cli::try_parse_from([
        "neutron",
        "ioctl",
        "generate",
        "--kernel-tree",
        "/kernel",
        "--headers",
        "include/uapi",
        "--output",
        "/tmp/pack",
        "--clang-arg=-DMODE=1",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Ioctl(IoctlCommand::Generate(_)))
    ));

    let cli = Cli::try_parse_from([
        "neutron",
        "trace",
        "--schema-pack",
        "base",
        "--schema-pack",
        "/tmp/device.json",
        "--no-schema-auto",
    ])
    .unwrap();
    let Some(Command::Trace(args)) = cli.command else {
        panic!("trace command");
    };
    assert_eq!(args.schema_pack, ["base", "/tmp/device.json"]);
    assert!(args.no_schema_auto);
}

#[test]
fn generator_uses_clang_and_emits_deterministic_dma_heap_pack() {
    let root = temp_dir("ioctl-generate");
    let headers = root.join("include/uapi/linux");
    fs::create_dir_all(&headers).unwrap();
    fs::write(
        headers.join("dma-heap.h"),
        r#"
typedef unsigned long long __u64;
typedef unsigned int __u32;
#define _IOC(dir,type,nr,size) (((dir)<<30)|((type)<<8)|(nr)|((size)<<16))
#define _IOWR(type,nr,data) _IOC(3,(type),(nr),sizeof(data))
struct dma_heap_allocation_data {
    __u64 len;
    __u32 fd;
    __u32 fd_flags;
    __u64 heap_flags;
};
#define DMA_HEAP_IOCTL_ALLOC _IOWR('H', 0, struct dma_heap_allocation_data)
"#,
    )
    .unwrap();
    let output = root.join("pack");
    let rust = root.join("generated.rs");
    let args = GenerateArgs {
        kernel_tree: root.clone(),
        headers: vec![PathBuf::from("include/uapi")],
        output: output.clone(),
        compile_commands: None,
        clang_arg: Vec::new(),
        manifest: None,
        emit_rust: Some(rust.clone()),
    };

    generate(&args).unwrap();
    let first = fs::read(output.join("schema.json")).unwrap();
    generate(&args).unwrap();
    assert_eq!(first, fs::read(output.join("schema.json")).unwrap());

    let pack: SchemaPack = serde_json::from_slice(&first).unwrap();
    pack.verify(&RuntimeIdentity {
        abi: "aarch64".into(),
        fingerprint: None,
        device: None,
        kernel_release: None,
    })
    .unwrap();
    let descriptor = &pack.descriptors[0];
    assert_eq!(descriptor.name, "DMA_HEAP_IOCTL_ALLOC");
    assert_eq!(descriptor.cmd, 0xc018_4800);
    assert_eq!(descriptor.size, 24);
    assert_eq!(descriptor.fields[0].name, "len");
    assert_eq!(descriptor.fields[1].offset, 8);
    let mut payload = [0u8; 24];
    payload[0..8].copy_from_slice(&4096u64.to_le_bytes());
    payload[8..12].copy_from_slice(&12u32.to_le_bytes());
    let decoded = SchemaRegistry::from_packs(vec![pack])
        .unwrap()
        .decode(0xc018_4800, &payload, None, None)
        .unwrap();
    assert_eq!(decoded.fields.values["len"], 4096);
    assert_eq!(decoded.fields.values["fd"], 12);
    assert!(fs::read_to_string(rust)
        .unwrap()
        .contains("DMA_HEAP_IOCTL_ALLOC"));
}

#[test]
fn generator_fails_when_no_ioctl_macro_resolves() {
    let root = temp_dir("ioctl-empty");
    let headers = root.join("include/uapi");
    fs::create_dir_all(&headers).unwrap();
    fs::write(headers.join("empty.h"), "struct empty { int x; };\n").unwrap();
    let error = generate(&GenerateArgs {
        kernel_tree: root.clone(),
        headers: vec![PathBuf::from("include/uapi")],
        output: root.join("pack"),
        compile_commands: None,
        clang_arg: Vec::new(),
        manifest: None,
        emit_rust: None,
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("no valid ioctl descriptors"), "{error}");
}

#[test]
fn generator_marks_unsafe_layout_members_opaque_and_merges_aliases() {
    let root = temp_dir("ioctl-layouts");
    let headers = root.join("include/uapi");
    fs::create_dir_all(&headers).unwrap();
    fs::write(
        headers.join("complex.h"),
        r#"
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
#define _IOC(dir,type,nr,size) (((dir)<<30)|((type)<<8)|(nr)|((size)<<16))
#define _IOWR(type,nr,data) _IOC(3,(type),(nr),sizeof(data))
enum mode { MODE_ZERO, MODE_ONE };
struct inner { __u32 value; };
struct complex {
    __u32 len;
    enum mode mode;
    __u16 values[2];
    struct inner nested;
    union { __u32 one; __u16 two; } choice;
    unsigned int flags:3;
    void *ptr;
    __u8 flex[];
};
#define COMPLEX_IOCTL _IOWR('Z', 2, struct complex)
#define COMPLEX_IOCTL_ALIAS COMPLEX_IOCTL
"#,
    )
    .unwrap();
    let output = root.join("pack");
    generate(&GenerateArgs {
        kernel_tree: root.clone(),
        headers: vec![PathBuf::from("include/uapi")],
        output: output.clone(),
        compile_commands: None,
        clang_arg: Vec::new(),
        manifest: None,
        emit_rust: None,
    })
    .unwrap();

    let pack: SchemaPack =
        serde_json::from_slice(&fs::read(output.join("schema.json")).unwrap()).unwrap();
    assert_eq!(pack.descriptors.len(), 1, "macro aliases are deduplicated");
    let fields = &pack.descriptors[0].fields;
    assert_eq!(
        fields.iter().find(|f| f.name == "mode").unwrap().kind,
        "enum"
    );
    assert_eq!(
        fields.iter().find(|f| f.name == "values").unwrap().count,
        Some(2)
    );
    assert!(fields.iter().find(|f| f.name == "nested").unwrap().opaque);
    assert!(fields.iter().find(|f| f.name == "choice").unwrap().opaque);
    assert!(fields.iter().find(|f| f.name == "flags").unwrap().opaque);
    assert_eq!(
        fields.iter().find(|f| f.name == "ptr").unwrap().kind,
        "pointer"
    );
    assert!(fields.iter().find(|f| f.name == "flex").unwrap().opaque);
}

#[test]
fn generator_applies_relative_compile_database_and_explicit_clang_args() {
    let root = temp_dir("ioctl-compile-db");
    let headers = root.join("uapi");
    let vendor = root.join("vendor");
    fs::create_dir_all(&headers).unwrap();
    fs::create_dir_all(&vendor).unwrap();
    fs::write(vendor.join("defs.h"), "#define SAMPLE_MAGIC 'Q'\n").unwrap();
    fs::write(
        headers.join("sample.h"),
        r#"
#include "defs.h"
#define _IOC(dir,type,nr,size) (((dir)<<30)|((type)<<8)|(nr)|((size)<<16))
#define _IOWR(type,nr,data) _IOC(3,(type),(nr),sizeof(data))
struct sample { unsigned int value; };
#define SAMPLE_IOCTL _IOWR(SAMPLE_MAGIC, SAMPLE_NR, struct sample)
"#,
    )
    .unwrap();
    let compile_commands = root.join("compile_commands.json");
    fs::write(
        &compile_commands,
        serde_json::to_vec(&serde_json::json!([{
            "directory": root,
            "arguments": ["clang", "-I", "vendor", "-c", "unused.c"]
        }]))
        .unwrap(),
    )
    .unwrap();
    let output = root.join("pack");
    generate(&GenerateArgs {
        kernel_tree: root.clone(),
        headers: vec![PathBuf::from("uapi")],
        output: output.clone(),
        compile_commands: Some(compile_commands),
        clang_arg: vec!["-DSAMPLE_NR=7".into()],
        manifest: None,
        emit_rust: None,
    })
    .unwrap();

    let pack: SchemaPack =
        serde_json::from_slice(&fs::read(output.join("schema.json")).unwrap()).unwrap();
    assert_eq!(pack.descriptors[0].magic, b'Q' as u32);
    assert_eq!(pack.descriptors[0].nr, 7);
    assert!(pack
        .metadata
        .clang_invocation
        .iter()
        .any(|arg| arg == "-DSAMPLE_NR=7"));
    assert!(pack
        .metadata
        .clang_invocation
        .iter()
        .any(|arg| arg.ends_with("/vendor")));
}

#[test]
fn malformed_ioctl_header_propagates_clang_failure() {
    let root = temp_dir("ioctl-malformed");
    let headers = root.join("uapi");
    fs::create_dir_all(&headers).unwrap();
    fs::write(
        headers.join("bad.h"),
        "#define _IOWR(t,n,x) sizeof(x)\n#define BAD _IOWR('B', 1, struct missing)\n",
    )
    .unwrap();
    let error = generate(&GenerateArgs {
        kernel_tree: root.clone(),
        headers: vec![PathBuf::from("uapi")],
        output: root.join("pack"),
        compile_commands: None,
        clang_arg: Vec::new(),
        manifest: None,
        emit_rust: None,
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("clang failed"), "{error}");
}

#[test]
fn manifest_supplies_exact_driver_constraints() {
    let root = temp_dir("ioctl-manifest");
    let headers = root.join("uapi");
    fs::create_dir_all(&headers).unwrap();
    fs::write(
        headers.join("sample.h"),
        r#"
#define _IOC(d,t,n,s) (((d)<<30)|((t)<<8)|(n)|((s)<<16))
#define _IOR(t,n,x) _IOC(2,(t),(n),sizeof(x))
struct sample { unsigned int value; };
#define SAMPLE_READ _IOR('S', 9, struct sample)
"#,
    )
    .unwrap();
    let manifest = root.join("manifest.json");
    fs::write(
        &manifest,
        serde_json::to_vec(&serde_json::json!({
            "descriptors": {
                "SAMPLE_READ": {
                    "family": "sample",
                    "fd_paths": ["/dev/sample*"],
                    "evidence": "Kbuild: sample.o",
                    "confidence": "exact"
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let output = root.join("schema.json");
    generate(&GenerateArgs {
        kernel_tree: root.clone(),
        headers: vec![PathBuf::from("uapi")],
        output: output.clone(),
        compile_commands: None,
        clang_arg: vec!["--target=x86_64-linux-gnu".into()],
        manifest: Some(manifest),
        emit_rust: None,
    })
    .unwrap();

    let pack: SchemaPack = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(pack.metadata.target_abi, "x86_64");
    assert_eq!(pack.descriptors[0].family.as_deref(), Some("sample"));
    assert_eq!(pack.descriptors[0].fd_paths, ["/dev/sample*"]);
    assert_eq!(pack.driver_evidence[0].confidence, "exact");
    assert_eq!(pack.driver_evidence[0].evidence, "Kbuild: sample.o");
}
