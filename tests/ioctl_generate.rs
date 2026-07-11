use std::fs;
use std::path::PathBuf;

use clap::Parser;
use neutron::cli::{Cli, Command, IoctlCommand};
use neutron::ioctl_schema::{generate, GenerateArgs, RuntimeIdentity, SchemaPack};

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
    pack.verify(&RuntimeIdentity::current()).unwrap();
    let descriptor = &pack.descriptors[0];
    assert_eq!(descriptor.name, "DMA_HEAP_IOCTL_ALLOC");
    assert_eq!(descriptor.cmd, 0xc018_4800);
    assert_eq!(descriptor.size, 24);
    assert_eq!(descriptor.fields[0].name, "len");
    assert_eq!(descriptor.fields[1].offset, 8);
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
