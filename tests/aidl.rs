use std::fs;
use std::path::PathBuf;

use clap::Parser;
use neutron::aidl::{decode_plugin, index_catalog, AidlCatalog, IndexArgs, ParcelView};
use neutron::binder_services::{BinderCatalog, BinderMethodMap, BinderServiceMap};
use neutron::cli::{AidlCommand, Cli, Command};
use sha2::{Digest, Sha256};

fn catalog() -> AidlCatalog {
    AidlCatalog::from_json(
        r#"{
          "schema":"neutron.aidl-catalog/v1",
          "interfaces":[{
            "descriptor":"android.hardware.security.keymint.IKeyMintDevice",
            "versions":[{
              "version":"3",
              "stability":"vintf",
              "provenance":["aosp:hardware/interfaces/security/keymint/aidl/IKeyMintDevice.aidl"],
              "transactions":[{
                "code":1,
                "method":"generateKey",
                "return_type":"KeyCreationResult",
                "oneway":false,
                "arguments":[{"name":"keyParams","type":"KeyParameter[]","direction":"in"}],
                "source":"aosp:hardware/interfaces/security/keymint/aidl/IKeyMintDevice.aidl",
                "confidence":"verified"
              }]
            }]
          }],
          "diagnostics":[]
        }"#,
    )
    .unwrap()
}

#[test]
fn cli_registers_aidl_index_decode_and_trace_catalog() {
    let cli = Cli::try_parse_from([
        "neutron",
        "aidl",
        "index",
        "aosp",
        "--vendor-tree",
        "vendor",
        "--output",
        "aidl-catalog.json",
        "--strict",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Aidl(AidlCommand::Index(_)))
    ));

    let cli = Cli::try_parse_from([
        "neutron",
        "aidl",
        "decode",
        "case",
        "--catalog",
        "aidl-catalog.json",
        "--plugin",
        "keymint",
        "--output",
        "decoded-aidl.json",
        "--show-sensitive-bytes",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Aidl(AidlCommand::Decode(_)))
    ));

    let cli = Cli::try_parse_from([
        "neutron",
        "trace",
        "--aidl-catalog",
        "aidl-catalog.json",
    ])
    .unwrap();
    let Some(Command::Trace(args)) = cli.command else {
        panic!("trace command expected")
    };
    assert_eq!(args.aidl_catalog.as_deref(), Some("aidl-catalog.json"));
}

#[test]
fn exact_descriptor_resolves_catalog_but_candidates_never_guess_method() {
    let aidl = catalog();
    let exact = BinderServiceMap::from_json(
        r#"{"300":{"7":"android.hardware.security.keymint.IKeyMintDevice/default"}}"#,
    )
    .unwrap();
    let legacy = BinderMethodMap::default();
    let mut candidates = BinderCatalog::default();
    candidates.merge_service_list(
        "0 default: [android.hardware.security.keymint.IKeyMintDevice] pid=200\n",
    );

    let verified = candidates
        .resolve_with_aidl(&exact, &legacy, Some(&aidl), 300, 7, 1)
        .unwrap();
    assert_eq!(
        verified.interface_descriptor.as_deref(),
        Some("android.hardware.security.keymint.IKeyMintDevice")
    );
    assert_eq!(verified.method.as_deref(), Some("generateKey"));
    assert_eq!(verified.aidl_version.as_deref(), Some("3"));
    assert!(verified.catalog_source.as_deref().unwrap().starts_with("aosp:"));

    let candidate = candidates
        .resolve_with_aidl(&exact, &legacy, Some(&aidl), 200, 9, 1)
        .unwrap();
    assert_eq!(candidate.method, None);
    assert_eq!(
        candidate.interface_candidates,
        vec!["android.hardware.security.keymint.IKeyMintDevice"]
    );

    let unknown = candidates
        .resolve_with_aidl(&exact, &legacy, Some(&aidl), 300, 7, 99)
        .unwrap();
    assert_eq!(unknown.method_label(), "code=99");
}

#[test]
fn conflicting_legacy_method_is_rejected() {
    let exact = BinderServiceMap::from_json(
        r#"{"300":{"7":"android.hardware.security.keymint.IKeyMintDevice/default"}}"#,
    )
    .unwrap();
    let legacy = BinderMethodMap::from_json(
        r#"{"android.hardware.security.keymint.IKeyMintDevice/default":{"1":"deleteKey"}}"#,
    )
    .unwrap();
    let error = BinderCatalog::default()
        .resolve_with_aidl(&exact, &legacy, Some(&catalog()), 300, 7, 1)
        .unwrap_err();
    assert!(error.to_string().contains("conflicting"));
}

fn utf16_token(descriptor: &str) -> Vec<u8> {
    let mut bytes = vec![0; 8];
    let units = descriptor.encode_utf16().collect::<Vec<_>>();
    bytes.extend_from_slice(&(units.len() as i32).to_le_bytes());
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes
}

fn parameter(tag: i32, value_tag: i32, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let size = 12 + value.len();
    bytes.extend_from_slice(&(size as i32).to_le_bytes());
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&value_tag.to_le_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn keymint_parcel() -> Vec<u8> {
    const ALGORITHM: i32 = 0x1000_0002;
    const APPLICATION_ID: i32 = 0x9000_0259u32 as i32;
    let mut parcel = utf16_token("android.hardware.security.keymint.IKeyMintDevice");
    parcel.extend_from_slice(&2i32.to_le_bytes());
    parcel.extend(parameter(ALGORITHM, 1, &32i32.to_le_bytes()));
    let mut blob = 3i32.to_le_bytes().to_vec();
    blob.extend_from_slice(&[1, 2, 3]);
    blob.push(0);
    parcel.extend(parameter(APPLICATION_ID, 14, &blob));
    parcel
}

#[test]
fn keymint_plugin_decodes_known_values_and_redacts_blobs() {
    let parcel = keymint_parcel();
    let view = ParcelView::new(&parcel, &[]).unwrap();
    let decoded = decode_plugin(
        "keymint",
        view,
        "android.hardware.security.keymint.IKeyMintDevice",
        "generateKey",
        catalog().lookup(
            "android.hardware.security.keymint.IKeyMintDevice",
            1,
        )
        .unwrap()
        .method,
        false,
    );
    assert_eq!(decoded["status"], "decoded");
    assert_eq!(decoded["arguments"]["keyParams"][0]["tag_name"], "ALGORITHM");
    assert_eq!(decoded["arguments"]["keyParams"][0]["value"]["variant"], "algorithm");
    assert_eq!(decoded["arguments"]["keyParams"][1]["tag_name"], "APPLICATION_ID");
    assert_eq!(decoded["arguments"]["keyParams"][1]["value"]["length"], 3);
    assert_eq!(
        decoded["arguments"]["keyParams"][1]["value"]["sha256"],
        format!("{:x}", Sha256::digest([1, 2, 3]))
    );
    assert!(decoded["arguments"]["keyParams"][1]["value"]
        .get("bytes")
        .is_none());
}

#[test]
fn keymint_plugin_preserves_unknown_union_tags_and_rejects_bad_views() {
    let mut parcel = utf16_token("android.hardware.security.keymint.IKeyMintDevice");
    parcel.extend_from_slice(&1i32.to_le_bytes());
    parcel.extend(parameter(123, 99, &7i32.to_le_bytes()));
    let decoded = decode_plugin(
        "keymint",
        ParcelView::new(&parcel, &[]).unwrap(),
        "android.hardware.security.keymint.IKeyMintDevice",
        "generateKey",
        catalog().lookup(
            "android.hardware.security.keymint.IKeyMintDevice",
            1,
        )
        .unwrap()
        .method,
        false,
    );
    assert_eq!(decoded["status"], "unsupported");
    assert_eq!(decoded["arguments"]["keyParams"][0]["value"]["union_tag"], 99);

    assert!(ParcelView::new(&parcel, &[parcel.len() as u64 + 1]).is_err());
    let truncated = &keymint_parcel()[..12];
    let decoded = decode_plugin(
        "keymint",
        ParcelView::new(truncated, &[]).unwrap(),
        "android.hardware.security.keymint.IKeyMintDevice",
        "generateKey",
        catalog().lookup(
            "android.hardware.security.keymint.IKeyMintDevice",
            1,
        )
        .unwrap()
        .method,
        false,
    );
    assert_eq!(decoded["status"], "truncated");
}

#[test]
fn catalog_json_is_deterministic_and_rejects_wrong_schema() {
    let first = catalog().to_pretty_json().unwrap();
    let second = AidlCatalog::from_json(&first)
        .unwrap()
        .to_pretty_json()
        .unwrap();
    assert_eq!(first, second);
    assert!(AidlCatalog::from_json(r#"{"schema":"wrong","interfaces":[]}"#).is_err());
}

#[test]
fn index_uses_generated_transaction_constants_and_is_deterministic() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!("neutron-aidl-index-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let tree = root.join("tree");
    fs::create_dir_all(tree.join("test")).unwrap();
    fs::write(
        tree.join("test/ITest.aidl"),
        "package test;\n@VintfStability interface ITest { oneway void ping(in int value) = 4; }\n",
    )
    .unwrap();
    fs::write(tree.join("test/Data.aidl"), "package test; parcelable Data;\n").unwrap();

    let compiler = root.join("fake-aidl");
    fs::write(
        &compiler,
        r#"#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; continue; fi
  case "$1" in --out=*) out="${1#--out=}";; esac
  shift
done
mkdir -p "$out/test"
printf '%s\n' 'public interface ITest {' 'String DESCRIPTOR = "test.ITest";' 'static final int TRANSACTION_ping = (android.os.IBinder.FIRST_CALL_TRANSACTION + 4);' '}' > "$out/test/ITest.java"
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&compiler).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&compiler, permissions).unwrap();

    let args = IndexArgs {
        aosp_root: tree,
        vendor_tree: Vec::new(),
        output: root.join("catalog.json"),
        aidl_bin: Some(compiler),
        strict: true,
    };
    let first = index_catalog(&args).unwrap().to_pretty_json().unwrap();
    let second = index_catalog(&args).unwrap().to_pretty_json().unwrap();
    assert_eq!(first, second);
    let indexed = AidlCatalog::from_json(&first).unwrap();
    let lookup = indexed.lookup("test.ITest", 5).unwrap();
    assert_eq!(lookup.method.method, "ping");
    assert!(lookup.method.oneway);
    assert_eq!(lookup.method.arguments[0].name, "value");
    assert_eq!(indexed.interfaces.len(), 1, "parcelable-only file ignored");
}

#[test]
fn decode_output_path_example_is_separate_from_testcase() {
    let root = std::env::temp_dir().join(format!("neutron-aidl-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("case")).unwrap();
    let output = root.join("decoded-aidl.json");
    let testcase = PathBuf::from(root.join("case"));
    assert!(!output.starts_with(testcase));
}
