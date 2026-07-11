use neutron::native::{
    aggregate_bookmarks, elf_map_metadata, translate_ip, CapturedMapping, GhidraBookmarkInput,
    NativeConfidence,
};
use std::process::Command;

#[test]
fn translates_non_zero_pt_load_offsets_exactly() {
    let exe = std::env::current_exe().unwrap();
    let bytes = std::fs::read(exe).unwrap();
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    let segment = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD && ph.p_filesz > 0)
        .unwrap();
    let delta = segment.p_filesz.min(0x20) - 1;
    let bias = 0x7000_0000_0000u64;
    let start = bias + segment.p_vaddr + delta;
    let offset = segment.p_offset + delta;
    let metadata = elf_map_metadata(&bytes, start, offset).unwrap();
    let mapping = CapturedMapping {
        start,
        end: start + 0x1000,
        offset,
        path: "/system/lib64/libfixture.so".into(),
        load_bias: metadata.load_bias,
        elf_type: metadata.elf_type,
        build_id: metadata.build_id,
        ..CapturedMapping::default()
    };

    let translated = translate_ip(&mapping, start + 0x42).unwrap();
    assert_eq!(translated.elf_vaddr, segment.p_vaddr + delta + 0x42);
    assert_eq!(translated.file_offset, offset + 0x42);
}

#[test]
fn bookmarks_aggregate_by_program_and_vaddr_deterministically() {
    let mut candidate = GhidraBookmarkInput::fixture("aa", 0x1234, "openat", 20);
    candidate.confidence = NativeConfidence::Candidate;
    candidate.program.captured_paths = vec!["/second/libfixture.so".into()];
    let inputs = vec![
        candidate,
        GhidraBookmarkInput::fixture("aa", 0x1234, "ioctl", 10),
    ];
    let document = aggregate_bookmarks(inputs, 32);

    assert_eq!(document.schema, "neutron.ghidra-bookmarks/v1");
    assert_eq!(document.programs.len(), 1);
    let bookmark = &document.programs[0].bookmarks[0];
    assert_eq!(bookmark.frequency, 2);
    assert_eq!(bookmark.contexts, vec!["ioctl", "openat"]);
    assert_eq!(bookmark.first_timestamp_ns, 10);
    assert_eq!(bookmark.last_timestamp_ns, 20);
    assert_eq!(bookmark.confidence, NativeConfidence::Candidate);
    assert_eq!(
        document.programs[0].program.captured_paths,
        vec!["/fixture.so", "/second/libfixture.so"]
    );
}

#[test]
fn cli_writes_versioned_native_and_ghidra_documents() {
    let root = std::env::temp_dir().join(format!(
        "neutron-native-map-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let capture = root.join("capture.ndjson");
    std::fs::write(
        &capture,
        concat!(
            "{\"type\":\"process_maps\",\"pid\":42,\"starttime\":9,\"maps_generation\":1,\"timestamp_ns\":10,\"mappings\":[{\"start\":4096,\"end\":8192,\"offset\":0,\"path\":\"/system/lib64/libfixture.so\",\"elf_type\":\"ET_DYN\",\"build_id\":\"aa\",\"load_bias\":0}]}\n",
            "{\"type\":\"stack_trace\",\"stack_trace_ref\":\"42:9:1:user:7\",\"pid\":42,\"starttime\":9,\"stack_kind\":\"user\",\"stack_id\":7,\"maps_generation\":1,\"timestamp_ns\":10,\"ips\":[4352],\"rendered\":[\"libfixture.so:camera_call+0x4\"]}\n",
            "{\"type\":\"syscall\",\"ts_ns\":10,\"pid\":42,\"event_id\":3,\"name\":\"ioctl\",\"stack_trace_refs\":[\"42:9:1:user:7\"]}\n"
        ),
    )
    .unwrap();
    let native = root.join("native.json");
    let output = Command::new(env!("CARGO_BIN_EXE_neutron"))
        .args(["native-map", capture.to_str().unwrap(), "--json-output"])
        .arg(&native)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&native).unwrap()).unwrap();
    assert_eq!(value["schema"], "neutron.native-map/v1");
    assert_eq!(value["events"][0]["context"], "ioctl");

    let ghidra = root.join("ghidra.json");
    let output = Command::new(env!("CARGO_BIN_EXE_neutron"))
        .args(["ghidra-export", capture.to_str().unwrap(), "--output"])
        .arg(&ghidra)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ghidra).unwrap()).unwrap();
    assert_eq!(value["schema"], "neutron.ghidra-bookmarks/v1");
    assert_eq!(value["programs"][0]["bookmarks"][0]["elf_vaddr"], 4352);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn native_output_rejects_hardlink_without_truncating_source() {
    let root = std::env::temp_dir().join(format!(
        "neutron-native-output-security-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let capture = root.join("capture.ndjson");
    std::fs::write(&capture, "").unwrap();
    let source = root.join("source.json");
    let output = root.join("output.json");
    std::fs::write(&source, b"keep-me").unwrap();
    std::fs::hard_link(&source, &output).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_neutron"))
        .args(["native-map", capture.to_str().unwrap(), "--json-output"])
        .arg(&output)
        .status()
        .unwrap();

    assert!(!status.success());
    assert_eq!(std::fs::read(&source).unwrap(), b"keep-me");
    let _ = std::fs::remove_dir_all(root);
}
