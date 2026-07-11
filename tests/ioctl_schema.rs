use neutron::ioctl_schema::{
    install_registry, Descriptor, Field, PackMetadata, RuntimeIdentity, SchemaPack, SchemaRegistry,
    Selectors,
};
use neutron::{decode::decode_ioctl_with_context, decode::render_decoded_ioctl_json};

fn descriptor(id: &str, name: &str, cmd: u32, path: &str) -> Descriptor {
    Descriptor {
        id: id.into(),
        name: name.into(),
        cmd,
        magic: (cmd >> 8) & 0xff,
        nr: cmd & 0xff,
        direction: (cmd >> 30) & 3,
        size: (cmd >> 16) & 0x3fff,
        type_name: "struct sample".into(),
        family: Some("sample".into()),
        fd_paths: vec![path.into()],
        fields: vec![
            Field::scalar("len", 0, 8, "u64"),
            Field::scalar("fd", 8, 4, "i32"),
            Field::scalar("ptr", 16, 8, "pointer"),
        ],
        capture_eligible: true,
        provenance: vec!["sample.h:1".into()],
        replaces: Vec::new(),
    }
}

fn pack(descriptors: Vec<Descriptor>) -> SchemaPack {
    let mut pack = SchemaPack {
        schema: "neutron.ioctl-schema/v1".into(),
        metadata: PackMetadata {
            name: "sample".into(),
            target_abi: std::env::consts::ARCH.into(),
            selectors: Selectors::default(),
            source_revision: None,
            clang_invocation: vec!["clang".into()],
        },
        descriptors,
        layouts: Vec::new(),
        driver_evidence: Vec::new(),
        content_hash: String::new(),
    };
    pack.seal().unwrap();
    pack
}

#[test]
fn generic_decoder_is_bounded_and_reports_truncation() {
    let cmd = 0xc018_7a01;
    let registry = SchemaRegistry::from_packs(vec![pack(vec![descriptor(
        "sample.alloc",
        "SAMPLE_ALLOC",
        cmd,
        "/dev/sample*",
    )])])
    .unwrap();
    let mut payload = [0u8; 12];
    payload[0..8].copy_from_slice(&4096u64.to_le_bytes());
    payload[8..12].copy_from_slice(&12i32.to_le_bytes());

    let decoded = registry
        .decode(cmd, &payload, Some("/dev/sample0"), None)
        .unwrap();
    assert_eq!(decoded.name, "SAMPLE_ALLOC");
    assert_eq!(decoded.fields.expected_size, 24);
    assert_eq!(decoded.fields.captured_size, 12);
    assert!(decoded.fields.truncated);
    assert_eq!(decoded.fields.values["len"], 4096);
    assert_eq!(decoded.fields.values["fd"], 12);
    assert!(!decoded.fields.values.contains_key("ptr"));
}

#[test]
fn full_cmd_and_fd_path_disambiguate_magic_collisions() {
    let cmd = 0xc018_4800;
    let mut dma = descriptor("dma.alloc", "DMA_ALLOC", cmd, "/dev/dma_heap/*");
    dma.family = Some("dma_heap".into());
    let mut snd = descriptor("snd.alloc", "SND_ALLOC", cmd, "/dev/snd/*");
    snd.family = Some("alsa".into());
    let registry = SchemaRegistry::from_packs(vec![pack(vec![dma, snd])]).unwrap();

    assert_eq!(
        registry
            .decode(cmd, &[0; 24], Some("/dev/dma_heap/system"), None)
            .unwrap()
            .name,
        "DMA_ALLOC"
    );
    assert_eq!(
        registry
            .decode(cmd, &[0; 24], Some("/dev/snd/hwC0D0"), None)
            .unwrap()
            .name,
        "SND_ALLOC"
    );
}

#[test]
fn conflicting_descriptor_requires_explicit_replacement() {
    let cmd = 0xc018_7a01;
    let first = descriptor("sample.alloc", "SAMPLE_ALLOC", cmd, "/dev/sample*");
    let mut conflict = first.clone();
    conflict.name = "SAMPLE_ALLOC_V2".into();
    let error = SchemaRegistry::from_packs(vec![pack(vec![first.clone()]), pack(vec![conflict.clone()])])
        .unwrap_err()
        .to_string();
    assert!(error.contains("replaces"), "{error}");

    conflict.replaces.push(first.id.clone());
    let registry = SchemaRegistry::from_packs(vec![pack(vec![first]), pack(vec![conflict])]).unwrap();
    assert_eq!(
        registry
            .decode(cmd, &[0; 24], Some("/dev/sample0"), None)
            .unwrap()
            .name,
        "SAMPLE_ALLOC_V2"
    );
}

#[test]
fn pack_hash_and_runtime_abi_are_verified() {
    let cmd = 0xc018_7a01;
    let mut valid = pack(vec![descriptor(
        "sample.alloc",
        "SAMPLE_ALLOC",
        cmd,
        "/dev/sample*",
    )]);
    valid.verify(&RuntimeIdentity::current()).unwrap();

    valid.descriptors[0].name.push_str("_TAMPERED");
    assert!(valid.verify(&RuntimeIdentity::current()).is_err());

    let mut wrong_abi = pack(Vec::new());
    wrong_abi.metadata.target_abi = "definitely-not-this-abi".into();
    wrong_abi.seal().unwrap();
    assert!(wrong_abi.verify(&RuntimeIdentity::current()).is_err());
}

#[test]
fn read_descriptors_are_exported_as_refresh_commands() {
    let cmd = 0x8018_7a02;
    let registry = SchemaRegistry::from_packs(vec![pack(vec![descriptor(
        "sample.read",
        "SAMPLE_READ",
        cmd,
        "/dev/sample*",
    )])])
    .unwrap();
    assert_eq!(registry.refresh_cmds().collect::<Vec<_>>(), vec![cmd]);
}

#[test]
fn active_pack_adds_ioctl_fields_without_replacing_legacy_objects() {
    let cmd = 0xc018_4800;
    let mut dma = descriptor(
        "dma.heap.alloc",
        "DMA_HEAP_IOCTL_ALLOC",
        cmd,
        "/dev/dma_heap/*",
    );
    dma.family = Some("dma_heap".into());
    dma.fields[1].name = "returned_fd".into();
    install_registry(SchemaRegistry::from_packs(vec![pack(vec![dma])]).unwrap());
    let mut payload = [0u8; 24];
    payload[0..8].copy_from_slice(&4096u64.to_le_bytes());
    payload[8..12].copy_from_slice(&12i32.to_le_bytes());

    let decoded = decode_ioctl_with_context(
        cmd,
        &payload,
        0,
        None,
        Some("/dev/dma_heap/system"),
    );
    let json: serde_json::Value = serde_json::from_str(&format!(
        "{{{}}}",
        render_decoded_ioctl_json(&decoded).trim_start_matches(',')
    ))
    .unwrap();
    assert_eq!(json["ioctl_name"], "DMA_HEAP_IOCTL_ALLOC");
    assert_eq!(json["dma_heap"]["returned_fd"], 12);
    assert_eq!(json["ioctl_fields"]["expected_size"], 24);
    assert_eq!(json["ioctl_fields"]["values"]["len"], 4096);
    assert_eq!(json["ioctl_fields"]["values"]["returned_fd"], 12);
}
