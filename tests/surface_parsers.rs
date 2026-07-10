use neutron::surface::{
    ioctl_label, parse_dumpsys_pid, parse_lshal_inventory, parse_module_names,
    parse_process_starttime, parse_process_status, parse_service_list_inventory,
    parse_vintf_manifest, parse_vndservice_list,
};

#[test]
fn service_inventory_is_deduplicated_and_sorted_by_name() {
    let input = r#"
Found 4 services:
3 zeta: [example.IZeta]
0 activity: [android.app.IActivityManager]
2 alpha: [example.IAlpha]
1 activity: [android.app.IActivityManager]
"#;

    let services = parse_service_list_inventory(input);
    let names: Vec<&str> = services
        .iter()
        .map(|service| service.name.as_str())
        .collect();

    assert_eq!(names, ["activity", "alpha", "zeta"]);
}

#[test]
fn vndservice_inventory_parses_vendor_service_names() {
    let input = r#"
1 vendor.example.second: [vendor.example.ISecond]
0 vendor.example.first: [vendor.example.IFirst]
"#;

    let services = parse_vndservice_list(input);
    let names: Vec<&str> = services
        .iter()
        .map(|service| service.name.as_str())
        .collect();

    assert_eq!(names, ["vendor.example.first", "vendor.example.second"]);
}

#[test]
fn lshal_inventory_keeps_proven_pids_and_stable_order() {
    let input = r#"
android.hardware.security.keymint@2.0::IKeyMintDevice/default 4/4 525
android.hardware.camera.provider@2.7::ICameraProvider/default 4/4 300
"#;

    let services = parse_lshal_inventory(input);

    assert_eq!(
        services[0].name,
        "android.hardware.camera.provider@2.7::ICameraProvider/default"
    );
    assert_eq!(services[0].pid, Some(300));
    assert_eq!(
        services[1].name,
        "android.hardware.security.keymint@2.0::IKeyMintDevice/default"
    );
    assert_eq!(services[1].pid, Some(525));
}

#[test]
fn dumpsys_pid_accepts_only_one_exact_numeric_line() {
    assert_eq!(parse_dumpsys_pid("525\n"), Some(525));
    assert_eq!(parse_dumpsys_pid("  525  \n"), Some(525));
    assert_eq!(parse_dumpsys_pid("service pid: 525\n"), None);
    assert_eq!(parse_dumpsys_pid("525\n526\n"), None);
}

#[test]
fn vintf_manifest_parses_aidl_and_hidl_declarations() {
    let xml = r#"
<manifest version="2.0" type="device">
  <hal format="aidl">
    <name>android.hardware.security.keymint</name>
    <version>3</version>
    <fqname>IKeyMintDevice/default</fqname>
  </hal>
  <hal format="hidl">
    <name>android.hardware.camera.provider</name>
    <transport>hwbinder</transport>
    <version>2.7</version>
    <interface>
      <name>ICameraProvider</name>
      <instance>default</instance>
    </interface>
  </hal>
</manifest>
"#;

    let declarations = parse_vintf_manifest(xml).expect("valid VINTF manifest");
    let aidl = declarations
        .iter()
        .find(|declaration| declaration.format == "aidl")
        .expect("AIDL declaration");
    assert_eq!(aidl.package, "android.hardware.security.keymint");
    assert_eq!(aidl.interface, "IKeyMintDevice");
    assert_eq!(aidl.instance, "default");

    let hidl = declarations
        .iter()
        .find(|declaration| declaration.format == "hidl")
        .expect("HIDL declaration");
    assert_eq!(hidl.package, "android.hardware.camera.provider");
    assert_eq!(hidl.interface, "ICameraProvider");
    assert_eq!(hidl.instance, "default");
    assert_eq!(hidl.transport.as_deref(), Some("hwbinder"));
}

#[test]
fn malformed_vintf_manifest_is_an_error() {
    assert!(parse_vintf_manifest("<manifest><hal>").is_err());
}

#[test]
fn process_status_reads_real_uid_and_gid() {
    let status = r#"Name:	android.hardwar
State:	S (sleeping)
Uid:	10123	10124	10125	10126
Gid:	3003	3004	3005	3006
"#;

    let parsed = parse_process_status(status).expect("valid process status");

    assert_eq!(parsed.uid, 10123);
    assert_eq!(parsed.gid, 3003);
}

#[test]
fn process_starttime_handles_spaces_in_comm() {
    let stat =
        "123 (android.hardware camera) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 19";

    assert_eq!(parse_process_starttime(stat).unwrap(), 424_242);
}

#[test]
fn module_names_are_unique_and_sorted() {
    let modules = r#"
zeta 4096 0 - Live 0xffffffffc0200000
alpha 8192 1 zeta, Live 0xffffffffc0100000
zeta 4096 0 - Live 0xffffffffc0200000
"#;

    assert_eq!(parse_module_names(modules), ["alpha", "zeta"]);
}

#[test]
fn ioctl_labels_cover_trusty_v4l2_and_unknown_commands() {
    assert_eq!(ioctl_label(0x4008_7280), "TIPC_IOC_CONNECT");
    assert_eq!(ioctl_label(0x4004_7280), "TIPC_IOC_CONNECT");
    assert_eq!(ioctl_label(0xc058_560f), "VIDIOC_QBUF");
    assert_eq!(ioctl_label(0xdead_beef), "cmd=0xdeadbeef");
}
