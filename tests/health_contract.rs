use neutron::health::{
    capture_health_contract_errors, capture_health_is_complete,
    format_capture_health_json_with_metadata, CaptureHealth, CaptureMetadata, CaptureScope,
    KprobePackScope, UserspaceHealth,
};
use neutron_common::{
    COUNTER_EVENTS_SUBMITTED, COUNTER_PAYLOAD_READ_FAILED, COUNTER_RINGBUF_RESERVE_FAILED,
    COUNTER_SLOT_COUNT,
};
use serde_json::Value;

fn render(health: &CaptureHealth, userspace: &UserspaceHealth) -> Value {
    render_with_scope(health, userspace, CaptureScope::unfiltered_raw_ndjson())
}

fn render_with_scope(
    health: &CaptureHealth,
    userspace: &UserspaceHealth,
    mut scope: CaptureScope,
) -> Value {
    let mut health = health.clone();
    health.slots[COUNTER_EVENTS_SUBMITTED as usize] =
        7_u64.saturating_add(userspace.shutdown_events_discarded);
    let mut userspace = userspace.clone();
    for (requested, available, enabled, source_available) in [
        (
            &mut scope.sources.logcat_requested,
            &mut scope.sources.logcat_available,
            &mut userspace.logcat_source_enabled,
            &mut userspace.logcat_source_available,
        ),
        (
            &mut scope.sources.selinux_logcat_requested,
            &mut scope.sources.selinux_logcat_available,
            &mut userspace.selinux_source_enabled,
            &mut userspace.selinux_source_available,
        ),
        (
            &mut scope.sources.tombstone_requested,
            &mut scope.sources.tombstone_available,
            &mut userspace.tombstone_source_enabled,
            &mut userspace.tombstone_source_available,
        ),
    ] {
        if *enabled {
            *requested = true;
            *available = *source_available;
        } else if *requested {
            *enabled = true;
            *source_available = *available;
        }
    }
    scope = scope.recompute_claim_scope();
    let mut attached_programs = vec![
        "trace_sys_enter".into(),
        "trace_sys_exit".into(),
        "trace_sched_process_exit".into(),
    ];
    if scope.instrumentation.binder_tracepoints {
        attached_programs.extend([
            "trace_binder_transaction".into(),
            "trace_binder_transaction_received".into(),
        ]);
    }
    attached_programs.extend(
        scope
            .packs
            .kprobe
            .iter()
            .flat_map(|pack| &pack.attached_sources)
            .map(|source| source.split_once('@').unwrap().0.to_string()),
    );
    let metadata = CaptureMetadata {
        driver_packs: scope.packs.driver.clone(),
        kprobe_packs: scope
            .packs
            .kprobe
            .iter()
            .map(|pack| pack.name.clone())
            .collect(),
        attached_programs,
        match_packages: scope.filters.match_packages.clone(),
        root_package: scope.observation.root_package.clone(),
        root_uid: scope.observation.root_uid,
        max_depth: scope.instrumentation.max_depth,
        max_processes: scope.instrumentation.max_processes,
        boot_id: Some("11111111-2222-3333-4444-555555555555".into()),
        bpf_object_sha256: Some(scope.producer.bpf_object_sha256.clone()),
        bpf_build_id: Some(scope.producer.bpf_build_id.clone()),
        bpf_abi_major: Some(neutron_common::BPF_ABI_MAJOR),
        bpf_abi_minor: Some(neutron_common::BPF_ABI_MINOR),
        bpf_event_size: Some(core::mem::size_of::<neutron_common::SyscallEvent>() as u32),
        bpf_feature_bits: Some(scope.producer.bpf_feature_bits),
        ring_size_bytes: Some(1 << 20),
        capture_scope: Some(scope),
        ..CaptureMetadata::default()
    };
    serde_json::from_str(&format_capture_health_json_with_metadata(
        &health, &userspace, 7, &metadata,
    ))
    .expect("capture health must be valid JSON")
}

#[test]
fn clean_health_json_status_is_complete() {
    let value = render(&CaptureHealth::default(), &UserspaceHealth::default());

    assert_eq!(value["status"], "complete");
    assert_eq!(value["degraded"], false);
    assert_eq!(value["binder_tracker_enabled"], true);
    assert!(value["read_errors"].as_array().is_some_and(Vec::is_empty));
    assert_eq!(value["capture_scope"]["schema"], "neutron.capture-scope/v1");
    assert_eq!(value["capture_scope"]["claim_scope_complete"], true);
    assert!(capture_health_is_complete(value.as_object().unwrap()));
}

#[test]
fn findings_only_is_transport_complete_but_not_claim_scope_complete() {
    let mut scope = CaptureScope::unfiltered_raw_ndjson();
    scope.output.event_mode = "findings_only".into();
    let value = render_with_scope(
        &CaptureHealth::default(),
        &UserspaceHealth::default(),
        scope.recompute_claim_scope(),
    );

    assert_eq!(value["status"], "complete");
    assert_eq!(value["degraded"], false);
    assert_eq!(value["capture_scope"]["claim_scope_complete"], false);
    assert_eq!(
        value["capture_scope"]["claim_scope_reasons"],
        serde_json::json!(["findings_only_output"])
    );
    assert!(capture_health_contract_errors(value.as_object().unwrap()).is_empty());
    assert!(!capture_health_is_complete(value.as_object().unwrap()));
}

#[test]
fn effective_filters_are_transport_complete_but_not_claim_scope_complete() {
    let mut scope = CaptureScope::unfiltered_raw_ndjson();
    scope.filters.bpf = vec!["syscall IN {29}".into(), "ioctl.type IN {0x9}".into()];
    scope.filters.userspace = vec![
        "fd_path glob {/dev/kgsl*}".into(),
        "comm glob {vendor-hal*}".into(),
        "binder.code IN {0x2}".into(),
    ];
    scope.filters.exclude_comm = vec!["traced".into()];
    scope.filters.match_expression = Some("syscall = 29 AND fd_path GLOB '/dev/kgsl*'".into());
    let value = render_with_scope(
        &CaptureHealth::default(),
        &UserspaceHealth::default(),
        scope.recompute_claim_scope(),
    );

    assert_eq!(value["status"], "complete");
    assert_eq!(value["degraded"], false);
    assert_eq!(value["capture_scope"]["claim_scope_complete"], false);
    for reason in [
        "bpf_filters",
        "userspace_filters",
        "excluded_commands",
        "match_expression",
    ] {
        assert!(value["capture_scope"]["claim_scope_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some(reason)));
    }
    assert!(capture_health_contract_errors(value.as_object().unwrap()).is_empty());
    assert!(!capture_health_is_complete(value.as_object().unwrap()));
}

#[test]
fn alert_rwx_filter_is_explicitly_outside_complete_negative_claim_scope() {
    let mut scope = CaptureScope::unfiltered_raw_ndjson();
    scope.filters.alert_rwx_only = true;
    let value = render_with_scope(
        &CaptureHealth::default(),
        &UserspaceHealth::default(),
        scope.recompute_claim_scope(),
    );

    assert_eq!(value["status"], "complete");
    assert_eq!(value["capture_scope"]["filters"]["alert_rwx_only"], true);
    assert_eq!(value["capture_scope"]["claim_scope_complete"], false);
    assert_eq!(
        value["capture_scope"]["claim_scope_reasons"],
        serde_json::json!(["alert_rwx_filter"])
    );
    assert!(capture_health_contract_errors(value.as_object().unwrap()).is_empty());
}

#[test]
fn binder_follow_domain_policy_limits_negative_claim_scope() {
    for (allow, deny) in [
        (vec!["u:r:hal_camera_default:s0".into()], Vec::new()),
        (Vec::new(), vec!["u:r:untrusted_app:s0".into()]),
    ] {
        let mut scope = CaptureScope::unfiltered_raw_ndjson();
        scope.instrumentation.follow_allow_domains = allow;
        scope.instrumentation.follow_deny_domains = deny;
        let value = render_with_scope(
            &CaptureHealth::default(),
            &UserspaceHealth::default(),
            scope.recompute_claim_scope(),
        );

        assert_eq!(value["status"], "complete");
        assert_eq!(value["capture_scope"]["claim_scope_complete"], false);
        assert_eq!(
            value["capture_scope"]["claim_scope_reasons"],
            serde_json::json!(["binder_follow_domain_filter"])
        );
        assert!(!capture_health_is_complete(value.as_object().unwrap()));
    }
}

#[test]
fn forged_complete_scope_with_domain_policy_is_rejected() {
    let mut value = render(&CaptureHealth::default(), &UserspaceHealth::default());
    value["capture_scope"]["instrumentation"]["follow_deny_domains"] =
        serde_json::json!(["u:r:untrusted_app:s0"]);

    let errors = capture_health_contract_errors(value.as_object().unwrap());
    assert!(errors
        .iter()
        .any(|error| error.contains("claim_scope_complete")));
}

#[test]
fn runtime_source_loss_is_structured_and_never_complete() {
    let userspace = UserspaceHealth {
        logcat_source_enabled: true,
        logcat_source_available: true,
        logcat_read_errors: 1,
        fd_poller_shutdown_samples_discarded: 2,
        tombstone_source_enabled: true,
        tombstone_source_available: false,
        ..UserspaceHealth::default()
    };
    let value = render(&CaptureHealth::default(), &userspace);

    assert_eq!(value["logcat_source"], "available");
    assert_eq!(value["logcat_read_errors"], 1);
    assert_eq!(value["fd_poller_shutdown_samples_discarded"], 2);
    assert_eq!(value["tombstone_source"], "unavailable");
    assert_eq!(value["status"], "unknown");
    assert!(!capture_health_is_complete(value.as_object().unwrap()));
}

#[test]
fn unsupported_logcat_fatal_classes_make_source_evidence_incomplete() {
    for userspace in [
        UserspaceHealth {
            logcat_source_enabled: true,
            logcat_source_available: true,
            logcat_unsupported_java_fatal: 1,
            ..UserspaceHealth::default()
        },
        UserspaceHealth {
            logcat_source_enabled: true,
            logcat_source_available: true,
            logcat_unsupported_anr: 1,
            ..UserspaceHealth::default()
        },
        UserspaceHealth {
            logcat_source_enabled: true,
            logcat_source_available: true,
            logcat_untrusted_native_exits: 1,
            ..UserspaceHealth::default()
        },
    ] {
        let value = render(&CaptureHealth::default(), &userspace);
        assert_eq!(value["status"], "incomplete");
        assert!(!capture_health_is_complete(value.as_object().unwrap()));
    }
}

#[test]
fn best_effort_external_sources_cannot_prove_their_own_absence() {
    let mut scope = CaptureScope::unfiltered_raw_ndjson();
    scope.sources.logcat_requested = true;
    scope.sources.logcat_available = true;
    scope.sources.selinux_logcat_requested = true;
    scope.sources.selinux_logcat_available = true;
    scope.sources.tombstone_requested = true;
    scope.sources.tombstone_available = true;
    scope.sources.tombstone_dir = Some("/data/tombstones".into());
    let value = render_with_scope(
        &CaptureHealth::default(),
        &UserspaceHealth::default(),
        scope.recompute_claim_scope(),
    );

    let reasons = value["capture_scope"]["claim_scope_reasons"]
        .as_array()
        .unwrap();
    for reason in [
        "logcat_gap_accounting_unavailable",
        "selinux_logcat_gap_accounting_unavailable",
        "tombstone_polling_gap_possible",
    ] {
        assert!(reasons.iter().any(|value| value.as_str() == Some(reason)));
    }
    assert!(!capture_health_is_complete(value.as_object().unwrap()));
}

#[test]
fn child_following_is_part_of_the_comparable_observation_scope() {
    let without_children = CaptureScope::unfiltered_raw_ndjson();
    let mut with_children = without_children.clone();
    with_children.observation.follow_children = true;

    assert_ne!(without_children, with_children);
    assert!(
        without_children
            .recompute_claim_scope()
            .claim_scope_complete
    );
    let with_children = with_children.recompute_claim_scope();
    assert!(!with_children.claim_scope_complete);
    assert_eq!(
        with_children.claim_scope_reasons,
        ["follow_children_clone3_unsupported"]
    );
}

#[test]
fn dirty_userspace_build_cannot_support_complete_negative_claims() {
    let mut scope = CaptureScope::unfiltered_raw_ndjson();
    scope.producer.userspace_git_dirty = true;
    let value = render_with_scope(
        &CaptureHealth::default(),
        &UserspaceHealth::default(),
        scope.recompute_claim_scope(),
    );

    assert_eq!(value["status"], "complete");
    assert_eq!(value["capture_scope"]["claim_scope_complete"], false);
    assert_eq!(
        value["capture_scope"]["claim_scope_reasons"],
        serde_json::json!(["userspace_source_dirty"])
    );
    assert!(!capture_health_is_complete(value.as_object().unwrap()));
}

#[test]
fn every_behavior_shaping_identity_changes_the_comparable_scope() {
    let baseline = CaptureScope::unfiltered_raw_ndjson();
    let mut variants = Vec::new();

    let mut source = baseline.clone();
    source.sources.binder_inflight_capacity += 1;
    variants.push(source);
    let mut source_mode = baseline.clone();
    source_mode.sources.fdgraph_pid_scope = "all".into();
    variants.push(source_mode);
    let mut findings = baseline.clone();
    findings.findings.enabled = true;
    findings.findings.rules_sha256 = Some("5".repeat(64));
    variants.push(findings);
    let mut enrichment = baseline.clone();
    enrichment.enrichment.aidl_catalog_sha256 = Some("6".repeat(64));
    variants.push(enrichment);
    let mut schema = baseline.clone();
    schema.packs.schema.push("vendor".into());
    schema
        .packs
        .schema_identities
        .push(neutron::health::CaptureContentIdentity {
            name: "vendor".into(),
            sha256: "7".repeat(64),
        });
    variants.push(schema);
    let mut bpf = baseline.clone();
    bpf.producer.bpf_object_sha256 = "8".repeat(64);
    variants.push(bpf);
    let mut userspace = baseline.clone();
    userspace.producer.userspace_binary_sha256 = "9".repeat(64);
    variants.push(userspace);

    for variant in variants {
        assert_ne!(baseline, variant);
        let value = serde_json::to_value(variant.recompute_claim_scope()).unwrap();
        CaptureScope::from_json_value(&value).expect("variant remains a valid scope");
    }
}

#[test]
fn forged_claim_scope_completeness_is_rejected() {
    let mut value = render(&CaptureHealth::default(), &UserspaceHealth::default());
    let scope = value["capture_scope"].as_object_mut().unwrap();
    scope["filters"]
        .as_object_mut()
        .unwrap()
        .insert("bpf".into(), serde_json::json!(["syscall IN {29}"]));

    let errors = capture_health_contract_errors(value.as_object().unwrap());
    assert!(errors
        .iter()
        .any(|error| error.contains("claim_scope_complete")));
}

#[test]
fn requested_kprobe_attachment_failure_is_incomplete_and_preserved() {
    let mut scope = CaptureScope::unfiltered_raw_ndjson();
    let failure = "kprobe_kgsl_ioctl@kgsl_ioctl:program_missing";
    scope.packs.kprobe.push(KprobePackScope {
        name: "kgsl".into(),
        requested_sources: vec!["kprobe_kgsl_ioctl@kgsl_ioctl".into()],
        attached_sources: Vec::new(),
        failures: vec![failure.into()],
    });
    let userspace = UserspaceHealth {
        kprobe_attach_failures: vec![format!("kgsl:{failure}")],
        ..UserspaceHealth::default()
    };
    let value = render_with_scope(
        &CaptureHealth::default(),
        &userspace,
        scope.recompute_claim_scope(),
    );

    assert_eq!(value["status"], "incomplete");
    assert_eq!(value["degraded"], true);
    assert_eq!(
        value["capture_scope"]["packs"]["kprobe"][0]["requested_sources"],
        serde_json::json!(["kprobe_kgsl_ioctl@kgsl_ioctl"])
    );
    assert_eq!(
        value["capture_scope"]["packs"]["kprobe"][0]["attached_sources"],
        serde_json::json!([])
    );
    assert_eq!(
        value["kprobe_attach_failures"],
        serde_json::json!([format!("kgsl:{failure}")])
    );
    assert!(capture_health_contract_errors(value.as_object().unwrap()).is_empty());
}

#[test]
fn known_drop_health_json_status_is_degraded() {
    let mut health = CaptureHealth::default();
    health.slots[COUNTER_RINGBUF_RESERVE_FAILED as usize] = 1;

    let value = render(&health, &UserspaceHealth::default());

    assert_eq!(value["status"], "degraded");
    assert_eq!(value["degraded"], true);
    assert_eq!(value["ringbuf_reserve_failed"], 1);
}

#[test]
fn payload_read_failure_is_explicit_and_degrades_capture() {
    let mut health = CaptureHealth::default();
    health.slots[COUNTER_PAYLOAD_READ_FAILED as usize] = 1;

    let value = render(&health, &UserspaceHealth::default());
    assert_eq!(value["payload_read_failed"], 1);
    assert_eq!(value["status"], "degraded");
}

#[test]
fn output_cap_health_json_status_is_incomplete() {
    let userspace = UserspaceHealth {
        output_cap_hit: true,
        ..UserspaceHealth::default()
    };

    let value = render(&CaptureHealth::default(), &userspace);

    assert_eq!(value["status"], "incomplete");
    assert_eq!(value["degraded"], true, "legacy consumers must fail closed");
}

#[test]
fn counter_read_error_health_json_status_is_unknown() {
    let health = CaptureHealth {
        read_errors: vec!["counter:ringbuf_reserve_failed:EIO".into()],
        ..CaptureHealth::default()
    };

    let value = render(&health, &UserspaceHealth::default());

    assert_eq!(value["status"], "unknown");
    assert_eq!(value["degraded"], true, "legacy consumers must fail closed");
    assert_eq!(
        value["read_errors"],
        serde_json::json!(["counter:ringbuf_reserve_failed:EIO"])
    );
}

#[test]
fn unknown_status_takes_precedence_over_incomplete() {
    let health = CaptureHealth {
        read_errors: vec!["map:COUNTERS:EACCES".into()],
        ..CaptureHealth::default()
    };
    let userspace = UserspaceHealth {
        output_cap_hit: true,
        ..UserspaceHealth::default()
    };

    let value = render(&health, &userspace);

    assert_eq!(value["status"], "unknown");
}

#[test]
fn path_capture_counters_are_wired_instead_of_false_zeroes() {
    let value = render(&CaptureHealth::default(), &UserspaceHealth::default());

    assert_eq!(value["path_read_failed"], 0);
    assert_eq!(value["path_truncated"], 0);
    assert_eq!(value["unsupported_counters"], serde_json::json!([]));

    assert_eq!(
        CaptureHealth::default().slots.len(),
        COUNTER_SLOT_COUNT as usize
    );
}

#[test]
fn sampling_makes_negative_evidence_incomplete() {
    let health = CaptureHealth::default();
    let userspace = UserspaceHealth {
        events_sampled_out: 1,
        ..UserspaceHealth::default()
    };
    let value = render(&health, &userspace);

    assert_eq!(value["status"], "incomplete");
    assert_eq!(value["degraded"], true);
}

#[test]
fn malformed_selinux_records_degrade_health() {
    let health = CaptureHealth::default();
    let userspace = UserspaceHealth {
        selinux_source_enabled: true,
        selinux_source_available: true,
        selinux_malformed: 1,
        ..UserspaceHealth::default()
    };
    let value = render(&health, &userspace);

    assert_eq!(value["status"], "degraded");
}

#[test]
fn unresolved_fd_graph_misses_degrade_health() {
    let health = CaptureHealth::default();
    let userspace = UserspaceHealth {
        fd_graph_miss: 2,
        fd_graph_backfilled: 1,
        ..UserspaceHealth::default()
    };

    assert_eq!(render(&health, &userspace)["status"], "degraded");
}

#[test]
fn bounded_or_expired_binder_branches_make_capture_incomplete() {
    for userspace in [
        UserspaceHealth {
            follow_policy_filtered: 1,
            ..UserspaceHealth::default()
        },
        UserspaceHealth {
            follow_ttl_expired: 1,
            ..UserspaceHealth::default()
        },
    ] {
        let value = render(&CaptureHealth::default(), &userspace);
        assert_eq!(value["status"], "incomplete");
        assert_eq!(value["degraded"], true);
    }
}

#[test]
fn binder_correlation_loss_is_counted_reasoned_and_non_complete() {
    for userspace in [
        UserspaceHealth {
            binder_tracker_evictions: 1,
            ..UserspaceHealth::default()
        },
        UserspaceHealth {
            binder_unmatched_receives: 1,
            ..UserspaceHealth::default()
        },
        UserspaceHealth {
            binder_causal_metadata_discarded: 1,
            ..UserspaceHealth::default()
        },
        UserspaceHealth {
            binder_invalid_callers: 1,
            ..UserspaceHealth::default()
        },
        UserspaceHealth {
            binder_tracker_disabled: true,
            ..UserspaceHealth::default()
        },
    ] {
        let value = render(&CaptureHealth::default(), &userspace);
        assert_eq!(value["status"], "incomplete");
        assert_eq!(value["degraded"], true);
        assert!(value["incomplete_reasons"]
            .as_array()
            .is_some_and(|reasons| !reasons.is_empty()));
        assert!(capture_health_contract_errors(value.as_object().unwrap()).is_empty());
    }

    let disabled = render(
        &CaptureHealth::default(),
        &UserspaceHealth {
            binder_tracker_disabled: true,
            ..UserspaceHealth::default()
        },
    );
    assert_eq!(disabled["binder_tracker_enabled"], false);
}

#[test]
fn complete_contract_rejects_silent_binder_correlation_loss() {
    let mut value = render(&CaptureHealth::default(), &UserspaceHealth::default());
    let object = value.as_object_mut().unwrap();
    object.insert("binder_tracker_evictions".into(), serde_json::json!(1));

    let errors = capture_health_contract_errors(object);
    assert!(errors.iter().any(|error| error.contains("Binder causal")));
}

#[test]
fn capture_health_schema_requires_all_evidence_loss_counters() {
    let schema: Value = serde_json::from_str(include_str!(
        "../schemas/neutron.capture-health-v1.schema.json"
    ))
    .unwrap();
    let required = schema["required"].as_array().unwrap();
    let properties = schema["properties"].as_object().unwrap();

    for field in [
        "binder_tracker_evictions",
        "binder_unmatched_receives",
        "binder_causal_metadata_discarded",
        "binder_invalid_callers",
        "binder_tracker_enabled",
        "capture_scope",
        "kprobe_attach_failures",
        "fd_poller_proc_disappeared",
        "fd_poller_proc_permission_errors",
        "fd_poller_proc_io_errors",
        "fd_poller_proc_parse_errors",
        "fd_poller_proc_truncations",
        "fd_poller_proc_races",
        "fd_poller_pid_reuse",
        "fd_poller_samples_suppressed_read_errors",
        "fd_poller_target_unreadable_polls",
        "fd_poller_scope_read_errors",
        "scenario_inflight_discarded",
        "scenario_context_discarded",
        "scenario_context_baseline_discarded",
        "binder_baseline_discarded",
        "logcat_baseline_drains",
        "logcat_baseline_lines_discarded",
        "logcat_baseline_events_discarded",
        "logcat_baseline_pending_discarded",
        "logcat_baseline_errors",
        "logcat_unprimed_drains",
        "logcat_incomplete_correlations",
        "logcat_malformed_correlations",
        "logcat_unsupported_java_fatal",
        "logcat_unsupported_anr",
        "logcat_untrusted_native_exits",
        "selinux_baseline_drains",
        "selinux_baseline_records_discarded",
        "selinux_baseline_pending_discarded",
        "selinux_baseline_errors",
        "selinux_unprimed_drains",
        "tombstone_baseline_primes",
        "tombstone_baseline_errors",
        "tombstone_baseline_files",
        "tombstone_unprimed_polls",
        "tombstone_file_identity_races",
        "tombstone_unmatched_in_scope",
        "tombstone_out_of_scope",
    ] {
        assert!(required.iter().any(|value| value.as_str() == Some(field)));
        assert!(properties.contains_key(field));
    }
    assert!(schema["allOf"]
        .as_array()
        .is_some_and(|rules| !rules.is_empty()));
}

#[test]
fn complete_contract_rejects_unreconciled_or_placeholder_provenance() {
    let mut value = render(&CaptureHealth::default(), &UserspaceHealth::default());
    let object = value.as_object_mut().unwrap();
    object.insert("events_submitted".into(), serde_json::json!(8));
    object.insert(
        "bpf_object_sha256".into(),
        serde_json::json!("0".repeat(64)),
    );
    object.insert("bpf_build_id".into(), serde_json::json!("0".repeat(40)));
    object.insert("bpf_feature_bits".into(), serde_json::json!(0));
    object.insert("max_processes".into(), serde_json::json!(0));
    object.insert("attached_programs".into(), serde_json::json!([]));

    let errors = capture_health_contract_errors(object);
    for expected in [
        "event",
        "all-zero",
        "feature",
        "max_processes",
        "attached_programs",
    ] {
        assert!(
            errors.iter().any(|error| error.contains(expected)),
            "missing {expected:?} error in {errors:?}"
        );
    }
}
