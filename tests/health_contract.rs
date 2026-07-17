use neutron::health::{format_capture_health_json, CaptureHealth, UserspaceHealth};
use neutron_common::{COUNTER_RINGBUF_RESERVE_FAILED, COUNTER_SLOT_COUNT};
use serde_json::Value;

fn render(health: &CaptureHealth, userspace: &UserspaceHealth) -> Value {
    serde_json::from_str(&format_capture_health_json(health, userspace, 7))
        .expect("capture health must be valid JSON")
}

#[test]
fn clean_health_json_status_is_complete() {
    let value = render(&CaptureHealth::default(), &UserspaceHealth::default());

    assert_eq!(value["status"], "complete");
    assert_eq!(value["degraded"], false);
    assert!(value["read_errors"].as_array().is_some_and(Vec::is_empty));
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
fn unsupported_counters_are_absent_instead_of_false_zeroes() {
    let value = render(&CaptureHealth::default(), &UserspaceHealth::default());

    for unsupported in [
        "path_read_failed",
        "path_truncated",
        "fd_lookup_missed",
        "symbolization_failed",
    ] {
        assert!(
            value.get(unsupported).is_none(),
            "unsupported counter {unsupported} must not be emitted as zero"
        );
    }

    assert_eq!(
        CaptureHealth::default().slots.len(),
        COUNTER_SLOT_COUNT as usize
    );
}
