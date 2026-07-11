use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use clap::Parser;
use neutron::causal::{
    expired_followed_pids, parse_follow_ttl, CausalRelation, FollowCandidate, FollowDecision,
    FollowPolicy,
};
use neutron::cli::{Cli, Command};

fn candidate<'a>(
    caller_domain: Option<&'a str>,
    callee_domain: Option<&'a str>,
    caller_relation: CausalRelation,
) -> FollowCandidate<'a> {
    FollowCandidate {
        caller_comm: None,
        caller_domain,
        callee_comm: None,
        callee_domain,
        caller_relation,
        caller_depth: 1,
    }
}

#[test]
fn domain_policy_denies_before_allowing_and_rejects_unknown_allowlist_members() {
    let policy = FollowPolicy::new(["hal_camera_default", "vendor_bad"], ["vendor_bad"]).unwrap();

    assert_eq!(
        policy.decide(candidate(
            Some("untrusted_app"),
            Some("vendor_bad"),
            CausalRelation::Exact,
        )),
        FollowDecision::Block("denied_domain")
    );
    assert_eq!(
        policy.decide(candidate(
            Some("untrusted_app"),
            Some("unknown_hal"),
            CausalRelation::Exact,
        )),
        FollowDecision::Block("domain_not_allowed")
    );
    assert_eq!(
        policy.decide(candidate(
            Some("untrusted_app"),
            Some("hal_camera_default"),
            CausalRelation::Exact,
        )),
        FollowDecision::Allow
    );
}

#[test]
fn special_process_transit_is_bounded() {
    let policy = FollowPolicy::new(std::iter::empty::<&str>(), std::iter::empty::<&str>()).unwrap();
    let mut through_manager = candidate(
        Some("servicemanager"),
        Some("hal_camera_default"),
        CausalRelation::Exact,
    );
    through_manager.caller_comm = Some("servicemanager");
    assert_eq!(
        policy.decide(through_manager),
        FollowDecision::Block("servicemanager_transit")
    );

    assert_eq!(
        policy.decide(candidate(
            Some("system_server"),
            Some("hal_camera_default"),
            CausalRelation::Inferred,
        )),
        FollowDecision::Block("inferred_system_server_transit")
    );
    assert_eq!(
        policy.decide(candidate(
            Some("system_server"),
            Some("hal_camera_default"),
            CausalRelation::Exact,
        )),
        FollowDecision::Allow
    );
}

#[test]
fn ttl_expiry_never_removes_roots() {
    assert_eq!(parse_follow_ttl("30s").unwrap(), Duration::from_secs(30));
    assert_eq!(parse_follow_ttl("2m").unwrap(), Duration::from_secs(120));
    assert!(parse_follow_ttl("0s").is_err());

    let seen = BTreeMap::from([(10, 100_u64), (20, 150), (30, 190)]);
    let roots = BTreeSet::from([10]);
    assert_eq!(expired_followed_pids(&seen, &roots, 200, 40), vec![20]);
}

#[test]
fn trace_cli_accepts_follow_guardrails_and_mvp_aliases() {
    let cli = Cli::try_parse_from([
        "neutron",
        "trace",
        "--package",
        "com.example.app",
        "--follow-binder",
        "--follow-depth",
        "3",
        "--follow-max-pids",
        "32",
        "--follow-ttl",
        "45s",
        "--follow-allow-domain",
        "hal_camera_default",
        "--follow-deny-domain",
        "vendor_bad",
    ])
    .unwrap();
    let Some(Command::Trace(args)) = cli.command else {
        panic!("trace command");
    };
    assert_eq!(args.max_depth, 3);
    assert_eq!(args.max_processes, 32);
    assert_eq!(args.follow_ttl, "45s");
    assert_eq!(args.follow_allow_domain, ["hal_camera_default"]);
    assert_eq!(args.follow_deny_domain, ["vendor_bad"]);
}
