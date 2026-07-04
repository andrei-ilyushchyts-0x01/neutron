//! Built-in workflow recipes for common Android security research tasks.

use std::io::{self, Write};

use anyhow::{Context, Result};
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum RecipesCommand {
    /// Print a low-noise Android content-provider research workflow.
    AndroidContentProvider,
    /// Binder LPE observation workflow using BPF syscall and binder tracepoints.
    BinderLpe,
    /// GPU driver harness workflow for KGSL/Mali ioctl observation.
    GpuDriverHarness,
    /// ALSA + Mali chain workflow for audio/GPU ioctl timelines.
    AlsaMaliChain,
    /// Unix-domain socket race workflow for MSG_PEEK and SCM_RIGHTS.
    UnixSocketRace,
    /// Media service crash workflow using media HAL driver packs.
    MediaServiceCrash,
}

pub fn android_content_provider_recipe() -> &'static str {
    r#"# Android Content-Provider Recipe

Trace one probing app plus the provider package UID, then compare
direct vs wrapped reads with summarize/window/diff.

1. Capture low-noise provider activity:

adb shell su -c '/data/local/tmp/neutron \
  --pid 0 \
  --json --raw --no-findings \
  --no-logcat --fdgraph-interval off --lookback-events 0 \
  --match-package com.example.probe \
  --match-android-provider content://com.android.contacts/contacts \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --output /data/local/tmp/provider_probe.ndjson'

For unattended sessions, replace the stop-cap with rotation:

adb shell su -c '/data/local/tmp/neutron \
  --pid 0 \
  --json --raw --no-findings \
  --match-package com.example.probe \
  --match-android-provider com.android.contacts \
  --rate-limit 1000 \
  --rotate-output-size 250mb \
  --output /data/local/tmp/provider_probe.ndjson'

2. Bracket each stimulus:

adb shell su -c '/data/local/tmp/neutron mark direct_read \
  --phase start --output /data/local/tmp/provider_probe.ndjson'

# Trigger the direct provider read.

adb shell su -c '/data/local/tmp/neutron mark direct_read \
  --phase end --output /data/local/tmp/provider_probe.ndjson'

3. Review:

adb shell /data/local/tmp/neutron summarize \
  --by comm,syscall,ret_class \
  --top 30 /data/local/tmp/provider_probe.ndjson

adb shell /data/local/tmp/neutron window \
  /data/local/tmp/provider_probe.ndjson \
  --anchor marker:direct_read --around 3s \
  > direct_read_windows.ndjson

Notes:
- --match-android-provider accepts a bare authority or content:// URI and
  resolves the declaring package UID via dumpsys package providers.
- Binder tracing is high-volume under --pid 0; add --binder only when you
  need transaction metadata and keep --rate-limit/--max-output-size.
- Neutron does not prove Java/Kotlin method-level authorization flow; pair
  traces with static review, logs, or instrumentation.
"#
}

pub fn binder_lpe_recipe() -> &'static str {
    r#"# Binder LPE Recipe

adb shell su -c '/data/local/tmp/neutron \
  --profile kernel-lpe --driver-pack binder \
  --json --raw --binder --capture matched+context=2s \
  --output /data/local/tmp/binder_lpe.ndjson'

Review with:

adb shell /data/local/tmp/neutron window /data/local/tmp/binder_lpe.ndjson \
  --anchor binder_call:callee_crashed --around 3s --summary
"#
}

pub fn gpu_driver_harness_recipe() -> &'static str {
    r#"# GPU Driver Harness Recipe

adb shell su -c '/data/local/tmp/neutron \
  --profile driver-harness --driver-pack kgsl,mali \
  --json --raw --fdgraph-interval 500ms \
  --capture matched+context=1s \
  --output /data/local/tmp/gpu_driver_harness.ndjson'

Review with:

adb shell /data/local/tmp/neutron summarize \
  --by comm,ioctl_family,ioctl_name,ret_class \
  /data/local/tmp/gpu_driver_harness.ndjson
"#
}

pub fn alsa_mali_chain_recipe() -> &'static str {
    r#"# ALSA + Mali Chain Recipe

adb shell su -c '/data/local/tmp/neutron \
  --profile driver-harness --driver-pack alsa,mali \
  --json --raw --capture matched+context=2s \
  --output /data/local/tmp/alsa_mali_chain.ndjson'

Review with:

adb shell /data/local/tmp/neutron window /data/local/tmp/alsa_mali_chain.ndjson \
  --anchor finding:R008_alsa_compat_candidate_errors --around 2s --summary
"#
}

pub fn unix_socket_race_recipe() -> &'static str {
    r#"# Unix Socket Race Recipe

adb shell su -c '/data/local/tmp/neutron \
  --profile kernel-lpe --driver-pack unix-socket \
  --json --raw --capture matched+context=1s \
  --output /data/local/tmp/unix_socket_race.ndjson'

Review with:

adb shell /data/local/tmp/neutron window /data/local/tmp/unix_socket_race.ndjson \
  --anchor finding:R009_unix_socket_rights_peek_race --around 1s
"#
}

pub fn media_service_crash_recipe() -> &'static str {
    r#"# Media Service Crash Recipe

adb shell su -c '/data/local/tmp/neutron \
  --profile driver-harness --driver-pack media-hal,binder \
  --json --raw --binder --fd-snapshot-on-finding \
  --output /data/local/tmp/media_service_crash.ndjson'

Review with:

adb shell /data/local/tmp/neutron window /data/local/tmp/media_service_crash.ndjson \
  --anchor crash --around 5s --summary
"#
}

pub fn run(command: RecipesCommand) -> Result<()> {
    let mut stdout = io::stdout().lock();
    match command {
        RecipesCommand::AndroidContentProvider => {
            writeln!(stdout, "{}", android_content_provider_recipe())
                .context("writing android-content-provider recipe")?;
        }
        RecipesCommand::BinderLpe => {
            writeln!(stdout, "{}", binder_lpe_recipe()).context("writing binder-lpe recipe")?;
        }
        RecipesCommand::GpuDriverHarness => {
            writeln!(stdout, "{}", gpu_driver_harness_recipe())
                .context("writing gpu-driver-harness recipe")?;
        }
        RecipesCommand::AlsaMaliChain => {
            writeln!(stdout, "{}", alsa_mali_chain_recipe())
                .context("writing alsa-mali-chain recipe")?;
        }
        RecipesCommand::UnixSocketRace => {
            writeln!(stdout, "{}", unix_socket_race_recipe())
                .context("writing unix-socket-race recipe")?;
        }
        RecipesCommand::MediaServiceCrash => {
            writeln!(stdout, "{}", media_service_crash_recipe())
                .context("writing media-service-crash recipe")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn android_content_provider_recipe_mentions_key_flags() {
        let recipe = android_content_provider_recipe();
        assert!(recipe.contains("--match-package"));
        assert!(recipe.contains("--match-android-provider"));
        assert!(recipe.contains("--max-output-size"));
        assert!(recipe.contains("--rotate-output-size"));
        assert!(recipe.contains("summarize"));
        assert!(recipe.contains("window"));
    }

    #[test]
    fn bpf_gap_recipes_are_registered() {
        let mut cmd = crate::cli::Cli::command();
        let recipes = cmd
            .find_subcommand_mut("recipes")
            .expect("recipes subcommand");
        let mut help = Vec::new();
        recipes.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        for name in [
            "binder-lpe",
            "gpu-driver-harness",
            "alsa-mali-chain",
            "unix-socket-race",
            "media-service-crash",
        ] {
            assert!(help.contains(name), "missing recipe {name}:\n{help}");
        }
    }
}
