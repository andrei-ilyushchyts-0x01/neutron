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
    /// Sequential Android system-app sweep with package status and health sidecars.
    SystemAppSweep,
    /// App launch baseline-vs-test workflow ending in a Markdown boundary report.
    LaunchDiff,
    /// User-action baseline-vs-test workflow ending in a Markdown boundary report.
    ActionDiff,
    /// Native surface and Binder-heavy workflow ending in a Markdown boundary report.
    NativeSurfaceAudit,
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

pub fn system_app_sweep_recipe() -> &'static str {
    r#"# Android System-App Sweep Recipe

Run one package-scoped capture at a time and keep the final
type:"capture_health" line in a sidecar so output caps remain auditable.

adb shell 'cat > /data/local/tmp/neutron_system_app_sweep.sh' <<'EOF'
#!/system/bin/sh
set -u

OUT_DIR="${1:-/data/local/tmp/neutron_system_app_sweep}"
DURATION="${2:-4}"
RATE_LIMIT="${3:-200}"
MAX_OUTPUT="${4:-256k}"

NEUTRON="/data/local/tmp/neutron"
BPF="/data/local/tmp/neutron.bpf.elf"

mkdir -p "$OUT_DIR/captures"
PKG_LIST="$OUT_DIR/pm_list_packages_s_f_U_show_versioncode.txt"
SUMMARY="$OUT_DIR/summary.tsv"

pm list packages -s -U -f --show-versioncode > "$PKG_LIST"
printf 'package\tuid\tversionCode\tapk_path\tmonkey_status\tneutron_status\texit_code\tbytes\tlines\thealth_output_cap_hit\n' > "$SUMMARY"

cleanup_neutron() {
  for pid in $(pidof neutron 2>/dev/null); do kill -INT "$pid" 2>/dev/null || true; done
  sleep 1
  for pid in $(pidof neutron 2>/dev/null); do kill -KILL "$pid" 2>/dev/null || true; done
}

while IFS= read -r line; do
  case "$line" in package:*) ;; *) continue ;; esac
  body="${line#package:}"
  path_pkg="${body%% versionCode:*}"
  rest="${body#* versionCode:}"
  version="${rest%% uid:*}"
  uid="${body##* uid:}"
  pkg="${path_pkg##*=}"
  apk_path="${path_pkg%=*}"
  safe="$(printf '%s' "$pkg" | tr -c 'A-Za-z0-9_.-' '_')"
  base="$OUT_DIR/captures/$safe"
  ndjson="$base.ndjson"
  health="$base.health.ndjson"
  stderr="$base.stderr"
  stdout="$base.stdout"
  monkey_log="$base.monkey"
  rm -f "$ndjson" "$health" "$stderr" "$stdout" "$monkey_log"
  cleanup_neutron

  timeout -s INT "$DURATION" "$NEUTRON" \
    --object "$BPF" \
    --json --raw --no-findings --no-logcat \
    --fdgraph-interval off --lookback-events 0 \
    --match-package "$pkg" \
    --rate-limit "$RATE_LIMIT" \
    --max-output-size "$MAX_OUTPUT" \
    --health-output "$health" \
    --output "$ndjson" \
    > "$stdout" 2> "$stderr" &
  neutron_pid="$!"

  sleep 1
  monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 > "$monkey_log" 2>&1
  wait "$neutron_pid"
  exit_code="$?"

  if grep -q 'Events injected:' "$monkey_log" 2>/dev/null; then monkey_status="launcher_injected";
  elif grep -q 'No activities found' "$monkey_log" 2>/dev/null; then monkey_status="no_launcher";
  else monkey_status="monkey_other"; fi

  if grep -q 'attached: trace_sys_enter' "$stderr" 2>/dev/null; then neutron_status="attached";
  elif grep -q '^Error:' "$stderr" 2>/dev/null; then neutron_status="error";
  else neutron_status="unknown"; fi

  bytes="$(wc -c < "$ndjson" 2>/dev/null | tr -d ' ')"
  lines="$(wc -l < "$ndjson" 2>/dev/null | tr -d ' ')"
  cap_hit="$(grep -q '"output_cap_hit":true' "$health" 2>/dev/null && echo true || echo false)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$pkg" "$uid" "$version" "$apk_path" "$monkey_status" "$neutron_status" "$exit_code" "${bytes:-0}" "${lines:-0}" "$cap_hit" \
    >> "$SUMMARY"
done < "$PKG_LIST"

cleanup_neutron
EOF

adb shell chmod 755 /data/local/tmp/neutron_system_app_sweep.sh
adb shell su -c '/data/local/tmp/neutron_system_app_sweep.sh'

Review:

adb shell su -c "awk -F '\t' 'NR>1 && \$10==\"true\" {print}' /data/local/tmp/neutron_system_app_sweep/summary.tsv"

Notes:
- Run sequentially; neutron also holds a capture lock and exits early if a
  second capture is active.
- Treat low line counts as "needs targeted trigger", not as safe.
- Treat packages resolving to shared/system UID warnings as UID-level traces,
  not package-isolated evidence.
- output_cap_hit in each health sidecar preserves cap accounting even when
  the primary NDJSON cannot receive the final capture_health line.
"#
}

pub fn launch_diff_recipe() -> &'static str {
    r#"# Launch Diff Recipe

Capture an idle package-scoped baseline, launch the app, then render a
Markdown boundary report with explicit package labeling.

1. Baseline:

adb shell su -c '/data/local/tmp/neutron \
  --json --raw --no-findings --no-logcat \
  --fdgraph-interval off --lookback-events 0 \
  --match-package com.example.app \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --health-output /data/local/tmp/launch_baseline.health.ndjson \
  --output /data/local/tmp/launch_baseline.ndjson'

2. Launch:

adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1

adb shell su -c '/data/local/tmp/neutron \
  --json --raw --binder --driver-pack binder \
  --match-package com.example.app \
  --capture matched+context=2s \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --health-output /data/local/tmp/launch_test.health.ndjson \
  --output /data/local/tmp/launch_test.ndjson'

3. Report:

neutron report /data/local/tmp/launch_test.ndjson \
  --baseline /data/local/tmp/launch_baseline.ndjson \
  --package com.example.app \
  --title "Launch Boundary Report" \
  --output launch-boundary-report.md
"#
}

pub fn action_diff_recipe() -> &'static str {
    r#"# Action Diff Recipe

Capture before/after traces around one user action and turn the behavior
delta into a Markdown boundary report.

1. Baseline:

adb shell su -c 'timeout -s INT 10 /data/local/tmp/neutron \
  --json --raw --binder --driver-pack binder \
  --match-package com.example.app \
  --capture matched+context=1s \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --output /data/local/tmp/action_baseline.ndjson'

2. Action capture:

adb shell su -c 'timeout -s INT 20 /data/local/tmp/neutron \
  --json --raw --binder --driver-pack binder \
  --match-package com.example.app \
  --capture matched+context=2s \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --output /data/local/tmp/action_test.ndjson' &

adb shell su -c '/data/local/tmp/neutron mark transfer_button \
  --phase start --output /data/local/tmp/action_test.ndjson'

# Trigger the user action under test.

adb shell su -c '/data/local/tmp/neutron mark transfer_button \
  --phase end --output /data/local/tmp/action_test.ndjson'

wait

3. Report:

neutron report /data/local/tmp/action_test.ndjson \
  --baseline /data/local/tmp/action_baseline.ndjson \
  --package com.example.app \
  --title "Action Boundary Report" \
  --output action-boundary-report.md
"#
}

pub fn native_surface_audit_recipe() -> &'static str {
    r#"# Native Surface Audit Recipe

Capture Binder plus native driver handoffs, prepare Binder attribution
inputs, then render the Markdown boundary report.

1. Capture:

adb shell su -c '/data/local/tmp/neutron \
  --profile driver-harness \
  --driver-pack binder,kgsl,mali,media-hal \
  --json --raw --binder \
  --match-package com.example.app \
  --capture matched+context=2s \
  --rate-limit 1000 \
  --max-output-size 500mb \
  --output /data/local/tmp/native_surface.ndjson'

2. Binder attribution inputs:

adb shell service list -p > service-list-p.txt

neutron binder-map service-list \
  --input service-list-p.txt \
  --output binder-catalog.json

neutron binder-map template /data/local/tmp/native_surface.ndjson \
  --output binder-services.template.json

3. Report:

neutron report /data/local/tmp/native_surface.ndjson \
  --package com.example.app \
  --binder-services binder-services.template.json \
  --binder-catalog binder-catalog.json \
  --title "Native Surface Boundary Report" \
  --output native-surface-boundary-report.md
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
        RecipesCommand::SystemAppSweep => {
            writeln!(stdout, "{}", system_app_sweep_recipe())
                .context("writing system-app-sweep recipe")?;
        }
        RecipesCommand::LaunchDiff => {
            writeln!(stdout, "{}", launch_diff_recipe()).context("writing launch-diff recipe")?;
        }
        RecipesCommand::ActionDiff => {
            writeln!(stdout, "{}", action_diff_recipe()).context("writing action-diff recipe")?;
        }
        RecipesCommand::NativeSurfaceAudit => {
            writeln!(stdout, "{}", native_surface_audit_recipe())
                .context("writing native-surface-audit recipe")?;
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

    #[test]
    fn system_app_sweep_recipe_mentions_health_and_cap_accounting() {
        let mut cmd = crate::cli::Cli::command();
        let recipes = cmd
            .find_subcommand_mut("recipes")
            .expect("recipes subcommand");
        let mut help = Vec::new();
        recipes.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(help.contains("system-app-sweep"));

        let recipe = system_app_sweep_recipe();
        assert!(recipe.contains("pm list packages -s"));
        assert!(recipe.contains("--match-package"));
        assert!(recipe.contains("--health-output"));
        assert!(recipe.contains("output_cap_hit"));
    }
}
