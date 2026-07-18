#!/usr/bin/env node

// Serialize release provenance from environment variables so tool output is
// JSON-escaped instead of interpolated into a shell here-document.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [outputPath] = process.argv.slice(2);
if (!outputPath) throw new Error("usage: generate-provenance.mjs OUTPUT");

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`missing provenance input ${name}`);
  return value;
};
const integer = (name) => {
  const value = Number.parseInt(required(name), 10);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`invalid numeric provenance input ${name}`);
  }
  return value;
};
const boolean = (name) => {
  const value = required(name);
  if (value !== "true" && value !== "false") {
    throw new Error(`invalid boolean provenance input ${name}`);
  }
  return value === "true";
};
const sha256 = (name) => {
  const value = required(name);
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`invalid SHA-256 provenance input ${name}`);
  }
  return value;
};
const optionalSha256 = (name) => {
  const value = process.env[name];
  if (!value) return null;
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`invalid SHA-256 provenance input ${name}`);
  }
  return value;
};
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const version = required("NEUTRON_PROV_VERSION");
const gitCommit = required("NEUTRON_PROV_GIT_COMMIT");
const gitDirty = boolean("NEUTRON_PROV_GIT_DIRTY");
const buildTimestamp = required("NEUTRON_PROV_BUILD_TIMESTAMP");
assert(/^[0-9a-f]{40}$/.test(gitCommit), "release git commit must be 40 lowercase hex");
assert(!gitDirty, "release provenance cannot describe a dirty build");

const readSelfInfo = (name, expectedTarget) => {
  const inputPath = required(name);
  const value = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  assert(value?.schema === "neutron.self-info/v1", `${name} has the wrong schema`);
  assert(value.tool?.version === version, `${name} version does not match release`);
  assert(value.tool?.git_commit === gitCommit, `${name} commit does not match release`);
  assert(value.tool?.git_dirty === false, `${name} claims a dirty build`);
  assert(
    value.tool?.build_timestamp === buildTimestamp,
    `${name} build timestamp does not match release`,
  );
  assert(value.tool?.target === expectedTarget, `${name} target does not match artifact`);
  assert(Array.isArray(value.tool?.feature_set), `${name} feature_set is not measured`);
  assert(
    Number.isSafeInteger(value.bpf?.abi_major) && value.bpf.abi_major > 0,
    `${name} has an invalid BPF ABI major`,
  );
  assert(
    Number.isSafeInteger(value.bpf?.event_size) && value.bpf.event_size > 0,
    `${name} has an invalid syscall event size`,
  );
  return value;
};

const hostSelfInfo = readSelfInfo(
  "NEUTRON_PROV_HOST_SELF_INFO",
  "x86_64-unknown-linux-gnu",
);
const agentSelfInfo = readSelfInfo(
  "NEUTRON_PROV_AGENT_SELF_INFO",
  "aarch64-unknown-linux-musl",
);
const measuredRustc = required("NEUTRON_PROV_RUSTC");
assert(
  hostSelfInfo.tool.rustc_version === measuredRustc &&
    agentSelfInfo.tool.rustc_version === measuredRustc,
  "binary self-info does not match the recorded rustc toolchain",
);
assert(
  hostSelfInfo.bpf.abi_major === agentSelfInfo.bpf.abi_major &&
    hostSelfInfo.bpf.event_size === agentSelfInfo.bpf.event_size,
  "host and Android binaries disagree on the userspace/BPF ABI",
);

const objectMeasurements = new Map();
for (const measurement of hostSelfInfo.bpf_objects ?? []) {
  const basename = path.basename(measurement?.path ?? "");
  assert(basename.length > 0, "measured BPF object is missing its path");
  assert(!objectMeasurements.has(basename), `duplicate measured BPF object ${basename}`);
  const identity = measurement?.identity;
  assert(identity?.build_id === gitCommit, `${basename} build ID does not match release`);
  assert(identity?.build_id_present === true, `${basename} has no build ID`);
  assert(
    identity?.abi_major === hostSelfInfo.bpf.abi_major &&
      identity?.syscall_event_size === hostSelfInfo.bpf.event_size,
    `${basename} ABI does not match the userspace binaries`,
  );
  assert(
    Number.isSafeInteger(identity?.feature_bits) && identity.feature_bits >= 0,
    `${basename} feature bits are invalid`,
  );
  objectMeasurements.set(basename, identity);
}
assert(objectMeasurements.size === 2, "release must measure exactly two BPF objects");
const stackless = objectMeasurements.get("neutron.bpf.elf");
const stacked = objectMeasurements.get("neutron-stacks.bpf.elf");
assert(stackless, "release did not measure neutron.bpf.elf");
assert(stacked, "release did not measure neutron-stacks.bpf.elf");

const STACKS_FEATURE_BIT = 1 << 3;
const RELEASE_BASE_FEATURE_BITS = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 4);
assert(
  stackless.feature_bits === RELEASE_BASE_FEATURE_BITS,
  "stackless BPF object does not advertise the exact release feature set",
);
assert(
  stacked.feature_bits === (stackless.feature_bits | STACKS_FEATURE_BIT),
  "stack-enabled BPF feature bits must equal stackless bits plus stacks",
);

const bpfSha256 = sha256("NEUTRON_PROV_BPF_SHA256");
const bpfStacksSha256 = sha256("NEUTRON_PROV_BPF_STACKS_SHA256");
assert(stackless.object_sha256 === bpfSha256, "stackless BPF measurement/hash mismatch");
assert(stacked.object_sha256 === bpfStacksSha256, "stacked BPF measurement/hash mismatch");

const strictRelease = boolean("NEUTRON_PROV_STRICT_RELEASE");
const minisignPublicKeySha256 = optionalSha256(
  "NEUTRON_PROV_MINISIGN_PUBLIC_KEY_SHA256",
);
assert(
  !strictRelease || minisignPublicKeySha256 !== null,
  "strict release provenance requires the approved minisign public-key hash",
);
const probeDebuggable = boolean("NEUTRON_PROV_PROBE_DEBUGGABLE");
const probeCertificateSha256 = sha256("NEUTRON_PROV_PROBE_CERT_SHA256");
const approvedProbeCertificateSha256 = optionalSha256(
  "NEUTRON_PROV_APPROVED_PROBE_CERT_SHA256",
);
assert(
  !strictRelease || probeCertificateSha256 === approvedProbeCertificateSha256,
  "strict release probe certificate does not match the approved identity",
);
assert(
  required("NEUTRON_PROV_PROBE_BUILD_TYPE") === "debug",
  "release probe build type must match assembleDebug",
);

const buildEnvironment = {
  runner_os: required("NEUTRON_PROV_RUNNER_OS"),
  runner_image_version: required("NEUTRON_PROV_RUNNER_IMAGE_VERSION"),
  runner_arch: required("NEUTRON_PROV_RUNNER_ARCH"),
  runner_environment: required("NEUTRON_PROV_RUNNER_ENVIRONMENT"),
};
buildEnvironment.identity_sha256 = crypto
  .createHash("sha256")
  .update(JSON.stringify(buildEnvironment))
  .digest("hex");

const provenance = {
  schema: "neutron.provenance/v1",
  version,
  git_commit: gitCommit,
  git_dirty: gitDirty,
  build_timestamp: buildTimestamp,
  toolchain: {
    rustc: measuredRustc,
    cargo: required("NEUTRON_PROV_CARGO"),
    bpf_linker: required("NEUTRON_PROV_BPF_LINKER"),
    java_runtime: required("NEUTRON_PROV_JAVA_RUNTIME"),
    java_vendor: required("NEUTRON_PROV_JAVA_VENDOR"),
    gradle: required("NEUTRON_PROV_GRADLE"),
    gradle_distribution_sha256: required("NEUTRON_PROV_GRADLE_SHA256"),
    android_gradle_plugin: required("NEUTRON_PROV_AGP"),
    android_compile_sdk: integer("NEUTRON_PROV_COMPILE_SDK"),
    android_build_tools: required("NEUTRON_PROV_BUILD_TOOLS"),
    aapt2: required("NEUTRON_PROV_AAPT2"),
    apksigner: required("NEUTRON_PROV_APKSIGNER"),
  },
  build_environment: buildEnvironment,
  targets: [hostSelfInfo.tool.target, agentSelfInfo.tool.target, "bpfel-unknown-none"],
  binaries: {
    host: {
      artifact: "host/neutron",
      sha256: sha256("NEUTRON_PROV_HOST_BINARY_SHA256"),
      self_info: hostSelfInfo.tool,
    },
    android_agent: {
      artifact: "android/neutron-agent",
      sha256: sha256("NEUTRON_PROV_AGENT_BINARY_SHA256"),
      self_info: agentSelfInfo.tool,
    },
  },
  bpf_abi: {
    major: stackless.abi_major,
    minor: stackless.abi_minor,
    event_size: stackless.syscall_event_size,
  },
  bpf_objects: {
    "neutron.bpf.elf": {
      sha256: bpfSha256,
      identity: stackless,
    },
    "neutron-stacks.bpf.elf": {
      sha256: bpfStacksSha256,
      identity: stacked,
    },
  },
  probe: {
    package: required("NEUTRON_PROV_PROBE_PACKAGE"),
    version_code: integer("NEUTRON_PROV_PROBE_VERSION_CODE"),
    version_name: required("NEUTRON_PROV_PROBE_VERSION_NAME"),
    target_sdk: integer("NEUTRON_PROV_PROBE_TARGET_SDK"),
    build_type: required("NEUTRON_PROV_PROBE_BUILD_TYPE"),
    debuggable: probeDebuggable,
    signing_certificate_sha256: probeCertificateSha256,
    signing_certificate_approved:
      strictRelease && probeCertificateSha256 === approvedProbeCertificateSha256,
    attacker_model: `ordinary_installed_app_target_sdk_${integer("NEUTRON_PROV_PROBE_TARGET_SDK")}_debuggable_${probeDebuggable}`,
  },
  release_authentication: {
    strict: strictRelease,
    minisign_public_key_sha256: minisignPublicKeySha256,
  },
  artifacts: {
    [required("NEUTRON_PROV_HOST_NAME")]: sha256("NEUTRON_PROV_HOST_SHA256"),
    [required("NEUTRON_PROV_AGENT_NAME")]: sha256("NEUTRON_PROV_AGENT_SHA256"),
    [required("NEUTRON_PROV_SOURCE_NAME")]: sha256("NEUTRON_PROV_SOURCE_SHA256"),
    "host/neutron": sha256("NEUTRON_PROV_HOST_BINARY_SHA256"),
    "android/neutron-agent": sha256("NEUTRON_PROV_AGENT_BINARY_SHA256"),
    "neutron.bpf.elf": bpfSha256,
    "neutron-stacks.bpf.elf": bpfStacksSha256,
    "neutron-probe.apk": sha256("NEUTRON_PROV_PROBE_SHA256"),
  },
};

fs.writeFileSync(outputPath, `${JSON.stringify(provenance, null, 2)}\n`, {
  mode: 0o600,
  flag: "wx",
});
