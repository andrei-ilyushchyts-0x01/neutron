#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoot = path.join(root, "target", "tmp");
fs.mkdirSync(temporaryRoot, { recursive: true });
const temporary = fs.mkdtempSync(path.join(temporaryRoot, "neutron-sbom-test-"));

const cargoMetadata = {
  packages: [
    {
      id: "path+file:///neutron#neutron@1.5.0-rc.1",
      name: "neutron",
      version: "1.5.0-rc.1",
      license: "Apache-2.0",
    },
    {
      id: "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
      name: "serde",
      version: "1.0.0",
      license: "MIT OR Apache-2.0",
    },
  ],
  workspace_members: ["path+file:///neutron#neutron@1.5.0-rc.1"],
  resolve: {
    nodes: [
      {
        id: "path+file:///neutron#neutron@1.5.0-rc.1",
        dependencies: [
          "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
        ],
      },
      {
        id: "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
        dependencies: [],
      },
    ],
  },
};

const gradleGraph = {
  schema: "neutron.gradle-dependencies/v1",
  gradleVersion: "8.10.2",
  components: [
    {
      id: "com.android.tools.build:gradle:8.7.3",
      group: "com.android.tools.build",
      name: "gradle",
      version: "8.7.3",
    },
    {
      id: "com.android.tools.build:builder-model:8.7.3",
      group: "com.android.tools.build",
      name: "builder-model",
      version: "8.7.3",
    },
    {
      id: "junit:junit:4.13.2",
      group: "junit",
      name: "junit",
      version: "4.13.2",
    },
    {
      id: "org.hamcrest:hamcrest-core:1.3",
      group: "org.hamcrest",
      name: "hamcrest-core",
      version: "1.3",
    },
  ],
  roots: [
    { component: "com.android.tools.build:gradle:8.7.3", scope: "build" },
    { component: "junit:junit:4.13.2", scope: "test" },
  ],
  dependencies: [
    {
      from: "com.android.tools.build:gradle:8.7.3",
      to: "com.android.tools.build:builder-model:8.7.3",
    },
    {
      from: "junit:junit:4.13.2",
      to: "org.hamcrest:hamcrest-core:1.3",
    },
  ],
};

function run(script, args, expectedStatus = 0) {
  const result = spawnSync(process.execPath, [path.join(root, script), ...args], {
    encoding: "utf8",
  });
  assert.equal(
    result.status,
    expectedStatus,
    `${script} status ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  return result;
}

try {
  const cargoPath = path.join(temporary, "cargo.json");
  const gradlePath = path.join(temporary, "gradle.json");
  const outputPath = path.join(temporary, "SBOM.spdx.json");
  fs.writeFileSync(cargoPath, JSON.stringify(cargoMetadata));
  fs.writeFileSync(gradlePath, JSON.stringify(gradleGraph));

  run("scripts/generate-sbom.mjs", [
    cargoPath,
    gradlePath,
    outputPath,
    "1.5.0-rc.1",
    "2026-07-17T00:00:00Z",
    "https://example.invalid/neutron/sbom/test",
    "host.tar.zst",
    "1".repeat(64),
    "agent.tar.zst",
    "2".repeat(64),
    "source.tar.gz",
    "3".repeat(64),
    "4".repeat(64),
  ]);
  run("scripts/validate-spdx.mjs", [outputPath]);

  const sbom = JSON.parse(fs.readFileSync(outputPath, "utf8"));
  const packageByPurl = new Map(
    sbom.packages.flatMap((pkg) =>
      (pkg.externalRefs || [])
        .filter((reference) => reference.referenceType === "purl")
        .map((reference) => [reference.referenceLocator, pkg]),
    ),
  );
  for (const purl of [
    "pkg:maven/com.android.tools.build/gradle@8.7.3",
    "pkg:maven/com.android.tools.build/builder-model@8.7.3",
    "pkg:maven/junit/junit@4.13.2",
    "pkg:maven/org.hamcrest/hamcrest-core@1.3",
  ]) {
    assert(packageByPurl.has(purl), `missing resolved Gradle component ${purl}`);
  }

  const agp = packageByPurl.get("pkg:maven/com.android.tools.build/gradle@8.7.3");
  const builder = packageByPurl.get(
    "pkg:maven/com.android.tools.build/builder-model@8.7.3",
  );
  const junit = packageByPurl.get("pkg:maven/junit/junit@4.13.2");
  const hamcrest = packageByPurl.get("pkg:maven/org.hamcrest/hamcrest-core@1.3");
  assert(
    sbom.relationships.some(
      (relationship) =>
        relationship.spdxElementId === agp.SPDXID &&
        relationship.relationshipType === "DEPENDS_ON" &&
        relationship.relatedSpdxElement === builder.SPDXID,
    ),
    "missing transitive AGP dependency edge",
  );
  assert(
    sbom.relationships.some(
      (relationship) =>
        relationship.spdxElementId === junit.SPDXID &&
        relationship.relationshipType === "DEPENDS_ON" &&
        relationship.relatedSpdxElement === hamcrest.SPDXID,
    ),
    "missing transitive JUnit dependency edge",
  );

  const invalidPath = path.join(temporary, "invalid.spdx.json");
  const invalid = structuredClone(sbom);
  invalid.packages = invalid.packages.filter((pkg) => pkg.SPDXID !== builder.SPDXID);
  fs.writeFileSync(invalidPath, JSON.stringify(invalid));
  const rejected = run("scripts/validate-spdx.mjs", [invalidPath], 1);
  assert.match(rejected.stderr, /unknown SPDX element/);
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
