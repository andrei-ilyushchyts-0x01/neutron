#!/usr/bin/env node

// Generate a deterministic SPDX 2.3 dependency graph from Cargo metadata and
// Gradle's resolved dependency graph. This describes software components, not
// merely the release archive files that carry them.

import crypto from "node:crypto";
import fs from "node:fs";

const [
  metadataPath,
  gradleGraphPath,
  outputPath,
  version,
  created,
  namespace,
  hostName,
  hostSha256,
  agentName,
  agentSha256,
  sourceName,
  sourceSha256,
  probeSha256,
] = process.argv.slice(2);

if (
  !probeSha256 ||
  ![hostSha256, agentSha256, sourceSha256, probeSha256].every((value) =>
    /^[0-9a-f]{64}$/.test(value),
  )
) {
  throw new Error(
    "usage: generate-sbom.mjs CARGO_METADATA GRADLE_GRAPH OUTPUT VERSION CREATED NAMESPACE HOST HOST_SHA AGENT AGENT_SHA SOURCE SOURCE_SHA PROBE_SHA",
  );
}

const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
const gradleGraph = JSON.parse(fs.readFileSync(gradleGraphPath, "utf8"));
if (
  gradleGraph.schema !== "neutron.gradle-dependencies/v1" ||
  typeof gradleGraph.gradleVersion !== "string" ||
  !Array.isArray(gradleGraph.components) ||
  !Array.isArray(gradleGraph.roots) ||
  !Array.isArray(gradleGraph.dependencies)
) {
  throw new Error("invalid resolved Gradle dependency graph");
}

const spdxId = (prefix, value) =>
  `SPDXRef-${prefix}-${crypto.createHash("sha256").update(value).digest("hex").slice(0, 20)}`;
const cargoId = new Map();
const packages = [];
const relationships = [];

function addArtifact(name, id, checksum) {
  packages.push({
    name,
    SPDXID: id,
    versionInfo: version,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: "NOASSERTION",
    licenseDeclared: "Apache-2.0",
    copyrightText: "NOASSERTION",
    checksums: [{ algorithm: "SHA256", checksumValue: checksum }],
    primaryPackagePurpose: "APPLICATION",
  });
  relationships.push({
    spdxElementId: "SPDXRef-DOCUMENT",
    relationshipType: "DESCRIBES",
    relatedSpdxElement: id,
  });
}

addArtifact(hostName, "SPDXRef-Package-Host", hostSha256);
addArtifact(agentName, "SPDXRef-Package-Agent", agentSha256);
addArtifact(sourceName, "SPDXRef-Package-Source", sourceSha256);

for (const pkg of [...metadata.packages].sort((a, b) => a.id.localeCompare(b.id))) {
  const id = spdxId("Cargo", pkg.id);
  cargoId.set(pkg.id, id);
  packages.push({
    name: pkg.name,
    SPDXID: id,
    versionInfo: pkg.version,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: "NOASSERTION",
    licenseDeclared: pkg.license || "NOASSERTION",
    copyrightText: "NOASSERTION",
    supplier: "NOASSERTION",
    externalRefs: [
      {
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: `pkg:cargo/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}`,
      },
    ],
  });
}

for (const node of metadata.resolve?.nodes || []) {
  const from = cargoId.get(node.id);
  if (!from) continue;
  for (const dependency of [...node.dependencies].sort()) {
    const to = cargoId.get(dependency);
    if (to) {
      relationships.push({
        spdxElementId: from,
        relationshipType: "DEPENDS_ON",
        relatedSpdxElement: to,
      });
    }
  }
}

const workspacePackages = metadata.workspace_members
  .map((id) => cargoId.get(id))
  .filter(Boolean)
  .sort();
for (const id of workspacePackages) {
  relationships.push({
    spdxElementId: "SPDXRef-Package-Source",
    relationshipType: "CONTAINS",
    relatedSpdxElement: id,
  });
}

const neutronPackage = metadata.packages.find(
  (pkg) => pkg.name === "neutron" && metadata.workspace_members.includes(pkg.id),
);
if (!neutronPackage) {
  throw new Error("Cargo metadata does not contain the neutron workspace package");
}
for (const artifact of ["SPDXRef-Package-Host", "SPDXRef-Package-Agent"]) {
  relationships.push({
    spdxElementId: artifact,
    relationshipType: "DEPENDS_ON",
    relatedSpdxElement: cargoId.get(neutronPackage.id),
  });
}

const probeId = "SPDXRef-Package-ProbeApk";
packages.push({
  name: "dev.neutron.probe",
  SPDXID: probeId,
  versionInfo: "1.0",
  downloadLocation: "NOASSERTION",
  filesAnalyzed: false,
  licenseConcluded: "NOASSERTION",
  licenseDeclared: "Apache-2.0",
  copyrightText: "NOASSERTION",
  checksums: [{ algorithm: "SHA256", checksumValue: probeSha256 }],
  primaryPackagePurpose: "APPLICATION",
  externalRefs: [
    {
      referenceCategory: "PACKAGE-MANAGER",
      referenceType: "purl",
      referenceLocator: "pkg:apk/dev.neutron.probe@1.0",
    },
  ],
});
relationships.push({
  spdxElementId: "SPDXRef-Package-Agent",
  relationshipType: "CONTAINS",
  relatedSpdxElement: probeId,
});

const gradleId = new Map();
for (const component of [...gradleGraph.components].sort((a, b) =>
  String(a.id).localeCompare(String(b.id)),
)) {
  if (
    typeof component.id !== "string" ||
    typeof component.group !== "string" ||
    typeof component.name !== "string" ||
    typeof component.version !== "string" ||
    !component.id ||
    !component.group ||
    !component.name ||
    !component.version ||
    gradleId.has(component.id)
  ) {
    throw new Error("invalid or duplicate Gradle component");
  }
  const id = spdxId("Gradle", component.id);
  gradleId.set(component.id, id);
  packages.push({
    name: `${component.group}:${component.name}`,
    SPDXID: id,
    versionInfo: component.version,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: "NOASSERTION",
    licenseDeclared: "NOASSERTION",
    copyrightText: "NOASSERTION",
    supplier: "NOASSERTION",
    externalRefs: [
      {
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: `pkg:maven/${encodeURIComponent(component.group)}/${encodeURIComponent(component.name)}@${encodeURIComponent(component.version)}`,
      },
    ],
  });
}

for (const dependency of gradleGraph.dependencies) {
  const from = gradleId.get(dependency.from);
  const to = gradleId.get(dependency.to);
  if (!from || !to) {
    throw new Error("Gradle dependency references an unknown component");
  }
  relationships.push({
    spdxElementId: from,
    relationshipType: "DEPENDS_ON",
    relatedSpdxElement: to,
  });
}

for (const root of gradleGraph.roots) {
  const component = gradleId.get(root.component);
  if (!component || !["build", "runtime", "test"].includes(root.scope)) {
    throw new Error("Gradle root references an unknown component or scope");
  }
  if (root.scope === "runtime") {
    relationships.push({
      spdxElementId: probeId,
      relationshipType: "DEPENDS_ON",
      relatedSpdxElement: component,
    });
  } else {
    relationships.push({
      spdxElementId: component,
      relationshipType:
        root.scope === "build" ? "BUILD_DEPENDENCY_OF" : "TEST_DEPENDENCY_OF",
      relatedSpdxElement: probeId,
    });
  }
}

const gradleToolId = spdxId("Gradle", `Gradle@${gradleGraph.gradleVersion}`);
packages.push({
  name: "Gradle",
  SPDXID: gradleToolId,
  versionInfo: gradleGraph.gradleVersion,
  downloadLocation: "NOASSERTION",
  filesAnalyzed: false,
  licenseConcluded: "NOASSERTION",
  licenseDeclared: "Apache-2.0",
  copyrightText: "NOASSERTION",
  externalRefs: [
    {
      referenceCategory: "PACKAGE-MANAGER",
      referenceType: "purl",
      referenceLocator: `pkg:generic/gradle@${encodeURIComponent(gradleGraph.gradleVersion)}`,
    },
  ],
});
relationships.push({
  spdxElementId: gradleToolId,
  relationshipType: "BUILD_DEPENDENCY_OF",
  relatedSpdxElement: probeId,
});

packages.sort((a, b) => a.SPDXID.localeCompare(b.SPDXID));
const uniqueRelationships = [
  ...new Map(
    relationships.map((relationship) => [
      `${relationship.spdxElementId}\0${relationship.relationshipType}\0${relationship.relatedSpdxElement}`,
      relationship,
    ]),
  ).values(),
].sort((a, b) =>
  `${a.spdxElementId}\0${a.relationshipType}\0${a.relatedSpdxElement}`.localeCompare(
    `${b.spdxElementId}\0${b.relationshipType}\0${b.relatedSpdxElement}`,
  ),
);

const document = {
  spdxVersion: "SPDX-2.3",
  dataLicense: "CC0-1.0",
  SPDXID: "SPDXRef-DOCUMENT",
  name: `neutron-${version}-software-bom`,
  documentNamespace: namespace,
  creationInfo: {
    created,
    creators: ["Tool: scripts/generate-sbom.mjs"],
  },
  documentDescribes: [
    "SPDXRef-Package-Agent",
    "SPDXRef-Package-Host",
    "SPDXRef-Package-Source",
  ],
  packages,
  relationships: uniqueRelationships,
};

fs.writeFileSync(outputPath, `${JSON.stringify(document, null, 2)}\n`, {
  mode: 0o600,
  flag: "wx",
});
