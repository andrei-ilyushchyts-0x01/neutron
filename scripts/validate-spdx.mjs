#!/usr/bin/env node

// Validate the SPDX 2.3 JSON profile emitted by generate-sbom.mjs without
// requiring a network fetch or an additional package-manager dependency.

import fs from "node:fs";

const [inputPath] = process.argv.slice(2);
if (!inputPath) {
  console.error("usage: validate-spdx.mjs SBOM.spdx.json");
  process.exit(1);
}

const fail = (message) => {
  throw new Error(`invalid SPDX 2.3 document: ${message}`);
};
const string = (value, field) => {
  if (typeof value !== "string" || value.length === 0) fail(`${field} must be a string`);
};
const array = (value, field) => {
  if (!Array.isArray(value)) fail(`${field} must be an array`);
};
const spdxIdPattern = /^SPDXRef-[A-Za-z0-9.-]+$/;
const relationshipTypes = new Set([
  "AMENDS",
  "ANCESTOR_OF",
  "BUILD_DEPENDENCY_OF",
  "BUILD_TOOL_OF",
  "CONTAINED_BY",
  "CONTAINS",
  "COPY_OF",
  "DATA_FILE_OF",
  "DEPENDENCY_MANIFEST_OF",
  "DEPENDENCY_OF",
  "DEPENDS_ON",
  "DESCENDANT_OF",
  "DESCRIBED_BY",
  "DESCRIBES",
  "DEV_DEPENDENCY_OF",
  "DEV_TOOL_OF",
  "DISTRIBUTION_ARTIFACT",
  "DOCUMENTATION_OF",
  "DYNAMIC_LINK",
  "EXAMPLE_OF",
  "EXPANDED_FROM_ARCHIVE",
  "FILE_ADDED",
  "FILE_DELETED",
  "FILE_MODIFIED",
  "GENERATED_FROM",
  "GENERATES",
  "HAS_PREREQUISITE",
  "METAFILE_OF",
  "OPTIONAL_COMPONENT_OF",
  "OPTIONAL_DEPENDENCY_OF",
  "OTHER",
  "PACKAGE_OF",
  "PATCH_APPLIED",
  "PATCH_FOR",
  "PREREQUISITE_FOR",
  "PROVIDED_DEPENDENCY_OF",
  "REQUIREMENT_DESCRIPTION_FOR",
  "RUNTIME_DEPENDENCY_OF",
  "SPECIFICATION_FOR",
  "STATIC_LINK",
  "TEST_CASE_OF",
  "TEST_DEPENDENCY_OF",
  "TEST_OF",
  "TEST_TOOL_OF",
  "VARIANT_OF",
]);

try {
  const document = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  if (document.spdxVersion !== "SPDX-2.3") fail("spdxVersion must be SPDX-2.3");
  if (document.dataLicense !== "CC0-1.0") fail("dataLicense must be CC0-1.0");
  if (document.SPDXID !== "SPDXRef-DOCUMENT") fail("document SPDXID is invalid");
  string(document.name, "name");
  string(document.documentNamespace, "documentNamespace");
  try {
    new URL(document.documentNamespace);
  } catch {
    fail("documentNamespace must be an absolute URI");
  }
  if (!document.creationInfo || typeof document.creationInfo !== "object") {
    fail("creationInfo is required");
  }
  string(document.creationInfo.created, "creationInfo.created");
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(document.creationInfo.created) ||
    Number.isNaN(Date.parse(document.creationInfo.created))
  ) {
    fail("creationInfo.created must be an SPDX timestamp");
  }
  array(document.creationInfo.creators, "creationInfo.creators");
  if (
    document.creationInfo.creators.length === 0 ||
    document.creationInfo.creators.some(
      (creator) =>
        typeof creator !== "string" || !/^(Person|Organization|Tool): .+/.test(creator),
    )
  ) {
    fail("creationInfo.creators is invalid");
  }

  array(document.packages, "packages");
  if (document.packages.length === 0) fail("packages must not be empty");
  const known = new Set([document.SPDXID]);
  for (const [index, pkg] of document.packages.entries()) {
    const label = `packages[${index}]`;
    if (!pkg || typeof pkg !== "object") fail(`${label} must be an object`);
    for (const field of [
      "name",
      "SPDXID",
      "downloadLocation",
      "licenseConcluded",
      "copyrightText",
    ]) {
      string(pkg[field], `${label}.${field}`);
    }
    if (!spdxIdPattern.test(pkg.SPDXID) || known.has(pkg.SPDXID)) {
      fail(`${label}.SPDXID is invalid or duplicated`);
    }
    known.add(pkg.SPDXID);
    if (typeof pkg.filesAnalyzed !== "boolean") fail(`${label}.filesAnalyzed must be boolean`);
    if (pkg.versionInfo !== undefined) string(pkg.versionInfo, `${label}.versionInfo`);
    if (pkg.checksums !== undefined) {
      array(pkg.checksums, `${label}.checksums`);
      for (const checksum of pkg.checksums) {
        if (
          checksum?.algorithm !== "SHA256" ||
          !/^[0-9a-f]{64}$/.test(checksum.checksumValue)
        ) {
          fail(`${label} has an invalid SHA256 checksum`);
        }
      }
    }
    if (pkg.externalRefs !== undefined) {
      array(pkg.externalRefs, `${label}.externalRefs`);
      for (const reference of pkg.externalRefs) {
        string(reference?.referenceCategory, `${label}.externalRefs.referenceCategory`);
        string(reference?.referenceType, `${label}.externalRefs.referenceType`);
        string(reference?.referenceLocator, `${label}.externalRefs.referenceLocator`);
        if (
          reference.referenceCategory === "PACKAGE-MANAGER" &&
          reference.referenceType === "purl" &&
          !reference.referenceLocator.startsWith("pkg:")
        ) {
          fail(`${label} has an invalid package URL`);
        }
      }
    }
  }

  array(document.documentDescribes, "documentDescribes");
  if (new Set(document.documentDescribes).size !== document.documentDescribes.length) {
    fail("documentDescribes contains duplicates");
  }
  for (const id of document.documentDescribes) {
    if (!known.has(id) || id === document.SPDXID) {
      fail(`documentDescribes references unknown SPDX element ${id}`);
    }
  }

  array(document.relationships, "relationships");
  const relationshipKeys = new Set();
  for (const [index, relationship] of document.relationships.entries()) {
    const label = `relationships[${index}]`;
    string(relationship?.spdxElementId, `${label}.spdxElementId`);
    string(relationship?.relationshipType, `${label}.relationshipType`);
    string(relationship?.relatedSpdxElement, `${label}.relatedSpdxElement`);
    if (!known.has(relationship.spdxElementId)) {
      fail(`${label} references unknown SPDX element ${relationship.spdxElementId}`);
    }
    if (!known.has(relationship.relatedSpdxElement)) {
      fail(`${label} references unknown SPDX element ${relationship.relatedSpdxElement}`);
    }
    if (!relationshipTypes.has(relationship.relationshipType)) {
      fail(`${label} has an invalid relationship type`);
    }
    const key = `${relationship.spdxElementId}\0${relationship.relationshipType}\0${relationship.relatedSpdxElement}`;
    if (relationshipKeys.has(key)) fail(`${label} duplicates another relationship`);
    relationshipKeys.add(key);
  }
  for (const id of document.documentDescribes) {
    if (!relationshipKeys.has(`${document.SPDXID}\0DESCRIBES\0${id}`)) {
      fail(`documentDescribes is missing its DESCRIBES relationship for ${id}`);
    }
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
