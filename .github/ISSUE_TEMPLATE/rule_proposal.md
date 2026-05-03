---
name: Rule proposal
about: Propose a new detector rule for the default ruleset
title: '[rule] '
labels: rule
---

## Suggested rule ID

<!-- Use the next free T0xx slot. Check neutron-rules/rules/default.yaml. -->

## Pattern

<!-- What runtime behavior does this rule detect? Be specific about syscalls,
     paths, or other observable signals. -->

## Why it matters

<!-- Why is this a useful signal? What category does it belong to
     (root_detection / antitamper / network_recon / memory / recon / ipc)? -->

## Draft YAML

```yaml
- id: T0xx_example
  name: ...
  description: ...
  severity: low | medium | high | critical
  category: ...
  conditions:
    - ...
```

## Test fixtures

<!-- Sketch a positive event and a negative event the rule should/shouldn't
     match. JSON snippets matching `neutron --json` output format are ideal. -->

**Positive (should match)**:
```json
{}
```

**Negative (should NOT match)**:
```json
{}
```

## References

<!-- Public documentation, blog posts, MITRE technique IDs, etc. -->
