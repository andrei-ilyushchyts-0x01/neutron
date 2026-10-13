# Reading a bounded observation

Neutron 1.6 presents capture limitations before conclusions. Use a private run
bundle and retain the exact userspace/BPF pair. See the device qualification
notes for the limits of each firmware and payload.

## Capture passport

`report`, `graph --format json` and `summarize` derive their capture passport from
one normalizer. It identifies the exact input bytes by SHA-256, records scenario
marker timestamps and roots, and carries the effective capture scope and health
restrictions. `diff` uses the same eligibility decision and additionally requires
matching scope and scenario contracts; refused comparisons produce no delta.

Transport health, capture completeness, bundle integrity and edge confidence are
separate. Detached analysis does not verify a bundle: run `neutron evidence verify
RUN_DIR`. A filtered run can have complete transport health and still support only
positive observations. A marker window is not an observation of application intent.
View filters, grouping, top-N and collapsed syscalls are identified separately.

## Report and graph

```sh
neutron report RUN_DIR/capture.ndjson --output report.md
neutron graph RUN_DIR/capture.ndjson --format json --output graph.json
neutron graph RUN_DIR/capture.ndjson --format mermaid --output graph.mmd
neutron summarize RUN_DIR/capture.ndjson --by type
```

Graph JSON uses `neutron.causal-graph/v3`; the v2 schema is retained for
historical artifacts. v3 adds a passport, view options and edge evidence basis.
Mermaid warnings and scope appear as visible nodes, not only source comments.

The report lists at most 64 causal spans and chooses its displayed chain from at
most 512 deterministic spans. Missing parents and unknown/inferred confidence stay
visible. Each timeline row refers to input record numbers under the passport's
capture hash; trace/span IDs identify merged enter/exit or Binder observations.
Separate traces are ordered for presentation, not joined into one semantic action.
Legacy records without causal IDs remain available in detailed counts and raw data.

`completed` in a legacy Binder event means dequeue. It does not establish handler
completion or successful authorization. Syscall return values retain failure or
missing-result status. FD labels remain best effort. Process membership and service
label confidence must not be confused with causal parent confidence.

External observations are not silently loaded from adjacent files. Use `neutron
evidence report RUN_DIR` for the verified imported evidence and its stimulus
identity. The detached capture report explicitly identifies this boundary.

## Capture readiness and teardown

```sh
neutron doctor --json --smoke --object neutron.bpf.elf --output-dir PRIVATE_DIR
neutron trace --subject pid:PID@STARTTIME --object neutron.bpf.elf \
  --raw --no-findings --run-dir PRIVATE_DIR/run --control-socket PRIVATE_DIR/control.sock
```

`--output-dir` must already exist and satisfy private-output ownership rules. The
check creates, syncs and removes a private temporary file and reports available
space. Space can change after startup; runtime write errors remain fatal.

Live run bundles include `readiness.json` (startup checks and effective scope) and
`teardown.json` (detach, source shutdown, discarded drain events and output flush).
They are hashed manifest artifacts and verified as a pair. A failure can leave a
private `failure.json`; failed loop/cleanup/finalization does not receive a seal.
Missing teardown means cleanup was not confirmed, including abrupt process death.
Historical bundles without lifecycle sidecars remain readable under their original
contract. A successful doctor smoke does not qualify full capture or all sources.

## Asynchronous work

Inferred graph edges now state their process/follow-context basis. Depth, process
caps, TTL, scope filters, dropped events and unavailable sources remain in the
passport. Exact edges require producer evidence; a nearby syscall in the same
process is not upgraded to exact. Unobserved or competing queued work stays unknown
or inferred. The framework does not claim a complete Android execution trace.


## Correlation boundaries in 1.6

Unknown or invalid producer relation values stay unknown. Every Binder dequeue
clears the receiving thread's previous synchronous context before installing a
matching observed transaction. A missing transaction or one-way dequeue cannot
inherit an earlier exact parent. Nested callbacks may consequently lose exact
ancestry when the outer context cannot be reconstructed; they are not guessed.

The report limits both its selected chain and timeline to 64 spans. Missing
parents stay visible in the selected chain. Inferred chain steps list up to eight
other observed same-PID delivery spans as review candidates; these are not new
causal edges and do not prove queue ownership or a matching process incarnation.
An enter-only syscall has no observed return value.

Reviewed Binder maps reject duplicate process identities, including numeric PID
aliases. Attempting to rebind a map invalidates its previous exact status before
checking the new context, so a failed rebind cannot retain old trust.
