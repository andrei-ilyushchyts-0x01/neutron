# Security policy

## Acceptable use

`neutron` is a tool for **authorized security research**. Acceptable uses
include:

- Assessing applications you wrote, own, or maintain.
- Conducting an audit under explicit written authorization (e.g. a signed
  scope from the application owner, an active bug-bounty program with
  in-scope binaries, or an internal penetration-testing engagement).
- Observing the behavior of your own device for educational or compliance
  purposes.

The following uses are **not authorized** by this project and may be illegal
in your jurisdiction:

- Attacking applications, services, or infrastructure you do not own or
  have permission to test.
- Bypassing access controls in commercial software outside an authorized
  bug-bounty or security-research engagement.
- Mass surveillance of third-party applications.

By using this tool you agree to comply with applicable law and the terms of
service of any third-party application you observe.

## Reporting a vulnerability in neutron itself

If you discover a vulnerability in `neutron`'s own code (the loader, the BPF
programs, the rule engine, build scripts, or shipped artifacts), please
report it privately rather than opening a public issue.

A private contact channel will be added in a follow-up release. In the
meantime, open a private security advisory via GitHub's "Report a
vulnerability" feature on the project page, or open a regular issue marked
`[security]` and we will move the discussion to a private channel before
disclosing details.

We aim to acknowledge reports within 7 days. Please include:

- A clear description of the issue and its impact.
- Reproduction steps or a minimal proof-of-concept.
- Your assessment of severity (CVSS v3.x is welcome, not required).
- Any suggested mitigations.

We will coordinate disclosure: once a fix is ready and a release is cut, we
will credit the reporter (with consent) in `CHANGELOG.md`.

## Supported versions

| Version    | Status     | Notes                                                       |
|------------|------------|-------------------------------------------------------------|
| `1.0.x`    | Supported  | Current line. Aya 0.13, kernel 6.1+ aarch64, BTF + CO-RE.   |
| `< 1.0`    | Unsupported | Pre-public development versions.                            |

## Out of scope

The following are not considered security issues in this project:

- The tool successfully observing an application that does not detect it
  (this is the intended behavior).
- Detection of the tool by an application (we do not promise undetectability
  in adversarial conditions).
- Issues that require root on a device the reporter does not own.
- Vulnerabilities in dependencies that have already been addressed
  upstream — please file those upstream and we will follow.
