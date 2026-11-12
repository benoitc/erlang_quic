# Security Policy

## Supported Versions

Security fixes are applied to the latest minor release on the `main` branch.

| Version | Supported |
| ------- | --------- |
| 2.7.x   | yes       |
| < 2.7   | no        |

## What is a security issue

Private reports are for problems that are not a deviation from a
specification erlang_quic implements: code execution; a peer accepted without
the authentication the configuration asks for (certificate chain, hostname
or client-certificate checks, PSK and session-ticket binding, Erlang
distribution node authentication); keys, secrets or one connection's data
reaching someone else; erlang_quic weakening TLS below what the
configuration allows.

## What is a bug

When the fix is to make erlang_quic follow a specification it implements
(QUIC, TLS 1.3 for QUIC, HTTP/3, QPACK and their extensions), it is a bug,
even when described as amplification, denial of service or a remote crash.
Report it as a public bug and cite the specification section; see
[Security issues and specification bugs](CONTRIBUTING.md#security-issues-and-specification-bugs).
We don't publish advisories or request CVEs for these, and advisories filed
for them are closed as bugs with a link to the fix.

Write the report in plain English, with a minimal reproduction, as described
in [CONTRIBUTING.md](CONTRIBUTING.md#write-for-the-person-who-reads-it).

## Reporting a Vulnerability

Please report suspected vulnerabilities privately through GitHub's
[Private Vulnerability Reporting](https://github.com/benoitc/erlang_quic/security/advisories/new).

Do not open public issues or pull requests for security problems.

When reporting, include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- Affected versions and platform details.
- Any suggested fix or mitigation.

You can expect an initial acknowledgement within 7 days. We will work with
you on a fix and coordinate disclosure once a patched release is available.
Credit will be given in the advisory unless you prefer to remain anonymous.
