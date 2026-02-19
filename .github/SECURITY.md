# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |

Only the latest release receives security updates. Users are encouraged to
upgrade to the most recent version.

## Reporting a Vulnerability

If you discover a security vulnerability in Cowrie, please report it
responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email **michel@oosterhof.net** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

You should receive an acknowledgment within 72 hours. We will work with you
to understand the issue and coordinate a fix and disclosure timeline.

## Scope

The following are in scope for security reports:

- Escape from the honeypot sandbox to the host system
- Remote code execution on the host (outside the honeypot)
- Authentication bypass of the management interface
- Denial of service against the honeypot host (not the emulated services)
- Vulnerabilities in dependencies that affect Cowrie

The following are **not** in scope:

- Attacks against the emulated SSH/Telnet services (this is expected behavior)
- Social engineering of project maintainers
- Issues in third-party output plugins not maintained by the Cowrie project
