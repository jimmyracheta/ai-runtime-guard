# Security Policy

## Supported Versions
Security fixes are prioritized for:
1. The latest release on `main`
2. The current development branch (`dev`) when a fix is not yet released

Older tags may not receive patches.

## Reporting a Vulnerability
Please report vulnerabilities privately.

Preferred contact:
1. Open a private security advisory in GitHub
2. Or email the maintainer: `avram.liviu@gmail.com`
3. Or join our discord server: `https://discord.gg/NJECm4fY`

Include:
1. Affected version or commit
2. Deployment mode (host or container)
3. Reproduction steps
4. Expected vs actual behavior
5. Impact assessment
6. Relevant policy snippets with secrets removed

Do not open public issues for exploitable vulnerabilities before triage.

## Response Process
1. Acknowledgement target: within 3 business days
2. Initial triage target: within 7 business days
3. Remediation timeline depends on severity and exploitability
4. Coordinated disclosure is preferred after a fix is available

## Scope and Threat Model
`ai-runtime-guard` enforces policy on MCP-routed tool calls.

In scope:
1. Policy bypasses for blocked or gated actions
2. Approval workflow bypasses
3. Workspace boundary bypasses
4. Runtime-state tampering bypasses for approvals, logs, and backups
5. Backup or restore security flaws that violate policy guarantees

Out of scope by design:
1. Direct shell or file tooling outside MCP routing
2. Attacks that bypass AIRG by using client-native tools not controlled by AIRG

## Severity Guidance
High severity examples:
1. Executing blocked destructive commands through AIRG
2. Self-approval or approval token bypass for confirmation-gated commands
3. Reading or modifying protected runtime files through guarded tools
4. Cross-workspace access that violates policy boundaries

Medium severity examples:
1. Incorrect enforcement order leading to unexpected allow outcomes
2. Reported events missing critical attribution fields in a way that hides abuse

Low severity examples:
1. Cosmetic logging inconsistencies without policy impact
2. Non-exploitable doc mismatches

## Security Hardening Recommendations for Operators
1. Keep runtime state paths outside the agent workspace
2. Keep approval actions out-of-band and operator-controlled
3. Restrict or disable native agent shell/file tools that can bypass MCP controls
4. Keep blocked command and sensitive path policies strict for destructive operations
5. Update to latest release and review release notes for security changes

## Safe Harbor
Good-faith security research and responsible disclosure are welcome.
Do not exfiltrate real secrets, do not disrupt production systems, and do not perform destructive testing outside controlled environments.
