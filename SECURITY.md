# Security Policy

## Supported Versions

The ACS Email Domain Checker is distributed as a single, self-contained
PowerShell script. Security fixes are applied to the **latest release only**, so
the most reliable way to stay protected is to run the newest version.

| Version | Supported |
|---------|-----------|
| Latest release (currently `2.10.x`) | :white_check_mark: |
| Any older version | :x: |

Because the tool is often downloaded and run standalone, older copies do **not**
update automatically. Always pull the latest `acs-domain-checker.ps1` (or the
latest Docker image tag) before deploying.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.** Publicly disclosing an unpatched issue puts
every existing deployment at risk.

Instead, report privately using **GitHub's private vulnerability reporting**:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability** to open a private advisory visible only to
   you and the maintainers:
   <https://github.com/mcaps-microsoft/azure-communication-services-domain-checker/security/advisories/new>

If you are unable to use private reporting, contact the maintainer privately via
<https://blakedrumm.com/> instead of opening a public issue.

### What to include

To help us triage quickly, please provide as much of the following as you can:

- A description of the issue and its potential impact.
- The affected version (shown in the footer of the web UI and in `-TestDomain`
  output).
- Step-by-step reproduction steps or a proof of concept.
- Relevant configuration (for example, which environment variables are set) —
  but **never include real API keys, tokens, or other secrets**.
- Your assessment of severity, if you have one.

### What to expect

- **Acknowledgement:** we aim to confirm receipt within **5 business days**.
- **Assessment:** we will investigate and tell you whether the report is
  accepted, along with an expected remediation timeline.
- **Fix & disclosure:** once a fix is ready we will coordinate disclosure with
  you and credit you for the finding, unless you prefer to remain anonymous.

We follow **coordinated disclosure**: please give us a reasonable opportunity to
ship a fix before disclosing details publicly.

## Scope

**In scope** — the code in this repository, including:

- The HTTP server and its routes (`/`, `/api/*`, `/dns`, `/terms`, `/privacy`).
- DNS-over-HTTPS, WHOIS/RDAP, DNSBL, and website-probe request handling
  (including SSRF, injection, and input-validation concerns).
- Output handling in the embedded single-page UI (for example, XSS).
- Authentication, rate limiting, security headers, and logging.

**Out of scope**, typically:

- Vulnerabilities already fixed in a newer release (please update first).
- Issues in the third-party services the tool queries (public DoH resolvers,
  WHOIS/RDAP registries, DNSBL providers) rather than in this code.
- Findings that require a misconfiguration the documentation explicitly warns
  against (for example, exposing the plaintext HTTP listener directly to the
  internet without a reverse proxy or `ACS_API_KEY`).
- Denial of service from unrealistic request volumes against a local tool.

## Deploying Securely

This tool runs a local HTTP listener intended for trusted/internal use. When
deploying beyond `localhost`:

- Put it **behind a reverse proxy that terminates HTTPS**; the built-in listener
  serves plain HTTP.
- Set **`ACS_API_KEY`** to require an API key on `/api/*` and `/dns`.
- Keep **rate limiting** enabled (`ACS_RATE_LIMIT_PER_MIN`, default `240`).
- Only set **`ACS_TRUSTED_PROXIES`** for proxies you actually control, so
  forwarded client-IP headers cannot be spoofed.
- Restrict **`ACS_ALLOWED_ORIGINS`** to the origins that should call the API.

See [`README.md`](README.md) for the full list of configuration options.
