# Azure Communication Services - Domain Checker Tool (***acs-domain-checker***)

## Overview
`acs-domain-checker` is a single-file PowerShell web UI + REST API to validate Azure Communication Services (ACS) email domain readiness. It checks DNS records (TXT/SPF, MX, DMARC, DKIM, CNAME), performs optional DNSBL reputation checks, and includes WHOIS/RDAP diagnostics.

## Features
- Single-file PowerShell HTTP server with an embedded SPA UI
- DNS checks: root TXT/SPF, ACS TXT, MX with A/AAAA resolution, DMARC, DKIM selectors, CNAME
- DNSBL reputation lookup with cached results
- WHOIS/RDAP diagnostics with fallback providers
- Optional API key auth and per-IP rate limiting
- Optional anonymous metrics (HMAC-hashed domains only)
- Optional Microsoft Entra ID sign-in for employee verification
- Container-ready (Linux/Windows Dockerfiles)

## Quick Start (Local)
To run the application locally, execute the following command in PowerShell:


# Run the UI and API on the default port (8080)

```powershell
./acs-domain-checker.ps1
```

Then, open your web browser and navigate to `http://localhost:8080`.

## Quick Start (Docker)
To run the application using Docker, use the following commands:


# Linux
```bash
docker build -f Dockerfile.linux -t acs-domain-checker .

docker run --rm -p 8080:8080 \
  -e ACS_API_KEY=your-key \
  acs-domain-checker
```

## API Endpoints
The following API endpoints are available:

- `/` : Web UI
- `/dns` : Aggregated readiness JSON
- `/api/base` : Root TXT/SPF/ACS TXT
- `/api/mx` : MX + A/AAAA resolution
- `/api/dmarc` : DMARC
- `/api/dkim` : DKIM
- `/api/cname` : CNAME
- `/api/reputation` : DNSBL reputation
- `/api/metrics` : Anonymous metrics snapshot

## Authentication
If `ACS_API_KEY` is set, API endpoints require an API key via header or query:

- Header: `X-Api-Key: <key>`
- Query (less secure): `?apiKey=<key>`

## Configuration (Environment Variables)
You can configure the application using the following environment variables:

- `PORT`: Port override for the web listener (default 8080)
- `ACS_DNS_RESOLVER`: `Auto`, `System`, or `DoH`
- `ACS_DNS_DOH_ENDPOINT`: DoH endpoint when resolver is DoH
- `ACS_ENABLE_ANON_METRICS`: `1` to enable anonymous metrics
- `ACS_ANON_METRICS_FILE`: Persist metrics to JSON
- `ACS_METRICS_HASH_KEY`: Stable hash key for domain hashing
- `ACS_API_KEY`: API key for `/api/*` and `/dns`
- `ACS_RATE_LIMIT_PER_MIN`: Requests per minute per client IP
- `ACS_ENTRA_CLIENT_ID`: Entra ID app registration client ID
- `ACS_ENTRA_TENANT_ID`: Optional tenant ID/domain
- `ACS_ISSUE_URL`: Issue tracker URL for the �Report issue� button

## Issue Reporting
To enable issue reporting, set `ACS_ISSUE_URL` to your issue tracker �new issue� URL. The application appends `domain` and `source` query parameters and shows a confirmation prompt when reporting an issue.

## MSAL Browser Library Updates

This repository uses the Microsoft Authentication Library (MSAL) for browser (`@azure/msal-browser`) to enable Microsoft Entra ID authentication. The library file `msal-browser.min.js` is checked into the repository root and served at `/assets/msal-browser.min.js`.

### Automated Updates

A GitHub Actions workflow (`.github/workflows/update-msal-browser.yml`) automatically checks for new releases of `@azure/msal-browser` and creates pull requests when updates are available.

**Update Schedule:**
- Runs automatically every Monday (GitHub Actions day 1 of week) at 9:00 AM UTC
- Can be triggered manually via GitHub Actions workflow dispatch

**How It Works:**
1. The workflow checks the latest version available on the npm registry
2. Compares it with the current version in `msal-browser.min.js`
3. If an update is available:
   - Downloads the package from npm
   - Extracts `lib/msal-browser.min.js` from the package
   - Updates both `msal-browser.min.js` and `package.json`
   - Creates a pull request with the changes
4. Review and merge the PR after testing

**Security Features:**
- Pinned GitHub Actions versions for reproducibility
- Downloads from official npm registry only
- Version verification from package metadata
- No arbitrary script execution

### Manual Update

To manually update to a specific version:

1. Navigate to **Actions** → **Update MSAL Browser Library** in the GitHub repository
2. Click **Run workflow**
3. Enter the desired version (e.g., `5.3.0`) or leave empty for the latest
4. Click **Run workflow**

### Pinning a Specific Version

If you need to prevent automatic updates and stay on a specific version:

1. Disable the scheduled workflow run by editing `.github/workflows/update-msal-browser.yml`:
   ```yaml
   on:
     # schedule:  # Comment out the schedule trigger
     #   - cron: '0 9 * * 1'
     workflow_dispatch:  # Keep manual dispatch available
   ```

2. Manually update to your desired version using the workflow dispatch method above

3. The application will continue to work with the checked-in version at that point

### Fallback CDNs

The UI (in `acs-domain-checker.ps1`) also includes fallback CDN URLs in case the local file cannot be loaded:
- `https://alcdn.msauth.net/browser/{version}/js/msal-browser.min.js`
- `https://cdn.jsdelivr.net/npm/@azure/msal-browser@{version}/dist/msal-browser.min.js`

**Note:** The CDN URLs in `acs-domain-checker.ps1` (in the `msalSources` array) have hardcoded versions and will need manual updates if you want them to match the latest version. The automated workflow only updates the checked-in `msal-browser.min.js` file.

## Security Notes
- Content Security Policy (CSP) is enforced with nonces for inline scripts/styles.
- Anonymous metrics do not store Personally Identifiable Information (PII) (domains are HMAC-hashed).
- Avoid using API keys in URLs for production environments to enhance security.

## License
MIT
