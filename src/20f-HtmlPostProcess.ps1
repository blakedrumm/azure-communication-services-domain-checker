# ===== HTML Post-Processing (Template Replacements) =====
$htmlPage = $htmlPage.Replace('__APP_VERSION__', $script:AppVersion)

# Inject Entra ID (Azure AD) client ID for Microsoft employee authentication.
# Set ACS_ENTRA_CLIENT_ID env var to an Azure AD app registration configured as a
# Single-Page Application (SPA) with redirect URI matching this app's origin.
$entraClientId = $env:ACS_ENTRA_CLIENT_ID
if ([string]::IsNullOrWhiteSpace($entraClientId)) { $entraClientId = '' }
$htmlPage = $htmlPage.Replace('__ENTRA_CLIENT_ID__', $entraClientId)

$entraTenantId = $env:ACS_ENTRA_TENANT_ID
if ([string]::IsNullOrWhiteSpace($entraTenantId)) { $entraTenantId = '' }
$htmlPage = $htmlPage.Replace('__ENTRA_TENANT_ID__', $entraTenantId)

$apiKey = $env:ACS_API_KEY
if ([string]::IsNullOrWhiteSpace($apiKey)) { $apiKey = '' }
$htmlPage = $htmlPage.Replace('__ACS_API_KEY__', $apiKey)

$issueUrl = $env:ACS_ISSUE_URL
if ([string]::IsNullOrWhiteSpace($issueUrl)) { $issueUrl = '' }
$htmlPage = $htmlPage.Replace('__ACS_ISSUE_URL__', $issueUrl)

