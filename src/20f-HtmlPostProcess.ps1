# ===== HTML Post-Processing (Template Replacements) =====
#
# SECURITY: Every replacement target below lands inside a single-quoted
# JavaScript string literal in 20a-HtmlScriptSetup.ps1. Without escaping, a
# value containing `'`, `\`, `</script>`, or a newline could either:
#   * break the surrounding JS literal (causing a runtime SyntaxError that
#     breaks the entire SPA), or
#   * end the inline <script> block early (`</script>` mid-literal closes
#     the script in HTML's tokenizer, opening a script-injection sink).
# We feed every value through ConvertTo-JsStringLiteralBody first to
# eliminate both classes of bug. The function does NOT add the surrounding
# quotes -- the template still owns those -- so it is a drop-in replacement
# for the previous raw .Replace() calls.
function ConvertTo-JsStringLiteralBody {
  param([string]$Value)
  if ($null -eq $Value) { return '' }
  $sb = [System.Text.StringBuilder]::new($Value.Length + 8)
  foreach ($ch in $Value.ToCharArray()) {
    switch ($ch) {
      '\' { [void]$sb.Append('\\') }
      "'" { [void]$sb.Append("\'") }
      '"' { [void]$sb.Append('\"') }
      '`' { [void]$sb.Append('\u0060') }
      "`r" { [void]$sb.Append('\r') }
      "`n" { [void]$sb.Append('\n') }
      "`t" { [void]$sb.Append('\t') }
      "`0" { [void]$sb.Append('\u0000') }
      '<' { [void]$sb.Append('\u003C') }   # neutralizes </script> sequences
      '>' { [void]$sb.Append('\u003E') }
      '&' { [void]$sb.Append('\u0026') }   # avoid HTML-entity confusion in attribute contexts
      default {
        $code = [int][char]$ch
        if ($code -lt 0x20) {
          [void]$sb.Append(('\u{0:X4}' -f $code))
        } else {
          [void]$sb.Append($ch)
        }
      }
    }
  }
  return $sb.ToString()
}

$htmlPage = $htmlPage.Replace('__APP_VERSION__', (ConvertTo-JsStringLiteralBody $script:AppVersion))

# Inject Entra ID (Azure AD) client ID for Microsoft employee authentication.
# Set ACS_ENTRA_CLIENT_ID env var to an Azure AD app registration configured as a
# Single-Page Application (SPA) with redirect URI matching this app's origin.
$entraClientId = $env:ACS_ENTRA_CLIENT_ID
if ([string]::IsNullOrWhiteSpace($entraClientId)) { $entraClientId = '' }
$htmlPage = $htmlPage.Replace('__ENTRA_CLIENT_ID__', (ConvertTo-JsStringLiteralBody $entraClientId))

$entraTenantId = $env:ACS_ENTRA_TENANT_ID
if ([string]::IsNullOrWhiteSpace($entraTenantId)) { $entraTenantId = '' }
$htmlPage = $htmlPage.Replace('__ENTRA_TENANT_ID__', (ConvertTo-JsStringLiteralBody $entraTenantId))

$apiKey = $env:ACS_API_KEY
if ([string]::IsNullOrWhiteSpace($apiKey)) { $apiKey = '' }
$htmlPage = $htmlPage.Replace('__ACS_API_KEY__', (ConvertTo-JsStringLiteralBody $apiKey))

$issueUrl = $env:ACS_ISSUE_URL
if ([string]::IsNullOrWhiteSpace($issueUrl)) { $issueUrl = '' }
$htmlPage = $htmlPage.Replace('__ACS_ISSUE_URL__', (ConvertTo-JsStringLiteralBody $issueUrl))

# MSAL SRI map: optional JSON object whose keys are URLs in msalSources and
# whose values are SRI integrity strings (e.g. "sha384-..."). When unset, no
# SRI is applied (preserves prior behavior). When set, the SPA refuses to
# execute a CDN copy whose bytes do not match.
#
# This value is parsed by JSON.parse() in the SPA, so it MUST land as a JSON
# literal in JS -- we therefore inject it WITHOUT calling
# ConvertTo-JsStringLiteralBody (otherwise the JSON quotes get escaped) but
# we DO validate it as JSON first (round-trip via ConvertFrom-Json /
# ConvertTo-Json) so a malformed env value can never break the page or
# inject script. Angle brackets are stripped to neutralize any embedded
# `</script>` sequence; backslashes and single quotes are then escaped so
# the JSON literal stays well-formed inside its surrounding single-quoted
# JS string.
$msalSriRaw = $env:ACS_MSAL_SRI
$msalSriJson = 'null'
if (-not [string]::IsNullOrWhiteSpace($msalSriRaw)) {
  try {
    $parsed = $msalSriRaw | ConvertFrom-Json -ErrorAction Stop
    $reSerialized = $parsed | ConvertTo-Json -Compress -Depth 4
    $msalSriJson = $reSerialized.Replace('<', '\u003C').Replace('>', '\u003E')
  } catch {
    $msalSriJson = 'null'
  }
}
$msalSriForJsLiteral = $msalSriJson.Replace('\', '\\').Replace("'", "\'")
$htmlPage = $htmlPage.Replace('__ACS_MSAL_SRI__', $msalSriForJsLiteral)

