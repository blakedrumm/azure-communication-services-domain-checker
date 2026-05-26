$raw = & .\acs-domain-checker.ps1 -TestDomain yemekevi.com.tr | Out-String
# Show the substring of raw JSON around the first occurrence of "spfValue"
$idx = $raw.IndexOf('"spfValue"')
if ($idx -ge 0) {
  "=== Raw JSON window around spfValue ==="
  $raw.Substring($idx, [Math]::Min(200, $raw.Length - $idx))
}
