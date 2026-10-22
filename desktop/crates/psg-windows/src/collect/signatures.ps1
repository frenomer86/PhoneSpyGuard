# Phone Spy Guard: Authenticode status of each file listed (one path per
# line) in the file named by $env:PSG_PATHS_FILE. Read-only.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$paths = Get-Content -LiteralPath $env:PSG_PATHS_FILE -Encoding UTF8 | Where-Object { $_ }
$result = @(foreach ($p in $paths) {
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $signer = ''
    if ($s.SignerCertificate) { $signer = $s.SignerCertificate.GetNameInfo('SimpleName', $false) }
    [ordered]@{ path = $p; status = [string]$s.Status; signer = [string]$signer }
})
ConvertTo-Json -InputObject $result -Depth 3 -Compress
