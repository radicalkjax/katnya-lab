# Katnya bootstrap stub probe (Q-212). Windows PowerShell 5.1 and pwsh 7.
param([Parameter(Mandatory=$true)][string]$Url, [Parameter(Mandatory=$true)][string]$Sha256, [string]$Out = 'katnya-asset.bin')
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
if ($PSVersionTable.PSVersion.Major -lt 6) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Out
$got = (Get-FileHash -Algorithm SHA256 -LiteralPath $Out).Hash.ToLowerInvariant()
if ($got -ne $Sha256.ToLowerInvariant()) {
  Remove-Item -LiteralPath $Out -Force
  [Console]::Error.WriteLine("katnya-bootstrap: SHA-256 mismatch (got $got, want $Sha256)"); exit 1
}
"katnya-bootstrap: OK sha256=$got via Invoke-WebRequest + Get-FileHash on PS $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
