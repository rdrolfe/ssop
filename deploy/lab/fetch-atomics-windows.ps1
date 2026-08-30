$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Output "=== Fetch atomics repo on Windows ==="
$dst = "C:\Windows\Temp\atomics"
if (Test-Path $dst) {
  Write-Output "atomics already present"
  exit 0
}

# Download + extract the atomic-red-team repo, keep only /atomics
$zip = "C:\Windows\Temp\atomics.zip"
Invoke-WebRequest -Uri "https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip" -OutFile $zip -UseBasicParsing
Write-Output ("downloaded: " + (Get-Item $zip).Length + " bytes")

$ext = "C:\Windows\Temp\atomics-extract"
if (Test-Path $ext) { Remove-Item $ext -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $ext -Force

$src = Get-ChildItem $ext -Directory | Select-Object -First 1
Move-Item (Join-Path $src.FullName "atomics") $dst -Force
Write-Output ("atomics present: " + (Test-Path $dst))

# Quick sanity: list a couple of T- dirs
Get-ChildItem $dst -Directory | Select-Object -First 5 | ForEach-Object { $_.Name }
