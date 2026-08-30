$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Output "=== ART install on Windows (hardened) ==="

# 1. Bootstrap NuGet provider non-interactively
Write-Output "--- NuGet provider ---"
try {
  Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
  Write-Output "NUGET-OK"
} catch {
  Write-Output ("NUGET-ERR: " + $_.Exception.Message)
}

# 2. Force-trust PSGallery
Write-Output "--- PSGallery trust ---"
try {
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
  Write-Output "TRUST-OK"
} catch {
  Write-Output ("TRUST-ERR: " + $_.Exception.Message)
}

# 3. Install the module, fully non-interactive
Write-Output "--- module install ---"
try {
  Install-Module -Name invoke-atomicredteam -Force -Confirm:$false -AllowClobber -Scope CurrentUser -ErrorAction Stop | Out-Null
  Write-Output "MODULE-OK"
} catch {
  Write-Output ("MODULE-ERR: " + $_.Exception.Message)
}

# 4. Verify
$mod = Get-Module -ListAvailable invoke-atomicredteam | Select-Object -First 1
if ($mod) {
  Write-Output ("VERIFIED: " + $mod.Name + " " + $mod.Version)
} else {
  Write-Output "VERIFIED: NOT FOUND"
}
