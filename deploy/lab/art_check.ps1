$ErrorActionPreference = "Continue"
Import-Module invoke-atomicredteam
Write-Output "=== Get-AtomicTechnique params ==="
(Get-Command Get-AtomicTechnique).Parameters.Keys | Sort-Object
Write-Output "=== Invoke-AtomicTest params ==="
(Get-Command Invoke-AtomicTest).Parameters.Keys | Sort-Object
