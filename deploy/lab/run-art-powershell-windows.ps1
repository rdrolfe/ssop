$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

Write-Output "=== Running ART T1059.001 (PowerShell) on Windows ==="
Import-Module invoke-atomicredteam -ErrorAction SilentlyContinue
$log = "C:\Windows\Temp\art-ps.log"
try {
  Invoke-AtomicTest T1059.001 -PathToAtomicsFolder C:\Windows\Temp\atomics -TestNumbers 1 -ExecutionLogPath $log -ErrorAction Stop
  Write-Output "T1059.001 DONE"
} catch {
  Write-Output ("T1059.001 ERR: " + $_.Exception.Message)
}
if (Test-Path $log) {
  Write-Output "--- execution log ---"
  Get-Content $log -Tail 25
}
