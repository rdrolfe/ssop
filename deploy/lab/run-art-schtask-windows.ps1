$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

Write-Output "=== Running ART T1053.005 (Scheduled Task) on Windows ==="
Import-Module invoke-atomicredteam -ErrorAction SilentlyContinue
$log = "C:\Windows\Temp\art-schtask.log"
try {
  Invoke-AtomicTest T1053.005 -PathToAtomicsFolder C:\Windows\Temp\atomics -TestNumbers 1 -ExecutionLogPath $log -ErrorAction Stop
  Write-Output "T1053.005 DONE"
} catch {
  Write-Output ("T1053.005 ERR: " + $_.Exception.Message)
}
if (Test-Path $log) {
  Write-Output "--- execution log ---"
  Get-Content $log -Tail 25
}
