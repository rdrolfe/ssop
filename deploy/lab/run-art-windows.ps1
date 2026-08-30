$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

Write-Output "=== Running ART T1059.003 (cmd) on Windows ==="
Import-Module invoke-atomicredteam -ErrorAction SilentlyContinue
$log = "C:\Windows\Temp\art-run.log"
try {
  Invoke-AtomicTest T1059.003 -PathToAtomicsFolder C:\Windows\Temp\atomics -TestNumbers 1 -ExecutionLogPath $log -ErrorAction Stop
  Write-Output "T1059.003 DONE"
} catch {
  Write-Output ("T1059.003 ERR: " + $_.Exception.Message)
}
if (Test-Path $log) {
  Write-Output "--- execution log ---"
  Get-Content $log -Tail 25
}
