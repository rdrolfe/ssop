$yaml = Get-Content "C:\Windows\Temp\atomics\T1059.001\T1059.001.yaml"
Write-Output "=== T1059.001 test names ==="
$yaml | Select-String -Pattern "^\s+- name: Test" | ForEach-Object { $_.Line.Trim() }
Write-Output "=== T1053.005 present? ==="
if (Test-Path "C:\Windows\Temp\atomics\T1053.005") {
  Get-ChildItem "C:\Windows\Temp\atomics\T1053.005" -Filter *.yaml | ForEach-Object { $_.Name }
} else {
  Write-Output "no T1053.005"
}
