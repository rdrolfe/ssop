# SSOP Windows target post-install provisioning.
# Runs at first logon via autounattend.xml. Sets static IPs (matched by MAC),
# enables OpenSSH + WinRM, installs the Wazuh agent (-> .75), installs
# Atomic Red Team. Password-free management via the injected SSH key.
$ErrorActionPreference = "Continue"
Start-Transcript -Path C:\Windows\Temp\provision.log -Append
$log = "C:\Windows\Temp\provision.log"

function Log($m) { Add-Content $log ("{0} {1}" -f (Get-Date -Format s), $m) }
Log "=== provision.ps1 start ==="

# --- 1. Static IPs by MAC (management .78 vmbr0 / attack .12 vmbr1) ---
# net0 (vmbr0, mgmt): 192.168.1.78/24 gw 192.168.1.1  (MAC 02:00:00:00:03:01)
# net1 (vmbr1, attack): 10.0.1.12/24 no gw                 (MAC 02:00:00:00:03:02)
try {
  $mgmt = Get-NetAdapter -Physical | Where-Object MacAddress -eq "02-00-00-00-03-01"
  if ($mgmt) {
    New-NetIPAddress -InterfaceIndex $mgmt.ifIndex -IPAddress 192.168.1.78 -PrefixLength 24 -DefaultGateway 192.168.1.1 -ErrorAction SilentlyContinue | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $mgmt.ifIndex -ServerAddresses 192.168.1.1 | Out-Null
    Log "mgmt NIC set: 192.168.1.78"
  } else { Log "WARN: mgmt NIC (MAC 02:00:00:00:03:01) not found" }
  $atk = Get-NetAdapter -Physical | Where-Object MacAddress -eq "02-00-00-00-03-02"
  if ($atk) {
    New-NetIPAddress -InterfaceIndex $atk.ifIndex -IPAddress 10.0.1.12 -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null
    Log "attack NIC set: 10.0.1.12"
  } else { Log "WARN: attack NIC (MAC 02:00:00:00:03:02) not found" }
} catch { Log "IP config error: $_" }

# --- 2. OpenSSH Server (removes firewall rules too) ---
try {
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
  Start-Service sshd -ErrorAction SilentlyContinue
  Set-Service -Name sshd -StartupType Automatic
  # allow the lab SSH keys for Administrator
  $authKey = "C:\ProgramData\ssh\administrators_authorized_keys"
  New-Item -ItemType Directory -Force -Path (Split-Path $authKey) | Out-Null
  @(
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJX5gp4lF87aBvG2h1DrQcxEIg6/qdw/ov2Wg1uodNRa hermes-ssop-agent"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEhF3+07VPlNsm1lUJBMkSM9DgzYmMxD2Enxltrn7VyS infra-agent-executor"
  ) | Set-Content $authKey
  icacls $authKey /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null
  Log "OpenSSH server enabled + lab keys installed"
} catch { Log "OpenSSH error: $_" }

# --- 3. Wazuh agent (-> 192.168.1.75) ---
try {
  $msi = "C:\Windows\Temp\wazuh-agent.msi"
  (New-Object Net.WebClient).DownloadFile("https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi", $msi)
  $p = Start-Process msiexec -ArgumentList "/i `"$msi`" /qn WAZUH_MANAGER=192.168.1.75 WAZUH_REGISTRATION_SERVER=192.168.1.75" -Wait -PassThru
  Log "wazuh agent install exit: $($p.ExitCode)"
} catch { Log "wazuh agent error: $_" }

# --- 4. Atomic Red Team ---
try {
  $env:PSModulePath += ";C:\Program Files\WindowsPowerShell\Modules"
  iwr -useb https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1 -OutFile C:\Windows\Temp\install-atomicredteam.ps1
  & C:\Windows\Temp\install-atomicredteam.ps1 | Out-Null
  Log "Atomic Red Team installed"
} catch { Log "ART install error: $_" }

Log "=== provision.ps1 done ==="
