# Optional Checkmk agent plugin (Windows) for "Monitoring Compliance".
#
# Emits a clean JSON capability section with running processes, running
# services (name + display name) and installed software. Preferred by the
# check plugin; without it Windows detection falls back to the ps and
# win_reg_uninstall sections plus the server-side HW/SW inventory.
#
# Install: place in the Checkmk agent's "plugins" directory
# (e.g. C:\ProgramData\checkmk\agent\plugins\) or deploy via the Agent Bakery.

$ErrorActionPreference = "SilentlyContinue"

Write-Output "<<<monitoring_compliance_inventory:sep(0)>>>"

$procs = @(Get-Process | Select-Object -ExpandProperty Name -Unique)

$services = @()
foreach ($s in Get-Service) {
    if ($s.Status -eq 'Running') {
        $services += $s.Name
        if ($s.DisplayName) { $services += $s.DisplayName }
    }
}
$services = @($services | Sort-Object -Unique)

$uninstall = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$pkgs = @()
foreach ($path in $uninstall) {
    foreach ($item in (Get-ItemProperty $path)) {
        if ($item.DisplayName) { $pkgs += $item.DisplayName }
    }
}
$pkgs = @($pkgs | Sort-Object -Unique)

$payload = [ordered]@{
    os            = "windows"
    processes     = @($procs)
    systemd_units = @()
    services      = @($services)
    packages      = @($pkgs)
}

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
# Depth covers nested arrays; -Compress keeps it on conceptually one document.
$payload | ConvertTo-Json -Compress -Depth 4
