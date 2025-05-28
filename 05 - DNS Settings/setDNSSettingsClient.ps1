<#
.SYNOPSIS
    Setzt (oder entfernt) statische DNS-Server **ausschließlich** auf dem/den
    produktiven Adapter(n) – d. h.:

    • Adapter hat ein Default-Gateway **oder**  
    • Adapter liegt in einem vom Benutzer übergebenen IPv4-Subnetz  
      (Parameter -TargetSubnet) **oder**  
    • Adapter hat ein explizit angegebenes Gateway (Parameter -TargetGateway)

.DESCRIPTION
    • Entwickelt für NinjaOne (NinjaRMM) – läuft als SYSTEM.  
    • Unterstützt Windows 10/11, Server 2012 R2 +.  
    • Berücksichtigt ausschließlich physische LAN- und WLAN-Adapter.  
    • Virtuelle, VPN-, Loopback-, Tunnel- und Wi-Fi-Direct-Interfaces werden
      ausgefiltert.  
    • DNS wird per Set-DnsClientServerAddress gesetzt; Fallback auf netsh, wenn nötig.  
    • Ändert *nur* Adapter, die die Kriterien oben erfüllen.  
    • Schreibt ein detailliertes Änderungsprotokoll (StdOut) und aktualisiert
      optional das Custom-Field **DNS_LastChange**.

.PARAMETER PrimaryDNS
    Neuer primärer DNS-Server (IPv4). Pflicht, sofern -ResetDHCP nicht verwendet wird.

.PARAMETER SecondaryDNS
    Optionaler zweiter DNS-Server (IPv4).

.PARAMETER TargetSubnet
    IPv4-Subnetz in CIDR-Notation (z. B. 192.168.10.0/24).  
    Wird angegeben, werden nur Adapter berücksichtigt, deren IPv4-Adresse
    innerhalb dieses Netzes liegt.

.PARAMETER TargetGateway
    Explizite Gateway-Adresse (z. B. 192.168.10.1).  
    Wird angegeben, werden nur Adapter berücksichtigt, deren Default-Gateway
    exakt dieser Adresse entspricht.

.PARAMETER AdapterName
    Optionale Liste von Adapter-Aliasen (Supports Wildcards: „Ethernet*“).

.PARAMETER ResetDHCP
    Entfernt statische DNS-Einträge und schaltet DNS auf DHCP zurück.

.PARAMETER NoCustomField
    Unterdrückt das Update des Custom-Fields „DNS_LastChange“.

.EXAMPLE
    .\setDNSSettings.ps1 -PrimaryDNS 10.0.0.10 -SecondaryDNS 10.0.0.11 `
        -TargetSubnet 10.0.0.0/23 -Verbose

.EXAMPLE
    .\setDNSSettings.ps1 -ResetDHCP -TargetGateway 192.168.178.1

.NOTES
    Datei    : setDNSSettings.ps1
    Autor:     Andreas Hepp
    Update:    28.05.2025
    Version:   1.2
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $false)]
    [string]$PrimaryDNS,

    [Parameter(Mandatory = $false)]
    [string]$SecondaryDNS,

    [Parameter(Mandatory = $false)]
    [string]$TargetSubnet,

    [Parameter(Mandatory = $false)]
    [string]$TargetGateway,

    [Parameter(Mandatory = $false)]
    [string[]]$AdapterName,

    [switch]$ResetDHCP,

    [switch]$NoCustomField
)

#--------------------------------------------------
#region 1 – Grundprüfungen & Settings
#--------------------------------------------------

# Hilfsfunktion zum Auslesen von Custom Fields aus NinjaRMM
function Get-NinjaCustomField {
    param (
        [string]$FieldName,
        [switch]$AsBoolean
    )
    
    $value = $null
    
    # Versuch 1: Ninja-Property-Get verwenden (wenn verfügbar)
    try {
        $value = Ninja-Property-Get $FieldName -ErrorAction SilentlyContinue
    } catch {}
    
    # Versuch 2: CLI verwenden
    if (-not $value) {
        $cli = 'C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe'
        if (Test-Path $cli) {
            try {
                $value = & $cli get $FieldName 2>$null
                if ($LASTEXITCODE -ne 0) { $value = $null }
            } catch {}
        }
    }
    
    # Wenn als Boolean gewünscht
    if ($AsBoolean -and $value) {
        return $value -in @('true', 'True', '1', 'yes', 'Yes', 'on', 'On')
    }
    
    return $value
}

# Custom Fields auslesen und Parameter ergänzen
$cf_PrimaryDNS = Get-NinjaCustomField -FieldName "DNS_PrimaryServer"
if ($cf_PrimaryDNS -and -not $PrimaryDNS) {
    $PrimaryDNS = $cf_PrimaryDNS.Trim()
    Write-Verbose "PrimaryDNS aus Custom Field: $PrimaryDNS"
}

$cf_SecondaryDNS = Get-NinjaCustomField -FieldName "DNS_SecondaryServer"
if ($cf_SecondaryDNS -and -not $SecondaryDNS) {
    $SecondaryDNS = $cf_SecondaryDNS.Trim()
    Write-Verbose "SecondaryDNS aus Custom Field: $SecondaryDNS"
}

$cf_TargetSubnet = Get-NinjaCustomField -FieldName "DNS_TargetSubnet"
if ($cf_TargetSubnet -and -not $TargetSubnet) {
    $TargetSubnet = $cf_TargetSubnet.Trim()
    Write-Verbose "TargetSubnet aus Custom Field: $TargetSubnet"
}

$cf_TargetGateway = Get-NinjaCustomField -FieldName "DNS_TargetGateway"
if ($cf_TargetGateway -and -not $TargetGateway) {
    $TargetGateway = $cf_TargetGateway.Trim()
    Write-Verbose "TargetGateway aus Custom Field: $TargetGateway"
}

$cf_AdapterName = Get-NinjaCustomField -FieldName "DNS_AdapterAliases"
if ($cf_AdapterName -and -not $AdapterName) {
    # Komma-getrennte Liste in Array umwandeln
    $AdapterName = $cf_AdapterName -split ',' | ForEach-Object { $_.Trim() }
    Write-Verbose "AdapterName aus Custom Field: $($AdapterName -join ', ')"
}

$cf_ResetDHCP = Get-NinjaCustomField -FieldName "DNS_ResetToDHCP" -AsBoolean
if ($cf_ResetDHCP -and -not $ResetDHCP) {
    $ResetDHCP = $true
    Write-Verbose "ResetDHCP aus Custom Field aktiviert"
}

# Grundprüfungen
if (-not $ResetDHCP -and -not $PrimaryDNS) {
    Write-Error "PrimaryDNS fehlt. Entweder -PrimaryDNS übergeben, Custom Field 'DNS_PrimaryServer' setzen oder -ResetDHCP verwenden."
    exit 1
}

$ErrorActionPreference = "Stop"
$VerbosePreference     = "Continue"

# Regex zum Unterdrücken virtueller Adapter
$virtualPattern = 'VMware|Hyper-V|VPN|loopback|Loopback|Tunnel|TAP|Microsoft Wi-Fi Direct|WAN Miniport|Bluetooth|Remote Access|[*]'

# Array mit erlaubten Adaptertypen (nur WLAN und LAN)
$allowedAdapterTypes = @(
    'Ethernet', 'LAN', 'WLAN', 'Wi-Fi', 'Wireless', 'Netzwerkadapter', 'Network Adapter',
    '802.11', 'Realtek', 'Intel', 'Broadcom', 'Atheros', 'Qualcomm', 'TP-Link', 'D-Link',
    'MediaTek', 'Killer', 'Marvell', 'NVIDIA', 'ASIX', 'Aquantia', 'Belkin', 'Linksys',
    'Microsoft Wireless', 'Microsoft Ethernet'
)

#--------------------------------------------------
#endregion
#region 2 – Hilfsfunktionen
#--------------------------------------------------

function Test-IPv4InSubnet {
    param (
        [string]$Ip,
        [string]$Cidr    # z. B. 192.168.10.0/24
    )
    try {
        [IPAddress]$ipAddr = $Ip
        $parts  = $Cidr.Split('/')
        [IPAddress]$netAddr = $parts[0]
        $prefix = [int]$parts[1]

        $ipBits   = [BitConverter]::ToUInt32($ipAddr.GetAddressBytes()[::-1],0)
        $netBits  = [BitConverter]::ToUInt32($netAddr.GetAddressBytes()[::-1],0)
        $maskBits = 0xffffffff -shl (32 - $prefix)

        return (($ipBits -band $maskBits) -eq ($netBits -band $maskBits))
    }
    catch { return $false }
}

function Get-TargetAdapters {

    $adapters = Get-NetAdapter |
        Where-Object {
            ($_.Status -in @('Up','Unknown') -or $_.LinkSpeed -gt 0) -and
            $_.InterfaceDescription -notmatch $virtualPattern
        }
    
    # Zusätzliche Filterung: Nur LAN und WLAN Adapter berücksichtigen
    $adapters = $adapters | Where-Object {
        $adapterDesc = $_.InterfaceDescription
        $isAllowedType = $false
        
        foreach ($type in $allowedAdapterTypes) {
            if ($adapterDesc -match $type) {
                $isAllowedType = $true
                break
            }
        }
        
        # Prüfung auf Netzwerkkategorien (WLAN oder LAN)
        $isPhysicalAdapter = $adapterDesc -match 'Ethernet|LAN|Wi-?Fi|WLAN|802\.11|Wireless'
        
        # Hardware-ID prüfen für bessere Erkennung
        $netAdapterHardware = Get-NetAdapterHardwareInfo -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
        $isWiFiAdapter = $false
        if ($netAdapterHardware) {
            # NDIS-Objekt prüfen ob es sich um WLAN handelt (PnP-ID enthält normalerweise WLAN/WiFi-Hinweise)
            $isWiFiAdapter = ($netAdapterHardware.PnPDeviceID -match 'PCI\\VEN_.+\\REV_.+\\|USB\\VID_.+\\PID_.+\\') -and
                             ($netAdapterHardware.PnPDeviceID -match 'WLAN|WiFi|Wireless|802\.11')
        }
        
        return $isAllowedType -or $isPhysicalAdapter -or $isWiFiAdapter
    }

    # Filter 1 – AdapterName (Wildcard)
    if ($PSBoundParameters.ContainsKey('AdapterName')) {
        $pattern = ($AdapterName -join '|') -replace '\*','.*'
        $adapters = $adapters | Where-Object Name -match $pattern
    }

    # Enrich mit IP/Gateway
    $enriched = foreach ($a in $adapters) {
        $cfg = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex
        [PSCustomObject]@{
            Adapter      = $a
            IPv4         = ($cfg.IPv4Address.IPAddress)[0]
            GatewayIPv4  = ($cfg.IPv4DefaultGateway.NextHop)[0]
        }
    }

    # Filter 2 – Default Gateway vorhanden (Basis-Kriterium)
    $enriched = $enriched | Where-Object { $_.GatewayIPv4 }

    # Filter 3 – TargetGateway
    if ($PSBoundParameters.ContainsKey('TargetGateway')) {
        $tg = $TargetGateway
        $enriched = $enriched | Where-Object { $_.GatewayIPv4 -eq $tg }
    }

    # Filter 4 – TargetSubnet
    if ($PSBoundParameters.ContainsKey('TargetSubnet')) {
        $subnet = $TargetSubnet
        $enriched = $enriched | Where-Object { Test-IPv4InSubnet $_.IPv4 $subnet }
    }

    return $enriched
}

function Set-Dns {
    param(
        [int]$IfIndex,
        [string[]]$Servers,
        [switch]$Dhcp
    )
    try {
        if ($Dhcp) {
            Set-DnsClientServerAddress -InterfaceIndex $IfIndex -ResetServerAddresses -ErrorAction Stop
        }
        else {
            Set-DnsClientServerAddress -InterfaceIndex $IfIndex -ServerAddresses $Servers -ErrorAction Stop
        }
    }
    catch {
        # Fallback (alte OS)
        $alias = (Get-NetAdapter -InterfaceIndex $IfIndex).InterfaceAlias
        if ($Dhcp) {
            netsh interface ip set dns name="$alias" source=dhcp
        } else {
            netsh interface ip set dns name="$alias" static $Servers[0] primary
            if ($Servers.Count -gt 1) {
                netsh interface ip add dns name="$alias" $Servers[1] index=2
            }
        }
    }
}

function Format-Output {
    param(
        [string]$Title,[string]$Content
    )
    Write-Output "`n==== $Title ====`n$Content`n=====================`n"
}

#--------------------------------------------------
#endregion
#region 3 – Ermitteln & Ändern
#--------------------------------------------------

$targets = Get-TargetAdapters
if (-not $targets) {
    Write-Error "Kein Adapter erfüllt die Selektionskriterien (Gateway/Subnetz/Name)."
    exit 1
}

$servers = @()
if (-not $ResetDHCP) {
    $servers += $PrimaryDNS
    if ($SecondaryDNS) { $servers += $SecondaryDNS }
}

$log = [System.Text.StringBuilder]::new()

foreach ($entry in $targets) {
    $ifIdx = $entry.Adapter.ifIndex
    $alias = $entry.Adapter.Name
    $old   = (Get-DnsClientServerAddress -InterfaceIndex $ifIdx -AddressFamily IPv4).ServerAddresses -join ','

    $action = if ($ResetDHCP) { 'DHCP aktiviert' } else { "DNS → $($servers -join ',')" }

    if ($PSCmdlet.ShouldProcess($alias, $action)) {
        Set-Dns -IfIndex $ifIdx -Servers $servers -Dhcp:$ResetDHCP
        [void]$log.AppendLine("[$alias] $action (alt: $old)  GW:$($entry.GatewayIPv4)")
        Write-Verbose "[$alias] $action"
    }
}

ipconfig /flushdns | Out-Null

Format-Output -Title "DNS-Änderungsprotokoll" -Content $log.ToString()

#--------------------------------------------------
#endregion
#region 4 – Custom-Field-Update
#--------------------------------------------------
if (-not $NoCustomField) {
    try {
        $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        $newValue  = if ($ResetDHCP) { "DHCP aktiviert $timestamp" }
                     else { "$($servers -join ', ') | $timestamp" }

        Ninja-Property-Set DNS_LastChange "$newValue"

        $cli = 'C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe'
        if (Test-Path $cli) { & $cli set DNS_LastChange "$newValue" }

        Write-Output "Custom Field 'DNS_LastChange' aktualisiert."
    }
    catch {
        Write-Warning "Custom-Field-Update fehlgeschlagen: $_"
    }
}

#--------------------------------------------------
#endregion
#region 5 – Fertig
#--------------------------------------------------
Write-Host "DNS-Einstellungen erfolgreich geändert."
exit 0
#--------------------------------------------------
#endregion
