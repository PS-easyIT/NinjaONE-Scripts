<#
.SYNOPSIS
    Setzt oder entfernt statische IPv4-DNS-Server nur auf produktiven Netzwerk­adaptern.

    Ein Adapter ist „produktiv“, wenn  
      • ein Default-Gateway vorhanden ist **oder**  
      • seine IPv4-Adresse im -TargetSubnet liegt **oder**  
      • sein Gateway der -TargetGateway-Adresse entspricht.

.DESCRIPTION
    • Ausgeführt als SYSTEM unter NinjaOne / NinjaRMM  
    • Windows 10/11 und Server 2012 R2 +  
    • Nur physische LAN/WLAN-Adapter – virtuelle, VPN, Loopback, Tunnel, Wi-Fi-Direct u.a. werden ignoriert  
    • `Set-DnsClientServerAddress`, Fallback `netsh` für Legacy-OS  
    • Aktualisiert optional das Custom-Field **DNS_LastChange**

.PARAMETERS
    -PrimaryDNS      (IPv4, Pflicht wenn -kein ResetDHCP)
    -SecondaryDNS    (IPv4, optional)
    -TargetSubnet    (CIDR, z. B. 192.168.10.0/24)
    -TargetGateway   (IPv4 Gateway)
    -AdapterName     (Alias/Wildcards, z. B. "Ethernet*")
    -ResetDHCP       (schaltet DNS auf DHCP)
    -NoCustomField   (verhindert Custom-Field-Update)

.EXITCODES
    0 = geändert 1 = Fehler 2 = nichts zu tun 3 = DNS geändert, Custom-Field fehlgeschlagen
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
    
    # Überprüfen, ob die Ninja-Property-Cmdlets existieren (ab Agent 5.3)
    $ninjaPropertyAvailable = $null
    if (-not $script:checkedNinjaPropertySupport) {
        try {
            $ninjaPropertyAvailable = Get-Command "Ninja-Property-Get" -ErrorAction SilentlyContinue
            $script:ninjaPropertySupport = $null -ne $ninjaPropertyAvailable
        } catch {
            $script:ninjaPropertySupport = $false
        }
        $script:checkedNinjaPropertySupport = $true
    }
    
    # Versuch 1: Ninja-Property-Get verwenden (wenn verfügbar)
    if ($script:ninjaPropertySupport) {
        try {
            $value = Ninja-Property-Get $FieldName -ErrorAction SilentlyContinue
        } catch {}
    }
    
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
    
    # Wenn als Boolean gewünscht - NUR true/1 als true interpretieren
    if ($AsBoolean -and $value) {
        return $value -match '^(true|1)$'
    }
    
    return $value
}

# Skriptvariablen initialisieren
$script:checkedNinjaPropertySupport = $false
$script:ninjaPropertySupport = $false


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

# DNS-Server-Validierung
if (-not $ResetDHCP) {
    try {
        # Primären DNS validieren
        [void][IPAddress]::Parse($PrimaryDNS)
        
        # Sekundären DNS validieren, wenn angegeben
        if ($SecondaryDNS) {
            [void][IPAddress]::Parse($SecondaryDNS)
        }
    }
    catch {
        Write-Error "Ungültige IP-Adresse für DNS-Server: $_"
        exit 1
    }
}

$ErrorActionPreference = "Stop"
$VerbosePreference     = "Continue"

# Regex zum Unterdrücken virtueller Adapter mit case-insensitive Pattern
$virtualPattern = '(?i)VMware|Hyper-V|VPN|loopback|Tunnel|TAP|Wi-Fi Direct|WAN Miniport|Bluetooth|Remote Access'

# Regex für erlaubte Adapter-Typen (LAN/WLAN)
$allowedPattern = '(?i)(Ethernet|LAN|Wi-?Fi|WLAN|802\.11|Wireless)'

# Array mit erlaubten Adaptertypen als Referenz
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
        # IP-Validierung
        if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$null)) {
            return $false
        }
        
        [IPAddress]$ipAddr = $Ip
        $parts = $Cidr.Split('/')
        
        # CIDR-Format validieren
        if ($parts.Length -ne 2) { return $false }
        if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$null)) {
            return $false
        }
        
        [IPAddress]$netAddr = $parts[0]
        
        # Präfix validieren (0-32)
        [int]$prefix = $parts[1]
        if ($prefix -lt 0 -or $prefix -gt 32) { return $false }

        $ipBits   = [BitConverter]::ToUInt32($ipAddr.GetAddressBytes()[::-1],0)
        $netBits  = [BitConverter]::ToUInt32($netAddr.GetAddressBytes()[::-1],0)
        $maskBits = 0xffffffff -shl (32 - $prefix)

        return (($ipBits -band $maskBits) -eq ($netBits -band $maskBits))
    }
    catch { return $false }
}

function Get-TargetAdapters {
    # Adapter filtern: Nur aktive Adapter, keine virtuellen Adapter, nur LAN/WLAN
    $adapters = Get-NetAdapter | Where-Object {
        ($_.Status -in @('Up','Unknown') -or $_.LinkSpeed -gt 0) -and
        $_.InterfaceDescription -inotmatch $virtualPattern -and
        $_.InterfaceDescription -match $allowedPattern
    }

    # Optional: Hardware-ID prüfung nur für Windows 10 2004+ / Server 2022+
    if ([Environment]::OSVersion.Version.Build -ge 19041) {
        $adapters = $adapters | Where-Object {
            $isWiFiAdapter = $false
            try {
                $hw = Get-NetAdapterHardwareInfo -InterfaceIndex $_.InterfaceIndex -ErrorAction Stop
                if ($hw) {
                    $isWiFiAdapter = $hw.PnPDeviceID -imatch 'WLAN|WiFi|Wireless|802\.11'
                }
            } catch {}
            # Nur Hardware-Check ergänzen, nicht ersetzen (OR-Bedingung)
            return $true -or $isWiFiAdapter
        }
    }

    # AdapterName-Filter (Wildcard)
    if ($AdapterName) {
        $pattern = ($AdapterName -join '|').Replace('*','.*')
        $adapters = $adapters | Where-Object { $_.Name -match $pattern }
    }

    # Anreicherung mit IP/Gateway-Informationen
    $enriched = foreach ($a in $adapters) {
        $cfg = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex
        [PSCustomObject]@{
            IfIndex = $a.ifIndex
            Alias   = $a.Name
            IPv4    = ($cfg.IPv4Address.IPAddress)[0]
            Gateway = ($cfg.IPv4DefaultGateway.NextHop)[0]
        }
    } | Where-Object Gateway  # Gateway muss vorhanden sein (Basis-Kriterium)

    # Gateway-Filter 
    if ($TargetGateway) {
        $enriched = $enriched | Where-Object { $_.Gateway -eq $TargetGateway }
    }

    # Subnetz-Filter
    if ($TargetSubnet) {
        $enriched = $enriched | Where-Object { Test-IPv4InSubnet $_.IPv4 $TargetSubnet }
    }

    return $enriched
}

function Set-DnsIPv4 {
    param(
        [int]$Idx,
        [string[]]$Srv,
        [switch]$Dhcp
    )
    try {
        if ($Dhcp) { 
            Set-DnsClientServerAddress -InterfaceIndex $Idx -ResetServerAddresses -EA Stop 
        } else { 
            Set-DnsClientServerAddress -InterfaceIndex $Idx -ServerAddresses $Srv -EA Stop 
        }
    } catch {
        # Fallback auf netsh für ältere Betriebssysteme
        $alias = (Get-NetAdapter -InterfaceIndex $Idx).InterfaceAlias
        if ($Dhcp) { 
            netsh interface ip set dns name="$alias" source=dhcp 
        } else {
            netsh interface ip set dns name="$alias" static $Srv[0] primary
            # Dynamische Indizes für alle weiteren DNS-Server
            for ($i = 1; $i -lt $Srv.Count; $i++) { 
                netsh interface ip add dns name="$alias" $Srv[$i] index=($i+1) 
            }
        }
    }
}

function CF-Update {
    param([string]$val)
    $ok = $false
    
    try { 
        Ninja-Property-Set DNS_LastChange "$val"; $ok = $true 
    } catch { }
    
    if (-not $ok) {
        $cli = 'C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe'
        if (Test-Path $cli) { 
            & $cli set DNS_LastChange "$val" 
            if (-not $LASTEXITCODE) { $ok = $true }
        }
    }
    return $ok
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

# Zähler für Änderungen initialisieren
$changed = 0
$skipped = 0

$targets = Get-TargetAdapters
if (-not $targets) {
    Write-Error "Kein Adapter erfüllt die Selektionskriterien (Gateway/Subnetz/Name)."
    exit 1
}

$servers = @()
if (-not $ResetDHCP) {
    # DNS-Duplikate entfernen
    $servers = @($PrimaryDNS, $SecondaryDNS) | Where-Object { $_ } | Select-Object -Unique
}

$log = [System.Text.StringBuilder]::new()

foreach ($entry in $targets) {
    $ifIdx = $entry.Adapter.ifIndex
    $alias = $entry.Adapter.Name
    $old   = (Get-DnsClientServerAddress -InterfaceIndex $ifIdx -AddressFamily IPv4).ServerAddresses -join ','

    $action = if ($ResetDHCP) { 'DHCP aktiviert' } else { "DNS → $($servers -join ',')" }
    
    # Prüfen, ob sich Einstellung wirklich ändert
    $new = if ($ResetDHCP) { "DHCP" } else { $servers -join ',' }
    if ($old -eq $new) { 
        Write-Warning "[$alias] DNS-Einstellungen unverändert"
        $skipped++
        continue
    }

    if ($PSCmdlet.ShouldProcess($alias, $action)) {
        # DNS-Einstellungen anwenden
        Set-Dns -IfIndex $ifIdx -Servers $servers -Dhcp:$ResetDHCP
        
        # Detailliertere Log-Information
        $logEntry = "[$alias] $action (alt: $old)"
        if ($entry.GatewayIPv4) {
            $logEntry += "  GW:$($entry.GatewayIPv4)"
        }
        [void]$log.AppendLine($logEntry)
        Write-Verbose "[$alias] $action"
        $changed++
    }
}

# Anderen Exit-Code verwenden wenn keine Änderung erfolgte
if ($changed -eq 0 -and $skipped -gt 0) {
    exit 2  # No Change
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

        # Beide Methoden versuchen
        $updateSuccess = $false
        
        try {
            Ninja-Property-Set DNS_LastChange "$newValue"
            $updateSuccess = $true
        } catch {
            Write-Verbose "Ninja-Property-Set fehlgeschlagen: $_"
        }

        $cli = 'C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe'
        if (-not $updateSuccess -and (Test-Path $cli)) { 
            $cliResult = & $cli set DNS_LastChange "$newValue" 2>&1
            if ($LASTEXITCODE -eq 0) {
                $updateSuccess = $true
            }
        }

        if ($updateSuccess) {
            Write-Output "Custom Field 'DNS_LastChange' aktualisiert."
        } else {
            Write-Error "Custom-Field-Update fehlgeschlagen"
            # Exitcode 3 (soft fail) für diesen speziellen Fall
            if ($changed -gt 0) { exit 3 }
        }
    }
    catch {
        Write-Error "Custom-Field-Update fehlgeschlagen: $_"
        if ($changed -gt 0) { exit 3 }
    }
}

#--------------------------------------------------
#region 5 – Fertig
#--------------------------------------------------
# Zusammenfassung der Ausführung erstellen
$summary = [System.Text.StringBuilder]::new()
[void]$summary.AppendLine("Zusammenfassung der Ausführung:")
[void]$summary.AppendLine("- Geänderte Adapter: $changed")
[void]$summary.AppendLine("- Unveränderte Adapter: $skipped")

Write-Output $summary.ToString()

if ($changed -gt 0) {
    Write-Host "DNS-Einstellungen erfolgreich geändert."
    exit 0  # Changed
} elseif ($skipped -gt 0) {
    Write-Host "Keine DNS-Einstellungen geändert, da bereits korrekt konfiguriert."
    exit 2  # No Change
} else {
    Write-Error "Keine passenden Adapter gefunden."
    exit 1  # Error
}
#--------------------------------------------------
#endregion
