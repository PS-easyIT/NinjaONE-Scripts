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

.PARAMETER PrimaryDNS
    Neuer primärer DNS-Server (IPv4). Pflicht im Static-Modus, wenn -ResetDHCP nicht verwendet wird.

.PARAMETER SecondaryDNS
    Optionaler zweiter DNS-Server (IPv4).

.PARAMETER TargetSubnet
    IPv4-Subnetz in CIDR-Notation (z. B. 192.168.10.0/24).
    Wird angegeben, werden nur Adapter berücksichtigt, deren IPv4-Adresse innerhalb dieses Netzes liegt.

.PARAMETER TargetGateway
    Explizite Gateway-Adresse (z. B. 192.168.10.1).
    Wird angegeben, werden nur Adapter berücksichtigt, deren Default-Gateway exakt dieser Adresse entspricht.

.PARAMETER AdapterName
    Optionale Liste von Adapter-Aliasen (Unterstützt Wildcards: "Ethernet*").

.PARAMETER ResetDHCP
    Entfernt statische DNS-Einträge und schaltet DNS auf DHCP zurück.
    Im DHCP-Modus darf PrimaryDNS nicht angegeben werden.

.PARAMETER NoCustomField
    Unterdrückt das Update des Custom-Fields "DNS_LastChange".

.EXITCODES 0/1/2
    0 = geändert
    1 = Fehler
    2 = nichts zu tun
    3 = DNS geändert, Custom-Field fehlgeschlagen

.NOTES
    Dateiname: setDNSSettingsClient.ps1
    Autor:     Andreas Hepp
    Update:    28.05.2025
    Version:   1.5
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'StaticDNS')]
param (
    [Parameter(Mandatory = $false, ParameterSetName = 'StaticDNS')]
    [ValidatePattern('^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')]
    [Alias('DNS1')]
    [string]$PrimaryDNS,

    [Parameter(Mandatory = $false, ParameterSetName = 'StaticDNS')]
    [ValidatePattern('^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')]
    [Alias('DNS2')]
    [string]$SecondaryDNS,

    [Parameter(Mandatory = $false, ParameterSetName = 'StaticDNS')]
    [Parameter(Mandatory = $false, ParameterSetName = 'DHCP')]
    [string]$TargetSubnet,

    [Parameter(Mandatory = $false, ParameterSetName = 'StaticDNS')]
    [Parameter(Mandatory = $false, ParameterSetName = 'DHCP')]
    [string]$TargetGateway,

    [Parameter(Mandatory = $false, ParameterSetName = 'StaticDNS')]
    [Parameter(Mandatory = $false, ParameterSetName = 'DHCP')]
    [string[]]$AdapterName,

    [Parameter(Mandatory = $true, ParameterSetName = 'DHCP')]
    [Parameter(Mandatory = $false, ParameterSetName = 'StaticDNS')]
    [switch]$ResetDHCP,

    [Parameter(Mandatory = $false, ParameterSetName = 'StaticDNS')]
    [Parameter(Mandatory = $false, ParameterSetName = 'DHCP')]
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
    
    # Wenn als Boolean gewünscht - true/1/yes als true, false/0/no als false, sonst null
    if ($AsBoolean) {
        if ($value -match '^(true|1|yes)$') { return $true }
        elseif ($value -match '^(false|0|no)$') { return $false }
        else { return $null }
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
if ($null -eq $cf_ResetDHCP) {
    Write-Warning "Ungültiger Wert in DNS_ResetToDHCP Custom Field"
}
elseif ($cf_ResetDHCP -and -not $ResetDHCP) {
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
$virtualPattern = '(?i)VMware|Hyper-V|vEthernet|VPN|loopback|Tunnel|TAP|Wi-Fi Direct|WAN Miniport|Bluetooth|Remote Access'

# Regex für erlaubte Adapter-Typen (LAN/WLAN)
$allowedPattern = '(?i)(Ethernet|LAN|Wi-?Fi|WLAN|802\.11|Wireless|Realtek|Intel|Broadcom|Atheros|Qualcomm|TP-Link|D-Link|MediaTek|Killer|Marvell|NVIDIA|ASIX|Aquantia|Belkin|Linksys|Microsoft Wireless|Microsoft Ethernet)'

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
        
        # Präfix validieren (1-32)
        [int]$prefix = $parts[1]
        if ($prefix -lt 1 -or $prefix -gt 32) {
            # Präfix 0 nicht erlaubt (entspricht dem kompletten Internet)
            return $false
        }

        # Korrekte PowerShell-Syntax für Byte-Array-Umkehrung
        $ipBytes = [byte[]]$ipAddr.GetAddressBytes()
        [array]::Reverse($ipBytes)
        $ipBits = [BitConverter]::ToUInt32($ipBytes, 0)
        
        $netBytes = [byte[]]$netAddr.GetAddressBytes()
        [array]::Reverse($netBytes)
        $netBits = [BitConverter]::ToUInt32($netBytes, 0)
        
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

    # Hardware-ID Cache für bessere Performance
    $hwCache = @{}
    
    # Hardware-ID prüfung nur für Windows 10 2004+ / Server 2022+
    if ([Environment]::OSVersion.Version.Build -ge 19041) {
        # Alle Hardware-Infos einmalig abrufen für bessere Performance
        try {
            foreach ($adapter in $adapters) {
                try {
                    $hw = Get-NetAdapterHardwareInfo -InterfaceIndex $adapter.InterfaceIndex -ErrorAction Stop
                    if ($hw) {
                        $hwCache[$adapter.InterfaceIndex] = $hw.PnPDeviceID -imatch 'WLAN|WiFi|Wireless|802\.11'
                    }
                } catch {
                    $hwCache[$adapter.InterfaceIndex] = $false
                }
            }
        } catch {
            # Bei globalem Fehler einfach mit leeren Cache fortfahren
            Write-Verbose "Hardware-Info konnte nicht abgerufen werden: $_"
        }
        
        # Nach der ersten Filterung bereits Adapter mit Pattern ausgewählt
        # Jetzt nur noch Adapter prüfen, die noch nicht durch das Pattern erkannt wurden
        $adapters = $adapters | Where-Object {
            # Entweder bereits durch Pattern qualifiziert...
            $_.InterfaceDescription -match $allowedPattern -or
            # ...oder durch Hardware-ID als WLAN identifiziert
            ($hwCache.ContainsKey($_.InterfaceIndex) -and $hwCache[$_.InterfaceIndex])
        }
    }

    # AdapterName-Filter (Wildcard) mit sicherem Escaping
    if ($AdapterName) {
        $pattern = ($AdapterName | ForEach-Object {
            [regex]::Escape($_) -replace '\\\*','.*'
        }) -join '|'
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
    }
    
    # Adapter-Selektionsstrategie gemäß Spezifikation:
    # 1. Wenn expliziter Gateway-Filter -> Nur mit passendem Gateway
    if ($TargetGateway) {
        $enriched = $enriched | Where-Object { $_.Gateway -eq $TargetGateway }
    }
    # 2. Wenn Subnetz-Filter -> Adapter in diesem Subnetz (mit oder ohne Gateway)
    elseif ($TargetSubnet) {
        $enriched = $enriched | Where-Object { Test-IPv4InSubnet $_.IPv4 $TargetSubnet }
    }
    # 3. Wenn weder Gateway- noch Subnetz-Filter -> Nur Adapter mit Gateway
    else {
        $enriched = $enriched | Where-Object Gateway
    }

    return $enriched
}

function Set-DnsIPv4 {
    param(
        [int]$Idx,
        [string[]]$Srv,
        [switch]$Dhcp
    )
    # Timeout-Parameter für den Job
    $timeoutSec = 15
    
    try {
        # Als Job ausführen, um Hänger bei defekten Treibern zu vermeiden
        $scriptBlock = {
            param($Idx, $Srv, $Dhcp)
            
            # Lokale Kopie des Arrays erstellen, um Nebeneffekte zu vermeiden
            [int]$localIdx = $Idx
            [string[]]$localSrv = $Srv.Clone()
            [bool]$localDhcp = $Dhcp
            
            if ($localDhcp) { 
                Set-DnsClientServerAddress -InterfaceIndex $localIdx -ResetServerAddresses -EA Stop 
            } else { 
                Set-DnsClientServerAddress -InterfaceIndex $localIdx -ServerAddresses $localSrv -EA Stop 
            }
        }
        
        $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $Idx, $Srv, $Dhcp
        if (Wait-Job $job -Timeout $timeoutSec) {
            # Job erfolgreich abgeschlossen
            Receive-Job $job -ErrorAction SilentlyContinue | Out-Null
            Remove-Job $job -Force
            return  # Erfolgreich beendet
        } else {
            # Timeout erreicht
            Stop-Job $job -Force
            Remove-Job $job -Force
            Write-Warning "Timeout bei Set-DnsClientServerAddress nach $timeoutSec Sekunden - Fallback auf netsh"
            # Weiter mit netsh-Fallback
        }
    } catch {
        Write-Verbose "Fehler bei Set-DnsClientServerAddress: $_"
        # Weiter mit netsh-Fallback
    }
    
    # Fallback auf netsh bei Timeout oder Fehler
    try {
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
    } catch {
        Write-Error "Fehler auch bei netsh-Fallback: $_"
    }
}

function CF-Update {
    param([string]$val)
    $ok = $false
    
    # Prüfen, ob Ninja-Property-Set verfügbar ist
    if (Get-Command Ninja-Property-Set -EA SilentlyContinue) {
        try { 
            Ninja-Property-Set DNS_LastChange "$val" 
            # Erfolgreich nur wenn kein Fehler aufgetreten ist
            $ok = $true
        } catch { 
            Write-Verbose "Fehler bei Ninja-Property-Set: $_" 
        }
    }
    
    # Fallback: CLI verwenden wenn Property-Set fehlgeschlagen ist
    if (-not $ok) {
        $cli = 'C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe'
        if (Test-Path $cli) { 
            try {
                $cliOutput = & $cli set DNS_LastChange "$val" 2>&1
                # Bei Erfolg ist LASTEXITCODE 0
                if ($LASTEXITCODE -eq 0) { 
                    $ok = $true 
                } else { 
                    Write-Verbose "CLI-Fehler (Code $LASTEXITCODE): $cliOutput" 
                }
            } catch {
                Write-Verbose "Fehler bei CLI-Aufruf: $_"
            }
        }
    }
    return $ok
}

function Format-Output {
    param(
        [string]$Title,
        [string]$Content
    )
    Write-Output "`n==== $Title ====`n$Content`n=====================`n"
}

#--------------------------------------------------
#endregion
#region 3 – Ausführung
#--------------------------------------------------

# Optional Logging aktivieren
$logPath = "$env:ProgramData\NinjaRMMAgent\Logs\DNS_$(Get-Date -f yyyyMMdd_HHmmss).log"
# Logs-Verzeichnis erstellen, falls nicht vorhanden
New-Item -ItemType Directory -Path (Split-Path $logPath) -EA Ignore | Out-Null
Start-Transcript -Path $logPath -ErrorAction SilentlyContinue

# Adapter ermitteln
$targets = Get-TargetAdapters
if (-not $targets) { 
    Write-Error 'Kein passender Adapter gefunden.'
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}

# DNS-Server-Liste erstellen (leeres Array bei DHCP, sonst deduplizierte Liste)
$servers = if ($ResetDHCP) { 
    @() 
} else { 
    @($PrimaryDNS, $SecondaryDNS) | Where-Object { $_ } | Select-Object -Unique 
}

# Fail-Fast: Wenn keine DNS-Server definiert und nicht ResetDHCP
if ($servers.Count -eq 0 -and -not $ResetDHCP) {
    Write-Error "Keine gültigen DNS-Server angegeben. Benutze -ResetDHCP oder gib mindestens einen DNS-Server an."
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}

# Zähler initialisieren
$changed = 0
$skipped = 0
$log = [System.Text.StringBuilder]::new()

# Adapter durchlaufen und DNS-Einstellungen ändern
foreach ($t in $targets) {
    # Aktuelle DNS-Server ermitteln (explizit nur IPv4)
    $old = (Get-DnsClientServerAddress -InterfaceIndex $t.IfIndex -AddressFamily IPv4).ServerAddresses -join ','
    $new = if ($ResetDHCP) { 'DHCP' } else { $servers -join ',' }
    
    # Nur ändern, wenn nötig
    if ($old -eq $new) { 
        $skipped++
        Write-Verbose "[$($t.Alias)] DNS-Einstellungen unverändert: $old"
        continue 
    }
    
    # Aktion definieren
    $action = if ($ResetDHCP) { 'DHCP aktiviert' } else { "DNS → $new" }
    
    # DNS-Änderung durchführen, wenn ShouldProcess das erlaubt
    if ($PSCmdlet.ShouldProcess($t.Alias, $action)) {
        Set-DnsIPv4 -Idx $t.IfIndex -Srv $servers -Dhcp:$ResetDHCP
        
        # Log-Eintrag erstellen
        $logEntry = "[$($t.Alias)] $action (alt: $old)"
        if ($t.Gateway) { $logEntry += " GW:$($t.Gateway)" }
        [void]$log.AppendLine($logEntry)
        Write-Verbose $logEntry
        $changed++
    }
}

# DNS-Cache leeren
ipconfig /flushdns | Out-Null

# Ergebnisse ausgeben
Write-Output "`n==== DNS-Änderungsprotokoll ====`n$($log.ToString())`n==============================="

#--------------------------------------------------
#endregion
#region 4 – Custom-Field
#--------------------------------------------------
if (-not $NoCustomField) {
    $ts = (Get-Date -f 'yyyy-MM-dd HH:mm')
    $val = if ($ResetDHCP) { "DHCP aktiviert $ts" } else { "$($servers -join ', ') | $ts" }
    
    if (-not (CF-Update $val)) { 
        Write-Warning 'Custom-Field-Update fehlgeschlagen.'
        if ($changed) { exit 3 }  # Soft-Fail: DNS geändert, aber CF nicht aktualisiert
    } else {
        Write-Output "Custom Field 'DNS_LastChange' aktualisiert."
    }
}

#--------------------------------------------------
#endregion
#region 5 – Zusammenfassung
#--------------------------------------------------

# Kompakte Zusammenfassung
Write-Output "`nZusammenfassung der Ausführung:`n- Geänderte Adapter: $changed`n- Unveränderte Adapter: $skipped`n"

# Exit-Code basierend auf Ergebnis
if ($changed) { 
    Write-Host "DNS-Einstellungen erfolgreich geändert."
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 0  # Changed 
} elseif ($skipped) { 
    Write-Host "Keine DNS-Einstellungen geändert, da bereits korrekt konfiguriert."
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 2  # No Change 
} else { 
    Write-Error "Keine passenden Adapter gefunden."
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1  # Error 
}

#--------------------------------------------------
#endregion
