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

# SIG # Begin signature block
# MIIoiQYJKoZIhvcNAQcCoIIoejCCKHYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDRTPDbRYZ437Vf
# 3KILDIlayMYh7MBqA869Mp8zoko3iqCCILswggXJMIIEsaADAgECAhAbtY8lKt8j
# AEkoya49fu0nMA0GCSqGSIb3DQEBDAUAMH4xCzAJBgNVBAYTAlBMMSIwIAYDVQQK
# ExlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLEx5DZXJ0dW0gQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkxIjAgBgNVBAMTGUNlcnR1bSBUcnVzdGVkIE5l
# dHdvcmsgQ0EwHhcNMjEwNTMxMDY0MzA2WhcNMjkwOTE3MDY0MzA2WjCBgDELMAkG
# A1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAl
# BgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAxMb
# Q2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAvfl4+ObVgAxknYYblmRnPyI6HnUBfe/7XGeMycxca6mR5rlC
# 5SBLm9qbe7mZXdmbgEvXhEArJ9PoujC7Pgkap0mV7ytAJMKXx6fumyXvqAoAl4Va
# qp3cKcniNQfrcE1K1sGzVrihQTib0fsxf4/gX+GxPw+OFklg1waNGPmqJhCrKtPQ
# 0WeNG0a+RzDVLnLRxWPa52N5RH5LYySJhi40PylMUosqp8DikSiJucBb+R3Z5yet
# /5oCl8HGUJKbAiy9qbk0WQq/hEr/3/6zn+vZnuCYI+yma3cWKtvMrTscpIfcRnNe
# GWJoRVfkkIJCu0LW8GHgwaM9ZqNd9BjuiMmNF0UpmTJ1AjHuKSbIawLmtWJFfzcV
# WiNoidQ+3k4nsPBADLxNF8tNorMe0AZa3faTz1d1mfX6hhpneLO/lv403L3nUlbl
# s+V1e9dBkQXcXWnjlQ1DufyDljmVe2yAWk8TcsbXfSl6RLpSpCrVQUYJIP4ioLZb
# MI28iQzV13D4h1L92u+sUS4Hs07+0AnacO+Y+lbmbdu1V0vc5SwlFcieLnhO+Nqc
# noYsylfzGuXIkosagpZ6w7xQEmnYDlpGizrrJvojybawgb5CAKT41v4wLsfSRvbl
# jnX98sy50IdbzAYQYLuDNbdeZ95H7JlI8aShFf6tjGKOOVVPORa5sWOd/7cCAwEA
# AaOCAT4wggE6MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLahVDkCw6A/joq8
# +tT4HKbROg79MB8GA1UdIwQYMBaAFAh2zcsH/yT2xc3tu5C84oQ3RnX3MA4GA1Ud
# DwEB/wQEAwIBBjAvBgNVHR8EKDAmMCSgIqAghh5odHRwOi8vY3JsLmNlcnR1bS5w
# bC9jdG5jYS5jcmwwawYIKwYBBQUHAQEEXzBdMCgGCCsGAQUFBzABhhxodHRwOi8v
# c3ViY2Eub2NzcC1jZXJ0dW0uY29tMDEGCCsGAQUFBzAChiVodHRwOi8vcmVwb3Np
# dG9yeS5jZXJ0dW0ucGwvY3RuY2EuY2VyMDkGA1UdIAQyMDAwLgYEVR0gADAmMCQG
# CCsGAQUFBwIBFhhodHRwOi8vd3d3LmNlcnR1bS5wbC9DUFMwDQYJKoZIhvcNAQEM
# BQADggEBAFHCoVgWIhCL/IYx1MIy01z4S6Ivaj5N+KsIHu3V6PrnCA3st8YeDrJ1
# BXqxC/rXdGoABh+kzqrya33YEcARCNQOTWHFOqj6seHjmOriY/1B9ZN9DbxdkjuR
# mmW60F9MvkyNaAMQFtXx0ASKhTP5N+dbLiZpQjy6zbzUeulNndrnQ/tjUoCFBMQl
# lVXwfqefAcVbKPjgzoZwpic7Ofs4LphTZSJ1Ldf23SIikZbr3WjtP6MZl9M7JYjs
# NhI9qX7OAo0FmpKnJ25FspxihjcNpDOO16hO0EoXQ0zF8ads0h5YbBRRfopUofbv
# n3l6XYGaFpAP4bvxSgD5+d2+7arszgowggaDMIIEa6ADAgECAhEAnpwE9lWotKcC
# bUmMbHiNqjANBgkqhkiG9w0BAQwFADBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gVGltZXN0
# YW1waW5nIDIwMjEgQ0EwHhcNMjUwMTA5MDg0MDQzWhcNMzYwMTA3MDg0MDQzWjBQ
# MQswCQYDVQQGEwJQTDEhMB8GA1UECgwYQXNzZWNvIERhdGEgU3lzdGVtcyBTLkEu
# MR4wHAYDVQQDDBVDZXJ0dW0gVGltZXN0YW1wIDIwMjUwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDHKV9n+Kwr3ZBF5UCLWOQ/NdbblAvQeGMjfCi/bibT
# 71hPkwKV4UvQt1MuOwoaUCYtsLhw8jrmOmoz2HoHKKzEpiS3A1rA3ssXUZMnSrbi
# iVpDj+5MtnbXSVEJKbccuHbmwcjl39N4W72zccoC/neKAuwO1DJ+9SO+YkHncRiV
# 95idWhxRAcDYv47hc9GEFZtTFxQXLbrL4N7N90BqLle3ayznzccEPQ+E6H6p00zE
# 9HUp++3bZTF4PfyPRnKCLc5ezAzEqqbbU5F/nujx69T1mm02jltlFXnTMF1vlake
# QXWYpGIjtrR7WP7tIMZnk78nrYSfeAp8le+/W/5+qr7tqQZufW9invsRTcfk7P+m
# nKjJLuSbwqgxelvCBryz9r51bT0561aR2c+joFygqW7n4FPCnMLOj40X4ot7wP2u
# 8kLRDVHbhsHq5SGLqr8DbFq14ws2ALS3tYa2GGiA7wX79rS5oDMnSY/xmJO5cupu
# SvqpylzO7jzcLOwWiqCrq05AXp51SRrj9xRt8KdZWpDdWhWmE8MFiFtmQ0AqODLJ
# Bn1hQAx3FvD/pte6pE1Bil0BOVC2Snbeq/3NylDwvDdAg/0CZRJsQIaydHswJwyY
# BlYUDyaQK2yUS57hobnYx/vStMvTB96ii4jGV3UkZh3GvwdDCsZkbJXaU8ATF/z6
# DwIDAQABo4IBUDCCAUwwdQYIKwYBBQUHAQEEaTBnMDsGCCsGAQUFBzAChi9odHRw
# Oi8vc3ViY2EucmVwb3NpdG9yeS5jZXJ0dW0ucGwvY3RzY2EyMDIxLmNlcjAoBggr
# BgEFBQcwAYYcaHR0cDovL3N1YmNhLm9jc3AtY2VydHVtLmNvbTAfBgNVHSMEGDAW
# gBS+VAIvv0Bsc0POrAklTp5DRBru4DAMBgNVHRMBAf8EAjAAMDkGA1UdHwQyMDAw
# LqAsoCqGKGh0dHA6Ly9zdWJjYS5jcmwuY2VydHVtLnBsL2N0c2NhMjAyMS5jcmww
# FgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMCIGA1UdIAQb
# MBkwCAYGZ4EMAQQCMA0GCyqEaAGG9ncCBQELMB0GA1UdDgQWBBSBjAagKFP8AD/b
# fp5KwR8i7LISiTANBgkqhkiG9w0BAQwFAAOCAgEAmQ8ZDBvrBUPnaL87AYc4Jlmf
# H1ZP5yt65MtzYu8fbmsL3d3cvYs+Enbtfu9f2wMehzSyved3Rc59a04O8NN7plw4
# PXg71wfSE4MRFM1EuqL63zq9uTjm/9tA73r1aCdWmkprKp0aLoZolUN0qGcvr9+Q
# G8VIJVMcuSqFeEvRrLEKK2xVkMSdTTbDhseUjI4vN+BrXm5z45EA3aDpSiZQuoNd
# 4RFnDzddbgfcCQPaY2UyXqzNBjnuz6AyHnFzKtNlCevkMBgh4dIDt/0DGGDOaTEA
# WZtUEqK5AlHd0PBnd40Lnog4UATU3Bt6GHfeDmWEHFTjHKsmn9Q8wiGj906bVgL8
# 35tfEH9EgYDklqrOUxWxDf1cOA7ds/r8pIc2vjLQ9tOSkm9WXVbnTeLG3Q57frTg
# CvTObd/qf3UzE97nTNOU7vOMZEo41AgmhuEbGsyQIDM/V6fJQX1RnzzJNoqfTTkU
# zUoP2tlNHnNsjFo2YV+5yZcoaawmNWmR7TywUXG2/vFgJaG0bfEoodeeXp7A4I4H
# aDDpfRa7ypgJEPeTwHuBRJpj9N+1xtri+6BzHPwsAAvUJm58PGoVsteHAXwvpg4N
# VgvUk3BKbl7xFulWU1KHqH/sk7T0CFBQ5ohuKPmFf1oqAP4AO9a3Yg2wBMwEg1zP
# Oh6xbUXskzs9iSa9yGwwgga5MIIEoaADAgECAhEAmaOACiZVO2Wr3G6EprPqOTAN
# BgkqhkiG9w0BAQwFADCBgDELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8g
# VGVjaG5vbG9naWVzIFMuQS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9u
# IEF1dGhvcml0eTEkMCIGA1UEAxMbQ2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAy
# MB4XDTIxMDUxOTA1MzIxOFoXDTM2MDUxODA1MzIxOFowVjELMAkGA1UEBhMCUEwx
# ITAfBgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5BLjEkMCIGA1UEAxMbQ2Vy
# dHVtIENvZGUgU2lnbmluZyAyMDIxIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAnSPPBDAjO8FGLOczcz5jXXp1ur5cTbq96y34vuTmflN4mSAfgLKT
# vggv24/rWiVGzGxT9YEASVMw1Aj8ewTS4IndU8s7VS5+djSoMcbvIKck6+hI1shs
# ylP4JyLvmxwLHtSworV9wmjhNd627h27a8RdrT1PH9ud0IF+njvMk2xqbNTIPsnW
# tw3E7DmDoUmDQiYi/ucJ42fcHqBkbbxYDB7SYOouu9Tj1yHIohzuC8KNqfcYf7Z4
# /iZgkBJ+UFNDcc6zokZ2uJIxWgPWXMEmhu1gMXgv8aGUsRdaCtVD2bSlbfsq7Biq
# ljjaCun+RJgTgFRCtsuAEw0pG9+FA+yQN9n/kZtMLK+Wo837Q4QOZgYqVWQ4x6cM
# 7/G0yswg1ElLlJj6NYKLw9EcBXE7TF3HybZtYvj9lDV2nT8mFSkcSkAExzd4prHw
# YjUXTeZIlVXqj+eaYqoMTpMrfh5MCAOIG5knN4Q/JHuurfTI5XDYO962WZayx7AC
# Ff5ydJpoEowSP07YaBiQ8nXpDkNrUA9g7qf/rCkKbWpQ5boufUnq1UiYPIAHlezf
# 4muJqxqIns/kqld6JVX8cixbd6PzkDpwZo4SlADaCi2JSplKShBSND36E/ENVv8u
# rPS0yOnpG4tIoBGxVCARPCg1BnyMJ4rBJAcOSnAWd18Jx5n858JSqPECAwEAAaOC
# AVUwggFRMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFN10XUwA23ufoHTKsW73
# PMAywHDNMB8GA1UdIwQYMBaAFLahVDkCw6A/joq8+tT4HKbROg79MA4GA1UdDwEB
# /wQEAwIBBjATBgNVHSUEDDAKBggrBgEFBQcDAzAwBgNVHR8EKTAnMCWgI6Ahhh9o
# dHRwOi8vY3JsLmNlcnR1bS5wbC9jdG5jYTIuY3JsMGwGCCsGAQUFBwEBBGAwXjAo
# BggrBgEFBQcwAYYcaHR0cDovL3N1YmNhLm9jc3AtY2VydHVtLmNvbTAyBggrBgEF
# BQcwAoYmaHR0cDovL3JlcG9zaXRvcnkuY2VydHVtLnBsL2N0bmNhMi5jZXIwOQYD
# VR0gBDIwMDAuBgRVHSAAMCYwJAYIKwYBBQUHAgEWGGh0dHA6Ly93d3cuY2VydHVt
# LnBsL0NQUzANBgkqhkiG9w0BAQwFAAOCAgEAdYhYD+WPUCiaU58Q7EP89DttyZqG
# Yn2XRDhJkL6P+/T0IPZyxfxiXumYlARMgwRzLRUStJl490L94C9LGF3vjzzH8Jq3
# iR74BRlkO18J3zIdmCKQa5LyZ48IfICJTZVJeChDUyuQy6rGDxLUUAsO0eqeLNhL
# Vsgw6/zOfImNlARKn1FP7o0fTbj8ipNGxHBIutiRsWrhWM2f8pXdd3x2mbJCKKtl
# 2s42g9KUJHEIiLni9ByoqIUul4GblLQigO0ugh7bWRLDm0CdY9rNLqyA3ahe8Wlx
# VWkxyrQLjH8ItI17RdySaYayX3PhRSC4Am1/7mATwZWwSD+B7eMcZNhpn8zJ+6MT
# yE6YoEBSRVrs0zFFIHUR08Wk0ikSf+lIe5Iv6RY3/bFAEloMU+vUBfSouCReZwSL
# o8WdrDlPXtR0gicDnytO7eZ5827NS2x7gCBibESYkOh1/w1tVxTpV2Na3PR7nxYV
# lPu1JPoRZCbH86gc96UTvuWiOruWmyOEMLOGGniR+x+zPF/2DaGgK2W1eEJfo2qy
# rBNPvF7wuAyQfiFXLwvWHamoYtPZo0LHuH8X3n9C+xN4YaNjt2ywzOr+tKyEVAot
# nyU9vyEVOaIYMk3IeBrmFnn0gbKeTTyYeEEUz/Qwt4HOUBCrW602NCmvO1nm+/80
# nLy5r0AZvCQxaQ4wgga5MIIEoaADAgECAhEA5/9pxzs1zkuRJth0fGilhzANBgkq
# hkiG9w0BAQwFADCBgDELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVj
# aG5vbG9naWVzIFMuQS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1
# dGhvcml0eTEkMCIGA1UEAxMbQ2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMB4X
# DTIxMDUxOTA1MzIwN1oXDTM2MDUxODA1MzIwN1owVjELMAkGA1UEBhMCUEwxITAf
# BgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5BLjEkMCIGA1UEAxMbQ2VydHVt
# IFRpbWVzdGFtcGluZyAyMDIxIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA6RIfBDXtuV16xaaVQb6KZX9Od9FtJXXTZo7b+GEof3+3g0ChWiKnO7R4
# +6MfrvLyLCWZa6GpFHjEt4t0/GiUQvnkLOBRdBqr5DOvlmTvJJs2X8ZmWgWJjC7P
# BZLYBWAs8sJl3kNXxBMX5XntjqWx1ZOuuXl0R4x+zGGSMzZ45dpvB8vLpQfZkfMC
# /1tL9KYyjU+htLH68dZJPtzhqLBVG+8ljZ1ZFilOKksS79epCeqFSeAUm2eMTGpO
# iS3gfLM6yvb8Bg6bxg5yglDGC9zbr4sB9ceIGRtCQF1N8dqTgM/dSViiUgJkcv5d
# LNJeWxGCqJYPgzKlYZTgDXfGIeZpEFmjBLwURP5ABsyKoFocMzdjrCiFbTvJn+bD
# 1kq78qZUgAQGGtd6zGJ88H4NPJ5Y2R4IargiWAmv8RyvWnHr/VA+2PrrK9eXe5q7
# M88YRdSTq9TKbqdnITUgZcjjm4ZUjteq8K331a4P0s2in0p3UubMEYa/G5w6jSWP
# UzchGLwWKYBfeSu6dIOC4LkeAPvmdZxSB1lWOb9HzVWZoM8Q/blaP4LWt6JxjkI9
# yQsYGMdCqwl7uMnPUIlcExS1mzXRxUowQref/EPaS7kYVaHHQrp4XB7nTEtQhkP0
# Z9Puz/n8zIFnUSnxDof4Yy650PAXSYmK2TcbyDoTNmmt8xAxzcMCAwEAAaOCAVUw
# ggFRMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFL5UAi+/QGxzQ86sCSVOnkNE
# Gu7gMB8GA1UdIwQYMBaAFLahVDkCw6A/joq8+tT4HKbROg79MA4GA1UdDwEB/wQE
# AwIBBjATBgNVHSUEDDAKBggrBgEFBQcDCDAwBgNVHR8EKTAnMCWgI6Ahhh9odHRw
# Oi8vY3JsLmNlcnR1bS5wbC9jdG5jYTIuY3JsMGwGCCsGAQUFBwEBBGAwXjAoBggr
# BgEFBQcwAYYcaHR0cDovL3N1YmNhLm9jc3AtY2VydHVtLmNvbTAyBggrBgEFBQcw
# AoYmaHR0cDovL3JlcG9zaXRvcnkuY2VydHVtLnBsL2N0bmNhMi5jZXIwOQYDVR0g
# BDIwMDAuBgRVHSAAMCYwJAYIKwYBBQUHAgEWGGh0dHA6Ly93d3cuY2VydHVtLnBs
# L0NQUzANBgkqhkiG9w0BAQwFAAOCAgEAuJNZd8lMFf2UBwigp3qgLPBBk58BFCS3
# Q6aJDf3TISoytK0eal/JyCB88aUEd0wMNiEcNVMbK9j5Yht2whaknUE1G32k6uld
# 7wcxHmw67vUBY6pSp8QhdodY4SzRRaZWzyYlviUpyU4dXyhKhHSncYJfa1U75cXx
# Ce3sTp9uTBm3f8Bj8LkpjMUSVTtMJ6oEu5JqCYzRfc6nnoRUgwz/GVZFoOBGdrSE
# tDN7mZgcka/tS5MI47fALVvN5lZ2U8k7Dm/hTX8CWOw0uBZloZEW4HB0Xra3qE4q
# zzq/6M8gyoU/DE0k3+i7bYOrOk/7tPJg1sOhytOGUQ30PbG++0FfJioDuOFhj99b
# 151SqFlSaRQYz74y/P2XJP+cF19oqozmi0rRTkfyEJIvhIZ+M5XIFZttmVQgTxfp
# fJwMFFEoQrSrklOxpmSygppsUDJEoliC05vBLVQ+gMZyYaKvBJ4YxBMlKH5ZHkRd
# loRYlUDplk8GUa+OCMVhpDSQurU6K1ua5dmZftnvSSz2H96UrQDzA6DyiI1V3ejV
# tvn2azVAXg6NnjmuRZ+wa7Pxy0H3+V4K4rOTHlG3VYA6xfLsTunCz72T6Ot4+tkr
# DYOeaU1pPX1CBfYj6EW2+ELq46GP8KCNUQDirWLU4nOmgCat7vN0SD6RlwUiSsMe
# CiQDmZwgwrUwggbpMIIE0aADAgECAhBiOsZKIV2oSfsf25d4iu6HMA0GCSqGSIb3
# DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBTeXN0
# ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBDQTAe
# Fw0yNTA3MzExMTM4MDhaFw0yNjA3MzExMTM4MDdaMIGOMQswCQYDVQQGEwJERTEb
# MBkGA1UECAwSQmFkZW4tV8O8cnR0ZW1iZXJnMRQwEgYDVQQHDAtCYWllcnNicm9u
# bjEeMBwGA1UECgwVT3BlbiBTb3VyY2UgRGV2ZWxvcGVyMSwwKgYDVQQDDCNPcGVu
# IFNvdXJjZSBEZXZlbG9wZXIsIEhlcHAgQW5kcmVhczCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOt2txKXx2UtfBNIw2kVihIAcgPkK3lp7np/qE0evLq2
# J/L5kx8m6dUY4WrrcXPSn1+W2/PVs/XBFV4fDfwczZnQ/hYzc8Ot5YxPKLx6hZxK
# C5v8LjNIZ3SRJvMbOpjzWoQH7MLIIj64n8mou+V0CMk8UElmU2d0nxBQyau1njQP
# CLvlfInu4tDndyp3P87V5bIdWw6MkZFhWDkILTYInYicYEkut5dN9hT02t/3rXu2
# 30DEZ6S1OQtm9loo8wzvwjRoVX3IxnfpCHGW8Z9ie9I9naMAOG2YpvpoUbLG3fL/
# B6JVNNR1mm/AYaqVMtAXJpRlqvbIZyepcG0YGB+kOQLdoQCWlIp3a14Z4kg6bU9C
# U1KNR4ueA+SqLNu0QGtgBAdTfqoWvyiaeyEogstBHglrZ39y/RW8OOa50pSleSRx
# SXiGW+yH+Ps5yrOopTQpKHy0kRincuJpYXgxGdGxxKHwuVJHKXL0nWScEku0C38p
# M9sYanIKncuF0Ed7RvyNqmPP5pt+p/0ZG+zLNu/Rce0LE5FjAIRtW2hFxmYMyohk
# afzyjCCCG0p2KFFT23CoUfXx59nCU+lyWx/iyDMV4sqrcvmZdPZF7lkaIb5B4PYP
# vFFE7enApz4Niycj1gPUFlx4qTcXHIbFLJDp0ry6MYelX+SiMHV7yDH/rnWXm5d3
# AgMBAAGjggF4MIIBdDAMBgNVHRMBAf8EAjAAMD0GA1UdHwQ2MDQwMqAwoC6GLGh0
# dHA6Ly9jY3NjYTIwMjEuY3JsLmNlcnR1bS5wbC9jY3NjYTIwMjEuY3JsMHMGCCsG
# AQUFBwEBBGcwZTAsBggrBgEFBQcwAYYgaHR0cDovL2Njc2NhMjAyMS5vY3NwLWNl
# cnR1bS5jb20wNQYIKwYBBQUHMAKGKWh0dHA6Ly9yZXBvc2l0b3J5LmNlcnR1bS5w
# bC9jY3NjYTIwMjEuY2VyMB8GA1UdIwQYMBaAFN10XUwA23ufoHTKsW73PMAywHDN
# MB0GA1UdDgQWBBQYl6R41hwxInb9JVvqbCTp9ILCcTBLBgNVHSAERDBCMAgGBmeB
# DAEEATA2BgsqhGgBhvZ3AgUBBDAnMCUGCCsGAQUFBwIBFhlodHRwczovL3d3dy5j
# ZXJ0dW0ucGwvQ1BTMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIH
# gDANBgkqhkiG9w0BAQsFAAOCAgEAQ4guyo7zysB7MHMBOVKKY72rdY5hrlxPci8u
# 1RgBZ9ZDGFzhnUM7iIivieAeAYLVxP922V3ag9sDVNR+mzCmu1pWCgZyBbNXykue
# KJwOfE8VdpmC/F7637i8a7Pyq6qPbcfvLSqiXtVrT4NX4NIvODW3kIqf4nGwd0h3
# 1tuJVHLkdpGmT0q4TW0gAxnNoQ+lO8uNzCrtOBk+4e1/3CZXSDnjR8SUsHrHdhnm
# qkAnYb40vf69dfDR148tToUj872yYeBUEGUsQUDgJ6HSkMVpLQz/Nb3xy9qkY33M
# 7CBWKuBVwEcbGig/yj7CABhIrY1XwRddYQhEyozUS4mXNqXydAD6Ylt143qrECD2
# s3MDQBgP2sbRHdhVgzr9+n1iztXkPHpIlnnXPkZrt89E5iGL+1PtjETrhTkr7nxj
# yMFjrbmJ8W/XglwopUTCGfopDFPlzaoFf5rH/v3uzS24yb6+dwQrvCwFA9Y9ZHy2
# ITJx7/Ll6AxWt7Lz9JCJ5xRyYeRUHs6ycB8EuMPAKyGpzdGtjWv2rkTXbkIYUjkl
# FTpquXJBc/kO5L+Quu0a0uKn4ea16SkABy052XHQqd87cSJg3rGxsagi0IAfxGM6
# 08oupufSS/q9mpQPgkDuMJ8/zdre0st8OduAoG131W+XJ7mm0gIuh2zNmSIet5RD
# oa8THmwxggckMIIHIAIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3Nl
# Y28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25p
# bmcgMjAyMSBDQQIQYjrGSiFdqEn7H9uXeIruhzANBglghkgBZQMEAgEFAKCBhDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEi
# BCAIpMf74rRj9AAQCCeM6By4c/j9ofR16puaFvX6djT9wDANBgkqhkiG9w0BAQEF
# AASCAgBUwBepmxRDB/VCnh0Gp9DxXd8UAMlRtVKvKpwUfYC+cgItpPjoEESxJ7PD
# o9CyL9p6jpfAEcmdqr7RGyg+IgfNzyFCeaY10BX543dPukhIf0E+//LqVzYJWyj8
# EXBeX2RtdVN9AIUqQxCq+gbSfbjCZAWSaQvnXa43NFL1P+9Kd+IAbq8A80i4eL9I
# vbSIvPX90CKjl2BBn6rDkMB0JVYFNGMYgfvqwbiby46X48yU97bWbzOVYYZLW1Gf
# t1m+nSmfVPsGU+appbTooBR83rREFDnS6o/I9yAs5W8wN5fw93ssfxyRZ0xbLpvX
# n3m5jkTMo6eDzmnS+LqmGuPGOqBX1fH1c3R2mgavQM2xWJxXj67ok0Rbf2zsm7Hx
# nD1tHLJIB0KBhnmlYUl9u+++cG78twIZpXmUf4fTQ3QcHQl69qQsd5GTKNwQgc4Y
# 5CQiuLbClgRZ5ydj3Rfr0NpKrGhswUPCXBzHxuPN7S2/qGtQTSSdUIfOI14UX99I
# vXh2mEfQV2ELUiHp8/y0KvVkRi/FEM8t5H5MwHMwrHySjSdBsCz2Ux1zAFG/ynHg
# D76SrsvjkPkZgYKxEyZvIGxi5cxTAO9KhT6Al2kpAVyTyNaz+Hnh4FZAe8gjil0i
# rpUGBrD4Ytk5gml5vop/KQL3Bg7wCsjG9xCbey1VlA2j9lqn0aGCBAQwggQABgkq
# hkiG9w0BCQYxggPxMIID7QIBATBrMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhB
# c3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBUaW1lc3Rh
# bXBpbmcgMjAyMSBDQQIRAJ6cBPZVqLSnAm1JjGx4jaowDQYJYIZIAWUDBAICBQCg
# ggFXMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcN
# MjUxMDI1MTgwMDU2WjA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCDPodw1ne0rw8uJ
# D6Iw5dr3e1QPGm4rI93PF1ThjPqg1TA/BgkqhkiG9w0BCQQxMgQwKBW2j0aXlT3S
# 5Nxpt2x9mvdbpZfKlIHh0K/FSlGX+veepb12z92dvhQmISBpNaQYMIGgBgsqhkiG
# 9w0BCRACDDGBkDCBjTCBijCBhwQUwyW4mxf8xQJgYc4rcXtFB92camowbzBapFgw
# VjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5B
# LjEkMCIGA1UEAxMbQ2VydHVtIFRpbWVzdGFtcGluZyAyMDIxIENBAhEAnpwE9lWo
# tKcCbUmMbHiNqjANBgkqhkiG9w0BAQEFAASCAgDDXSz3Tqp/DbdSLpOOtNFOPPny
# t66JcuKHTF2FAW80GloVz5Z9TTnCRv7HS6/cNdOISNYW71J1ShTK5xwS8ih23QGc
# VoMeLMMD/g2MYl99AwegbDal0HuKDeLk8vHjo6wEuQHgZc+DB6+K+Umz7fsDMuB4
# sm9uNqYgJGT8xVvmVL8Zg+Vk6Lr8t8T5sKkhvI7PX1g+MkBjVs8C3wVSQs1nqwBl
# iuXc9QZSYRVHUXhQbPqRzGKyOFNm5sDxSvgTaYuQa7JqrSOagVj9exnu4WXadXkn
# BPAI9TVvyXwziBteXUbCPdgZWw05+MNA+ylqWJfcR3UW1G+M+EcUo7NJOs7CAv04
# 57edmzgggTQT2XVE6h/ouu3D4eSev3LoFuZZxSq9UKxTEm6A+ZUGpvSBwx1YkHXV
# OXPXooYU52DmxwcoA0aMHBjdoxeTVMVwnjm/34lrLFMiBBKeeupP3B5L7BTeTJVK
# tKh2H2r7aGFz/A654Mz3ln2pAZHp05N9vmFA1DuZ9K/hX1JlzUZH9Hlc8ja/jg5+
# z5onFcsW/DvvguB/hJLftt3rPad0eawhd8TYBNab7MYTD68ENNK5rO9+Z2SFjUS/
# onjgtNdmda5/C7c94a+WlvCy8SWZLyrIBNkHmaGrjWYdb45iTjBCWM80+k7brODv
# MulaX7laBbwl3tpz8w==
# SIG # End signature block
