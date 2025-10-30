<#
.SYNOPSIS
    Liest DNS-Einstellungen von Clients aus und generiert einen Bericht.

.DESCRIPTION
    Dieses Skript sammelt DNS-Serveradressen von allen Netzwerkadaptern auf dem Client und
    generiert einen strukturierten Bericht. Es ist für die Ausführung über NINJA RMM konzipiert.

.PARAMETER NoCSV
    Mit diesem Parameter wird keine CSV-Datei erstellt.

.PARAMETER NoCustomField
    Mit diesem Parameter wird das Custom Field nicht aktualisiert.

.PARAMETER LogRetentionDays
    Anzahl der Tage, für die CSV-Berichte aufbewahrt werden sollen (Standard: 30).

.NOTES
    Dateiname: readDNSSettingsClient.ps1
    Autor:     Andreas Hepp
    Update:    28.05.2025
    Version:   1.4
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$NoCSV,
    
    [Parameter(Mandatory = $false)]
    [switch]$NoCustomField,
    
    [Parameter(Mandatory = $false)]
    [object]$LogRetentionDays = 30
)

#requires -Version 5.1

#region Initialisierung und Konfiguration
# Sicherstellen, dass Fehler und Verbose ausgegeben werden
$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"

# Parameter-Validierung und Konvertierung
if ($LogRetentionDays -isnot [int]) {
    $LogRetentionDays = 30
}

# Optional Logging aktivieren - im gleichen Verzeichnis wie das Set-Skript
$logDir = "$env:ProgramData\NinjaRMMAgent\Logs"
$logPath = "$logDir\DNSClient_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)
# Logs-Verzeichnis erstellen, falls nicht vorhanden
New-Item -ItemType Directory -Path $logDir -EA Ignore | Out-Null
Start-Transcript -Path $logPath -ErrorAction SilentlyContinue

# Modulprüfung und Fallback vorbereiten
if (-not (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue)) {
    Write-Verbose "Cmdlet Get-DnsClientServerAddress nicht verfügbar - WMI-Fallback wird verwendet."
}
#endregion

#region Hilfsfunktionen
# Funktion zum Formatieren der Ausgabe
function Format-Output {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [string]$Content
    )
    
    Write-Output "`n==== $Title ====`n"
    Write-Output "$Content"
    Write-Output "`n=====================`n"
}
#endregion

#region DNS-Informationssammlung
# Funktion zum Sammeln von DNS-Informationen mit modernen PowerShell-Cmdlets
function Get-DnsInfoModern {
    try {
        # Systeminfos sammeln
        $computerInfo = Get-ComputerInfo | Select-Object CsName, CsDomain, OsName, OsVersion
        $hostname = $computerInfo.CsName
        $domain = $computerInfo.CsDomain
        $osInfo = "$($computerInfo.OsName) $($computerInfo.OsVersion)"
        
        # Adapter sammeln - Kompatibilität mit älteren Treibern
        # Filter für virtuelle und spezielle Interfaces
        $networkAdapters = Get-NetAdapter | Where-Object { 
            ($_.Status -in @('Up','Unknown') -or $_.LinkSpeed -gt 0) -and 
            # Erweiterte Blacklist für virtuelle, Container und spezielle Adapter
            $_.InterfaceDescription -notmatch 'VMware|Hyper-V|vEthernet|WSL|Docker|VPN|loopback|Loopback|Tunnel|TAP|Wi-Fi Direct|WAN Miniport|Bluetooth'
        }
        $dnsReport = @()
        
        foreach ($adapter in $networkAdapters) {
            $adapterName = $adapter.Name
            $adapterType = $adapter.InterfaceDescription
            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex
            
            # DNS-Einstellungen abrufen
            $dnsSettings = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex | 
                          Where-Object { $_.AddressFamily -eq 2 -or $_.AddressFamily -eq 23 } # IPv4 (2) und IPv6 (23)
            
            # DNS-Suffix für diesen Adapter
            $dnsSuffix = (Get-DnsClient -InterfaceIndex $adapter.ifIndex).ConnectionSpecificSuffix
            if ([string]::IsNullOrEmpty($dnsSuffix)) {
                $dnsSuffix = "(Keine)"
            }
            
            # IP-Konfiguration
            $ipAddress = ($ipConfig.IPv4Address.IPAddress) -join ", "
            if ([string]::IsNullOrEmpty($ipAddress)) {
                $ipAddress = "(Keine)"
            }
            
            $ipv6Address = ($ipConfig.IPv6Address.IPAddress) -join ", "
            if ([string]::IsNullOrEmpty($ipv6Address)) {
                $ipv6Address = "(Keine)"
            }
            
            # Gateway
            $gateway = ($ipConfig.IPv4DefaultGateway.NextHop) -join ", "
            if ([string]::IsNullOrEmpty($gateway)) {
                $gateway = "(Keine)"
            }
            
            # DNS-Server sammeln
            $dnsServers = $dnsSettings | ForEach-Object {
                $addressFamily = if ($_.AddressFamily -eq 2) { "IPv4" } else { "IPv6" }
                $serverAddresses = $_.ServerAddresses -join ", "
                if ([string]::IsNullOrEmpty($serverAddresses)) {
                    $serverAddresses = "(Keine)"
                }
                
                [PSCustomObject]@{
                    AdapterName = $adapterName
                    AddressFamily = $addressFamily
                    ServerAddresses = $serverAddresses
                }
            }
            
            $dnsReport += [PSCustomObject]@{
                AdapterName = $adapterName
                AdapterDescription = $adapterType
                IPAddress = $ipAddress
                IPv6Address = $ipv6Address
                Gateway = $gateway
                DNSSuffix = $dnsSuffix
                DNSServers = $dnsServers
            }
        }
        
        return @{
            Hostname = $hostname
            Domain = $domain
            OSInfo = $osInfo
            DnsReport = $dnsReport
        }
    }
    catch {
        Write-Warning "Fehler bei Get-DnsInfoModern: $_"
        return $null
    }
}

# Funktion zum Sammeln von DNS-Informationen mit WMI für ältere Server (Windows 2008 R2)
function Get-DnsInfoWMI {
    try {
        # Systeminfos sammeln mit WMI
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem
        
        $hostname = $computerSystem.Name
        $domain = $computerSystem.Domain
        $osName = $osInfo.Caption
        $osVersion = $osInfo.Version
        $osInfoString = "$osName $osVersion"
        
        # Adapter sammeln mit WMI
        # Filter für virtuelle und spezielle Interfaces
        $networkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { 
            $_.IPEnabled -eq $true -and 
            # VMware, HyperV, VPN und Loopback ausfiltern
            $_.Description -notmatch 'VMware|Hyper-V|VPN|loopback|Loopback|Tunnel|TAP|Microsoft Wi-Fi Direct|WAN Miniport'
        }
        $dnsReport = @()
        
        foreach ($adapter in $networkAdapters) {
            $adapterName = $adapter.Description
            $adapterType = $adapter.Description
            
            # IP-Konfiguration
            $ipAddress = ($adapter.IPAddress | Where-Object { $_ -match '^[0-9]+\.' }) -join ", "
            if ([string]::IsNullOrEmpty($ipAddress)) {
                $ipAddress = "(Keine)"
            }
            
            $ipv6Address = ($adapter.IPAddress | Where-Object { $_ -match ':' }) -join ", "
            if ([string]::IsNullOrEmpty($ipv6Address)) {
                $ipv6Address = "(Keine)"
            }
            
            # Gateway
            $gateway = ($adapter.DefaultIPGateway) -join ", "
            if ([string]::IsNullOrEmpty($gateway)) {
                $gateway = "(Keine)"
            }
            
            # DNS-Suffix
            $dnsSuffix = $adapter.DNSDomainSuffixSearchOrder -join ", "
            if ([string]::IsNullOrEmpty($dnsSuffix)) {
                $dnsSuffix = "(Keine)"
            }
            
            # DNS-Server
            $dnsServerAddresses = $adapter.DNSServerSearchOrder -join ", "
            if ([string]::IsNullOrEmpty($dnsServerAddresses)) {
                $dnsServerAddresses = "(Keine)"
            }
            
            $dnsServers = @([PSCustomObject]@{
                AdapterName = $adapterName
                AddressFamily = "IPv4"
                ServerAddresses = $dnsServerAddresses
            })
            
            $dnsReport += [PSCustomObject]@{
                AdapterName = $adapterName
                AdapterDescription = $adapterType
                IPAddress = $ipAddress
                IPv6Address = $ipv6Address
                Gateway = $gateway
                DNSSuffix = $dnsSuffix
                DNSServers = $dnsServers
            }
        }
        
        return @{
            Hostname = $hostname
            Domain = $domain
            OSInfo = $osInfoString
            DnsReport = $dnsReport
        }
    }
    catch {
        Write-Warning "Fehler bei Get-DnsInfoWMI: $_"
        return $null
    }
}

# Versuche zuerst mit modernen Cmdlets, dann mit WMI-Fallback
try {
    $dnsInfo = Get-DnsInfoModern
    if (-not $dnsInfo) {
        Write-Output "Verwende WMI-Fallback für ältere Betriebssysteme..."
        $dnsInfo = Get-DnsInfoWMI
    }
    
    # Ergebnisse extrahieren
    $hostname = $dnsInfo.Hostname
    $domain = $dnsInfo.Domain
    $osInfo = $dnsInfo.OSInfo
    $dnsReport = $dnsInfo.DnsReport
}
catch {
    Write-Error "Kritischer Fehler beim Sammeln der DNS-Informationen: $_"
    exit 1
}
#endregion

# Netzwerkadapter und DNS-Informationen werden jetzt über die Funktionen Get-DnsInfoModern oder Get-DnsInfoWMI abgerufen

# Prüfen, ob überhaupt aktive Adapter gefunden wurden
if (-not $dnsReport -or $dnsReport.Count -eq 0) { 
    Write-Error "Keine aktiven Netzwerkadapter gefunden."
    exit 1 
}

Write-Verbose "$($dnsReport.Count) aktive Netzwerkadapter gefunden."

#region Berichtsgenerierung
# Bericht generieren
$reportOutput = [System.Text.StringBuilder]::new()

# Header
[void]$reportOutput.AppendLine("DNS-Einstellungen Bericht")
[void]$reportOutput.AppendLine("========================")
[void]$reportOutput.AppendLine("Erstellt: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')")
[void]$reportOutput.AppendLine("")

# System-Informationen
[void]$reportOutput.AppendLine("## System-Informationen")
[void]$reportOutput.AppendLine("Hostname: $hostname")
[void]$reportOutput.AppendLine("Domain/Workgroup: $domain")
[void]$reportOutput.AppendLine("Betriebssystem: $osInfo")
[void]$reportOutput.AppendLine("")

# DNS-Einstellungen nach Adapter
[void]$reportOutput.AppendLine("## DNS-Einstellungen nach Netzwerkadapter")

foreach ($adapter in $dnsReport) {
    [void]$reportOutput.AppendLine("\n### Adapter: $($adapter.AdapterName)")
    [void]$reportOutput.AppendLine("Beschreibung: $($adapter.AdapterDescription)")
    [void]$reportOutput.AppendLine("IP-Adresse (IPv4): $($adapter.IPAddress)")
    [void]$reportOutput.AppendLine("IP-Adresse (IPv6): $($adapter.IPv6Address)")
    [void]$reportOutput.AppendLine("Gateway: $($adapter.Gateway)")
    [void]$reportOutput.AppendLine("DNS-Suffix: $($adapter.DNSSuffix)")
    
    [void]$reportOutput.AppendLine("\nDNS-Server:")
    foreach ($dns in $adapter.DNSServers) {
        [void]$reportOutput.AppendLine("- $($dns.AddressFamily): $($dns.ServerAddresses)")
    }
    [void]$reportOutput.AppendLine("---")
}

# Ausgabe für NINJA RMM
Format-Output -Title "DNS-Einstellungen Bericht" -Content $reportOutput.ToString()

# Zusätzlich: Für NINJA RMM - Kurze Zusammenfassung als separate Ausgabe
$summaryOutput = [System.Text.StringBuilder]::new()

# Für Log-Ausgabe komplettere Information mit Adapter-Namen
[void]$summaryOutput.AppendLine("Hostname: $hostname | Domain: $domain")
foreach ($adapter in $dnsReport) {
    $ipv4DNS = ($adapter.DNSServers | Where-Object { $_.AddressFamily -eq "IPv4" }).ServerAddresses
    [void]$summaryOutput.AppendLine("$($adapter.AdapterName): $ipv4DNS")
}

# Für Custom Field nur die reinen DNS-Server sammeln
$customFieldDnsServers = [System.Collections.ArrayList]@()
$adapterDnsServers = @{} # Speichert DNS je Adapter für Mismatch-Erkennung

foreach ($adapter in $dnsReport) {
    $ipv4DNS = ($adapter.DNSServers | Where-Object { $_.AddressFamily -eq "IPv4" }).ServerAddresses
    if ($ipv4DNS -and $ipv4DNS -ne "(Keine)") {
        # Für Custom Field sammeln (ohne Duplikate)
        if ($customFieldDnsServers -notcontains $ipv4DNS) {
            $null = $customFieldDnsServers.Add($ipv4DNS)
        }
        
        # Für DNS-Mismatch-Erkennung je Adapter speichern
        $adapterDnsServers[$adapter.AdapterName] = $ipv4DNS
    }
}


# DNS Mismatch-Erkennung: Prüfen, ob verschiedene DNS-Server bei aktiven Adaptern vorhanden sind
$hasDnsMismatch = $false

# Nur prüfen wenn mindestens zwei Adapter mit DNS-Servern vorhanden sind
if ($adapterDnsServers.Keys.Count -gt 1) {
    $firstDnsServer = $null
    
    # Den ersten DNS-Server als Referenz nehmen
    foreach ($adapter in $adapterDnsServers.Keys) {
        if (-not $firstDnsServer) {
            $firstDnsServer = $adapterDnsServers[$adapter]
        } else {
            # DNS-Server dieses Adapters mit dem Referenz-DNS vergleichen
            if ($adapterDnsServers[$adapter] -ne $firstDnsServer) {
                $hasDnsMismatch = $true
                Write-Verbose "DNS-Mismatch gefunden: Adapter '$adapter' verwendet '$($adapterDnsServers[$adapter])' statt '$firstDnsServer'"
                break
            }
        }
    }
}

# DNS-Mismatch-Warnung in den Bericht aufnehmen, wenn gefunden
if ($hasDnsMismatch) {
    [void]$reportOutput.AppendLine("`n## Warnungen")
    [void]$reportOutput.AppendLine("Warnung: Unterschiedliche DNS-Server zwischen Adaptern erkannt!")
    [void]$reportOutput.AppendLine("Dies kann zu Netzwerkproblemen und inkonsistentem Verhalten führen.")
}

# Ausgabe der Zusammenfassung
Format-Output -Title "DNS-Zusammenfassung" -Content $summaryOutput.ToString()
#endregion

#region CSV-Export
# === CSV-Datei für Tabular Report erstellen ===========================
if (-not $NoCSV) {
    try {
        # Verzeichnis für Berichte erstellen, falls nicht vorhanden
        $reportDir = Join-Path $logDir 'Reports'
        New-Item -Path $reportDir -ItemType Directory -EA Ignore | Out-Null
        
        # Log-Rotation: Alte Berichte löschen (nach LogRetentionDays)
        if ($LogRetentionDays -gt 0) {
            $oldReports = Get-ChildItem -Path $reportDir -Filter 'DNS_Report_*.csv' |
                          Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$LogRetentionDays) }
            
            if ($oldReports -and $oldReports.Count -gt 0) {
                Write-Output "$($oldReports.Count) alte Berichte werden gelöscht (älter als $LogRetentionDays Tage)"
                $oldReports | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
        
        # CSV-Datei erstellen (permanenter Speicherort) mit Zeitstempel zur Vermeidung von Namenskonflikten
        $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
        $csvFile = Join-Path -Path $reportDir -ChildPath "DNS_Report_${hostname}_${timestamp}.csv"
        
        # Daten für CSV vorbereiten
        $csvData = @()
        foreach ($adapter in $dnsReport) {
            foreach ($dns in $adapter.DNSServers) {
                $csvData += [PSCustomObject]@{
                    Hostname = $hostname
                    Domain = $domain
                    AdapterName = $adapter.AdapterName
                    AdapterDescription = $adapter.AdapterDescription
                    IPAddress = $adapter.IPAddress
                    Gateway = $adapter.Gateway
                    DNSSuffix = $adapter.DNSSuffix
                    AddressFamily = $dns.AddressFamily
                    DNSServers = $dns.ServerAddresses
                    ReportDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                }
            }
        }
        
        # CSV exportieren (mit Force zum Überschreiben vorhandener Dateien)
        $csvData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8 -Force
        Write-Output "CSV-Bericht erstellt: $csvFile"
        
        # Temporäre Datei für Ninja-Anhang erstellen (mit Zeitstempel gegen Namenskonflikte)
        $tempCsvPath = Join-Path $env:TEMP "DNSReport_${hostname}_${timestamp}.csv"
        $csvData | Export-Csv -Path $tempCsvPath -NoTypeInformation -Encoding UTF8 -Force
        Write-Output "SCRIPT_FILE:$tempCsvPath"  # <- Ninja erkennt das Präfix und hängt die Datei an
    }
    catch {
        Write-Warning "CSV-Export fehlgeschlagen: $_"
    }
}
else {
    Write-Output "CSV-Export übersprungen (Parameter -NoCSV aktiviert)"
}
#endregion

#region Custom-Field-Update
# === Custom-Field-Update für DNS_Summary mit DNS-Server-Adressen =========
if (-not $NoCustomField) {
    try {
        # Liste für alle gefundenen DNS-Server
        $dnsServerList = [System.Collections.ArrayList]@()
        
        # Über alle Adapter iterieren und ihre DNS-Server sammeln
        foreach ($adapter in $dnsReport) {
            # Für jeden Adapter über die DNS-Server-Einträge iterieren
            foreach ($dnsInfo in $adapter.DNSServers) {
                # Nur IPv4 DNS-Server berücksichtigen
                if ($dnsInfo.AddressFamily -eq "IPv4") {
                    $servers = $dnsInfo.ServerAddresses
                    if ($servers -and $servers -ne "(Keine)") {
                        # Einzelne Server extrahieren (falls mehrere durch Komma getrennt sind)
                        $serverArray = $servers -split "[,;]" | ForEach-Object { $_.Trim() }
                        foreach ($server in $serverArray) {
                            if ($server -and $server -ne "(Keine)" -and $server -notmatch "^$") {
                                $null = $dnsServerList.Add($server)
                            }
                        }
                    }
                }
            }
        }
        
        # Duplikate entfernen
        $uniqueDnsServers = $dnsServerList | Select-Object -Unique
        
        # Kommagetrennter String mit den DNS-Servern
        $fieldValue = if ($uniqueDnsServers.Count) {
            $uniqueDnsServers -join ", "
        } else {
            "Keine DNS-Server gefunden"
        }

        # Custom Field DNS_Summary aktualisieren
        Ninja-Property-Set DNS_Summary "$fieldValue"
        Write-Verbose "Custom Field 'DNS_Summary' erfolgreich mit DNS-Server-Adressen befüllt"
    }
    catch {
        Write-Warning "Custom-Field-Update für 'DNS_Summary' fehlgeschlagen: $_"
    }
}
else {
    Write-Output "Custom-Field-Update übersprungen (Parameter -NoCustomField aktiviert)"
}

# Transcript beenden
Stop-Transcript -ErrorAction SilentlyContinue
#endregion
 
#region Abschluss
Write-Verbose "Skriptausführung erfolgreich abgeschlossen."
Write-Host "DNS-Bericht erfolgreich erstellt." 
exit 0 
#endregion
# SIG # Begin signature block
# MIIoiQYJKoZIhvcNAQcCoIIoejCCKHYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCfdtaYfaKvtswC
# IJedG/4Aj4o+SKuJFIq5+A5vVQOTvaCCILswggXJMIIEsaADAgECAhAbtY8lKt8j
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
# BCBegua7gQ7j9GI8Njmr+/UsGsfV4TkvMAb/MQBMACZHhTANBgkqhkiG9w0BAQEF
# AASCAgAORWyoqRAhlo/CByCINRfS9HlpKNe7znz412Hk7WGlL340Ui6R1DCYd8Fc
# C/fQ3p6BL+u4a5GIJ/RGgI9lEGMOn2uKG4yDYq5R9uFovVahNs0nnN8125+Ay2jY
# BRTnkBAgYaqX7BGocgn1RcgH5Xx6GgFk6ly1oE6k0ioScOFnz7dQKpOxVVqcDKC9
# C8ThkrdBwNAGmvi83Anr/jBYOL98ARMnknQoemJkah9XU2m8zOJ1y+TDGJ/ttUAZ
# z95frueU7W+Y/SbvRiFwzRzY1FV4fgtpRI2PI59Zksi7hlSR5ADuteLRJMiuPaAq
# U+NgYVlXP3weYNMC0mpGe/W/3MFVfS4txZzbPOWYemZzzon8M0oGkp+X2fMZqMC7
# mnozy7y+QLAEtC8RuOMkgn4WHFM3dpfU6BvxiNwhiRCOGfcG2SUiaP7x+AD//Nid
# RujnFRreKfYP/b5Br2OU9Ecok7MLYTGFjJMQm/WMPNxRtD3MFT8CItl8HmItpx88
# Pl6+STzK9ys0TmezQzP09aaBtadQwNa8usYKFSIm1uWeRLmuR6+vJLTLg9M+7JSk
# rkfYORIVypBXhPx2JrCFmVoqdJEcLVYYqlI2GAicPswupqNXeb2x3vvMHvV5aqo9
# 22YGQGBrXWv9LgaH36qnnmo4/90bdVdEVRcvGD93bhjDjsNpk6GCBAQwggQABgkq
# hkiG9w0BCQYxggPxMIID7QIBATBrMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhB
# c3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBUaW1lc3Rh
# bXBpbmcgMjAyMSBDQQIRAJ6cBPZVqLSnAm1JjGx4jaowDQYJYIZIAWUDBAICBQCg
# ggFXMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcN
# MjUxMDI1MTgwMDUyWjA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCDPodw1ne0rw8uJ
# D6Iw5dr3e1QPGm4rI93PF1ThjPqg1TA/BgkqhkiG9w0BCQQxMgQwAOKYExGFuk3v
# pMH+6le8WcKj+Yr783SWHc0SgrqOLBcGxHyg0WstSgvRFIR/L6+KMIGgBgsqhkiG
# 9w0BCRACDDGBkDCBjTCBijCBhwQUwyW4mxf8xQJgYc4rcXtFB92camowbzBapFgw
# VjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5B
# LjEkMCIGA1UEAxMbQ2VydHVtIFRpbWVzdGFtcGluZyAyMDIxIENBAhEAnpwE9lWo
# tKcCbUmMbHiNqjANBgkqhkiG9w0BAQEFAASCAgDEr1GdfnMMKeZIntAABOw+c9Pe
# X500LvNNhAayYUGtBtJ7bvesxMRJza9yt6rFghvOY2kZGQUdbr/aGBDYOPfOd60B
# CHpEkN6jq7F7qMTILv9jwqa2DjerMM4+Q52ioRmUX/Bepm6JaoRxzPVmTZySCO6a
# /0rnksQMcmfgG/WfG5iDRtO+NzbJeVT9f1C7YNq9uvxdka+JDkFJ+8n34PKqkPQT
# w5YNT5AuAJATl8lmNfp2VVC0JKSOkmzWgoWAZMTeXOOjltSuLntUymbS0ix0ak1G
# YEUryEPDfQYwkIEGGsIDxtYr8e4q0ke/ZtlWm3hzhRznwQYHm30/X1BQq4n4Oqa3
# k1/vbnR8s3Jtr27d6rN7J2F4DZwyncj1l0NBHgrupW6D1oOa+h8GkVSg7IKtD/cD
# uPuWa/mVnNOy7CIoKVM1KBAyaOR329pMQKZV3YmY4KqHnUrw5VY9QUKfiVX0WizH
# T923EP7PIq5MMY3oaizrDQSSUUzNWXeiY3ZAPXiVcMCKqUBxLC5ErJ19AzPJMVBc
# J3Eau3eBmrExqVUQQRa0uJjPQ5p2bWCSUCr1Pzy9DIY4u7vJSl+7V1dgwmqgmNAA
# F9+Emch5Kzj+1phseLRNvj934450gWXmcKHFbba9DKuP0Py86RjiUq++OiGcbtKh
# 8WQYiiHjOohO0R84PA==
# SIG # End signature block
