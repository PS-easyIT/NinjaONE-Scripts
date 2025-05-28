### NinjaOne bringt (Frühjahr 2025) keinen „fertigen" Bericht mit, der systemübergreifend alle auf den Endpunkten konfigurierten DNS-Server sammelt und in einem Dashboard/Report anzeigt.

**NinjaOne Integration Guide**
* https://github.com/PS-easyIT/NinjaONE-Scripts/blob/main/05%20-%20DNS%20Settings/NinjaRMM-Guide_ENG.md

---

# DNS-Client-Skripte für NinjaOne

Dieses Repository enthält **zwei PowerShell-Skripte**, die Hand in Hand arbeiten:

| Skript | Zweck |
| ------ | ------- |
| **setDNSSettingsClient.ps1** | Setzt _statische_ IPv4-DNS-Server **oder** setzt Adapter auf DHCP zurück, auf allen *produktiven* physischen Adaptern. |
| **readDNSSettingsClient.ps1** | Liest die aktuellen DNS-Einstellungen von allen produktiven Adaptern und erstellt einen menschenlesbaren Bericht (Markdown/Konsole), einen optionalen CSV-Export und aktualisiert Zusammenfassungs-Custom-Fields in NinjaOne. |

Beide Skripte wurden von **Andreas Hepp** entwickelt - **www.phinit.de** oder **www.psscripts.de**

---

## 1. Funktionen auf einen Blick

### setDNSSettingsClient.ps1

* Erkennt *produktive* Adapter (Standard-GW vorhanden **oder** innerhalb des Ziel-Subnetzes **oder** passend zum expliziten Gateway).
* Unterstützt nur physische LAN/WLAN – schließt vNICs, VPN, Hyper-V, WSL, Docker usw. aus.
* Verwendet `Set-DnsClientServerAddress` mit `netsh`-Fallback für ältere Betriebssysteme/hängende Treiber.
* Optionale Custom-Field-Aktualisierung (`DNS_LastChange`) mit vollständiger Audit-Zeichenfolge.
* Gibt **Exit-Codes** zurück:  
  `0` = geändert | `2` = nichts zu tun | `1` = Fehler | `3` = DNS geändert, aber CF-Update fehlgeschlagen.

### readDNSSettingsClient.ps1

* Moderne `Get-DnsClient*`-Cmdlets mit automatischem WMI-Fallback für ≤ Win 2008 R2.
* Erstellt Konsolen-Markdown plus optionales CSV (`C:\ProgramData\NinjaRMMAgent\Logs\Reports`).
* Erkennt DNS-Abweichungen zwischen aktiven Adaptern.
* Schreibt `DNS_Summary` (Text) und `DNS_Mismatch` (Boolean) Custom-Fields.
* Log- & Berichtsrotation (`LogRetentionDays`, Standard 30).

---

## 2. Parameter

| Skript | Hauptparameter | Hinweise |
| ------ | -------------- | ----- |
| **setDNSSettingsClient.ps1** | `-PrimaryDNS` `-SecondaryDNS` `-TargetSubnet` `-TargetGateway` `-AdapterName` `-ResetDHCP` `-NoCustomField` | `-PrimaryDNS` erforderlich, außer bei `-ResetDHCP`. Alle Parameter können über Custom Fields vorausgefüllt werden. |
| **readDNSSettingsClient.ps1** | `-NoCSV` `-NoCustomField` `-LogRetentionDays` | Sicher eigenständig oder im Zeitplan ausführbar. |

Führen Sie beide Skripte mit `-Verbose` aus, um den detaillierten Ablauf zu sehen.

---

## 3. Erforderliche Custom Fields

| Feldname | Typ | Verwendet von | Zweck |
| ---------- | ---- | ------- | ------- |
| `DNS_PrimaryServer` | Text | set | Wert für `-PrimaryDNS`, wenn Parameter weggelassen |
| `DNS_SecondaryServer` | Text | set | Wert für `-SecondaryDNS` |
| `DNS_TargetSubnet` | Text | set | z.B. `192.168.10.0/24` |
| `DNS_TargetGateway` | Text | set | Explizite Gateway-IP |
| `DNS_AdapterAliases` | Text | set | Kommagetrennte Wildcard-Adapternamen |
| `DNS_ResetToDHCP` | Checkbox/Boolean | set | Wenn **true**, erzwingt `-ResetDHCP`-Modus |
| `DNS_LastChange` | Text (mehrzeilig) | set | Vom Skript mit Zeitstempel aktualisiert |
| `DNS_Summary` | Text (mehrzeilig) | read | Konsolidierte IPv4-DNS-Liste |
| `DNS_Mismatch` | Checkbox/Boolean | read | **true**, wenn Adapter unterschiedliche DNS verwenden |

---

## 4. Dateispeicherorte

Alle Logs und CSVs werden hier gespeichert:

```
C:\ProgramData\NinjaRMMAgent\Logs
└─ Reports
```

Die Rotation wird automatisch verwaltet.
