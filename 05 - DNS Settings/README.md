# DNS-Toolset für NinjaOne  
*Version 1.4 · Update 28-05-2025*  
Autor : **Andreas Hepp**

---

## Inhaltsverzeichnis
1. [readDNSSettingsClient.ps1](#readdnssettingsclientps1)  
2. [setDNSSettings.ps1](#setdnssettingsps1)  

---

## readDNSSettingsClient.ps1

### Zweck
Erfasst alle **physischen** aktiven Adapter, protokolliert IPv4/IPv6-Adressen, Gateway & DNS-Server, erzeugt optional eine CSV und füllt Custom-Fields für Auswertungen in NinjaOne.

### Hauptfunktionen
| Funktion | Beschreibung |
|----------|--------------|
| **Modern / WMI-Fallback** | Nutzt `Get-DnsClient*`; fällt bei Legacy-OS auf WMI zurück. |
| **Adapter-Filter** | Exkludiert VMware, Hyper-V, VPN, Loopback u. a.; optional Aliasfilter. |
| **CSV-Export** | Zeitgestempelter Bericht im Agentpfad; Log-Rotation via `-LogRetentionDays`. |
| **Custom-Fields** | `DNS_Summary` (Resolver-Liste) · `DNS_Mismatch` (Boolean) |
| **Verbose-Log** | Detailausgabe im Activities-Tab (`-Verbose`). |

### Parameter (Auszug)

| Parameter            | Pflicht | Default | Beschreibung                               |
|----------------------|---------|---------|--------------------------------------------|
| `-NoCSV`             | Nein    | –       | Unterdrückt CSV-Export.                    |
| `-NoCustomField`     | Nein    | –       | Kein Custom-Field-Update.                  |
| `-LogRetentionDays`  | Nein    | 30      | Aufbewahrungstage für alte Reports.        |

### Beispiel
```powershell
.
eadDNSSettingsClient.ps1 -Verbose -LogRetentionDays 60
```

### Ninja-Integration
1. *Library ▸ Automation ▸ Add* → PowerShell (Windows).  
2. **Collect output files** aktivieren.  
3. Policy/Scheduled Task (z. B. wöchentlich).  
4. Vorher Custom-Fields anlegen  
   * `DNS_Summary` → Multi-Line Text  
   * `DNS_Mismatch` → Checkbox/Boolean  

---

## setDNSSettings.ps1

### Zweck
Setzt neue DNS-Server **oder** stellt DNS via DHCP zurück – **nur** auf produktiven
Adaptern (Default-Gateway oder Filter Subnetz/Gateway/Alias).

### Hauptfunktionen
| Funktion | Beschreibung |
|----------|--------------|
| **Gezielte Adapterwahl** | Filter nach Gateway, Subnetz (CIDR), Alias o. Custom-Field. |
| **Physische LAN/WLAN**   | Virtuelle/VPN/Tunnel-Adapter werden übersprungen. |
| **Dual-Path Setting**    | `Set-DnsClientServerAddress` → Fallback `netsh` bei Alt-OS. |
| **Change-Control**       | Loggt Alt/Neu-Resolver; bei Soll = Ist → Exit 2. |
| **Custom-Field**        | Aktualisiert `DNS_LastChange` (Zeitstempel + Resolver). |

### Parameter (Auszug)

| Parameter           | Pflicht | Beschreibung                                         |
|---------------------|---------|------------------------------------------------------|
| `-PrimaryDNS`       | Ja¹     | Neuer primärer Resolver.                             |
| `-SecondaryDNS`     | Nein    | Optionaler zweiter Resolver.                         |
| `-ResetDHCP`        | Nein    | Entfernt statische DNS (PrimaryDNS entfällt).        |
| `-TargetSubnet`     | Nein    | Nur Adapter in diesem Netz (CIDR).                   |
| `-TargetGateway`    | Nein    | Nur Adapter mit passendem Gateway.                   |
| `-AdapterName`      | Nein    | Wildcards („Ethernet*“).                             |
| `-NoCustomField`    | Nein    | Unterdrückt Feld `DNS_LastChange`.                   |

¹ Pflicht, wenn **nicht** `-ResetDHCP`.

### Beispiele
```powershell
# DNS 10.0.0.10 / 10.0.0.11 in Subnetz 10.0.0.0/23 setzen
.\setDNSSettings.ps1 -PrimaryDNS 10.0.0.10 -SecondaryDNS 10.0.0.11 -TargetSubnet 10.0.0.0/23

# DNS zurück auf DHCP bei Gateway 192.168.178.1
.\setDNSSettings.ps1 -ResetDHCP -TargetGateway 192.168.178.1 -Verbose
```

### Exit-Codes
| Code | Bedeutung                           | Ninja-Status |
|------|-------------------------------------|--------------|
| **0** | Änderung(en) erfolgreich durchgeführt | Success      |
| **2** | Keine Änderung notwendig (Soll = Ist) | Warning      |
| **1** | Fehler (Parameter/Runtime)          | Error        |

---

## Allgemeine Hinweise & Best Practices

1. **Vor dem Roll-out testen**  
   *Device → Actions → Run Script* mit `-Verbose`, Activities-Log prüfen.

2. **Reihenfolge einhalten**  
   `read…` regelmäßig per Policy, `set…` nur ad-hoc oder per Abweichungs-Trigger.

3. **Custom-Fields zentral steuern**  
   *DNS_PrimaryServer*, *DNS_SecondaryServer*, *DNS_TargetSubnet*, *DNS_TargetGateway*, *DNS_AdapterAliases*, *DNS_ResetToDHCP*  
   → verändern das Verhalten ohne Policy-Anpassung.

4. **Alerting**  
   Smart-Group „DNS_Mismatch = true“ ⇒ Ticket oder Mail.

5. **Rollback**  
   Separates Task-Profil mit `-ResetDHCP`, um rasch auf DHCP-Resolver umzuschalten.
