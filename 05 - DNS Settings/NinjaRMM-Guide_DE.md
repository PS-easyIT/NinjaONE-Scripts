# Integrationsleitfaden (Deutsch) – DNS‑Skripte für NinjaOne

> Version 1.0 – 28. Mai 2025  
> Autor: Andreas Hepp

## 1  Voraussetzungen  
| Komponente | Mindestversion |
|------------|----------------|
| **NinjaOne Agent** | 5.3 (wegen `Ninja-Property-Set/Get`) |
| **Windows** | 10/11 bzw. Server 2012 R2 + |
| **PowerShell** | 5.1 |

---

## 2  Custom‑Fields anlegen  

| Feldname | Typ | Zweck |
|----------|-----|-------|
| `DNS_PrimaryServer` | Text | Primärer DNS für **set**‑Skript |
| `DNS_SecondaryServer` | Text | Sekundärer DNS |
| `DNS_TargetSubnet` | Text | CIDR-Subnetzfilter (optional) |
| `DNS_TargetGateway` | Text | Gateway-Filter (optional) |
| `DNS_AdapterAliases` | Text | Kommagetrennte Adapternamen/Wildcards |
| `DNS_ResetToDHCP` | Boolean | „Auf DHCP zurücksetzen“ |
| `DNS_LastChange` | Text (Multi‑Line) | Wird vom **set**‑Skript gefüllt |
| `DNS_Summary` | Text (Multi‑Line) | Wird vom **read**‑Skript gefüllt |
| `DNS_Mismatch` | Boolean | **read** setzt *true*, wenn Adapter unterschiedliche DNS‑Server nutzen |

**Hinweis:** Werden Custom‑Fields nicht angelegt, funktionieren die Skripte trotzdem, nur werden keine Werte übernommen bzw. geschrieben.

---

## 3  Skripte importieren

1. _Administration → Skripte → Neues Skript_  
2. Dateityp: **PowerShell**, Ausführen als **SYSTEM**  
3. **setDNSSettingsClient.ps1** hochladen  
   * Empfehlung: Parameter *leer* lassen → Steuerung via Custom‑Fields  
4. **readDNSSettingsClient.ps1** hochladen  
   * optional `-NoCSV` bzw. `-NoCustomField` vorbelegen

---

## 4  Automations-/Richtlinienbeispiele

| Aufgabe | Zeitplan | Skript | Bemerkung |
|---------|----------|--------|-----------|
| DNS prüfen | Stündlich | **read** | Schreibt Zusammenfassung + CSV-Bericht |

---

## 5  Monitoring & Alerting

* **Benutzerdefinierte Metrik**:  
  *Bedingung:* `DNS_Mismatch == true`  
  → Ticket oder Alert auslösen.

* **Dashboard‑Widget:** Zeige Geräte, bei denen `DNS_LastChange` älter als _x_ Tage ist.

---

## 6  Berichte

Das **read**‑Skript legt CSV‑Dateien in  
```
C:\\ProgramData\\NinjaRMMAgent\\Logs\\Reports\\DNS_Report_<Hostname>_<Zeitstempel>.csv
```  
ab. Die letzten *n* Tage (Standard 30) werden automatisch aufgeräumt.  
NinjaOne hängt zusätzlich die jeweils aktuelle CSV als Attachment an die
Skriptausgabe (erkennbar an `SCRIPT_FILE:`).

---

## 7  Troubleshooting

| Symptom | Ursache / Lösung |
|---------|------------------|
| Skriptfehler „Cmdlet Get‑DnsClientServerAddress nicht gefunden“ | Alte Windows‑Version → WMI‑Fallback wird genutzt, Information kann eingeschränkt sein. |
| `DNS_LastChange` wird nicht beschrieben | Prüfen, ob Agent ≥ 5.3 und Custom‑Field existiert. |
| Unterschiedliche DNS, aber `DNS_Mismatch` bleibt *false* | Prüfen, ob alle Adapter aktive IPv4‑Adressen haben. Virtuelle Adapter werden ignoriert. |

