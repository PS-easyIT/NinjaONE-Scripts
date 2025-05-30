# NinjaOne DNS-Skripte - Integrationsleitfaden

## Inhaltsverzeichnis
- [1. Voraussetzungen](#1-voraussetzungen)
- [2. Custom-Fields anlegen](#2-custom-fields-anlegen)
- [3. Skripte importieren](#3-skripte-importieren)
- [4. Automations-/Richtlinienbeispiele](#4-automations-richtlinienbeispiele)
- [5. Berichte](#5-berichte)

## 1. Voraussetzungen

| Komponente | Mindestversion |
|------------|----------------|
| **NinjaOne Agent** | 5.3 (wegen `Ninja-Property-Set/Get`) |
| **Windows** | 10/11 bzw. Server 2012 R2 + |
| **PowerShell** | 5.1 |

---

## 2. Custom-Fields anlegen

| Feldname | Typ | Zweck |
|----------|-----|-------|
| `DNS_PrimaryServer` | Text | Primärer DNS für **set**-Skript |
| `DNS_SecondaryServer` | Text | Sekundärer DNS |
| `DNS_TargetSubnet` | Text | CIDR-Subnetzfilter (optional) |
| `DNS_TargetGateway` | Text | Gateway-Filter (optional) |
| `DNS_AdapterAliases` | Text | Kommagetrennte Adapternamen/Wildcards |
| `DNS_ResetToDHCP` | Boolean | „Auf DHCP zurücksetzen" |
| `DNS_LastChange` | Text (Multi-Line) | Wird vom **set**-Skript gefüllt |
| `DNS_Summary` | Text (Multi-Line) | Wird vom **read**-Skript gefüllt |
| `DNS_Mismatch` | Boolean | **read** setzt *true*, wenn Adapter unterschiedliche DNS-Server nutzen |

**Hinweis:** Werden Custom‑Fields nicht angelegt, funktionieren die Skripte trotzdem, nur werden keine Werte übernommen bzw. geschrieben.

### Anlegen des Custom Field „DNS_Summary"

1. Melden Sie sich in der NinjaOne-Konsole an.
2. Navigieren Sie zu **Einstellungen** (Zahnradsymbol) → **Endpoint Management** → **Benutzerdefinierte Felder**.
3. Wählen Sie **Global**
4. Klicken Sie auf **Benutzerdefiniertes Feld hinzufügen**.
5. Feldname: `DNS_Summary`
6. Anzeigename: `DNS_Summary`
7. Feldtyp: **Mehrzeiliger Text** (Text / Multi-Line)
8. Sichtbarkeit: Aktivieren Sie „**Skriptzugriff**", damit Ihr PowerShell-Skript das Feld beschreiben kann
9. Auf **Speichern** klicken.

---

## 3  Skripte importieren

### Import des PowerShell-Skripts

1. Klicken Sie auf **Neues Skript** → **Script importieren**.
2. Name: `readDNSSettingsClient`
3. Beschreibung: Liest DNS-Server-IPs aus und speichert sie in DNS_Summary.
4. Typ: **PowerShell**

### Überprüfung

Nach dem nächsten Agent-Check-In erscheint im Geräte-Detailfenster unter **Benutzerdefinierte Felder** das Feld `DNS_Summary` mit den ausgelesenen DNS-Server-IP-Adressen.


---

## 4  Automations-/Richtlinienbeispiele

| Aufgabe | Zeitplan | Skript | Bemerkung |
|---------|----------|--------|-----------|
| DNS prüfen | Stündlich | **read** | Schreibt Zusammenfassung + CSV-Bericht |


## 5  Berichte

Das **read**‑Skript legt CSV‑Dateien in  
```
C:\\ProgramData\\NinjaRMMAgent\\Logs\\Reports\\DNS_Report_<Hostname>_<Zeitstempel>.csv
```  
ab. Die letzten *n* Tage (Standard 30) werden automatisch aufgeräumt.  
NinjaOne hängt zusätzlich die jeweils aktuelle CSV als Attachment an die
Skriptausgabe (erkennbar an `SCRIPT_FILE:`).

