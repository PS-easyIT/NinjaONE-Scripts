# NinjaOne – Integration Guide  

**readDNSSettingsClient.ps1** & **setDNSSettings.ps1**

> Diese Anleitung erklärt Schritt für Schritt,  
> • wie Sie die beiden Skripte in NinjaOne hochladen  
> • wie Sie die benötigten Custom Fields anlegen  
> • und wie Sie die Automatisierung (Policies / Scheduled Tasks) konfigurieren.

---

## 1. Voraussetzungen

| Komponente | Erforderlich |
|------------|--------------|
| NinjaOne-Agent | Version ≥ 5.2 <br>(für **Ninja-Property-* Cmdlets** ≥ 5.3 empfohlen) |
| Betriebssystem | Windows 10/11, Server 2012 R2 oder neuer |
| PowerShell     | Version 5.1 (Standard bei o. g. OS) |
| Netzwerk       | Die Skripte setzen **nur IPv4-DNS** – IPv6 wird ignoriert |

---

## 2. Custom Fields anlegen  

> **Standort**: *Administration → Allgemein → Custom Fields*  

| Feldname | Typ | Zweck |
|----------|-----|-------|
| `DNS_PrimaryServer`   | Text (einzeilig) | Gewünschter primärer DNS-Server |
| `DNS_SecondaryServer` | Text (einzeilig) | Optionaler sekundärer DNS-Server |
| `DNS_TargetSubnet`    | Text (einzeilig) | IPv4-CIDR, z. B. `192.168.10.0/24` |
| `DNS_TargetGateway`   | Text (einzeilig) | Exaktes Gateway, z. B. `192.168.10.1` |
| `DNS_AdapterAliases`  | Text (einzeilig) | Komma-getrennte Alias-Wildcard(s) – z. B. `Ethernet*,Wi-Fi` |
| `DNS_ResetToDHCP`     | Boolean          | **true** ⇒ DNS wieder per DHCP beziehen |
| `DNS_Summary`         | Multiline Text   | Kurze Zusammenfassung aus *read*-Script |
| `DNS_Mismatch`        | Boolean          | true ⇒ unterschiedliche DNS je Adapter |
| `DNS_LastChange`      | Text (einzeilig) | Zeitstempel der letzten Änderung |

> *Tipp*: Ordnen Sie die Felder einer eigenen Kategorie „DNS Scripts“ zu,  
> so behalten Sie im Asset-Detail die Übersicht.

---

## 3. Skripte hochladen

1. **Administration → Scripting → Neues Skript**
2. Typ **PowerShell**, Policy-Stufe **Device / System**  
   (unbedingt *Run as System* lassen)
3. Datei-Inhalt jeweils einfügen  
   * `readDNSSettingsClient.ps1`  
   * `setDNSSettings.ps1`
4. „Speichern & Veröffentlichen“

> **Versionsverwaltung**  
> Legen Sie eine eigene Ordnerstruktur im Script-Repository an (z. B. `/DNS/`).  
> Bei Updates einfach die neue Version einchecken und alten Revision-Tag beibehalten.

---

## 4. Automation-Beispiele

### 4.1 Read-Script (Inventar / Monitoring)

| Einstellung         | Wert |
|---------------------|------|
| **Trigger**         | Zeitplan – täglich 07:00 |
| **Skriptparameter** | Keine (oder `-Verbose`) |
| **Erwarteter Exit** | 0 |

Effekt  
* CSV wird im Agent-Ordner gespeichert & als Attachment hochgeladen  
* Custom Fields **DNS_Summary** & **DNS_Mismatch** werden aktualisiert  
* „DNS-Mismatch“ kann in Policies als Filter / Notification genutzt werden

### 4.2 Set-Script (Remediation)

| Szenario | Trigger |
|----------|---------|
| **Roll-out** fester DNS | Einmal-Task oder Policy-Automatisierung |
| **Reset auf DHCP**      | Task mit Parameter `-ResetDHCP` **oder** Custom-Field `DNS_ResetToDHCP=true` |

**Parametervarianten**

| Methode | Beispiel |
|---------|----------|
| Direkt in NinjaOne GUI | `-PrimaryDNS 10.0.0.10 -SecondaryDNS 10.0.0.11 -TargetSubnet 10.0.0.0/23` |
| Per Custom Fields (empfohlen) | Keine CLI-Parameter; Script liest Werte aus Feldern |

**Exit-Codes für Workflow-Automation**

| Code | Bedeutung | Aktionsempfehlung |
|------|-----------|-------------------|
| 0 | DNS wurde geändert | Erfolg / Ticket-Notiz |
| 2 | Es gab nichts zu ändern | Erfolg ohne Alarm |
| 3 | DNS geändert, Custom Field konnte **nicht** gesetzt werden | Ticket an RMM-Admin |
| 1 | Fehler (z. B. fehlender PrimaryDNS) | Retry / Alert |

---

## 5. Tipps & Best Practices

* **Testgruppe**: Führen Sie Skripte erst auf wenigen Test-Geräten aus.  
* **Logging**: Beide Skripte schreiben ein ausführliches Protokoll in StdOut → im Ninja-Log sichtbar.  
* **Rollback**: Ein Task mit `-ResetDHCP` stellt den Ursprungszustand wieder her.  
* **IPv6**: Wird bewusst ausgefiltert. Falls Ihr Netzwerk IPv6-DNS benötigt, verwenden Sie stattdessen ein angepasstes Script.  
* **Script-Timeouts**: Standard-Timeout (15 min) genügt, Laufzeit liegt typischerweise < 30 s.  
* **Antivirus / Firewall**: Keine speziellen Ausnahmen notwendig – es werden ausschließlich Windows-Cmdlets und *netsh* verwendet.  
* **Policies**: Kombinieren Sie den „DNS_Mismatch=true“-Filter, um abweichende Systeme automatisch zu reparieren (Run *set*-Script).

---

## 6. Troubleshooting

| Problem | Ursache / Lösung |
|---------|------------------|
| Custom Fields werden nicht gefüllt | Agent < 5.3 – stellen Sie sicher, dass der *CLI*-Fallback funktioniert (Pfad korrekt, Feldnamen exakt). |
| Exit-Code 3 | DNS erfolgreich geändert, aber Custom-Field-Update schlug fehl → prüfen Sie Feld-Namen & Schreibrechte. |
| „Kein Adapter erfüllt…“ | Selektionsfilter zu eng: prüfen Sie -TargetSubnet / -TargetGateway / -AdapterName. |
| Skript bricht ab mit „Ungültige IPv4-Adresse“ | Tippfehler im DNS- oder Gateway-Feld. Nur reine IPv4-Adressen zulässig. |

---

**© 2025 Andreas Hepp – MIT License**  
Pull-Requests & Issues willkommen!  
