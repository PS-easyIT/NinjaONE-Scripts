### NinjaOne does not provide (at least as of spring 2025) any "ready-made" report that collects all DNS servers configured on endpoints across systems and displays them in a dashboard/report.


**NinjaOne Integration Guide**
* https://github.com/PS-easyIT/NinjaONE-Scripts/blob/main/05%20-%20DNS%20Settings/NinjaRMM-Guide_ENG.md

---

# DNS Client Scripts for NinjaOne

This repository contains **two PowerShell scripts** that work hand‑in‑hand:

| Script | Purpose |
| ------ | ------- |
| **setDNSSettingsClient.ps1** | Sets _static_ IPv4 DNS servers **or** resets adapters back to DHCP on all *productive* physical adapters. |
| **readDNSSettingsClient.ps1** | Reads the current DNS settings from all productive adapters and produces a human readable report (markdown/std‑out), an optional CSV export and updates summary custom‑fields in NinjaOne. |

Both scripts were written by **Andreas Hepp** - **www.phinit.de** or **www.psscripts.de**

---

## 1. Features at a Glance

### setDNSSettingsClient.ps1

* Detects *productive* adapters (default‑GW present **or** inside target subnet **or** matches explicit gateway).
* Supports physical LAN/WLAN only – excludes vNICs, VPN, Hyper‑V, WSL, Docker, etc.
* Uses `Set‑DnsClientServerAddress`, with `netsh` fallback for legacy OS/hanging drivers.
* Optional custom‑field update (`DNS_LastChange`) with full audit string.
* Returns **exit codes**  
  `0` = changed  |  `2` = nothing to do  |  `1` = error  |  `3` = DNS changed but CF update failed.

### readDNSSettingsClient.ps1

* Modern `Get‑DnsClient*` cmdlets with automatic WMI fallback for ≤ Win 2008 R2.
* Produces console markdown plus optional CSV (`C:\ProgramData\NinjaRMMAgent\Logs\Reports`).
* Detects DNS mismatch between active adapters.
* Writes `DNS_Summary` (string) and `DNS_Mismatch` (boolean) custom‐fields.
* Log & report rotation (`LogRetentionDays`, default 30).

---

## 2. Parameters

| Script | Key Parameters | Notes |
| ------ | -------------- | ----- |
| **setDNSSettingsClient.ps1** | `‑PrimaryDNS` `‑SecondaryDNS` `‑TargetSubnet` `‑TargetGateway` `‑AdapterName` `‑ResetDHCP` `‑NoCustomField` | `‑PrimaryDNS` required unless `‑ResetDHCP`. All params can be pre‑filled via custom fields. |
| **readDNSSettingsClient.ps1** | `‑NoCSV` `‑NoCustomField` `‑LogRetentionDays` | Safe to run stand‑alone or on schedule. |

Run either script with `‑Verbose` to see detailed flow.

---

## 3. Required Custom Fields

| Field Name | Type | Used by | Purpose |
| ---------- | ---- | ------- | ------- |
| `DNS_PrimaryServer` | Text | set | Value for `‑PrimaryDNS` if parameter omitted |
| `DNS_SecondaryServer` | Text | set | Value for `‑SecondaryDNS` |
| `DNS_TargetSubnet` | Text | set | e.g. `192.168.10.0/24` |
| `DNS_TargetGateway` | Text | set | Explicit gateway IP |
| `DNS_AdapterAliases` | Text | set | Comma separated wildcard adapter names |
| `DNS_ResetToDHCP` | Checkbox/Boolean | set | If **true** forces `‑ResetDHCP` mode |
| `DNS_LastChange` | Text (multi‑line) | set | Updated by script with timestamp |
| `DNS_Summary` | Text (multi‑line) | read | Consolidated IPv4 DNS list |
| `DNS_Mismatch` | Checkbox/Boolean | read | **true** if adapters use different DNS |

---

## 4. File Locations

All logs and CSVs are written below:

```
C:\ProgramData\NinjaRMMAgent\Logs
└─ Reports
```

Rotation is handled automatically.


