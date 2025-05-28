
# Integration Guide – DNS Client Scripts in NinjaOne

## 1  Create Custom Fields

| Name | Type | Suggestion |
| ---- | ---- | ---------- |
| **DNS_PrimaryServer** | _Text_ | e.g. `10.0.0.10` |
| **DNS_SecondaryServer** | _Text_ | optional, `1.1.1.1` |
| **DNS_TargetSubnet** | _Text_ | e.g. `10.0.0.0/24` |
| **DNS_TargetGateway** | _Text_ | e.g. `10.0.0.1` |
| **DNS_AdapterAliases** | _Text_ | `Ethernet*,Wi‑Fi*` |
| **DNS_ResetToDHCP** | _Checkbox / Boolean_ | default **unchecked** |
| **DNS_LastChange** | _Multi‑line text_ | (leave empty) |
| **DNS_Summary** | _Multi‑line text_ | (populated by read script) |
| **DNS_Mismatch** | _Checkbox / Boolean_ | (populated by read script) |

> **Tip**: Place the fields in a section called “Networking – DNS”.

---

## 2  Upload the Scripts

1. In **Administration → Scripting**, click **+ Add Script**.  
2. Upload `setDNSSettingsClient.ps1` → Language *PowerShell* → OS *Windows*.  
3. Repeat for `readDNSSettingsClient.ps1`.

Set the script **description** to include the required custom fields for future admins.

---

## 3  Testing

1. Pick a test device.  
2. Fill the custom fields (`DNS_PrimaryServer` + optionally others).  
3. Run **setDNSSettingsClient** with parameters:

```powershell
-Verbose
```

4. Run **readDNSSettingsClient** – verify output & custom‑fields.

---

## 4  Automation Policy

Create a policy that:

| Order | Condition | Action |
| ----- | --------- | ------ |
| 1 | Always | **Script:** `readDNSSettingsClient.ps1` (daily) |

(Adjust frequency as needed.)

---

## 5  Alert on DNS Mismatch

* Go to **Administration → Policy Management → Monitors**  
* Add **Custom Field Monitor**:  
  * **Field** `DNS_Mismatch`  
  * **Trigger** when **equals** `true`  
  * Severity = Warning  
  * Auto‑clear when value returns to `false`.

---

## 6  Optional – Self‑Service “Reset to DHCP”

Set **DNS_ResetToDHCP = true** on a device or via mass‑edit.  
Next **setDNSSettingsClient** run will revert DNS and write confirmation to `DNS_LastChange`. Afterwards clear the checkbox.

---

## 7  Troubleshooting

* Check the device **Activities** log → each script writes a concise summary.
* Full log files: `C:\ProgramData\NinjaRMMAgent\Logs\DNS*.log`.
* CSV audit files: `Logs\Reports\DNS_Report_*.csv`.

---

All done – your DNS baseline is now both **enforced** and **audited**!
