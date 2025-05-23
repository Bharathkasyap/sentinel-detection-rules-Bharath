# sentinel-detection-rules-Bharath
Microsoft Sentinel Detection Rules
# 🛰️ Microsoft Sentinel Detection Rules – Bharath Devulapalli (VBDev)

A professional collection of **custom KQL-based analytic rules** designed for use with Microsoft Sentinel. These **detection rules** are built to detect real-world attack patterns, adversary behaviors, and malicious indicators by leveraging log telemetry across Windows, Azure, Defender, Office 365, and cloud environments.

This project is curated by **Bharath Devulapalli (VBDev)** to showcase security automation, SOC readiness, and hands-on SIEM experience — ideal for blue teams, threat hunters, and detection engineers.

---

## 🚨 What are Detection Rules?

Detection Rules in Microsoft Sentinel are **scheduled analytic queries** written in **Kusto Query Language (KQL)** that:
- Continuously scan your security data
- Detect suspicious or malicious behavior
- Trigger alerts and playbooks
- Map directly to **MITRE ATT&CK tactics and techniques**

They are essential to build a **proactive threat detection engine**.

---

## 🧠 Why They Matter

| Benefit                        | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| 🎯 Proactive Threat Detection | Move from reactive alerting to early detection of attacker behaviors       |
| 🛡️ ATT&CK Framework Mapping   | Align detections with TTPs (Tactics, Techniques, Procedures)               |
| 📈 SOC Efficiency              | Reduce alert fatigue with curated and contextual rules                     |
| 🔄 Automation Ready           | Integrate detections with Playbooks (SOAR) to auto-contain or investigate  |
| 📋 Resume Impact              | Shows real SIEM + KQL + Threat Intel experience to recruiters              |

---

## 🧰 How to Use These Rules

1. Go to Microsoft Sentinel → `Analytics` blade.
2. Click `+ Create` → `Scheduled query rule`.
3. Copy the KQL from any `.yaml` or `.kql` file in this repo.
4. Paste it into the query window, set rule logic, tactics, severity, entities.
5. Enable the rule and monitor it from `Incidents` view.

> You can also use Azure Resource Manager (ARM) templates or `az sentinel` CLI for rule import/export.

---

## 📘 Detection Rule Table

| #  | Rule Name                        | MITRE Tactic         | Description                                     | Language | Detection Logic Link |
|----|----------------------------------|-----------------------|-------------------------------------------------|----------|----------------------|
| 1  | detect-brute-force-logon        | Credential Access     | Multiple failed login attempts                  | KQL      | [View Rule](./rules/detect-brute-force-logon.yaml) |
| 2  | detect-rdp-from-unusual-ip      | Lateral Movement      | Suspicious RDP from foreign/rare location       | KQL      | [View Rule](./rules/detect-rdp-from-unusual-ip.yaml) |
| 3  | detect-powershell-obfuscation   | Execution             | Base64 or encoded PowerShell usage              | KQL      | [View Rule](./rules/detect-powershell-obfuscation.yaml) |
| 4  | detect-msdt-follina-abuse       | Initial Access        | Office launching MSDT (CVE-2022-30190)          | KQL      | [View Rule](./rules/detect-msdt-follina-abuse.yaml) |
| 5  | detect-new-admin-user           | Privilege Escalation  | New user added to local or AD admin groups      | KQL      | [View Rule](./rules/detect-new-admin-user.yaml) |
| 6  | detect-lsassy-memory-dumps      | Credential Access     | Potential LSASS dump via LOLBIN tools           | KQL      | [View Rule](./rules/detect-lsassy-memory-dumps.yaml) |
| 7  | detect-scheduled-task-creation  | Persistence           | Abnormal task creation for persistence          | KQL      | [View Rule](./rules/detect-scheduled-task-creation.yaml) |
| 8  | detect-base64-in-commandline    | Defense Evasion       | Obfuscated scripts or reverse shells            | KQL      | [View Rule](./rules/detect-base64-in-commandline.yaml) |
| 9  | detect-dns-tunneling            | Command & Control     | Unusually long or frequent DNS requests         | KQL      | [View Rule](./rules/detect-dns-tunneling.yaml) |
| 10 | detect-azure-impossible-travel  | Initial Access        | Azure AD sign-ins from distant countries        | KQL      | [View Rule](./rules/detect-azure-impossible-travel.yaml) |

---

## 🧠 Example Rule Logic (KQL)

```kql
// detect-brute-force-logon.kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| project TimeGenerated, Account, FailedAttempts
