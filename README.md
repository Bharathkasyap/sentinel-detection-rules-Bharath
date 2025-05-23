# 🛰️ Microsoft Sentinel Detection Rules – Bharath Devulapalli (VBDev)

> “Detection is not just alerting, it’s storytelling — crafted in KQL.”  
> — *Bharath Devulapalli (VBDev)*

A professionally curated collection of **KQL-based analytic rules** for Microsoft Sentinel built to detect adversary behaviors using real-world attack telemetry across Windows, Azure, Defender, M365, and hybrid environments.

🎯 Ideal for: SOC Analysts • Detection Engineers • Threat Hunters • Blue Team Interns  
📁 Format: `.yaml` detection rules + embedded threat context  
🛡️ ATT&CK-aligned • Resume-ready • GitHub-portable

---

## 🚨 What are Sentinel Detection Rules?

**Detection Rules** in Microsoft Sentinel are scheduled **Kusto Query Language (KQL)** analytics that:
- Continuously scan log data from cloud & on-prem environments
- Trigger real-time alerts based on suspicious behavior
- Integrate with SOAR playbooks for automated response
- Map directly to the **MITRE ATT&CK® Framework**

---

## 🧠 Why This Repository Matters

| 🌐 Benefit                    | 💡 Explanation                                                                 |
|------------------------------|-------------------------------------------------------------------------------|
| 🔍 Real Adversary Detection  | All rules mimic attacker behavior observed in real enterprise threats        |
| 🧠 Analyst-Ready Context     | Embedded threat hunting tips, MITRE mapping, and response advice             |
| 📦 GitHub Portability        | Clone and deploy instantly into any Sentinel instance                        |
| 🎓 Resume Power              | Showcase hands-on SIEM, KQL, MITRE & SOC knowledge in interviews              |
| 🤖 Automation-Enabled        | Easily pair with Sentinel Playbooks to auto-contain threats                  |

---

## 🧰 How to Use These `.yaml` Rules

### 👨‍💻 Manual GUI Method

1. Open **Microsoft Sentinel** → Go to **Analytics**  
2. Click **+ Create** → **Scheduled query rule**  
3. Copy the `query:` from any `.yaml` file  
4. Paste it into the **Query box**  
5. Fill in:
   - Rule name
   - Description
   - Severity (`High`, `Medium`, etc.)
   - MITRE tactic and technique
   - Entity mappings (from `entityMappings`)
6. Save → You're live!

---

### ⚙️ Optional: Automate via Azure CLI

1. Convert `.yaml` to `.json` using online tools or script  
2. Use `az sentinel alert-rule create` to deploy in bulk  
3. See [Microsoft Docs](https://learn.microsoft.com/en-us/azure/sentinel/tutorial-detections-create) for ARM template usage

---

## 📋 Detection Rules Index

| #  | Rule Name                          | MITRE Tactic         | Description                                        | Link |
|----|------------------------------------|-----------------------|----------------------------------------------------|------|
| 1  | detect-brute-force-logon           | Credential Access     | Multiple failed login attempts                     | [🔍](./rules/detect-brute-force-logon.yaml) |
| 2  | detect-rdp-from-unusual-ip         | Lateral Movement      | RDP access from rare foreign IPs                   | [🔍](./rules/detect-rdp-from-unusual-ip.yaml) |
| 3  | detect-powershell-obfuscation      | Execution             | Obfuscated/encoded PowerShell                      | [🔍](./rules/detect-powershell-obfuscation.yaml) |
| 4  | detect-msdt-follina-abuse          | Initial Access        | MSDT exploit (CVE-2022-30190)                      | [🔍](./rules/detect-msdt-follina-abuse.yaml) |
| 5  | detect-new-admin-user              | Privilege Escalation  | New user added to privileged group                 | [🔍](./rules/detect-new-admin-user.yaml) |
| 6  | detect-lsassy-memory-dumps         | Credential Access     | Dumping LSASS via Procdump or Rundll32             | [🔍](./rules/detect-lsassy-memory-dumps.yaml) |
| 7  | detect-scheduled-task-creation     | Persistence           | New scheduled tasks via schtasks                   | [🔍](./rules/detect-scheduled-task-creation.yaml) |
| 8  | detect-base64-in-commandline       | Defense Evasion       | Base64 strings in command-line activity            | [🔍](./rules/detect-base64-in-commandline.yaml) |
| 9  | detect-dns-tunneling               | C2 (Command & Control)| DNS tunneling via long frequent requests           | [🔍](./rules/detect-dns-tunneling.yaml) |
| 10 | detect-azure-impossible-travel     | Initial Access        | Geo-impossible Azure sign-ins                      | [🔍](./rules/detect-azure-impossible-travel.yaml) |
| 11 | detect-successful-logon-after-failures | Credential Access | Brute-force success after many 4625 failures       | [🔍](./rules/detect-successful-logon-after-failures.yaml) |
| 12 | detect-password-spray              | Credential Access     | Spray attack from same IP across multiple users    | [🔍](./rules/detect-password-spray.yaml) |
| 13 | detect-process-injection           | Defense Evasion       | VirtualAllocEx, WriteProcessMemory activity        | [🔍](./rules/detect-process-injection.yaml) |
| 14 | detect-command-line-recon          | Discovery             | Recon commands: whoami, ipconfig, net user         | [🔍](./rules/detect-command-line-recon.yaml) |
| 15 | detect-smb-lateral-movement        | Lateral Movement      | Remote file execution via SMB shares               | [🔍](./rules/detect-smb-lateral-movement.yaml) |
| 16 | detect-unusual-service-installation| Persistence           | Malicious services registered                      | [🔍](./rules/detect-unusual-service-installation.yaml) |
| 17 | detect-email-forwarding-rule-creation | Collection         | Auto-forward rules to external domains             | [🔍](./rules/detect-email-forwarding-rule-creation.yaml) |
| 18 | detect-multiple-vpn-failures       | Initial Access        | Repeated VPN failures from one source              | [🔍](./rules/detect-multiple-vpn-failures.yaml) |
| 19 | detect-psexec-usage-across-network | Lateral Movement      | PsExec execution across network                    | [🔍](./rules/detect-psexec-usage-across-network.yaml) |
| 20 | detect-cleared-windows-event-logs  | Defense Evasion       | Event 1102 – audit log cleared                     | [🔍](./rules/detect-cleared-windows-event-logs.yaml) |

---

## 🔎 Example Rule Snippet

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| project TimeGenerated, Account, FailedAttempts
