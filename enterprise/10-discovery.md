# 10. Discovery (TA0007)

## เป้าหมายของผู้โจมตี

เข้าใจสภาพแวดล้อมหลังเจาะเข้ามา: ตัวเองเป็นใคร มีสิทธิ์อะไร, admin คือใคร, Domain Controller/file server/backup อยู่ที่ไหน, มี security software อะไร, และในคลาวด์มี resource อะไร
คำสั่ง discovery เป็นคำสั่งปกติของ admin จึงต้องดู **รูปแบบ** (หลายคำสั่งต่อเนื่องในเวลาสั้น, จากผู้ใช้ที่ไม่ใช่ IT, จาก process แปลก)

## ลำดับการทำงานที่พบบ่อย

1. Host: `whoami /all`, `hostname`, `systeminfo`, `ipconfig /all`, `tasklist`, `netstat -ano`
2. Domain: `net group "Domain Admins" /domain`, `nltest /dclist:`, `nltest /domain_trusts`, AdFind, SharpHound/BloodHound
3. Network: ping sweep, port scan ภายใน (445, 3389, 5985, 1433), `net view`
4. Security & backup: ตรวจ AV/EDR ที่ติดตั้ง, ค้นหา Veeam/backup server (เป้าหมายของ ransomware)
5. Cloud: list subscription/role/storage, `aws sts get-caller-identity`, enumerate S3/Blob

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| คำสั่งสำรวจ | `DeviceProcessEvents` |
| LDAP / AD recon | `IdentityQueryEvents`, `AlertInfo` (MDI) |
| Internal scanning | `DeviceNetworkEvents` |
| Cloud enumeration | `AWSCloudTrail`, `AuditLogs` |

---

## T1087 Account Discovery / T1069 Permission Groups Discovery / T1482 Domain Trust Discovery

**วิธีทำงาน** — ระบุบัญชีและกลุ่มสิทธิ์สูง, trust ระหว่างโดเมน และเส้นทางสิทธิ์ที่สั้นที่สุดไปยัง Domain Admin (BloodHound ดึง session, ACL, group membership ผ่าน LDAP/SMB)

**KQL — "Discovery burst" หลายเครื่องมือในเวลาสั้น**
```kql
let recon = dynamic(["whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe", "quser.exe",
                     "qwinsta.exe", "arp.exe", "route.exe", "netstat.exe", "tasklist.exe", "dsquery.exe", "adfind.exe",
                     "nslookup.exe", "hostname.exe", "klist.exe", "setspn.exe", "csvde.exe", "ldifde.exe"]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ (recon)
| summarize Tools = dcount(FileName), Commands = make_set(ProcessCommandLine, 25), Parents = make_set(InitiatingProcessFileName, 5)
    by DeviceName, AccountName, bin(Timestamp, 15m)
| where Tools >= 5
| order by Tools desc
```

**KQL — คำสั่งที่เจาะจงกลุ่ม admin และ trust**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("Domain Admins", "Enterprise Admins", "domain_trusts", "/dclist", "trustedDomain",
                                    "Get-ADGroupMember", "Get-DomainGroupMember", "Invoke-BloodHound", "SharpHound", "adfind")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**KQL — LDAP reconnaissance (Defender for Identity)**
```kql
IdentityQueryEvents
| where Timestamp > ago(1d)
| where Protocol =~ "Ldap"
| summarize Queries = count(), Targets = dcount(QueryTarget), QueryTypes = make_set(QueryType, 10)
    by DeviceName, AccountUpn, bin(Timestamp, 15m)
| where Targets > 100
```

**วิธีรับมือ**
1. ยืนยันว่าเป็นทีม IT หรือ pentest ที่ได้รับอนุญาตหรือไม่
2. ถ้าไม่ใช่: เครื่องนี้มีผู้โจมตีอยู่แล้ว → ย้อนหาจุดเข้า ([Initial Access](03-initial-access.md)) และ persistence
3. สิ่งที่ถูกค้นบอกเป้าหมายถัดไป: ถ้าค้น Domain Admins → เฝ้า logon ของบัญชีเหล่านั้น; ถ้าค้น backup → ปกป้อง backup ทันที
4. Isolate ถ้าพบร่วมกับ execution/C2 ที่น่าสงสัย

**ป้องกันระยะยาว** — จำกัดสิทธิ์ enumerate session (`NetCease`, ปรับ SAM-R restriction), ลดเส้นทางสิทธิ์ที่ BloodHound เห็น, honeytoken account ใน Domain Admins ที่แจ้งเตือนเมื่อมีคนค้น/ใช้

**False positive** — script login, เครื่องมือ inventory, helpdesk → baseline ตาม AccountName และ parent

---

## T1046 Network Service Discovery

**วิธีทำงาน** — สแกนภายในหาพอร์ต SMB (445), RDP (3389), WinRM (5985), SQL (1433), SSH (22) ด้วย Nmap, Advanced IP Scanner, SoftPerfect, หรือ script

**KQL — เครื่องเดียวเชื่อมต่อหลายปลายทาง/หลายพอร์ตในเวลาสั้น**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType in ("ConnectionAttempt", "ConnectionFailed", "ConnectionSuccess")
| where ipv4_is_private(RemoteIP)
| summarize Targets = dcount(RemoteIP), Ports = dcount(RemotePort), PortList = make_set(RemotePort, 20)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 10m)
| where Targets > 50 or (Ports > 20 and Targets > 5)
| order by Targets desc
```

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("nmap.exe", "masscan.exe", "advanced_ip_scanner.exe", "netscan.exe", "angryip.exe", "rustscan.exe")
     or ProcessVersionInfoProductName has_any ("Advanced IP Scanner", "SoftPerfect Network Scanner", "Nmap")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

**วิธีรับมือ** — แยกเครื่องที่สแกน, ตรวจว่าเชื่อมต่อสำเร็จไปที่ไหนแล้วบ้าง (เป้าหมาย lateral movement), ตรวจเครื่องปลายทางที่สำคัญ

**ป้องกันระยะยาว** — Network segmentation, host firewall บล็อก inbound SMB/RDP/WinRM บน workstation, NDR

**False positive** — vulnerability scanner, monitoring (SCOM, Zabbix, PRTG), SCCM → allowlist ตามเครื่อง

---

## T1518.001 Security Software Discovery / T1518.002 Backup Software Discovery

**KQL**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("Get-MpComputerStatus", "Get-MpPreference", "WinDefend", "AntiVirusProduct", "SecurityCenter2",
                                    "sense", "CrowdStrike", "csagent", "SentinelAgent", "Sophos", "veeam", "backup exec", "commvault")
| where ProcessCommandLine has_any ("query", "Get-", "wmic", "tasklist", "sc ", "findstr", "Select-String")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**วิธีรับมือ** — การค้นหา EDR/backup เป็นสัญญาณนำของ [Defense Impairment](08-defense-impairment.md) และ [Impact](15-impact.md): ยกระดับเป็น High, ตรวจว่ามี tamper attempt ตามมาหรือไม่, ยืนยันว่า backup แยกบัญชีและเครือข่าย

---

## T1580 / T1526 / T1619 Cloud Infrastructure, Service และ Storage Discovery

**วิธีทำงาน** — ใช้ credential คลาวด์ที่ได้มา list resource ทุกประเภท (EC2, S3, IAM, Key Vault, Storage account) เพื่อหาข้อมูลและสิทธิ์

**KQL — AWS: API ประเภท List/Describe/Get จำนวนมากจาก identity เดียว**
```kql
AWSCloudTrail
| where TimeGenerated > ago(1d)
| where EventName startswith "List" or EventName startswith "Describe" or EventName startswith "Get"
| summarize APIs = dcount(EventName), Calls = count(), Services = dcount(EventSource),
            Errors = countif(isnotempty(ErrorCode)), IPs = make_set(SourceIpAddress, 5)
    by UserIdentityArn, bin(TimeGenerated, 1h)
| where APIs > 40 or Services > 10
| order by APIs desc
```

**KQL — Entra ID: การดึงข้อมูล directory จำนวนมากผ่าน Graph (เช่น ROADtools, AzureHound)**
```kql
// ผู้ใช้ที่เริ่มใช้เครื่องมือ CLI/PowerShell ของ Entra ID เป็นครั้งแรกในรอบ 30 วัน
let tools = dynamic(["Microsoft Azure CLI", "Azure Active Directory PowerShell", "Microsoft Graph Command Line Tools", "Azure PowerShell"]);
let signins = union SigninLogs, AADNonInteractiveUserSignInLogs
| where ResultType == "0" and AppDisplayName in~ (tools);
signins
| where TimeGenerated > ago(1d)
| summarize SignIns = count(), IPs = make_set(IPAddress, 10) by UserPrincipalName, AppDisplayName
| join kind=leftanti (
    signins | where TimeGenerated between (ago(30d) .. ago(1d))
    | summarize by UserPrincipalName, AppDisplayName
  ) on UserPrincipalName, AppDisplayName
```

**วิธีรับมือ** — ยืนยันกับเจ้าของ identity, ถ้าไม่ได้รับอนุญาต revoke session/access key, ตรวจว่าหลังสำรวจแล้วมีการอ่านข้อมูล ([T1530](12-collection.md#t1530-data-from-cloud-storage)) หรือเพิ่มสิทธิ์หรือไม่

**ป้องกันระยะยาว** — least privilege บน IAM/RBAC, Conditional Access จำกัดการใช้ CLI/PowerShell เฉพาะ admin บนอุปกรณ์ที่จัดการแล้ว

---

## Checklist ตอบสนองระดับ Tactic

- [ ] ระบุคำสั่งทั้งหมดที่ผู้โจมตีรัน → นี่คือ "แผนที่" ที่ผู้โจมตีรู้แล้ว
- [ ] ปกป้องเป้าหมายที่ถูกค้น: บัญชี admin, DC, backup server, file server สำคัญ
- [ ] หาเครื่องอื่นที่มี discovery pattern เดียวกัน (มักกระจายตามการเคลื่อนที่)
- [ ] ตรวจ Tactic ก่อนหน้า (เข้ามาอย่างไร) และถัดไป (credential access, lateral movement)
