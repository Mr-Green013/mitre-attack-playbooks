# 05. Persistence (TA0003)

## เป้าหมายของผู้โจมตี

รักษาการเข้าถึงไว้แม้เครื่องรีบูต ผู้ใช้เปลี่ยนรหัสผ่าน หรือมัลแวร์ตัวแรกถูกลบ — ผู้โจมตีมักวาง persistence **หลายจุดพร้อมกัน** (เครื่อง + บัญชี + คลาวด์)
การกำจัดไม่ครบทุกจุดคือสาเหตุอันดับต้นที่ผู้โจมตีกลับมาได้หลังปิดเหตุ

## ลำดับการทำงานที่พบบ่อย

| ระดับ | กลไก |
|---|---|
| เครื่อง (Windows) | Run key / Startup folder, Scheduled task, Service, WMI event subscription, DLL hijack |
| เครื่อง (Linux/macOS) | cron, systemd service/timer, `~/.bashrc`, `authorized_keys`, LaunchAgent/LaunchDaemon |
| Server software | Web shell, IIS module, Exchange transport agent, SQL stored procedure |
| บัญชี | สร้างบัญชีใหม่, เพิ่มเข้ากลุ่ม admin, เพิ่ม SSH key |
| คลาวด์ / Identity | เพิ่ม secret/cert ให้ App/Service Principal, OAuth app consent, ลงทะเบียน device/MFA method, แก้ Conditional Access, federation backdoor |

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| Registry autorun, service | `DeviceRegistryEvents` |
| Scheduled task | `DeviceEvents` (ScheduledTaskCreated), `SecurityEvent` (4698) |
| ไฟล์ใน web root / startup | `DeviceFileEvents` |
| บัญชีและกลุ่ม on-prem | `SecurityEvent` (4720, 4728, 4732, 4756), `IdentityDirectoryEvents` |
| Entra ID / App | `AuditLogs` |

---

## T1547.001 Registry Run Keys / Startup Folder

**วิธีทำงาน** — เพิ่มค่าใน `HKCU|HKLM\Software\Microsoft\Windows\CurrentVersion\Run(Once)` หรือวางไฟล์/shortcut ใน Startup folder เพื่อรันทุกครั้งที่ผู้ใช้ล็อกอิน

**KQL**
```kql
DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\Microsoft\Windows\CurrentVersion\Run", @"\Microsoft\Windows\CurrentVersion\RunOnce",
                             @"\Microsoft\Windows NT\CurrentVersion\Winlogon")
| where RegistryValueData has_any (@"\AppData\", @"\Temp\", @"\Users\Public\", @"\ProgramData\", "powershell", "mshta",
                                   "rundll32", "wscript", "cscript", "regsvr32", "http")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData
```

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FolderPath has @"\Start Menu\Programs\Startup\"
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, SHA256
```

**วิธีรับมือ**
1. ตรวจไฟล์ที่ค่า registry ชี้ไป (hash, signer, ผู้สร้าง)
2. เก็บหลักฐาน → ลบค่า registry/ไฟล์ → ตรวจ persistence จุดอื่นบนเครื่องเดียวกัน (ใช้ Autoruns หรือ Live Response)
3. ค้นค่าเดียวกันทั่วองค์กร

**ป้องกันระยะยาว** — ASR rules, WDAC, ผู้ใช้ไม่มีสิทธิ์ local admin (M1026)

**False positive** — ซอฟต์แวร์ที่ติดตั้งใน `%AppData%` ตามปกติ (Teams, Zoom, OneDrive, Spotify) → allowlist ตาม signer

---

## T1053.005 Scheduled Task

**วิธีทำงาน** — สร้าง task ที่รันเมื่อ logon/boot หรือตามช่วงเวลาด้วยสิทธิ์ SYSTEM มักตั้งชื่อคล้าย task ของ Windows หรือซ่อนโดยลบค่า `SD` ใน registry

**KQL**
```kql
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "ScheduledTaskCreated"
| extend Fields = parse_json(AdditionalFields)
| extend TaskName = tostring(Fields.TaskName), TaskContent = tostring(Fields.TaskContent)
| where TaskContent has_any ("powershell", "cmd.exe", "mshta", "rundll32", "regsvr32", "wscript", @"\AppData\", @"\Temp\", @"\Users\Public\", "http")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, TaskName, TaskContent
```

**วิธีรับมือ** — export XML ของ task เป็นหลักฐาน (`schtasks /query /tn <name> /xml`), ลบ task, ตรวจไฟล์ที่ task เรียก, ค้น task ชื่อเดียวกันทั่วองค์กร

**False positive** — agent ของซอฟต์แวร์ (updater ของ browser, Adobe, backup) → allowlist ตาม path ที่ signed

---

## T1543.003 Windows Service (Create or Modify System Process)

**วิธีทำงาน** — ติดตั้ง service ใหม่หรือแก้ `ImagePath` ของ service เดิมให้ชี้ไปที่ payload รันด้วยสิทธิ์ SYSTEM ทุกครั้งที่บูต

**KQL** — ใช้ query ของ [T1569.002](04-execution.md#t1569002-service-execution) และเพิ่มการจับการแก้ service เดิม:
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has_any (" create ", " config ") and ProcessCommandLine has "binpath"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**วิธีรับมือ** — หยุดและลบ service, คืนค่า `ImagePath` ของ service เดิมจาก baseline, ตรวจว่าบัญชีที่สร้างมีสิทธิ์ admin มาได้อย่างไร

### Linux: systemd / cron / authorized_keys

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any ("/etc/systemd/system/", "/etc/cron", "/var/spool/cron/", "/.ssh/authorized_keys", "/etc/rc.local", "/.bashrc", "/etc/ld.so.preload")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath
```

---

## T1098 Account Manipulation (คลาวด์)

### T1098.001 Additional Cloud Credentials

**วิธีทำงาน** — เพิ่ม client secret หรือ certificate ให้ App Registration / Service Principal ที่มีสิทธิ์สูงอยู่แล้ว (เช่น `Mail.Read`, `Directory.ReadWrite.All`) เพื่อเข้าถึงข้อมูลได้ต่อแม้ reset รหัสผ่านผู้ใช้ทั้งหมด (เทคนิคที่ APT29 ใช้)

**KQL**
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add service principal credentials", "Certificates and secrets management", "Add service principal")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
         ActorIP = tostring(InitiatedBy.user.ipAddress),
         Target = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, ActorIP, Target, Result
```

### T1098.003 Additional Cloud Roles / เพิ่มเข้ากลุ่ม admin

**KQL — เพิ่มสมาชิกใน directory role**
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add member to role", "Add eligible member to role", "Add member to role completed (PIM activation)")
| mv-expand TargetResources
| mv-expand Prop = TargetResources.modifiedProperties
| where tostring(Prop.displayName) == "Role.DisplayName"
| extend Role = trim(@'"', tostring(Prop.newValue)),
         Actor = tostring(InitiatedBy.user.userPrincipalName),
         Member = tostring(TargetResources.userPrincipalName)
| where Role has_any ("Global Administrator", "Privileged Role Administrator", "Application Administrator",
                      "Cloud Application Administrator", "Exchange Administrator", "Security Administrator", "Hybrid Identity Administrator")
| project TimeGenerated, OperationName, Actor, Member, Role
```

**KQL — on-prem: เพิ่มเข้ากลุ่มสิทธิ์สูง**
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4732, 4756)
| where TargetUserName in~ ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators", "DnsAdmins")
| project TimeGenerated, Computer, Activity, Group = TargetUserName, Member = MemberName, By = SubjectUserName
```

**วิธีรับมือ (T1098)**
1. ยืนยันกับเจ้าของแอป/ผู้อนุมัติ change
2. ถ้าไม่ได้รับอนุญาต: ลบ secret/cert/สมาชิกที่เพิ่ม, ตรวจ sign-in ของ service principal (`AADServicePrincipalSignInLogs`) ตั้งแต่เวลาที่เพิ่ม
3. ตรวจว่าแอปเข้าถึงอะไรไปแล้ว (Graph activity, MailItemsAccessed)
4. Reset บัญชีที่เป็นผู้กระทำ (Actor) — บัญชีนั้นถูกยึดแล้ว

**ป้องกันระยะยาว** — PIM สำหรับทุก role สิทธิ์สูง, จำกัดผู้ที่เป็น owner ของ app, app instance property lock, alert ทุกครั้งที่เพิ่ม credential ให้แอปที่มี application permission

### T1098.004 SSH Authorized Keys / T1098.005 Device Registration

- SSH: ใช้ query Linux ด้านบน (`/.ssh/authorized_keys`)
- Device registration: `AuditLogs | where OperationName in ("Register device", "Add registered owner to device")` แล้วเทียบกับ sign-in ที่น่าสงสัยก่อนหน้า

---

## T1136 Create Account

**KQL**
```kql
union
  (SecurityEvent | where TimeGenerated > ago(7d) | where EventID == 4720
   | project TimeGenerated, Source = "AD/Local", NewAccount = TargetUserName, By = SubjectUserName, Computer),
  (AuditLogs | where TimeGenerated > ago(7d) | where OperationName == "Add user"
   | project TimeGenerated, Source = "Entra ID", NewAccount = tostring(TargetResources[0].userPrincipalName),
             By = tostring(InitiatedBy.user.userPrincipalName), Computer = "")
```

**วิธีรับมือ** — เทียบกับ HR/ticket การสร้างบัญชี, disable บัญชีที่ไม่มีที่มา, ตรวจการใช้งานของบัญชีนั้นตั้งแต่ถูกสร้าง

**ป้องกันระยะยาว** — การสร้างบัญชีผ่าน identity governance workflow เท่านั้น, แจ้งเตือนบัญชีที่สร้างนอกเวลาทำการหรือโดยบัญชีที่ไม่ใช่ HR/IAM

---

## T1505.003 Web Shell

**วิธีทำงาน** — หลังเจาะ web server ([T1190](03-initial-access.md#t1190-exploit-public-facing-application)) จะวางไฟล์ `.aspx/.ashx/.jsp/.php` ที่รับคำสั่งผ่าน HTTP

**KQL**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".aspx" or FileName endswith ".ashx" or FileName endswith ".asmx" or FileName endswith ".jsp"
     or FileName endswith ".jspx" or FileName endswith ".php"
| where FolderPath has_any (@"\inetpub\", @"\wwwroot\", @"\FrontEnd\HttpProxy\", @"\webapps\", "/var/www/")
| where InitiatingProcessFileName in~ ("w3wp.exe", "java.exe", "php-cgi.exe", "httpd.exe", "cmd.exe", "powershell.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, SHA256
```

**วิธีรับมือ** — เก็บไฟล์และ IIS/web log, ลบ web shell, ค้น request ที่เรียกไฟล์นั้นเพื่อดูคำสั่งที่ถูกสั่งและ IP ผู้โจมตี, แพตช์ช่องโหว่ต้นทาง, rotate credential บนเซิร์ฟเวอร์

**False positive** — การ deploy เว็บตามปกติ (initiating process เป็น `msdeploy.exe`, CI agent) → allowlist

---

## T1556 Modify Authentication Process

**วิธีทำงาน** — แก้กลไกยืนยันตัวตนเพื่อเข้าได้ตลอด: ปิด/เพิ่ม MFA method ของเหยื่อ (T1556.006), แก้ Conditional Access ให้ยกเว้นตัวเอง (T1556.009), ติดตั้ง password filter DLL บน DC (T1556.002), backdoor PTA agent หรือ federation (T1556.007)

**KQL — การแก้ MFA และ Conditional Access**
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("conditional access policy", "security info", "StrongAuthentication",
                               "Set domain authentication", "Set federation settings on domain", "Update authentication methods policy")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
         Target = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, Target, Result
```

**KQL — password filter / LSA package ใหม่บน DC**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\SYSTEM\CurrentControlSet\Control\Lsa"
| where RegistryValueName in~ ("Notification Packages", "Authentication Packages", "Security Packages")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryValueName, RegistryValueData
```

**วิธีรับมือ** — คืนค่า policy/method จาก baseline, ถ้ามีการแก้ federation หรือ LSA บน DC ให้ถือเป็นการยึด identity ระดับ **Critical** (ต้อง rotate krbtgt สองรอบ, token-signing certificate และตรวจ DC ทุกเครื่อง)

**ป้องกันระยะยาว** — CA policy อยู่ใต้ PIM และ change control, Protected Actions ใน Entra ID, ตรวจ DC ด้วย baseline และ MDI

---

## Checklist ตอบสนองระดับ Tactic

- [ ] ไล่ตรวจ persistence **ทุกประเภท** บนเครื่องที่เกี่ยวข้อง (Autoruns / Live Response) ไม่หยุดที่จุดแรกที่เจอ
- [ ] ตรวจฝั่ง identity: บัญชีใหม่, สมาชิกกลุ่มสิทธิ์สูง, MFA method, app credential, OAuth consent, device ที่ลงทะเบียนในช่วงเกิดเหตุ
- [ ] ลบ persistence ทั้งหมด **พร้อมกัน** ในหน้าต่างเวลาเดียว (ลดโอกาสผู้โจมตีรู้ตัวแล้วสร้างใหม่)
- [ ] Reset credential ที่ผู้โจมตีอาจเข้าถึงได้หลังลบ persistence
- [ ] เฝ้าระวังเข้มข้นต่อ 30 วันว่า persistence กลับมาหรือไม่
