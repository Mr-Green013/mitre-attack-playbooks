# 06. Privilege Escalation (TA0004)

## เป้าหมายของผู้โจมตี

ยกระดับจากผู้ใช้ทั่วไปเป็น local admin / SYSTEM / root และจาก local admin ไปเป็น Domain Admin หรือ Global Admin
สิทธิ์สูงเปิดทางให้ dump credential, ปิด EDR และควบคุมทั้งโดเมน

## ลำดับการทำงานที่พบบ่อย

1. สำรวจหาช่องทาง (WinPEAS, SharpUp, LinPEAS, BloodHound)
2. ใช้ misconfiguration: UAC bypass, service permission อ่อน, unquoted path, `sudo` ที่ตั้งค่าผิด
3. ใช้ token: service account ที่มี `SeImpersonatePrivilege` → Potato → SYSTEM
4. ใช้ช่องโหว่ kernel/driver (รวม BYOVD — นำ driver ที่มีช่องโหว่มาลงเอง)
5. ระดับโดเมน/tenant: แก้ GPO, ACL ของ AD object, ADCS template, หรือ role ใน Entra ID

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| Registry ของ UAC bypass | `DeviceRegistryEvents` |
| Process ที่รันเป็น SYSTEM จาก service account | `DeviceProcessEvents` |
| Driver load | `DeviceEvents` |
| GPO / AD object change | `SecurityEvent` (5136, 5137), `IdentityDirectoryEvents` |

---

## T1548.002 Bypass User Account Control

**วิธีทำงาน** — ใช้ binary ที่ auto-elevate (`fodhelper.exe`, `computerdefaults.exe`, `eventvwr.exe`, `sdclt.exe`) ซึ่งอ่านคำสั่งจาก registry ใต้ HKCU ผู้โจมตีเขียนคำสั่งของตัวเองลงไปก่อน แล้วเรียก binary นั้นเพื่อรันแบบ high integrity โดยไม่มี prompt

**KQL — registry ที่ใช้ทำ UAC bypass**
```kql
DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (@"\ms-settings\shell\open\command", @"\mscfile\shell\open\command",
                             @"\Folder\shell\open\command", @"\exefile\shell\open\command", @"\Launcher.SystemSettings\shell\open\command")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData
```

**KQL — auto-elevate binary สร้าง shell**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("fodhelper.exe", "computerdefaults.exe", "eventvwr.exe", "sdclt.exe", "slui.exe", "wsreset.exe")
| where FileName !in~ ("conhost.exe", "mmc.exe", "werfault.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

**วิธีรับมือ** — ลบ registry key, ตรวจ payload ที่ถูกรัน, ถือว่าผู้โจมตีมี local admin บนเครื่องนั้นแล้ว → ตรวจ [Credential Access](09-credential-access.md)

**ป้องกันระยะยาว** — ผู้ใช้ไม่เป็น local admin (UAC bypass ใช้ได้เฉพาะบัญชีที่อยู่ในกลุ่ม Administrators), ตั้ง UAC เป็น *Always notify* (M1052), LAPS สำหรับบัญชี local admin

---

## T1134 Access Token Manipulation

**วิธีทำงาน** — service account (IIS AppPool, MSSQL) มี `SeImpersonatePrivilege` ตามปกติ เครื่องมือตระกูล Potato (PrintSpoofer, GodPotato, JuicyPotato) หลอกให้ SYSTEM ยืนยันตัวตนกับ named pipe แล้วขโมย token มาสร้าง process ใหม่เป็น SYSTEM

**KQL — service process สร้าง shell ที่รันเป็น SYSTEM**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("w3wp.exe", "sqlservr.exe", "httpd.exe", "tomcat9.exe", "java.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe")
| where AccountName =~ "system" or ProcessIntegrityLevel =~ "System"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, AccountName, ProcessCommandLine
```

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("PrintSpoofer", "GodPotato", "JuicyPotato", "RoguePotato", "SweetPotato", "EfsPotato", "RemotePotato")
    or FileName has "potato"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
```

**วิธีรับมือ** — นี่มักเป็นขั้นต่อจาก [T1190](03-initial-access.md#t1190-exploit-public-facing-application) บน web/SQL server: isolate เซิร์ฟเวอร์, หาช่องทางเข้าแรก, rotate credential ทั้งหมดบนเครื่อง

**ป้องกันระยะยาว** — ใช้ Group Managed Service Account, ปิด Print Spooler บนเซิร์ฟเวอร์ที่ไม่ใช่ print server, ไม่ให้ app pool รันด้วยบัญชีที่มีสิทธิ์ในโดเมน

---

## T1068 Exploitation for Privilege Escalation (รวม BYOVD)

**วิธีทำงาน** — ใช้ช่องโหว่ใน kernel/driver/ซอฟต์แวร์ที่รันด้วยสิทธิ์สูง กลุ่ม ransomware นิยมนำ driver ของ vendor ที่มีช่องโหว่ (signed แต่ exploit ได้) มาโหลดเพื่อได้สิทธิ์ kernel แล้วปิด EDR

**KQL — driver ที่โหลดบนเครื่องจำนวนน้อย (ไม่ค่อยพบในองค์กร)**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DriverLoad"
| summarize Devices = dcount(DeviceName), FirstSeen = min(Timestamp), Paths = make_set(FolderPath, 5)
    by FileName, SHA256
| where Devices <= 2 and FirstSeen > ago(2d)
| order by FirstSeen desc
```

**วิธีรับมือ** — ตรวจ SHA256 กับรายชื่อ vulnerable driver (เช่น loldrivers.io), ถ้าตรง ถือว่ามีความพยายามปิด EDR ([Tactic 08](08-defense-impairment.md)) → isolate และ reimage

**ป้องกันระยะยาว** — เปิด Microsoft Vulnerable Driver Blocklist, HVCI/Memory Integrity, ASR *Block abuse of exploited vulnerable signed drivers*, แพตช์ OS ตามรอบ

---

## T1484 Domain or Tenant Policy Modification

### T1484.001 Group Policy Modification

**วิธีทำงาน** — ผู้ที่มีสิทธิ์แก้ GPO สามารถสั่งให้ทุกเครื่องในโดเมนรัน script, สร้าง scheduled task หรือปิด Defender — ใช้ทั้งเพื่อยกระดับสิทธิ์และกระจาย ransomware

**KQL — แก้ไข GPO (ต้องเปิด audit Directory Service Changes)**
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (5136, 5137, 5141)
| where EventData has "groupPolicyContainer"
| project TimeGenerated, Computer, EventID, SubjectUserName, EventData
```

**วิธีรับมือ** — ระบุ GPO ที่ถูกแก้และสิ่งที่เปลี่ยน (เปรียบเทียบกับ backup GPO), คืนค่า, ตรวจว่าเครื่องไหนดึง policy ใหม่ไปแล้ว, reset บัญชีที่แก้

**ป้องกันระยะยาว** — จำกัดสิทธิ์แก้ GPO เฉพาะ Tier 0, backup GPO รายวัน, ตรวจ ACL ของ GPO ด้วย BloodHound/PingCastle เป็นรอบ

### T1484.002 Trust Modification

**วิธีทำงาน** — เพิ่ม/แก้ federation ของโดเมนใน Entra ID เพื่อให้ IdP ของผู้โจมตีออก token ที่ tenant เชื่อถือ (backdoor ระดับ tenant)

**KQL** — ดู query `Set federation settings on domain` ใน [T1556](05-persistence.md#t1556-modify-authentication-process) — ถ้าพบโดยไม่มี change ให้ถือเป็น **Critical**

---

## Checklist ตอบสนองระดับ Tactic

- [ ] ระบุสิทธิ์ที่ผู้โจมตีได้ (local admin / SYSTEM / domain / tenant) — กำหนดขอบเขต reset credential
- [ ] ถ้าได้ SYSTEM บนเครื่องใด ให้ถือว่า credential ทุกตัวที่เคยล็อกอินบนเครื่องนั้นรั่วแล้ว
- [ ] ถ้าได้สิทธิ์ระดับโดเมน: เตรียมแผน Tier 0 recovery (krbtgt reset 2 รอบ, ตรวจ DC, GPO, AdminSDHolder)
- [ ] ปิดช่องทางที่ใช้ (แพตช์, ลบสิทธิ์เกิน, แก้ ACL) ก่อนคืนระบบ
