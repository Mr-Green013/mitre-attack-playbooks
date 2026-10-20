# 11. Lateral Movement (TA0008)

## เป้าหมายของผู้โจมตี

เคลื่อนจากเครื่องแรกไปยังเครื่องที่มีค่ามากกว่า — server, Domain Controller, backup, ระบบการเงิน, jump host ไป OT หรือ tenant คลาวด์
ใช้ credential ที่ขโมยได้ใน [Tactic 09](09-credential-access.md) ร่วมกับช่องทางบริหารระบบมาตรฐาน (RDP, SMB, WinRM, WMI, SSH)

## ลำดับการทำงานที่พบบ่อย

1. เลือกเป้าหมายจาก [Discovery](10-discovery.md)
2. ยืนยันตัวตนด้วย hash/ticket/รหัสผ่าน (T1550)
3. รันคำสั่งระยะไกล: PsExec / Impacket (SMB + service), WMI, WinRM, RDP, DCOM (T1021)
4. คัดลอกเครื่องมือไปเครื่องปลายทาง (T1570)
5. ใช้ระบบกระจายซอฟต์แวร์ขององค์กร (SCCM, Intune, PDQ, RMM) เพื่อไปทุกเครื่องพร้อมกัน (T1072)

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| Logon ระยะไกล | `DeviceLogonEvents`, `IdentityLogonEvents`, `SecurityEvent` (4624, 4648) |
| Remote execution | `DeviceProcessEvents`, `DeviceRegistryEvents` |
| ไฟล์ที่ถูกคัดลอกผ่าน SMB | `DeviceFileEvents` (`RequestProtocol`, `RequestSourceIP`) |
| Network ภายใน | `DeviceNetworkEvents` |

---

## T1021 Remote Services

### T1021.001 Remote Desktop Protocol

**วิธีทำงาน** — ล็อกอิน RDP ด้วยบัญชีที่ขโมยมา บางครั้งใช้ Restricted Admin mode เพื่อ Pass-the-Hash ผ่าน RDP

**KQL — บัญชีเดียว RDP เข้าหลายเครื่องในเวลาสั้น**
```kql
DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess"
| summarize Targets = dcount(DeviceName), TargetList = make_set(DeviceName, 20), Sources = make_set(RemoteIP, 10)
    by AccountName, AccountDomain, bin(Timestamp, 1h)
| where Targets >= 3
```

**KQL — RDP ระหว่าง workstation (ไม่ควรเกิดในองค์กรที่ทำ tiering)**
```kql
DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess"
| join kind=inner (DeviceInfo | where Timestamp > ago(1d) | summarize arg_max(Timestamp, DeviceType, OSPlatform) by DeviceName) on DeviceName
| where DeviceType == "Workstation"
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteDeviceName
```

### T1021.002 SMB/Windows Admin Shares (PsExec, Impacket)

**วิธีทำงาน** — เชื่อมต่อ `ADMIN$`/`C$` เพื่อวางไฟล์ แล้วสร้าง service ระยะไกลให้รัน (PsExec, `psexec.py`, `smbexec.py`) หรือรันผ่าน WMI แล้วเขียนผลลัพธ์กลับไปที่ `ADMIN$` (`wmiexec.py`)

**KQL — สัญญาณ PsExec และ Impacket บนเครื่องปลายทาง**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("PSEXESVC.exe", "PAExec.exe", "csexecsvc.exe", "remcomsvc.exe")
     or (InitiatingProcessFileName =~ "services.exe" and FileName =~ "cmd.exe" and ProcessCommandLine has_any (@"\\127.0.0.1\", "%COMSPEC%", "echo"))
     or (InitiatingProcessFileName =~ "wmiprvse.exe" and ProcessCommandLine matches regex @"(?i)\\\\127\.0\.0\.1\\(ADMIN|C)\$\\__")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### T1021.006 Windows Remote Management

**KQL**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| where FileName !in~ ("conhost.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

**วิธีรับมือ (T1021)**
1. หา **เครื่องต้นทาง** (`RemoteIP`, `RemoteDeviceName`) — นั่นคือเครื่องที่ผู้โจมตีอยู่ก่อน
2. ทำ "lateral movement graph": ต้นทาง → ปลายทาง → ปลายทางถัดไป ด้วย query ข้างบนทั้งชุด
3. Isolate ทุกเครื่องในเส้นทางพร้อมกัน (ทำทีละเครื่องจะทำให้ผู้โจมตีย้ายหนี)
4. Disable/reset บัญชีที่ใช้เคลื่อนที่, ตรวจ persistence บนทุกเครื่องปลายทาง

**ป้องกันระยะยาว**
- Host firewall: workstation ไม่รับ inbound SMB/RDP/WinRM จาก workstation (M1030)
- Tiered admin model + Privileged Access Workstation (M1026)
- LAPS (รหัสผ่าน local admin ไม่ซ้ำกัน), ปิด `LocalAccountTokenFilterPolicy`, ASR *Block process creations from PSExec and WMI*
- RDP ต้องผ่าน gateway ที่มี MFA

**False positive** — helpdesk ใช้ RDP/PsExec, SCCM remote tools → แยกด้วยบัญชี helpdesk เฉพาะและเครื่องต้นทางที่กำหนด

---

## T1550 Use Alternate Authentication Material

### T1550.002 Pass the Hash / T1550.003 Pass the Ticket

**วิธีทำงาน** — ใช้ NTLM hash หรือ Kerberos ticket แทนรหัสผ่าน (Mimikatz `sekurlsa::pth`, Rubeus `ptt`, Impacket `-hashes`)

**KQL — logon แบบ NewCredentials ที่มาจาก Mimikatz `sekurlsa::pth`**
```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624 and LogonType == 9
| where LogonProcessName =~ "seclogo" and AuthenticationPackageName =~ "Negotiate"
| project TimeGenerated, Computer, TargetUserName, SubjectUserName, IpAddress, ProcessName
```

**KQL — บัญชี admin ยืนยันตัวตนด้วย NTLM ไปหลายเครื่อง**
```kql
IdentityLogonEvents
| where Timestamp > ago(1d)
| where Protocol =~ "Ntlm" and ActionType == "LogonSuccess"
| summarize Targets = dcount(DestinationDeviceName), TargetList = make_set(DestinationDeviceName, 20)
    by AccountName, DeviceName, bin(Timestamp, 1h)
| where Targets >= 5
```

### T1550.001 Application Access Token / T1550.004 Web Session Cookie

ใช้ token/cookie ที่ขโมยมาเข้าถึง M365/Azure จากเครื่องผู้โจมตี — ดู query session ใช้หลายประเทศใน [AiTM](09-credential-access.md#t1539--t1557-aitm-และการขโมย-session-cookie)

**วิธีรับมือ (T1550)** — reset password **สองครั้ง** สำหรับบัญชีที่ถูกใช้ hash (ล้าง password history ที่ใช้ทำ NTLM), purge Kerberos ticket (`klist purge`) บนเครื่องที่เกี่ยวข้อง, revoke cloud session; ถ้าพบ Golden Ticket → krbtgt reset 2 รอบ

**ป้องกันระยะยาว** — Protected Users group สำหรับ admin (ไม่ใช้ NTLM/RC4, ไม่ cache), Credential Guard, ลด/ปิด NTLM, Token Protection ใน Conditional Access

---

## T1570 Lateral Tool Transfer

**วิธีทำงาน** — คัดลอก payload/เครื่องมือไปเครื่องอื่นผ่าน SMB, `certutil` จาก web server ภายใน, หรือ `bitsadmin`

**KQL — executable ถูกเขียนลงเครื่องผ่าน SMB จากเครื่องอื่น**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where RequestProtocol =~ "SMB"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1" or FileName endswith ".bat" or FileName endswith ".sys"
| summarize Targets = dcount(DeviceName), TargetList = make_set(DeviceName, 20), Files = make_set(FileName, 10)
    by RequestSourceIP, RequestAccountName, SHA256
| order by Targets desc
```

**วิธีรับมือ** — ไฟล์เดียวกัน (SHA256) ถูกวางหลายเครื่อง = ผู้โจมตีกำลังกระจาย (มักก่อน ransomware) → block hash ทั้งองค์กรทันที, isolate เครื่องต้นทาง (`RequestSourceIP`)

---

## T1072 Software Deployment Tools

**วิธีทำงาน** — ยึดคอนโซล SCCM/Intune/PDQ/RMM แล้วสั่ง deploy script ไปทุกเครื่อง (ช่องทางที่ ransomware ใช้กระจายเร็วที่สุด)

**KQL — Intune: สร้างหรือแก้ device script / app**
```kql
IntuneAuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("DeviceManagementScript", "DeviceHealthScript", "MobileApp")
| where OperationName has_any ("Create", "Patch", "Assign")
| project TimeGenerated, OperationName, Identity, Properties
```

**วิธีรับมือ** — หยุด/ยกเลิก deployment ที่ไม่ได้รับอนุญาตทันที, ระงับบัญชีผู้ดูแลคอนโซล, ตรวจเครื่องที่ได้รับ deployment แล้ว

**ป้องกันระยะยาว** — คอนโซลจัดการเป็น Tier 0, Multi Admin Approval ของ Intune, PIM สำหรับ Intune Administrator

---

## Checklist ตอบสนองระดับ Tactic

- [ ] สร้างแผนภาพเส้นทางการเคลื่อนที่ (เครื่อง → เครื่อง, บัญชีที่ใช้, เวลา)
- [ ] Contain ทุกเครื่องในเส้นทาง **พร้อมกัน** + disable บัญชีที่ใช้
- [ ] ตรวจว่าถึง Tier 0 (DC, Entra Connect, ADFS, คอนโซลจัดการ, backup) หรือยัง — ถ้าถึง ยกระดับเป็น Critical
- [ ] Block hash ของเครื่องมือที่ถูกคัดลอกทั้งองค์กร
- [ ] ทบทวน segmentation ที่ทำให้การเคลื่อนที่นี้เป็นไปได้
