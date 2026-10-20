# 04. Execution (TA0002)

## เป้าหมายของผู้โจมตี

ทำให้โค้ดของตัวเองรันบนระบบเป้าหมาย — ผ่าน interpreter ที่มีอยู่แล้ว (PowerShell, cmd, bash, Python), เครื่องมือบริหารระบบ (WMI, service, scheduled task), การหลอกผู้ใช้ หรือคำสั่งบริหารคลาวด์/คอนเทนเนอร์/ESXi
ใน v20 รวม **Prompt Injection** (T1698 Indirect, T1699 Direct) ที่สั่งให้ AI agent ขององค์กรทำงานแทนผู้โจมตี

## ลำดับการทำงานที่พบบ่อย

1. ผู้ใช้เปิดไฟล์/ลิงก์ (T1204) → LOLBin หรือ script interpreter ทำงาน (T1059)
2. Script ดาวน์โหลด stage ถัดไปเข้าหน่วยความจำ (`IEX (New-Object Net.WebClient).DownloadString(...)`)
3. ใช้ WMI / service / scheduled task เพื่อรันซ้ำ หรือรันบนเครื่องอื่น (T1047, T1569, T1053)
4. บนคลาวด์: ใช้ Run Command / SSM / Cloud Shell (T1651) หรือ container exec (T1609); บน ESXi ใช้ `esxcli`/`vim-cmd` (T1675)

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| Process + command line | `DeviceProcessEvents`, `SecurityEvent` (4688) |
| PowerShell script block | `Event` (Microsoft-Windows-PowerShell/Operational 4104) |
| Service / Scheduled task | `DeviceRegistryEvents`, `DeviceEvents`, `SecurityEvent` (4697, 4698) |
| Cloud admin command | `AzureActivity`, `AWSCloudTrail` |

---

## T1059 Command and Scripting Interpreter

### T1059.001 PowerShell

**วิธีทำงาน**
PowerShell เข้าถึง .NET, WMI และ Windows API ได้โดยไม่ต้องวางไฟล์ ผู้โจมตีใช้ `-EncodedCommand` เพื่อซ่อนคำสั่ง, `-WindowStyle Hidden`, `-ExecutionPolicy Bypass` และดาวน์โหลดโค้ดเข้า memory ด้วย `DownloadString` + `IEX`

**สัญญาณ**
- command line มี encoded command, download cradle หรือ `FromBase64String`
- PowerShell ถูกเรียกจาก Office, browser, `wmiprvse.exe`, `mshta.exe`
- Script block (4104) ที่มี `AmsiUtils`, `VirtualAlloc`, `Invoke-Mimikatz`, `System.Reflection.Assembly::Load`

**KQL — PowerShell ที่มีรูปแบบการโจมตี**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| where ProcessCommandLine matches regex @"(?i)(\s-e(c|nc|ncodedcommand)?\s|frombase64string|iex\s*\(|invoke-expression|downloadstring|downloadfile|net\.webclient|invoke-webrequest|start-bitstransfer|\s-w(indowstyle)?\s+h(idden)?|-ep\s+bypass|-executionpolicy\s+bypass)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**KQL — Script block ที่น่าสงสัย (ต้องเปิด 4104 และเก็บ Operational log)**
```kql
Event
| where TimeGenerated > ago(1d)
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| where RenderedDescription has_any ("AmsiUtils", "amsiInitFailed", "VirtualAlloc", "Invoke-Mimikatz", "Reflection.Assembly]::Load",
                                    "Invoke-Shellcode", "DownloadString", "System.Net.Sockets.TCPClient")
| project TimeGenerated, Computer, RenderedDescription
```

**วิธีรับมือ**
1. ถอด base64 (`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(...))`) ใน sandbox เพื่อดูคำสั่งจริง — ห้ามรันบนเครื่องจริง
2. ดึง URL/IP จากคำสั่ง → ตรวจว่าดาวน์โหลดสำเร็จหรือไม่ (`DeviceNetworkEvents` ช่วงเวลาเดียวกัน)
3. ดู process tree ทั้งต้น (parent) และปลาย (child) เพื่อหาจุดเริ่มต้นและสิ่งที่ถูกสร้างต่อ
4. ถ้ามี payload ถูกโหลด: isolate เครื่อง, ตรวจ persistence ([Tactic 05](05-persistence.md))
5. Block URL/IP/hash และค้นหาทั่วองค์กรด้วย command line รูปแบบเดียวกัน

**ป้องกันระยะยาว**
- เปิด Script Block Logging, Module Logging, AMSI (M1049)
- Constrained Language Mode ผ่าน WDAC สำหรับผู้ใช้ทั่วไป, ถอด PowerShell v2 (M1042)
- จำกัดผู้ที่รัน PowerShell ได้ด้วย AppLocker/WDAC บนเครื่องที่ไม่จำเป็น (M1038)

**False positive** — SCCM/Intune, เครื่องมือ monitoring และ script ของทีม IT มักใช้ `-EncodedCommand` → ทำ allowlist ตาม parent process + hash ของ script

### T1059.003 Windows Command Shell / T1059.004 Unix Shell

**วิธีทำงาน** — `cmd.exe /c` ต่อคำสั่งหลายคำสั่ง, ใช้ `^` และตัวแปร environment พรางคำสั่ง; บน Linux ใช้ `curl ... | sh` หรือ `bash -i >& /dev/tcp/...` (reverse shell)

**KQL — reverse shell และ download-pipe-to-shell บน Linux (MDE for Linux)**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine matches regex @"(curl|wget)[^|;]*\|\s*(ba|da|z)?sh"
     or ProcessCommandLine has_any ("/dev/tcp/", "bash -i", "nc -e", "ncat -e", "mkfifo", "socat exec:")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**KQL — cmd ที่ถูกพรางด้วย caret หรือ set/call**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "cmd.exe"
| extend Carets = countof(ProcessCommandLine, "^")
| where Carets > 5 or ProcessCommandLine matches regex @"(?i)%[a-z]+:~\d+,\d+%"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**วิธีรับมือ** — เหมือน PowerShell: ดู tree, หาปลายทาง network, isolate ถ้ามี payload; สำหรับ Linux ตรวจ `~/.bash_history`, crontab, systemd unit และ `authorized_keys` เพิ่ม

---

## T1204 User Execution

**วิธีทำงาน** — หลอกให้ผู้ใช้เปิดไฟล์ (T1204.002), คลิกลิงก์ (T1204.001), หรือในแคมเปญ ClickFix ล่าสุดคือหลอกให้ **copy คำสั่งไปวางใน Run dialog / Terminal** เอง (T1204.004 Malicious Copy and Paste)

**สัญญาณ** — `explorer.exe` เป็น parent ของ `powershell.exe`/`mshta.exe` พร้อม command line ที่มี URL (มักมาจากการวางใน Win+R)

**KQL — คำสั่งที่ผู้ใช้วางใน Run dialog (ClickFix)**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\Explorer\RunMRU"
| where RegistryValueData has_any ("powershell", "mshta", "curl", "http", "iex", "cmd /c", "msiexec")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryValueData
```

**วิธีรับมือ** — สัมภาษณ์ผู้ใช้ว่าทำตามคำแนะนำจากเว็บไหน (เพื่อ block โดเมน), ตรวจ child process และ network ของคำสั่งนั้น, จัดการเหมือน T1059

**ป้องกันระยะยาว** — ASR rules, SmartScreen, ปิด Run dialog ผ่าน GPO สำหรับผู้ใช้ที่ไม่จำเป็น, awareness เรื่อง "fake CAPTCHA / fix it" (M1017)

---

## T1047 Windows Management Instrumentation

**วิธีทำงาน** — ใช้ `wmic process call create` หรือ `Invoke-CimMethod Win32_Process Create` เพื่อรันคำสั่งบนเครื่องตัวเองหรือเครื่องอื่น (ไม่ต้องสร้าง service), Impacket `wmiexec.py` ใช้วิธีนี้

**KQL — WMI provider สร้าง shell (รวมรูปแบบ wmiexec)**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe")
| extend ImpacketPattern = ProcessCommandLine matches regex @"(?i)\\\\127\.0\.0\.1\\(ADMIN|C)\$\\__\d"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ImpacketPattern
```

**วิธีรับมือ** — หาเครื่องต้นทางจาก `DeviceLogonEvents` (LogonType Network) ช่วงเวลาเดียวกัน แล้วตรวจเครื่องต้นทางด้วย; ถ้าเป็น Impacket ถือเป็น lateral movement ([Tactic 11](11-lateral-movement.md)) ระดับ High

**ป้องกันระยะยาว** — ASR *Block process creations originating from PSExec and WMI commands*, จำกัด DCOM/WMI จาก workstation ถึง workstation (M1030)

---

## T1569.002 Service Execution

**วิธีทำงาน** — สร้าง service ชั่วคราวให้รันคำสั่งด้วยสิทธิ์ SYSTEM (PsExec สร้าง `PSEXESVC`, Impacket `smbexec`/`psexec.py` สร้าง service ชื่อสุ่ม)

**KQL — service ใหม่ที่ ImagePath ชี้ไป shell หรือโฟลเดอร์ชั่วคราว**
```kql
DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"\SYSTEM\CurrentControlSet\Services\" and RegistryValueName =~ "ImagePath"
| where RegistryValueData has_any ("cmd.exe", "powershell", "%COMSPEC%", @"\Temp\", @"\Users\Public\", @"\ProgramData\", "rundll32", @"\\127.0.0.1\")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueData
```

**วิธีรับมือ** — ระบุเครื่องต้นทาง (service ถูกสร้างผ่าน SMB/RPC จากเครื่องอื่นเกือบเสมอ), หยุดและลบ service, reset credential ของบัญชีที่ใช้สร้าง

---

## T1053 Scheduled Task/Job (การรัน)

รายละเอียด persistence อยู่ใน [Tactic 05](05-persistence.md#t1053005-scheduled-task) ส่วนนี้เน้นการใช้ scheduled task เพื่อ **รันทันที/รันระยะไกล** (`schtasks /create /s <remote> ... /ru SYSTEM` แล้ว `/run`)

**KQL — สร้าง task บนเครื่องอื่น**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create" and ProcessCommandLine has "/s "
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

## T1651 Cloud Administration Command / T1609 Container Administration Command

**วิธีทำงาน** — เมื่อได้สิทธิ์คลาวด์ ผู้โจมตีใช้ Azure *Run Command*, AWS SSM `SendCommand` หรือ `kubectl exec` เพื่อรันคำสั่งใน VM/container โดยไม่ต้องมีรหัสผ่านของเครื่อง

**KQL — Azure Run Command / AWS SSM**
```kql
union
  (AzureActivity
   | where TimeGenerated > ago(7d)
   | where OperationNameValue has_any ("MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION", "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE")
   | project TimeGenerated, Actor = Caller, Action = OperationNameValue, Target = _ResourceId, SourceIP = CallerIpAddress),
  (AWSCloudTrail
   | where TimeGenerated > ago(7d)
   | where EventSource == "ssm.amazonaws.com" and EventName in ("SendCommand", "StartSession")
   | project TimeGenerated, Actor = UserIdentityArn, Action = EventName, Target = RequestParameters, SourceIP = SourceIpAddress)
```

**วิธีรับมือ** — ยืนยันกับเจ้าของ workload, ถ้าไม่ได้รับอนุญาต: ระงับ identity ที่สั่ง, ตรวจ output/command ที่ถูกรัน, snapshot disk เพื่อ forensic

**ป้องกันระยะยาว** — จำกัด role ที่ใช้ Run Command/SSM ด้วย PIM/JIT, แจ้งเตือนทุกครั้งที่ใช้ใน production

---

## T1698 / T1699 Prompt Injection (ใหม่ใน v20)

**วิธีทำงาน**
- **Direct (T1699)** — ผู้โจมตีพิมพ์คำสั่งเข้า chatbot/agent ขององค์กรโดยตรงเพื่อให้ข้ามข้อจำกัดหรือเรียก tool ที่อันตราย
- **Indirect (T1698)** — ฝังคำสั่งไว้ในเนื้อหาที่ AI จะอ่าน (อีเมล, เอกสาร SharePoint, หน้าเว็บ, ticket) เมื่อ AI agent ประมวลผลเนื้อหานั้น จะทำตามคำสั่ง เช่น ส่งข้อมูลออก ([T1700](14-exfiltration.md#t1700-ai-enabled-exfiltration))

**วิธีตรวจสอบ** — ยังไม่มีตาราง/คอลัมน์มาตรฐานที่ใช้ได้ทุก tenant จึงไม่ให้ KQL ตายตัว แนวทาง:
- เปิด audit ของ AI app (เช่น Microsoft Purview audit สำหรับ Copilot interaction) และส่งเข้า SIEM
- เฝ้าระวัง agent ที่เรียก tool เขียน/ส่งข้อมูล (send mail, create share link, HTTP request) ไปยังปลายทางภายนอก
- ตรวจเนื้อหาที่มี hidden text (ตัวอักษรสีขาว, zero-width, HTML comment) ในเอกสารที่ AI ใช้เป็น knowledge source

**วิธีรับมือ** — หยุด agent/connector ที่เกี่ยวข้อง, ระบุเนื้อหาต้นทางที่มีคำสั่งฝัง แล้วลบหรือกักไว้, ตรวจ action ทั้งหมดที่ agent ทำหลังอ่านเนื้อหานั้น, rotate token ของ connector

**ป้องกันระยะยาว** — ให้ agent มีสิทธิ์น้อยที่สุด, ต้องมีมนุษย์อนุมัติ action ที่ส่งข้อมูลออกหรือเปลี่ยนแปลงระบบ, แยกเนื้อหาจากภายนอกออกจาก instruction, จำกัด egress ของ agent

---

## Checklist ตอบสนองระดับ Tactic

- [ ] สร้าง process tree ตั้งแต่จุดเริ่ม (อีเมล/เว็บ/ช่องโหว่) จนถึง payload สุดท้าย
- [ ] ถอดรหัส command line / script ทั้งหมดใน sandbox และดึง IOC
- [ ] ตรวจว่ามีการเชื่อมต่อออกจากเครื่องหลังรันคำสั่งหรือไม่ (C2 / download)
- [ ] Isolate เครื่องถ้า payload ทำงานสำเร็จ
- [ ] ค้นหาคำสั่ง/hash เดียวกันทั่วองค์กร และตรวจ persistence ที่อาจถูกสร้าง
