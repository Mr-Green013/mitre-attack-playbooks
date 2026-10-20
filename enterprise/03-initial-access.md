# 03. Initial Access (TA0001)

## เป้าหมายของผู้โจมตี

ได้จุดยืนแรก (foothold) ในเครือข่ายหรือ tenant คลาวด์ — โค้ดที่รันได้บนเครื่องหนึ่งเครื่อง หรือบัญชีที่ล็อกอินได้หนึ่งบัญชี
ทุกเหตุการณ์ร้ายแรงเริ่มที่ขั้นนี้ การตรวจจับได้ที่นี่ตัดวงจรได้ถูกที่สุด

## ลำดับการทำงานที่พบบ่อย

| ช่องทาง | ตัวอย่าง |
|---|---|
| อีเมล / ข้อความ | ไฟล์แนบ ISO/LNK/HTML, ลิงก์ AiTM, Teams external chat |
| ระบบที่เปิดสู่อินเทอร์เน็ต | ช่องโหว่ VPN/Firewall/Exchange/Web app (มักเป็น CVE ใน KEV) |
| บัญชีที่ถูกต้อง | รหัสผ่านจาก infostealer หรือ password spray เข้า VPN/M365 |
| Remote service ที่เปิดทิ้งไว้ | RDP/SSH/Citrix ที่ไม่มี MFA |
| Supply chain / คู่ค้า | อัปเดตซอฟต์แวร์ที่ถูกฝังโค้ด, MSP/vendor ที่มีสิทธิ์เข้าระบบ |
| ทางกายภาพ | USB (T1091), อุปกรณ์แปลกปลอม (T1200), Wi-Fi (T1669) |

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| อีเมลและการคลิก | `EmailEvents`, `EmailAttachmentInfo`, `UrlClickEvents` |
| Process ลูกของ Office / Web server | `DeviceProcessEvents` |
| Sign-in จากภายนอก | `SigninLogs`, `AADNonInteractiveUserSignInLogs` |
| Inbound connection ไปที่ RDP/SSH | `DeviceNetworkEvents`, `CommonSecurityLog` |

---

## T1566 Phishing

### T1566.001 Spearphishing Attachment

**วิธีทำงาน**
ส่งไฟล์แนบที่หลบ Mark-of-the-Web: ไฟล์ ISO/IMG/VHD ที่ข้างในมี LNK + DLL, ไฟล์ OneNote, HTML smuggling หรือ ZIP ที่มีรหัสผ่าน เมื่อผู้ใช้เปิด LNK จะเรียก `rundll32`/`mshta`/`powershell` เพื่อรัน payload

**สัญญาณ**
- ไฟล์แนบนามสกุลเสี่ยงถูกส่งถึงกล่องจดหมาย (Delivered)
- Office / Outlook / Explorer สร้าง process ลูกเป็น script interpreter หรือ LOLBin
- มีการ mount ISO แล้วรันไฟล์จาก drive letter ใหม่

**KQL — ไฟล์แนบเสี่ยงที่ส่งถึงผู้ใช้**
```kql
let riskyExt = dynamic(["iso", "img", "vhd", "vhdx", "lnk", "hta", "js", "jse", "vbs", "vbe", "wsf", "one", "chm", "html", "htm", "svg"]);
EmailAttachmentInfo
| where Timestamp > ago(1d)
| extend Ext = tolower(tostring(split(FileName, ".")[-1]))
| where Ext in (riskyExt)
| join kind=inner (EmailEvents | where Timestamp > ago(1d) | where DeliveryAction == "Delivered") on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, FileName, FileType, SHA256, ThreatTypes
```

**KQL — Office/Outlook สร้าง process ที่ไม่ควรสร้าง**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe", "msaccess.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                      "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
```

### T1566.002 Spearphishing Link

**วิธีทำงาน** — ลิงก์ไปหน้า login ปลอมแบบ AiTM (Evilginx, Tycoon 2FA) ที่ขโมยทั้งรหัสผ่านและ session cookie หลังผ่าน MFA หรือลิงก์ดาวน์โหลด payload จาก OneDrive/SharePoint ปลอม

**KQL — คลิกลิงก์แล้วมี sign-in จาก IP อื่นภายใน 30 นาที (รูปแบบ AiTM)**
```kql
let clicks = UrlClickEvents
| where Timestamp > ago(1d)
| where ActionType in ("ClickAllowed", "ClickedThrough") or IsClickedThrough == true
| project ClickTime = Timestamp, AccountUpn = tolower(AccountUpn), Url, ClickIP = IPAddress;
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == "0"
| project SigninTime = TimeGenerated, AccountUpn = tolower(UserPrincipalName), SigninIP = IPAddress,
          AppDisplayName, Country = tostring(LocationDetails.countryOrRegion)
| join kind=inner clicks on AccountUpn
| where SigninTime between (ClickTime .. (ClickTime + 30m))
| where SigninIP != ClickIP
| project ClickTime, SigninTime, AccountUpn, Url, ClickIP, SigninIP, Country, AppDisplayName
```

**วิธีรับมือ (T1566 ทั้งหมด)**
1. **Scope อีเมล** — ใช้ Threat Explorer หา message เดียวกัน (sender, subject, hash, URL) แล้ว soft delete จากทุกกล่อง
2. **ใครเปิด/คลิก** — ใช้ query ด้านบนหาผู้ใช้ที่เปิดไฟล์หรือคลิก
3. **ถ้ามี process ลูกเกิดขึ้น** — isolate เครื่อง, เก็บ investigation package, ไล่ดู [Execution](04-execution.md) และ [Persistence](05-persistence.md) บนเครื่องนั้น
4. **ถ้ากรอกรหัสผ่าน** — reset password, revoke sessions, ตรวจ MFA method และ inbox rule ที่ถูกเพิ่ม ([T1114.003](12-collection.md))
5. Block sender, domain, URL, hash ที่ Tenant Allow/Block List และ MDE indicators

**ป้องกันระยะยาว**
- บล็อกนามสกุลเสี่ยงที่ mail gateway, Safe Attachments / Safe Links (M1049, M1021)
- ASR: *Block all Office applications from creating child processes*, *Block execution of potentially obfuscated scripts*
- Phishing-resistant MFA และ Conditional Access ที่ต้องใช้ compliant device (ทำให้ cookie ที่ขโมยไปใช้ไม่ได้)
- ปิด macro จากอินเทอร์เน็ต (ค่าเริ่มต้นของ M365 ปัจจุบัน) และ auto-mount ISO ถ้าไม่ใช้

**False positive** — add-in ของ Office ที่เรียก `cmd.exe` (เช่น ระบบเอกสารบางยี่ห้อ), ผู้ใช้ทำงานผ่าน VPN หลังคลิก (IP เปลี่ยนแต่ไม่ใช่ AiTM)

---

## T1190 Exploit Public-Facing Application

**วิธีทำงาน**
โจมตีช่องโหว่ของระบบที่เปิดสู่อินเทอร์เน็ต — VPN/firewall (Ivanti, Fortinet, Palo Alto, Citrix), Exchange, web app (SQLi, deserialization, file upload) — แล้ววาง web shell หรือรันคำสั่งด้วยสิทธิ์ของ service ทันที อุปกรณ์ edge มักไม่มี EDR จึงตรวจจับยาก

**สัญญาณ**
- Process ของ web server (`w3wp.exe`, `java.exe`, `httpd`) สร้าง shell หรือรันคำสั่งสำรวจระบบ
- ไฟล์ `.aspx/.jsp/.php` ใหม่ใน web root (ดู [T1505.003](05-persistence.md))
- อุปกรณ์ edge มีการเชื่อมต่อออกไปยัง IP แปลก, มี admin login ใหม่, config เปลี่ยน

**KQL — web server รันคำสั่ง**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "tomcat9.exe", "php-cgi.exe", "UMWorkerProcess.exe")
     or (InitiatingProcessFileName in~ ("java.exe", "node.exe") and InitiatingProcessCommandLine has_any ("tomcat", "catalina", "jboss", "weblogic", "confluence", "server.js"))
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe", "nltest.exe",
                      "certutil.exe", "bitsadmin.exe", "curl.exe", "systeminfo.exe", "ipconfig.exe", "sh", "bash")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

**วิธีรับมือ**
1. ระบุช่องโหว่ (CVE) จาก request log ช่วงเวลาเดียวกัน — ตรวจ vendor advisory ว่ามี IOC/integrity checker ให้หรือไม่
2. **ถือว่าระบบถูกยึดแล้ว** — แยกเครื่องออกจากเครือข่ายภายใน (ยังให้บริการผ่าน WAF ได้ถ้าจำเป็นทางธุรกิจ)
3. ค้นหา web shell, บัญชีใหม่, scheduled task, และ credential ที่เก็บบนเครื่อง (service account, config file) → rotate ทั้งหมด
4. สำหรับอุปกรณ์ edge: เก็บ log/config ก่อน, ทำ factory reset ตามคำแนะนำ vendor, อัปเดตเป็นเวอร์ชันที่แก้แล้ว, rotate credential ของ admin และ VPN user
5. ตรวจ lateral movement จากเครื่องนี้ ([Tactic 11](11-lateral-movement.md))

**ป้องกันระยะยาว**
- SLA แพตช์ระบบ internet-facing (เช่น CISA KEV ≤ 7 วัน) (M1051)
- WAF, แยก DMZ, application pool รันด้วยบัญชีสิทธิ์ต่ำ (M1048)
- ส่ง log ของอุปกรณ์ edge เข้า SIEM และทำ integrity check เป็นรอบ

**False positive** — งาน deployment/health check ที่เรียก script ผ่าน web server, Exchange (`UMWorkerProcess`) บางเวอร์ชันมี process ลูกปกติ

---

## T1133 External Remote Services และ T1078 Valid Accounts

**วิธีทำงาน**
ใช้บัญชีจริง (จาก infostealer, spray, รหัสผ่าน default) ล็อกอินผ่าน VPN, RDP, Citrix, SSH หรือ M365 โดยตรง พฤติกรรมเหมือนพนักงานจึงตรวจยาก ต้องดูความผิดปกติของบริบท (ประเทศ, อุปกรณ์, เวลา, ความเร็วการเดินทาง)

**KQL — sign-in สำเร็จจากประเทศที่ผู้ใช้ไม่เคยใช้ใน 30 วัน**
```kql
let known = SigninLogs
| where TimeGenerated between (ago(30d) .. ago(1d)) and ResultType == "0"
| summarize by UserPrincipalName, Country = tostring(LocationDetails.countryOrRegion);
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| join kind=leftanti known on UserPrincipalName, Country
| project TimeGenerated, UserPrincipalName, IPAddress, Country, AppDisplayName,
          AuthenticationRequirement, DeviceOS = tostring(DeviceDetail.operatingSystem), RiskLevelDuringSignIn
```

**KQL — RDP/SSH ที่รับการเชื่อมต่อจาก IP สาธารณะ**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort in (3389, 22, 5985, 5986)
| where not(ipv4_is_private(RemoteIP))
| summarize Connections = count(), Sources = make_set(RemoteIP, 20) by DeviceName, LocalPort
```

**วิธีรับมือ**
1. ติดต่อเจ้าของบัญชีผ่านช่องทางอื่น (โทรศัพท์) ว่าเป็นคนล็อกอินจริงหรือไม่
2. ถ้าไม่ใช่: disable บัญชี → reset password → revoke sessions → ลบ MFA method ที่ไม่รู้จัก → ตรวจ device ที่ลงทะเบียนใหม่
3. ไล่ดูกิจกรรมหลัง sign-in: `OfficeActivity`, `AuditLogs`, `CloudAppEvents` (อ่านเมล, ดาวน์โหลดไฟล์, สร้าง inbox rule, เพิ่ม app consent)
4. ถ้า RDP เปิดสู่อินเทอร์เน็ต: ปิดทันทีและให้เข้าผ่าน VPN/ZTNA, ตรวจบัญชี local admin บนเครื่องนั้น
5. ตรวจหา infostealer บนเครื่องผู้ใช้ (ถ้าเป็นแหล่งที่มาของรหัสผ่าน)

**ป้องกันระยะยาว** — MFA ทุกบัญชีรวม VPN (M1032), Conditional Access บล็อก legacy authentication, ไม่เปิด RDP/SSH สู่อินเทอร์เน็ต (M1035), ลบบัญชีที่ไม่ใช้งาน

**False positive** — ผู้ใช้เดินทาง, VPN ส่วนตัว, IP ของผู้ให้บริการมือถือที่ geolocation ผิด

---

## T1195 Supply Chain Compromise

**วิธีทำงาน**
ฝังโค้ดในซอฟต์แวร์หรือ library ก่อนถึงมือองค์กร — อัปเดตซอฟต์แวร์ที่ถูก trojan (เช่น SolarWinds/C0024, 3CX), package บน npm/PyPI ที่ชื่อคล้ายของจริง, หรือ dependency ที่ถูกยึด (T1195.001/.002)

**สัญญาณ** — process ของซอฟต์แวร์ที่เชื่อถือได้เริ่มสร้าง shell หรือติดต่อโดเมนที่ไม่เคยติดต่อ หลังการอัปเดต

**KQL — ซอฟต์แวร์ติดตั้งในเครื่องสร้าง shell ที่พบในเครื่องจำนวนน้อย**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFolderPath startswith @"C:\Program Files"
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe")
| summarize Devices = dcount(DeviceName), FirstSeen = min(Timestamp), Example = take_any(ProcessCommandLine)
    by InitiatingProcessFileName, InitiatingProcessVersionInfoCompanyName, FileName
| where Devices < 5 and FirstSeen > ago(2d)
```

**วิธีรับมือ** — ระบุเวอร์ชันและช่วงเวลาที่ได้รับผลกระทบตาม advisory, ถอนหรือ rollback ซอฟต์แวร์, block IOC, ตรวจทุกเครื่องที่ติดตั้งเวอร์ชันนั้น, rotate credential ที่ซอฟต์แวร์เข้าถึงได้

**ป้องกันระยะยาว** — SBOM และ inventory ของซอฟต์แวร์, pin dependency พร้อม hash, private package registry, จำกัดสิทธิ์ network ของเซิร์ฟเวอร์จัดการ (egress allowlist)

---

## T1199 Trusted Relationship

**วิธีทำงาน** — เข้าผ่านคู่ค้าที่มีสิทธิ์อยู่แล้ว เช่น MSP ที่มี GDAP/delegated admin, vendor ที่มี VPN หรือบัญชี guest ใน tenant

**KQL — sign-in จากบัญชีของ tenant อื่น (guest / partner)**
```kql
SigninLogs
| where TimeGenerated > ago(7d) and ResultType == "0"
| where HomeTenantId != ResourceTenantId
| summarize SignIns = count(), Apps = make_set(AppDisplayName, 10), IPs = make_set(IPAddress, 10)
    by UserPrincipalName, HomeTenantId
| order by SignIns desc
```

**วิธีรับมือ** — ระงับสิทธิ์ของคู่ค้ารายนั้นชั่วคราว, แจ้งคู่ค้าให้ตรวจสอบฝั่งตัวเอง, ทบทวนกิจกรรมทั้งหมดของบัญชีคู่ค้า

**ป้องกันระยะยาว** — ใช้ GDAP แบบ least privilege และมีวันหมดอายุ, Cross-tenant access settings, Access Reviews รายไตรมาส, สัญญาที่กำหนดให้คู่ค้าแจ้งเหตุภายในเวลาที่กำหนด

---

## Checklist ตอบสนองระดับ Tactic

- [ ] ระบุช่องทางเข้า (อีเมล / ช่องโหว่ / บัญชี / คู่ค้า / กายภาพ) และเวลาที่เข้ามาครั้งแรก
- [ ] ปิดช่องทางนั้น: แพตช์, ปิดพอร์ต, reset/revoke บัญชี, block sender/URL
- [ ] หาเครื่องและบัญชีอื่นที่ได้รับผลจากช่องทางเดียวกัน
- [ ] ตรวจ Tactic ถัดไปบนจุดที่ถูกเจาะ: Execution, Persistence, Credential Access
- [ ] ยืนยันว่าไม่มีบัญชี/กุญแจ/อุปกรณ์ใหม่ที่ผู้โจมตีเพิ่มไว้ก่อนปิดเหตุ
