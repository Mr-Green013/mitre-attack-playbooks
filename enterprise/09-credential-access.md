# 09. Credential Access (TA0006)

## เป้าหมายของผู้โจมตี

ขโมยรหัสผ่าน, NTLM hash, Kerberos ticket, session cookie, token และกุญแจ เพื่อสวมรอยผู้ใช้ที่มีสิทธิ์สูงกว่าและเคลื่อนที่ไปยังระบบอื่น
นี่คือ **choke point** สำคัญ: ถ้าป้องกันขั้นนี้ได้ ผู้โจมตีจะติดอยู่บนเครื่องแรก

## ลำดับการทำงานที่พบบ่อย

| ที่มาของ credential | เทคนิค |
|---|---|
| Memory ของ LSASS | T1003.001 (Mimikatz, comsvcs MiniDump, procdump, nanodump) |
| ฐานข้อมูล AD | T1003.003 NTDS.dit, T1003.006 DCSync |
| Kerberos | T1558.003 Kerberoasting, T1558.004 AS-REP Roasting, Golden/Silver ticket |
| การเดารหัสผ่าน | T1110.003 Password Spraying, T1110.004 Credential Stuffing |
| MFA | T1621 MFA fatigue, T1111 MFA interception, T1557 AiTM |
| Session / token | T1539 Steal Web Session Cookie, T1528 Steal Application Access Token |
| ไฟล์ / registry / browser | T1552 Unsecured Credentials, T1555 Password Stores |
| ใบรับรอง | T1649 ADCS abuse (ESC1–ESC8) |

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| การเข้าถึง LSASS | `DeviceEvents` (OpenProcessApiCall), `DeviceProcessEvents` |
| Kerberos / DCSync | `SecurityEvent` (4768, 4769, 4662), `IdentityLogonEvents`, `AlertInfo` (MDI) |
| Sign-in / MFA | `SigninLogs`, `AADNonInteractiveUserSignInLogs` |
| Failed logon on-prem | `IdentityLogonEvents`, `SecurityEvent` (4625, 4771) |

---

## T1003.001 LSASS Memory

**วิธีทำงาน** — ด้วยสิทธิ์ admin/SYSTEM ผู้โจมตีอ่าน memory ของ `lsass.exe` ซึ่งเก็บ NTLM hash, Kerberos ticket และบางครั้งรหัสผ่าน plaintext ของทุกคนที่ล็อกอินอยู่ แล้วนำไปทำ Pass-the-Hash/Ticket

**สัญญาณ**
- process ที่ไม่ใช่ security software เปิด handle ไปที่ `lsass.exe`
- `rundll32 comsvcs.dll, MiniDump`, `procdump -ma lsass`, ไฟล์ `.dmp` ที่มีคำว่า lsass
- Task Manager สร้าง dump ของ lsass

**KQL — เปิด handle ไปที่ LSASS**
```kql
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "svchost.exe", "csrss.exe",
                                        "wininit.exe", "lsm.exe", "WmiPrvSE.exe", "MRT.exe", "taskmgr.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, AdditionalFields
```

**KQL — เครื่องมือ dump ที่พบบ่อย**
```kql
union
  (DeviceProcessEvents
   | where Timestamp > ago(1d)
   | where (ProcessCommandLine has "comsvcs" and ProcessCommandLine has_any ("MiniDump", "#24"))
        or (ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("-ma", "procdump", "dump", "createdump"))
        or ProcessCommandLine has_any ("sekurlsa::", "lsadump::", "kerberos::", "privilege::debug", "nanodump", "pypykatz")
   | project Timestamp, DeviceName, AccountName, Detail = ProcessCommandLine),
  (DeviceFileEvents
   | where Timestamp > ago(1d)
   | where ActionType == "FileCreated" and FileName has "lsass" and FileName endswith ".dmp"
   | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Detail = FolderPath)
```

**วิธีรับมือ**
1. **High/Critical** — isolate เครื่องทันที
2. ระบุบัญชีทุกบัญชีที่มี session บนเครื่องนั้นในช่วง 7 วัน (`DeviceLogonEvents`) → **ถือว่า credential รั่วทั้งหมด**
3. Reset password บัญชีเหล่านั้น เริ่มจากบัญชีสิทธิ์สูงและ service account; ถ้ามี Domain Admin ล็อกอินอยู่ → เตรียม Tier 0 recovery
4. ไล่ตรวจการใช้ credential เหล่านั้นจากเครื่องอื่น (Pass-the-Hash ใน [Tactic 11](11-lateral-movement.md))
5. ลบไฟล์ dump และเครื่องมือ, หาช่องทางที่ได้สิทธิ์ admin

**ป้องกันระยะยาว** — Credential Guard, LSA Protection (`RunAsPPL`), ASR *Block credential stealing from LSASS*, ห้าม Domain Admin ล็อกอิน workstation (tiering), LAPS (M1043, M1026)

**False positive** — security/backup/monitoring agent บางตัวเปิด handle ไป LSASS → allowlist ตาม path + signer

---

## T1003.006 DCSync และ T1003.003 NTDS

**วิธีทำงาน**
- **DCSync** — บัญชีที่มีสิทธิ์ `Replicating Directory Changes (All)` ขอข้อมูล replication จาก DC จากเครื่องใดก็ได้ ได้ hash ของทุกบัญชีรวม `krbtgt`
- **NTDS** — copy ไฟล์ `ntds.dit` + SYSTEM hive ผ่าน `ntdsutil ifm`, volume shadow copy หรือ backup

**KQL — DCSync จากบัญชีที่ไม่ใช่ DC (ต้องเปิด audit 4662 + SACL)**
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4662
| where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c")
| where not(SubjectUserName endswith "$")
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, ObjectName, Properties
```

**KQL — Defender for Identity alert**
```kql
AlertInfo
| where Timestamp > ago(7d)
| where Title has_any ("DCSync", "replication of directory services", "Golden Ticket", "Kerberoasting", "AS-REP", "NTDS")
| join kind=inner AlertEvidence on AlertId
| project Timestamp, Title, Severity, EntityType, AccountName, DeviceName, RemoteIP
```

**KQL — NTDS extraction**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "ntdsutil.exe" and ProcessCommandLine has_any ("ifm", "create full"))
     or (ProcessCommandLine has "ntds.dit")
     or (FileName =~ "vssadmin.exe" and ProcessCommandLine has "create shadow")
     or (FileName =~ "reg.exe" and ProcessCommandLine has "save" and ProcessCommandLine has_any (@"HKLM\SYSTEM", @"HKLM\SAM", @"HKLM\SECURITY"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**วิธีรับมือ** — **Critical (โดเมนถูกยึด)**
1. Disable บัญชีที่ทำ DCSync และหาที่มาของสิทธิ์ (ใครให้ replication rights)
2. Reset `krbtgt` **2 รอบ** โดยเว้นระยะเวลาเท่ากับ max ticket lifetime (ค่าเริ่มต้น 10 ชม.) ระหว่างรอบ
3. Reset ทุกบัญชีสิทธิ์สูง, service account และ computer account ของ DC
4. ตรวจ persistence ระดับโดเมน: AdminSDHolder, GPO, บัญชีใหม่ใน Domain Admins, SID History, ADCS template

**False positive** — Microsoft Entra Connect (`MSOL_*` / `Sync_*`) ทำ replication โดยปกติ → allowlist บัญชีนั้น และต้องปกป้องเครื่อง Entra Connect เป็น Tier 0

---

## T1558 Steal or Forge Kerberos Tickets

### T1558.003 Kerberoasting

**วิธีทำงาน** — ผู้ใช้โดเมนคนใดก็ขอ service ticket (TGS) ของบัญชีที่มี SPN ได้ ticket นั้นเข้ารหัสด้วย hash ของ service account ผู้โจมตีนำไป crack แบบ offline ด้วย Hashcat (ใช้ RC4 = `0x17` จะ crack ง่ายกว่า)

**KQL — ขอ TGS แบบ RC4 จำนวนมาก**
```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$" and ServiceName !~ "krbtgt"
| summarize Services = dcount(ServiceName), ServiceList = make_set(ServiceName, 20)
    by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
| where Services >= 5
```

### T1558.004 AS-REP Roasting

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4768
| where PreAuthType == "0"
| project TimeGenerated, Computer, TargetUserName, IpAddress, TicketEncryptionType
```

**วิธีรับมือ** — Reset password ของ service account ที่ถูกขอ ticket (ทำให้ hash ที่ crack ได้ใช้ไม่ได้), ตรวจ logon ของ service account เหล่านั้นจากที่แปลก, ตรวจเครื่องต้นทาง (`IpAddress`)

**ป้องกันระยะยาว** — gMSA หรือรหัสผ่าน service account ยาว ≥ 25 ตัวอักษร, ปิด RC4 (บังคับ AES), ลบ SPN ที่ไม่ใช้, เปิด Kerberos pre-auth ทุกบัญชี, ตั้ง honeypot SPN account ไว้จับ

---

## T1110.003 Password Spraying

**วิธีทำงาน** — ลองรหัสผ่านยอดนิยม 1–2 ตัว (`Summer2026!`, `Company@123`) กับบัญชีจำนวนมาก ช้าพอไม่ให้ติด lockout

**KQL — Entra ID**
```kql
SigninLogs
| where TimeGenerated > ago(1d)
| summarize Failed = countif(ResultType in ("50126", "50053")), Success = countif(ResultType == "0"),
            Users = dcount(UserPrincipalName), SuccessUsers = make_set_if(UserPrincipalName, ResultType == "0", 20)
    by IPAddress, bin(TimeGenerated, 1h)
| where Users > 10 and Failed > 10
| order by Users desc
```

**KQL — on-prem (Defender for Identity)**
```kql
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| summarize Users = dcount(AccountUpn), Attempts = count(), Protocols = make_set(Protocol) by IPAddress, DeviceName, bin(Timestamp, 1h)
| where Users > 10
```

**วิธีรับมือ** — บัญชีใน `SuccessUsers` คือบัญชีที่ถูกเจาะ: reset + revoke sessions + ตรวจกิจกรรมหลัง sign-in; block IP; บังคับ MFA ให้บัญชีที่ยังไม่มี

**ป้องกันระยะยาว** — MFA ทุกบัญชี, บล็อก legacy auth, Entra Password Protection (banned passwords รวมชื่อองค์กร), Smart Lockout

---

## T1621 Multi-Factor Authentication Request Generation (MFA fatigue)

**วิธีทำงาน** — มีรหัสผ่านแล้ว จึงส่ง push MFA ซ้ำๆ (มักตอนกลางคืน) จนผู้ใช้กดอนุมัติ หรือโทรหลอกว่าเป็น IT ให้กดอนุมัติ

**KQL**
```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("500121", "50074", "50076")
| summarize Prompts = count(), FirstPrompt = min(TimeGenerated), LastPrompt = max(TimeGenerated), IPs = make_set(IPAddress, 10)
    by UserPrincipalName, bin(TimeGenerated, 30m)
| where Prompts >= 5
| join kind=leftouter (
    SigninLogs | where TimeGenerated > ago(1d) and ResultType == "0"
    | summarize LastSuccess = max(TimeGenerated) by UserPrincipalName
  ) on UserPrincipalName
| extend ApprovedAfterSpam = LastSuccess > FirstPrompt
```

**วิธีรับมือ** — ติดต่อผู้ใช้ทันที; ถ้า `ApprovedAfterSpam` เป็นจริงให้ถือว่าบัญชีถูกยึด: reset password, revoke sessions, ตรวจ MFA method ใหม่และ inbox rule

**ป้องกันระยะยาว** — number matching + additional context (ค่าเริ่มต้นของ Microsoft Authenticator ปัจจุบัน), phishing-resistant MFA สำหรับบัญชีสำคัญ, ให้ผู้ใช้รายงาน push ที่ไม่ได้ขอ

---

## T1539 / T1557 AiTM และการขโมย Session Cookie

**วิธีทำงาน** — หน้า phishing แบบ reverse proxy ส่งต่อการล็อกอินจริงไปที่ Microsoft แล้วเก็บ session cookie ที่ได้หลังผ่าน MFA ผู้โจมตีนำ cookie ไปใช้จากเครื่องตัวเองได้ทันที (MFA ไม่ช่วย ถ้าไม่ใช่แบบ phishing-resistant) ; infostealer ก็ขโมย cookie จาก browser ได้เช่นกัน

**KQL — session เดียวกันถูกใช้จากหลายประเทศ/ASN**
```kql
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == "0"
| where isnotempty(SessionId)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Countries = dcount(Country), CountryList = make_set(Country), IPs = make_set(IPAddress, 10),
            Apps = make_set(AppDisplayName, 10)
    by UserPrincipalName, SessionId
| where Countries > 1
```

**วิธีรับมือ** — revoke sessions (refresh token ทั้งหมด), reset password, ตรวจ MFA method / device / inbox rule / OAuth consent ที่ถูกเพิ่ม, ใช้ query คลิกลิงก์ใน [T1566.002](03-initial-access.md#t1566002-spearphishing-link) หาเหยื่อรายอื่นของแคมเปญเดียวกัน

**ป้องกันระยะยาว** — Phishing-resistant MFA (FIDO2/Passkey/WHfB), Conditional Access ต้องการ compliant/hybrid-joined device, Token Protection, sign-in frequency ที่สั้นลงสำหรับแอปสำคัญ

---

## T1552 Unsecured Credentials

**วิธีทำงาน** — ค้นหารหัสผ่านในไฟล์ (`findstr /si password`, Snaffler, TruffleHog) (T1552.001), registry (T1552.002), shell history, private key (T1552.004), Group Policy Preferences `cpassword` (T1552.006), และ Cloud Instance Metadata (`169.254.169.254`) (T1552.005)

**KQL — ค้นหารหัสผ่านในไฟล์/registry**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName in~ ("findstr.exe", "powershell.exe", "pwsh.exe") and ProcessCommandLine has_any ("password", "passwd", "pwd=", "cpassword", "credential")
         and ProcessCommandLine has_any ("/s", "-Recurse", "Select-String", "findstr"))
     or (FileName =~ "reg.exe" and ProcessCommandLine has "query" and ProcessCommandLine has_any ("password", "Winlogon"))
     or ProcessCommandLine has_any ("Snaffler", "SharpHound", "LaZagne", "trufflehog")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**KQL — process แปลกเรียก Cloud metadata endpoint**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIP == "169.254.169.254"
| where InitiatingProcessFileName in~ ("curl", "wget", "python", "python3", "powershell.exe", "pwsh", "bash", "sh", "curl.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

**วิธีรับมือ** — ระบุไฟล์/ค่าที่ถูกอ่าน, rotate credential ที่พบทั้งหมด (ไม่ใช่แค่ลบไฟล์), สำหรับ cloud role ให้ revoke session ของ role และตรวจ API call ที่ใช้ credential นั้น

**ป้องกันระยะยาว** — secret manager (Key Vault, Secrets Manager), ลบ GPP password, IMDSv2 บังคับ (AWS), secret scanning ใน file share และ repo

---

## Checklist ตอบสนองระดับ Tactic

- [ ] ทำรายการ credential ที่อาจรั่ว (บัญชีที่ล็อกอินบนเครื่อง, service account, secret ในไฟล์, token)
- [ ] Reset/rotate ตามลำดับ: Tier 0 → admin → service account → ผู้ใช้ทั่วไป
- [ ] Revoke session/refresh token ของบัญชีคลาวด์ที่เกี่ยวข้อง
- [ ] ถ้า DC/krbtgt เกี่ยวข้อง: ทำ krbtgt reset 2 รอบตามแผน Tier 0 recovery
- [ ] ตรวจการใช้ credential ที่รั่วหลังเวลาเกิดเหตุ (lateral movement, cloud sign-in)
