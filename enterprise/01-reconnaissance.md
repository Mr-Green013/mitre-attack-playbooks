# 01. Reconnaissance (TA0043)

## เป้าหมายของผู้โจมตี

รวบรวมข้อมูลขององค์กรก่อนลงมือ: IP/โดเมนที่เปิดสู่อินเทอร์เน็ต, ซอฟต์แวร์และเวอร์ชัน, รายชื่อและอีเมลพนักงาน, ผู้ให้บริการภายนอก และรหัสผ่านที่เคยรั่ว
ข้อมูลเหล่านี้กำหนดว่าผู้โจมตีจะเข้ามาทางไหนใน [Initial Access](03-initial-access.md)

## ลำดับการทำงานที่พบบ่อย

1. **Passive OSINT** — ค้น DNS/WHOIS, Certificate Transparency, Shodan/Censys, LinkedIn, GitHub (ไม่แตะระบบขององค์กร จึงตรวจจับไม่ได้)
2. **Active scanning** — สแกน IP block, พอร์ต, เวอร์ชันซอฟต์แวร์, path บนเว็บ
3. **Identity enumeration** — ตรวจว่าอีเมลไหนมีจริงผ่านหน้า login (เช่น Entra ID) และหารหัสผ่านจาก breach dump
4. **Phishing for information** — หลอกถามข้อมูลหรือรหัสผ่านโดยยังไม่ส่งมัลแวร์
5. ใน v20 มี **T1682 Query Public AI Services** — ใช้ LLM สาธารณะสรุปข้อมูลเป้าหมายหรือหาช่องโหว่ (มองไม่เห็นจากฝั่งองค์กร)

> ขั้นนี้ส่วนใหญ่เกิดนอกเครือข่าย เป้าหมายหลักของฝ่ายป้องกันคือ **ลดสิ่งที่เปิดเผย** และ **จับสัญญาณที่แตะระบบเรา** (scan, enumeration, phishing)

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| การ scan ที่ firewall / WAF | `CommonSecurityLog`, `W3CIISLog` |
| User enumeration / credential validation | `SigninLogs`, `AADNonInteractiveUserSignInLogs` |
| Phishing for information | `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents` |

---

## T1595 Active Scanning

**วิธีทำงาน**
ผู้โจมตีใช้ Masscan/Nmap สแกนช่วง IP ขององค์กร (T1595.001), ใช้ Nuclei/Nessus หาช่องโหว่ (T1595.002) และใช้ ffuf/gobuster เดา path เช่น `/.git/`, `/backup.zip`, `/api/swagger` (T1595.003)

**สัญญาณ**
- IP ภายนอกเดียวกันถูก firewall drop หลายพอร์ตหรือหลายปลายทางในเวลาสั้น
- HTTP 404 จำนวนมากจาก IP เดียว, User-Agent ของเครื่องมือสแกน (`Nuclei`, `sqlmap`, `Nikto`, `zgrab`)

**KQL — scan ที่ firewall**
```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceAction in~ ("deny", "drop", "block", "reject")
| summarize Ports = dcount(DestinationPort), Targets = dcount(DestinationIP), Hits = count()
    by SourceIP, bin(TimeGenerated, 1h)
| where Ports > 20 or Targets > 50
| order by Hits desc
```

**KQL — wordlist scanning บน IIS**
```kql
W3CIISLog
| where TimeGenerated > ago(1d)
| where scStatus == "404"
| summarize NotFound = count(), UniquePaths = dcount(csUriStem), UA = take_any(csUserAgent)
    by cIP, sSiteName, bin(TimeGenerated, 10m)
| where UniquePaths > 100
| order by NotFound desc
```

**วิธีรับมือ**
1. ตรวจว่า IP เป็น scanner ที่องค์กรจ้าง (EASM vendor, pentest) หรือ research scanner ที่รู้จักหรือไม่
2. ดูว่ามี request ไหนได้ HTTP 200/500 กับ path อ่อนไหว — ถ้ามี ให้ถือเป็นเหตุ Initial Access ที่อาจสำเร็จ และไปที่ [T1190](03-initial-access.md#t1190-exploit-public-facing-application)
3. Block IP/ASN ที่ WAF ถ้าเป็นการสแกนเชิงรุก (ได้ผลระยะสั้นเท่านั้น)
4. ส่งรายการ path/พอร์ตที่ถูกสแกนบ่อยให้ทีม infra ตรวจว่าเปิดเกินจำเป็นหรือไม่

**ป้องกันระยะยาว**
- ทำ External Attack Surface Management และทะเบียน asset ที่เปิดสู่อินเทอร์เน็ต
- ลบไฟล์ backup/`.git`/`.env` ออกจาก web root, ซ่อน version banner
- WAF rate limit และ bot protection (M1056 Pre-compromise)

**False positive** — vulnerability scanner ภายในหรือของ vendor, uptime monitor, search engine crawler

---

## T1589 Gather Victim Identity Information

**วิธีทำงาน**
รวบรวมอีเมลพนักงาน (T1589.002), ชื่อ (T1589.003) และรหัสผ่านที่รั่ว (T1589.001) แล้วตรวจว่าบัญชีมีจริงผ่าน login endpoint ของ Entra ID / OWA / VPN

**สัญญาณ**
- `SigninLogs` มี error `50034` (user not found) หรือ `50126` (invalid password) จาก IP เดียวกับหลายบัญชี
- การลองบัญชีที่ไม่มีจริงหลายชื่อแสดงว่ากำลังเดารูปแบบอีเมล

**KQL — identity enumeration บน Entra ID**
```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("50034", "50126", "50053")
| summarize Users = dcount(UserPrincipalName), Attempts = count(),
            Codes = make_set(ResultType), Apps = make_set(AppDisplayName, 5)
    by IPAddress, bin(TimeGenerated, 1h)
| where Users > 10
| order by Users desc
```

**วิธีรับมือ**
1. ตรวจว่ามี sign-in **สำเร็จ** (`ResultType == "0"`) จาก IP เดียวกันหรือไม่ — ถ้ามี ยกระดับเป็น [Password Spraying](09-credential-access.md#t1110003-password-spraying)
2. รายชื่อบัญชีที่ถูกลอง = รายชื่อเป้าหมาย phishing ในอนาคต แจ้งผู้ใช้กลุ่มนี้ให้ระวัง
3. ตรวจบัญชีเหล่านี้กับ breach dump/TI feed และบังคับเปลี่ยนรหัสผ่านถ้าพบ
4. Block IP ด้วย Conditional Access Named Location ถ้ามาจากประเทศที่ไม่มีธุรกิจ

**ป้องกันระยะยาว**
- เปิด Smart Lockout และ Microsoft Entra Password Protection (banned password list)
- MFA ทุกบัญชี (M1032), Dark web / breach monitoring
- ลดข้อมูลอีเมลและโครงสร้างองค์กรที่เปิดเผยบนเว็บไซต์

**False positive** — ผู้ใช้พิมพ์อีเมลผิด, ระบบ legacy ที่ใช้รหัสผ่านเก่า, NAT ของสำนักงานใหญ่

---

## T1598 Phishing for Information

**วิธีทำงาน**
ส่งข้อความหลอกเพื่อเอาข้อมูล ไม่ใช่เพื่อรันมัลแวร์: ลิงก์ไปหน้า login ปลอม (T1598.003), ไฟล์แนบ HTML ฟอร์มปลอม (T1598.002), DM ผ่าน LinkedIn/Teams (T1598.001) หรือโทรศัพท์/vishing (T1598.004)

**สัญญาณ**
- อีเมลที่ Defender ระบุ `ThreatTypes` มี Phish และมีผู้ใช้คลิกผ่าน
- ผู้ใช้คลิก URL แล้วตามด้วย sign-in จาก IP แปลกภายในไม่กี่นาที (สัญญาณของ AiTM)

**KQL — ผู้ใช้ที่คลิกลิงก์ phishing**
```kql
let phish = EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| project NetworkMessageId, SenderFromAddress, Subject;
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickAllowed" or IsClickedThrough == true
| join kind=inner phish on NetworkMessageId
| project Timestamp, AccountUpn, Url, SenderFromAddress, Subject, IPAddress
```

**วิธีรับมือ**
1. ติดต่อผู้ใช้ที่คลิก: กรอกข้อมูลอะไรไปหรือไม่
2. ถ้ากรอกรหัสผ่าน: reset password, **revoke sessions** (`Revoke-MgUserSignInSession`), ตรวจ MFA method ที่เพิ่มใหม่
3. ใช้ Threat Explorer ลบอีเมลเดียวกันจากทุกกล่อง (soft delete) และ block sender/URL
4. ไล่ตรวจ sign-in ของผู้ใช้หลังเวลาคลิก — ดูหัวข้อ [AiTM](09-credential-access.md#t1539--t1557-aitm-และการขโมย-session-cookie)

**ป้องกันระยะยาว**
- Phishing-resistant MFA (M1032), Safe Links, จำกัด external chat ใน Teams
- Helpdesk ต้องยืนยันตัวตนแบบ out-of-band ก่อน reset MFA (ป้องกัน vishing)
- Security awareness และปุ่ม Report Phish (M1017)

**False positive** — phishing simulation ภายใน (ทำ allowlist ตามโดเมนของ vendor)

---

## T1593 Search Open Websites/Domains และ T1596 Search Open Technical Databases

**วิธีทำงาน** — ค้น GitHub/GitLab หา secret ที่ commit พลาด (T1593.003), ค้น certificate transparency หาซับโดเมนใหม่ (T1596.003), ใช้ Shodan หาอุปกรณ์ที่เปิดอยู่ (T1596.005)

**วิธีตรวจสอบ** — ตรวจจากภายในไม่ได้ ใช้วิธีมองแบบผู้โจมตี:
- เปิด secret scanning / push protection บน repo ขององค์กร
- Monitor certificate transparency ของโดเมนตัวเอง (เช่น crt.sh) เพื่อเจอซับโดเมนที่ไม่รู้จัก
- ค้นชื่อองค์กรและ IP range บน Shodan/Censys เป็นรอบ

**วิธีรับมือเมื่อพบ secret รั่ว** — revoke/rotate key ทันที (ไม่ใช่แค่ลบ commit), ตรวจ log การใช้ key ย้อนหลังตั้งแต่วันที่ commit

---

## Checklist ตอบสนองระดับ Tactic

- [ ] ระบุว่าการสำรวจมาจาก IP/ASN ใด และมีอะไรที่ **สำเร็จ** (HTTP 200, sign-in success) หรือไม่
- [ ] รวบรวมรายชื่อบัญชี/ระบบที่ถูกเล็ง → เพิ่มการเฝ้าระวังใน 30 วันถัดไป
- [ ] ตรวจว่าระบบที่ถูกสแกนมีช่องโหว่ที่อยู่ใน CISA KEV หรือไม่ → แพตช์เร่งด่วน
- [ ] ปิด/ลดสิ่งที่เปิดเผยโดยไม่จำเป็น (พอร์ต, path, ข้อมูลพนักงาน)
- [ ] บันทึก IOC ลง TI platform เพื่อใช้จับใน Tactic ถัดไป
