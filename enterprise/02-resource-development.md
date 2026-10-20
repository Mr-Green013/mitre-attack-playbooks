# 02. Resource Development (TA0042)

## เป้าหมายของผู้โจมตี

เตรียมทรัพยากรที่จะใช้โจมตี: โดเมนและเซิร์ฟเวอร์ C2, บัญชีอีเมล/โซเชียล/คลาวด์, มัลแวร์และเครื่องมือ, ใบรับรอง และ content ที่สร้างด้วย AI (T1683 Generate Content ใน v20)
ทั้งหมดเกิดนอกองค์กร การป้องกันจึงอาศัย **Threat Intelligence** และ **การจับครั้งแรกที่ทรัพยากรเหล่านี้ถูกใช้กับเรา**

## ลำดับการทำงานที่พบบ่อย

1. จดโดเมนเลียนแบบ (typosquat) หรือซื้อโดเมนเก่าที่มี reputation ดี (T1583.001)
2. เช่า VPS / serverless / CDN ทำ C2 redirector (T1583.003, T1583.007) หรือยึดเซิร์ฟเวอร์ของคนอื่น (T1584)
3. สร้างหรือยึดบัญชีอีเมล/โซเชียล/คลาวด์ (T1585, T1586) เพื่อส่ง phishing หรือ host payload
4. ซื้อหรือพัฒนามัลแวร์/exploit, ดาวน์โหลดเครื่องมือ open source (T1587, T1588) รวมถึงใช้ AI ช่วยเขียน (T1588.007)
5. วาง payload บนบริการที่น่าเชื่อถือ (OneDrive, GitHub, Pastebin) และทำ SEO poisoning (T1608)

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| การเชื่อมต่อไปยังโดเมน/IP ใน TI feed | `DeviceNetworkEvents`, `CommonSecurityLog`, `ThreatIntelligenceIndicator` |
| โดเมนที่ไม่เคยเห็นในองค์กรมาก่อน | `DeviceNetworkEvents` |
| อีเมลจากโดเมนเลียนแบบ | `EmailEvents` |

---

## T1583 / T1584 Acquire / Compromise Infrastructure

**วิธีทำงาน**
ผู้โจมตีต้องมีปลายทางให้มัลแวร์ติดต่อกลับ จึงจดโดเมนใหม่ ใช้ VPS ราคาถูก หรือซ่อนหลังบริการคลาวด์ที่น่าเชื่อถือ (Cloudflare Workers, Azure Front Door) บางกลุ่มยึด router/NAS ตามบ้านมาเป็น proxy (ORB network) เพื่อให้ IP ดูเป็นผู้ใช้ทั่วไป

**สัญญาณ**
- เครื่องในองค์กรเชื่อมต่อ IP/domain ที่อยู่ใน TI feed
- เชื่อมต่อโดเมนที่ไม่เคยมีเครื่องไหนในองค์กรติดต่อมาก่อน (newly observed domain)

**KQL — match กับ Threat Intelligence**
```kql
let iocDomains = toscalar(
    ThreatIntelligenceIndicator
    | where TimeGenerated > ago(14d) and Active == true and ExpirationDateTime > now()
    | where isnotempty(DomainName)
    | summarize make_set(tolower(DomainName), 10000));
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where isnotempty(RemoteUrl)
| extend Host = tolower(tostring(parse_url(iff(RemoteUrl startswith "http", RemoteUrl, strcat("https://", RemoteUrl))).Host))
| where Host in (iocDomains)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
```

**KQL — โดเมนที่องค์กรไม่เคยติดต่อในรอบ 30 วัน**
```kql
let baseline = DeviceNetworkEvents
| where Timestamp between (ago(30d) .. ago(1d))
| where isnotempty(RemoteUrl)
| summarize by RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(1d) and isnotempty(RemoteUrl)
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| join kind=leftanti baseline on RemoteUrl
| summarize Devices = dcount(DeviceName), Procs = make_set(InitiatingProcessFileName, 5) by RemoteUrl
| where Devices <= 2
```

**สิ่งที่ต้องปรับ** — tenant ที่ใช้ TI แบบใหม่อาจต้องเปลี่ยนเป็นตาราง `ThreatIntelIndicators`; query ที่สองให้ผลเยอะ ใช้เพื่อ hunting ไม่เหมาะตั้งเป็น rule ตรงๆ

**วิธีรับมือ**
1. ตรวจ reputation และอายุโดเมน (WHOIS) — โดเมนอายุน้อยกว่า 30 วันน่าสงสัยมาก
2. ดู process ที่เชื่อมต่อ: browser ทั่วไปหรือ process แปลก (`rundll32`, `powershell`) — ถ้าเป็นแบบหลังให้ไปที่ [C2](13-command-and-control.md)
3. Block domain/IP ที่ proxy, DNS และ MDE custom indicator
4. ค้นย้อนหลัง 30 วันว่ามีเครื่องอื่นติดต่อปลายทางเดียวกันหรือไม่

**ป้องกันระยะยาว** — บล็อกหมวด Newly Registered Domains ที่ proxy/DNS filter, ใช้ TI feed ที่อัปเดตอัตโนมัติ, จดโดเมน typosquat ที่สำคัญของแบรนด์ตัวเองไว้ก่อน

**False positive** — SaaS ใหม่ที่ฝ่ายอื่นเริ่มใช้, CDN ที่เปลี่ยนชื่อโฮสต์บ่อย

---

## T1588 / T1587 Obtain / Develop Capabilities

**วิธีทำงาน**
ผู้โจมตีใช้เครื่องมือสำเร็จรูป (Cobalt Strike, Sliver, Mimikatz, Impacket, Rclone) หรือเขียน loader เอง และอาจซื้อหรือขโมย code signing certificate (T1588.003) เพื่อให้มัลแวร์ดูน่าเชื่อถือ

**วิธีตรวจสอบ**
- เครื่องมือเหล่านี้จะถูกตรวจจับตอนใช้งานใน Tactic ถัดไป เช่น Mimikatz ใน [T1003](09-credential-access.md), Rclone ใน [T1567](14-exfiltration.md)
- เฝ้าระวังไฟล์ที่ signed ด้วยใบรับรองที่ถูกเพิกถอนหรือไม่รู้จัก

**KQL — ไฟล์ที่รันโดยมีลายเซ็นไม่ถูกต้องหรือไม่เคยพบ**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| join kind=leftouter (
    DeviceFileCertificateInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, *) by SHA1
    | project SHA1, Signer, IsTrusted, IsSigned, CertificateSerialNumber
  ) on SHA1
| where IsSigned == true and IsTrusted == false
| summarize Devices = dcount(DeviceName), Example = take_any(ProcessCommandLine) by FileName, SHA1, Signer
```

**วิธีรับมือ** — ส่ง hash ไปวิเคราะห์ (sandbox), block hash / certificate ผ่าน MDE indicator, ค้นหา hash เดียวกันทั้งองค์กร

**ป้องกันระยะยาว** — WDAC policy ที่อนุญาตเฉพาะ publisher ที่รู้จัก (M1038), ASR rule *Block executable files unless they meet a prevalence, age, or trusted list criterion*

---

## T1585 / T1586 Establish / Compromise Accounts

**วิธีทำงาน**
สร้างบัญชีปลอมเป็น recruiter หรือ vendor หรือยึดบัญชีอีเมลจริงของคู่ค้าเพื่อส่ง phishing ที่ดูน่าเชื่อถือ (Business Email Compromise ผ่าน vendor)

**KQL — อีเมลจากโดเมนที่คล้ายโดเมนคู่ค้า/ขององค์กร**
```kql
let ownDomains = dynamic(["contoso.com", "contoso.co.th"]);   // โดเมนจริงขององค์กรและคู่ค้า
let brands = @"contoso|fabrikam";                              // ชื่อแบรนด์ที่ผู้โจมตีน่าจะเลียนแบบ
EmailEvents
| where Timestamp > ago(7d)
| extend SenderDomain = tolower(tostring(split(SenderFromAddress, "@")[1]))
| where SenderDomain !in (ownDomains)
| where SenderDomain matches regex brands
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction
```

**สิ่งที่ต้องปรับ** — ใส่โดเมนและแบรนด์จริง; query นี้จับโดเมนที่มีชื่อแบรนด์อยู่ (เช่น `contoso-billing.com`, `mycontoso.net`) แต่ไม่ครอบคลุม homoglyph (`c0ntoso`) — ใช้ Defender *Impersonation protection* ร่วมด้วย

**วิธีรับมือ** — แจ้งคู่ค้าว่าบัญชีอาจถูกยึด, ยืนยันคำขอเปลี่ยนบัญชีธนาคารทางโทรศัพท์ที่รู้จักอยู่แล้วเสมอ, ใส่โดเมนปลอมใน Tenant Allow/Block List

---

## T1608 Stage Capabilities

**วิธีทำงาน** — วาง payload บนบริการที่องค์กรไว้ใจ (OneDrive, Google Drive, GitHub, Discord CDN), ทำ SEO poisoning ให้ลิงก์ดาวน์โหลดปลอมขึ้นอันดับต้น (T1608.006) และใน v20 คือ AI Result Poisoning (T1608.007) ที่ทำให้ AI search แนะนำเว็บของผู้โจมตี

**KQL — ดาวน์โหลดไฟล์ executable จาก file-sharing / CDN สาธารณะ**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FileName endswith ".exe" or FileName endswith ".msi" or FileName endswith ".zip" or FileName endswith ".iso"
| where FileOriginUrl has_any ("cdn.discordapp.com", "raw.githubusercontent.com", "github.com", "pastebin.com",
                               "transfer.sh", "dropbox.com", "mediafire.com", "1drv.ms")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FileOriginUrl, FileOriginReferrerUrl, SHA256
```

**วิธีรับมือ** — ตรวจว่าไฟล์ถูกเปิดหรือไม่ (`DeviceProcessEvents` ด้วย SHA256 เดียวกัน), ถ้าเปิดแล้วให้ถือเป็นเหตุ [Execution](04-execution.md); แจ้งผู้ให้บริการให้ถอดไฟล์

**ป้องกันระยะยาว** — software catalog ภายใน (Company Portal) เพื่อลดการดาวน์โหลดจากเว็บ, SmartScreen, ASR rules

---

## Checklist ตอบสนองระดับ Tactic

- [ ] นำ IOC (domain, IP, hash, certificate) ที่พบไป block ทุกจุด: DNS, proxy, firewall, MDE indicators, Exchange block list
- [ ] ค้นย้อนหลัง 30–90 วันว่ามีการติดต่อ IOC เหล่านี้มาก่อนหรือไม่
- [ ] ส่ง IOC เข้า TI platform พร้อม context (แคมเปญ, ช่วงเวลา, ความมั่นใจ)
- [ ] ถ้าพบบัญชีของคู่ค้าถูกยึด แจ้งคู่ค้าและเพิ่มการตรวจสอบธุรกรรมที่เกี่ยวข้อง
