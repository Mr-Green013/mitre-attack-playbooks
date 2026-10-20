# 12. Collection (TA0009)

## เป้าหมายของผู้โจมตี

รวบรวมข้อมูลที่มีค่า — อีเมลผู้บริหาร, เอกสารการเงิน/สัญญา, ฐานข้อมูลลูกค้า, source code, ข้อมูลใน SharePoint/Teams/cloud storage — แล้วบีบอัดเตรียมส่งออก
ใน ransomware สมัยใหม่ (double extortion) ขั้นนี้เกิด **ก่อน** การเข้ารหัสเสมอ

## ลำดับการทำงานที่พบบ่อย

1. ค้นหาไฟล์ตามคำค้น (`confidential`, `password`, `contract`, `.pst`, `.bak`) บน file share และ endpoint
2. ดึงอีเมลผ่าน Graph/EWS หรือตั้ง forwarding rule (T1114)
3. ดาวน์โหลดจำนวนมากจาก SharePoint/OneDrive/Confluence/Git (T1213) และ cloud storage (T1530)
4. รวมไฟล์ไว้ที่โฟลเดอร์ staging (T1074) แล้วบีบอัดพร้อมรหัสผ่าน (T1560)

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| Archive utility | `DeviceProcessEvents` |
| Mailbox access / inbox rule | `OfficeActivity`, `CloudAppEvents` |
| SharePoint / OneDrive download | `OfficeActivity` |
| Cloud storage read | `StorageBlobLogs`, `AWSCloudTrail` (S3 data events) |
| ไฟล์บน file share | `DeviceFileEvents`, `SecurityEvent` (5145 ถ้าเปิด) |

---

## T1560 Archive Collected Data

**วิธีทำงาน** — บีบอัดด้วย 7-Zip/WinRAR/`tar`/`Compress-Archive` พร้อมตั้งรหัสผ่าน (ให้ DLP อ่านไม่ได้) และแบ่งไฟล์เป็นส่วนเล็ก (`-v500m`)

**KQL — archive พร้อมรหัสผ่านหรือแบ่งไฟล์**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (ProcessVersionInfoOriginalFileName in~ ("7z.exe", "7za.exe", "7zr.exe", "rar.exe", "WinRAR.exe") or FileName in~ ("7z.exe", "7za.exe", "rar.exe", "winrar.exe"))
| where ProcessCommandLine matches regex @"(?i)\s-(p|hp)\S+" or ProcessCommandLine matches regex @"(?i)\s-v\d+[kmg]"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**KQL — archive ขนาดใหญ่ถูกสร้างบน server**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FileName endswith ".7z" or FileName endswith ".rar" or FileName endswith ".zip" or FileName matches regex @"\.(7z|rar|zip)\.\d{3}$"
| where FileSize > 500000000
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, FolderPath, FileSize
```

**วิธีรับมือ** — หยุด process และเก็บไฟล์ archive ไว้ (เป็นหลักฐานว่าข้อมูลอะไรถูกเตรียมออก), ตรวจ network ถัดจากนั้นทันที ([Exfiltration](14-exfiltration.md)), แจ้งทีม legal/privacy เตรียมประเมินข้อมูลรั่วไหล

**ป้องกันระยะยาว** — จำกัดการติดตั้ง archive utility บนเซิร์ฟเวอร์, DLP, ลดสิทธิ์อ่าน file share แบบกว้าง (M1022)

**False positive** — งาน backup/log rotation ที่ใช้ 7-Zip → allowlist ตาม scheduled task และบัญชีบริการ

---

## T1114 Email Collection

### T1114.003 Email Forwarding Rule

**วิธีทำงาน** — สร้าง inbox rule หรือ mailbox forwarding ส่งอีเมลทั้งหมดหรือเฉพาะคำค้น (invoice, payment) ไปยังภายนอก — ใช้ต่อใน Business Email Compromise

**KQL**
```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in~ ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "UpdateInboxRules", "New-TransportRule")
| where Parameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo", "ForwardingSmtpAddress", "ForwardingAddress")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
```

### T1114.002 Remote Email Collection

**วิธีทำงาน** — ใช้ token ของผู้ใช้หรือแอปที่มีสิทธิ์ `Mail.Read` ดึงอีเมลผ่าน Graph/EWS จำนวนมาก

**KQL — การเข้าถึงอีเมลปริมาณสูง (ต้องเปิด MailItemsAccessed audit)**
```kql
OfficeActivity
| where TimeGenerated > ago(1d)
| where Operation == "MailItemsAccessed"
| summarize Events = count(), IPs = make_set(ClientIP, 10) by UserId, bin(TimeGenerated, 1h)
| where Events > 500
| order by Events desc
```

**วิธีรับมือ (T1114)**
1. ลบ rule/forwarding, ตรวจว่ามีอีเมลถูกส่งออกไปแล้วกี่ฉบับและอะไรบ้าง (Message trace)
2. จัดการบัญชีเป็นบัญชีถูกยึด: reset, revoke sessions, ตรวจ MFA method และ OAuth app
3. ถ้าเป็น BEC: แจ้งการเงินและคู่ค้าให้ระงับการโอนที่ค้างอยู่
4. ใช้ MailItemsAccessed ประเมินว่าอีเมลใดถูกอ่าน (สำหรับรายงานข้อมูลรั่วไหล)

**ป้องกันระยะยาว** — Outbound spam policy ปิด automatic external forwarding, alert policy สำหรับ forwarding/redirect rule, ตรวจ OAuth consent (admin consent workflow)

---

## T1213 Data from Information Repositories

**วิธีทำงาน** — ดาวน์โหลดจำนวนมากจาก SharePoint/OneDrive (T1213.002), Confluence (T1213.001), Git (T1213.003), Teams/Slack (T1213.005), ฐานข้อมูล (T1213.006)

**KQL — ดาวน์โหลดไฟล์จาก SharePoint/OneDrive จำนวนมาก**
```kql
OfficeActivity
| where TimeGenerated > ago(1d)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileAccessed")
| summarize Files = dcount(OfficeObjectId), Sites = dcount(Site_Url), IPs = make_set(ClientIP, 5), UA = take_any(UserAgent)
    by UserId, bin(TimeGenerated, 1h)
| where Files > 300
| order by Files desc
```

**วิธีรับมือ** — เทียบกับ baseline ของผู้ใช้ (เคยดาวน์โหลดจำนวนนี้หรือไม่), ตรวจ IP/อุปกรณ์ที่ใช้ (managed หรือไม่), ถ้าเป็นบัญชีถูกยึดหรือพนักงานที่กำลังลาออก ให้ระงับสิทธิ์และเก็บหลักฐานตามนโยบาย insider risk

**ป้องกันระยะยาว** — Conditional Access session control (block download บนอุปกรณ์ไม่จัดการ), sensitivity label, จำกัดการแชร์ทั้งองค์กร ("Everyone except external users")

---

## T1530 Data from Cloud Storage

**วิธีทำงาน** — ใช้ credential/SAS token/access key ที่ได้มา อ่าน object จาก Azure Blob หรือ S3 จำนวนมาก หรือ bucket ที่เปิด public โดยไม่ตั้งใจ

**KQL — Azure Blob: IP ใหม่อ่านข้อมูลจำนวนมาก**
```kql
StorageBlobLogs
| where TimeGenerated > ago(1d)
| where OperationName == "GetBlob" and StatusCode == 200
| summarize Reads = count(), Bytes = sum(ResponseBodySize), Blobs = dcount(Uri)
    by AccountName, CallerIpAddress, AuthenticationType, bin(TimeGenerated, 1h)
| where Blobs > 1000 or Bytes > 5000000000
```

**KQL — AWS S3 (ต้องเปิด CloudTrail data events)**
```kql
AWSCloudTrail
| where TimeGenerated > ago(1d)
| where EventSource == "s3.amazonaws.com" and EventName == "GetObject"
| summarize Objects = count(), Buckets = make_set(tostring(parse_json(RequestParameters).bucketName), 10)
    by UserIdentityArn, SourceIpAddress, bin(TimeGenerated, 1h)
| where Objects > 1000
```

**วิธีรับมือ** — revoke SAS/access key ที่ใช้, ตรวจว่า key มาจากไหน (ไฟล์, repo, metadata), ประเมินข้อมูลที่ถูกอ่านเพื่อแจ้งผู้เกี่ยวข้องตามกฎหมาย (PDPA)

**ป้องกันระยะยาว** — ปิด public access ระดับ account/organization, ใช้ Entra ID/IAM role แทน shared key, SAS อายุสั้นแบบ user delegation, Defender for Storage / GuardDuty S3 protection

---

## Checklist ตอบสนองระดับ Tactic

- [ ] ระบุข้อมูลที่ถูกรวบรวม (ไฟล์, อีเมล, ฐานข้อมูล) และความอ่อนไหว (PII, ความลับทางการค้า)
- [ ] เก็บหลักฐาน staging/archive ไว้เพื่อประเมินขอบเขตการรั่วไหล
- [ ] ตรวจทันทีว่ามีการส่งออกเกิดขึ้นแล้วหรือไม่
- [ ] แจ้งทีม legal/DPO ถ้าเกี่ยวข้องกับข้อมูลส่วนบุคคล (PDPA กำหนดแจ้ง สคส. ภายใน 72 ชม. เมื่อมีความเสี่ยงต่อสิทธิของเจ้าของข้อมูล)
