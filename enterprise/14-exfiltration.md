# 14. Exfiltration (TA0010)

## เป้าหมายของผู้โจมตี

นำข้อมูลออกจากองค์กร — เพื่อจารกรรม หรือเพื่อขู่เปิดเผยข้อมูล (double extortion) ช่องทางที่นิยมคือ cloud storage (MEGA, S3), ช่องทาง C2 เดิม และการแชร์/คัดลอกข้อมูลไปยังบัญชีคลาวด์ของผู้โจมตี
ใน v20 มี **T1700 AI-Enabled Exfiltration** — สั่ง AI agent ขององค์กรให้ส่งข้อมูลออกผ่าน prompt injection

## ลำดับการทำงานที่พบบ่อย

1. บีบอัดและแบ่งไฟล์ ([T1560](12-collection.md#t1560-archive-collected-data))
2. อัปโหลดด้วย Rclone / MEGAcmd / WinSCP / `curl` ไปยัง cloud storage (T1567.002)
3. หรือส่งผ่าน C2 เดิมแบบทยอย (T1041, T1030) หรือโปรโตคอลอื่น เช่น FTP/SFTP/DNS (T1048)
4. ในคลาวด์: แชร์ snapshot/bucket ให้บัญชีของผู้โจมตี (T1537)

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| เครื่องมืออัปโหลด | `DeviceProcessEvents` |
| ปลายทางและปริมาณข้อมูล | `DeviceNetworkEvents`, `CommonSecurityLog` (`SentBytes`) |
| Cloud sharing | `AWSCloudTrail`, `AzureActivity` |
| Email / SharePoint ออกนอก | `EmailEvents`, `OfficeActivity` |

---

## T1567 Exfiltration Over Web Service

### T1567.002 Exfiltration to Cloud Storage

**วิธีทำงาน** — Rclone เป็นเครื่องมืออันดับหนึ่งของกลุ่ม ransomware: ตั้งค่า remote (MEGA, S3, SFTP) ใน `rclone.conf` แล้ว `rclone copy` หลายเธรด มักถูกเปลี่ยนชื่อไฟล์

**KQL — Rclone และ MEGA (รวมกรณีเปลี่ยนชื่อ)**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessVersionInfoOriginalFileName =~ "rclone.exe"
     or ProcessVersionInfoProductName has "Rclone"
     or (ProcessCommandLine has_any (" copy ", " sync ", " move ") and ProcessCommandLine has_any ("mega:", "s3:", "sftp:", "ftp:", "--transfers", "--multi-thread-streams", "--config"))
     or FileName in~ ("MEGAcmdServer.exe", "MEGAsync.exe", "mega-put.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
```

**KQL — การเชื่อมต่อไปยังบริการฝากไฟล์ที่ไม่ได้ใช้ในองค์กร**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any ("mega.nz", "mega.co.nz", "mega.io", "transfer.sh", "gofile.io", "file.io", "temp.sh", "anonfiles",
                           "sendspace.com", "uploadfiles.io", "filemail.com", "pcloud.com", "put.io")
| summarize Connections = count(), Processes = make_set(InitiatingProcessFileName, 10) by DeviceName, RemoteUrl
```

**KQL — ปริมาณข้อมูลขาออกผิดปกติ (Firewall/Proxy)**
```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where isnotempty(SentBytes) and not(ipv4_is_private(DestinationIP))
| summarize SentGB = round(sum(SentBytes) / 1073741824.0, 2), Sessions = count(), Dest = make_set(DestinationHostName, 10)
    by SourceIP, DestinationIP
| where SentGB > 2
| order by SentGB desc
```

**วิธีรับมือ**
1. **High/Critical** — block ปลายทางทันทีที่ firewall/proxy และ kill process
2. เก็บ `rclone.conf` (มีปลายทางและ credential ของผู้โจมตี — ส่งให้ผู้ให้บริการ/หน่วยงานบังคับใช้กฎหมาย)
3. ประเมินว่าข้อมูลอะไรออกไปและปริมาณเท่าไร (ใช้ archive ที่พบ, bytes ที่ส่ง, ไฟล์ที่ถูกอ่าน)
4. แจ้ง legal/DPO; ตรวจหา ransomware precursor ทันทีเพราะ exfil มักเกิดก่อนการเข้ารหัส 1–3 วัน

**ป้องกันระยะยาว** — CASB/proxy บล็อก cloud storage ที่ไม่ได้รับอนุญาต (อนุญาตเฉพาะ tenant ขององค์กร), egress allowlist บน server, DLP (M1021, M1057)

**False positive** — งาน backup ไปยังคลาวด์ที่ได้รับอนุญาต (มักใช้ Rclone เช่นกัน) → allowlist ตามเครื่อง + บัญชี + ปลายทาง

### T1567.001 Exfiltration to Code Repository / T1567.004 Webhook

ส่งข้อมูลไป GitHub gist หรือ webhook (Discord, Slack, Teams) — ตรวจด้วย `DeviceNetworkEvents` ที่ `RemoteUrl has_any ("discord.com/api/webhooks", "hooks.slack.com", "webhook.office.com", "api.github.com")` จาก process ที่ไม่ใช่ browser/แอปแชต

---

## T1041 Exfiltration Over C2 Channel / T1048 Alternative Protocol / T1030 Data Transfer Size Limits

**วิธีทำงาน** — ส่งข้อมูลผ่าน C2 เดิมแบบแบ่งก้อนเล็กเพื่อไม่ให้ปริมาณพุ่ง (T1030) หรือใช้ FTP/SFTP/SMTP/DNS ที่ไม่ใช่ช่องทาง C2 (T1048)

**KQL — process ที่ไม่ใช่ browser ส่งข้อมูลมากกว่ารับ (ต้องมี proxy log ที่บันทึก bytes)**
```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where isnotempty(SentBytes) and isnotempty(ReceivedBytes)
| summarize Sent = sum(SentBytes), Received = sum(ReceivedBytes), Sessions = count() by SourceIP, DestinationHostName
| where Sent > 100000000 and Sent > Received * 5
| extend SentMB = round(Sent / 1048576.0, 1), Ratio = round(todouble(Sent) / todouble(max_of(Received, 1)), 1)
| order by SentMB desc
```

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (20, 21, 22, 69, 989, 990, 2222) and RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ ("WinSCP.exe", "FileZilla.exe")   // ปรับตามเครื่องมือที่องค์กรอนุญาต
| summarize Connections = count(), Destinations = make_set(RemoteIP, 10) by DeviceName, InitiatingProcessFileName, RemotePort
```

**วิธีรับมือ** — เหมือน T1567: block, ประเมินข้อมูลที่ออกไป, ตรวจ C2 ([Tactic 13](13-command-and-control.md))

---

## T1537 Transfer Data to Cloud Account

**วิธีทำงาน** — แทนที่จะดาวน์โหลด ผู้โจมตีแชร์ snapshot/AMI/bucket ให้บัญชี AWS ของตัวเอง หรือสร้าง SAS URL ของ disk ใน Azure แล้ว copy ข้อมูลภายใน backbone ของผู้ให้บริการ (ไม่ผ่าน firewall ขององค์กรเลย)

**KQL**
```kql
union
  (AWSCloudTrail
   | where TimeGenerated > ago(7d)
   | where EventName in ("ModifySnapshotAttribute", "ModifyImageAttribute", "ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute",
                         "PutBucketPolicy", "PutBucketAcl", "PutBucketReplication", "CreateExportTask")
   | where RequestParameters has_any ("createVolumePermission", "launchPermission", "restore", "Principal", "AccessControlPolicy", "ReplicationConfiguration", "destination")
   | project TimeGenerated, Actor = UserIdentityArn, Action = EventName, Detail = RequestParameters, SourceIP = SourceIpAddress),
  (AzureActivity
   | where TimeGenerated > ago(7d)
   | where OperationNameValue has_any ("MICROSOFT.COMPUTE/SNAPSHOTS/BEGINGETACCESS/ACTION", "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION",
                                       "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION")
   | project TimeGenerated, Actor = Caller, Action = OperationNameValue, Detail = _ResourceId, SourceIP = CallerIpAddress)
```

**วิธีรับมือ** — ยกเลิกการแชร์/SAS (`EndGetAccess`, ลบ permission), rotate storage key, ตรวจว่ามีการ copy ไปแล้วหรือไม่ (S3 server access log, Storage logs)

**ป้องกันระยะยาว** — SCP/Azure Policy ห้ามแชร์ snapshot/AMI ข้ามบัญชีที่ไม่อยู่ใน organization, ปิด shared key access บน storage account

---

## T1700 AI-Enabled Exfiltration

**วิธีทำงาน** — ใช้ [prompt injection](04-execution.md#t1698--t1699-prompt-injection-ใหม่ใน-v20) ให้ AI agent ที่มีสิทธิ์อ่านข้อมูลขององค์กร ส่งข้อมูลออก เช่น ฝังข้อมูลใน URL ของรูปภาพ markdown, ส่งอีเมล, หรือเรียก HTTP tool

**วิธีตรวจสอบ** — เฝ้าระวัง action ขาออกของ agent (ส่งเมล/แชร์ลิงก์/HTTP request) ไปยังโดเมนภายนอกที่ไม่เคยติดต่อ และ response ของ AI ที่มี URL ยาวผิดปกติไปยังโดเมนภายนอก (ต้องเปิด audit log ของแพลตฟอร์ม AI)

**วิธีรับมือ** — ปิด tool/connector ขาออกของ agent ชั่วคราว, ระบุเนื้อหาต้นทางที่ฝังคำสั่ง, ประเมินข้อมูลที่ agent เข้าถึงได้ในช่วงนั้น

**ป้องกันระยะยาว** — agent อ่านได้เฉพาะข้อมูลที่ผู้ใช้คนนั้นมีสิทธิ์ (ไม่ใช้ service account กว้าง), allowlist ปลายทางที่ agent ส่งข้อมูลได้, ปิดการ render รูปภาพจาก URL ภายนอกในคำตอบ

---

## Checklist ตอบสนองระดับ Tactic

- [ ] Block ปลายทางและช่องทางทั้งหมดที่ใช้ส่งออก
- [ ] ประเมินข้อมูลที่ออกไป: ประเภท, จำนวนรายการ, เจ้าของข้อมูล, ช่วงเวลา
- [ ] แจ้ง legal/DPO และผู้บริหาร; ประเมินหน้าที่แจ้งตาม PDPA / กฎหมายเฉพาะอุตสาหกรรม
- [ ] เตรียมรับมือ extortion (ไม่ติดต่อผู้โจมตีเองโดยไม่ผ่านทีมที่กำหนด)
- [ ] ตรวจและปกป้อง backup ทันที — ขั้นถัดไปมักเป็น [Impact](15-impact.md)
