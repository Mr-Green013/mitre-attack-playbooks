# 13. Command and Control (TA0011)

## เป้าหมายของผู้โจมตี

สร้างช่องทางสื่อสารกับเครื่องที่ยึดได้เพื่อสั่งงาน, ดาวน์โหลดเครื่องมือ และส่งข้อมูลกลับ โดยกลมกลืนกับ traffic ปกติ: HTTPS ไปยัง CDN/cloud, DNS, บริการแชต/คลาวด์ยอดนิยม หรือซอฟต์แวร์ remote access ที่ถูกกฎหมาย

## ลำดับการทำงานที่พบบ่อย

1. Implant (Cobalt Strike, Sliver, Havoc, Brute Ratel) ติดต่อกลับเป็นจังหวะ (beacon) พร้อม jitter
2. ใช้ domain fronting / CDN / cloud function เป็น redirector (T1090.004)
3. ช่องทางสำรอง: DNS tunneling (T1071.004), web service เช่น Telegram/Slack/OneDrive (T1102)
4. ติดตั้ง RMM ที่ถูกกฎหมาย (AnyDesk, ScreenConnect) เป็น C2 ที่ AV ไม่จับ (T1219)
5. ทำ tunnel เข้าเครือข่ายภายใน (ngrok, Cloudflare Tunnel, Chisel, SSH reverse) (T1572)

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| การเชื่อมต่อออกจาก endpoint | `DeviceNetworkEvents` |
| Proxy / Firewall | `CommonSecurityLog` |
| DNS | `DnsEvents`, `DeviceEvents` (DnsQueryResponse) |
| RMM / tunnel binary | `DeviceProcessEvents` |

---

## T1071.001 Web Protocols (Beaconing)

**วิธีทำงาน** — implant ติดต่อ HTTPS ไปยัง C2 ทุก N วินาที ± jitter ทำให้เกิดรูปแบบการเชื่อมต่อที่สม่ำเสมอผิดธรรมชาติ

**KQL — ตรวจจับจังหวะการเชื่อมต่อที่สม่ำเสมอ**
```kql
let minConnections = 50;
let maxJitter = 0.2;   // ส่วนเบี่ยงเบนมาตรฐาน / ค่าเฉลี่ยของช่วงห่าง
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "Teams.exe", "ms-teams.exe", "OneDrive.exe",
                                        "MsSense.exe", "MsMpEng.exe", "svchost.exe", "outlook.exe", "SearchApp.exe")
| summarize Times = make_list(Timestamp, 2000), Connections = count()
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| where Connections >= minConnections
| mv-apply Times to typeof(datetime) on (
    order by Times asc
    | extend Delta = datetime_diff("second", Times, prev(Times))
    | where isnotnull(Delta) and Delta > 0
    | summarize AvgDelta = avg(Delta), StdDelta = stdev(Delta))
| extend Jitter = round(StdDelta / AvgDelta, 3)
| where Jitter < maxJitter
| project DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, Connections, AvgDelta, Jitter
| order by Jitter asc
```

**วิธีรับมือ**
1. ตรวจ RemoteIP/URL: อายุโดเมน, ASN (VPS?), certificate, TI
2. ตรวจ process ที่ติดต่อ: signed หรือไม่, อยู่ที่ไหน, ถูก inject หรือไม่ ([T1055](07-stealth.md#t1055-process-injection))
3. ยืนยันแล้ว → isolate, block IP/domain ที่ firewall/proxy/MDE, ค้นทั้งองค์กรว่าเครื่องไหนติดต่อปลายทางเดียวกัน
4. เก็บ memory ก่อน kill เพื่อดึง config ของ implant (C2 สำรอง, sleep time)

**ป้องกันระยะยาว** — egress filtering: server ออกอินเทอร์เน็ตได้เฉพาะปลายทางที่จำเป็น, TLS inspection สำหรับหมวดที่ไม่จัดประเภท, บล็อก newly registered domains (M1031, M1037)

**False positive** — agent ที่ poll ตามรอบ (update, telemetry, monitoring) → allowlist ตาม process + domain

---

## T1071.004 DNS

**วิธีทำงาน** — ฝังข้อมูลใน subdomain (`<base32-data>.c2domain.com`) และรับคำสั่งผ่าน TXT/CNAME record (iodine, dnscat2, Cobalt Strike DNS beacon)

**KQL — subdomain ยาวและหลากหลายผิดปกติต่อ parent domain**
```kql
DnsEvents
| where TimeGenerated > ago(1d)
| where SubType == "LookupQuery"
| extend Labels = split(Name, ".")
| extend Parent = strcat_array(array_slice(Labels, -2, -1), "."), Sub = tostring(Labels[0])
| summarize Queries = count(), UniqueNames = dcount(Name), AvgSubLen = avg(strlen(Sub)), Clients = make_set(ClientIP, 10)
    by Parent
| where UniqueNames > 200 and AvgSubLen > 25
| order by UniqueNames desc
```

**วิธีรับมือ** — block parent domain ที่ DNS resolver, หาเครื่องต้นทาง (`ClientIP`) และ process ที่ทำ query, isolate

**ป้องกันระยะยาว** — บังคับให้ทุกเครื่องใช้ DNS ภายในเท่านั้น (บล็อก outbound 53 และ DoH ที่ไม่อนุญาต), DNS filtering / RPZ

**False positive** — CDN และ security vendor บางรายใช้ subdomain ยาว (เช่น ชื่อที่มี hash) → allowlist parent domain

---

## T1219 Remote Access Tools

**วิธีทำงาน** — ติดตั้ง AnyDesk, ScreenConnect, RustDesk, Atera, Splashtop แบบ unattended (มักหลังได้สิทธิ์ admin หรือหลอกผู้ใช้ทาง helpdesk scam) ได้ทั้งหน้าจอและการโอนไฟล์ผ่าน infrastructure ที่น่าเชื่อถือ ใน v20 รวม IDE tunneling (VS Code tunnels, T1219.001) และ hardware KVM (T1219.003)

**KQL — RMM ที่ไม่ได้รับอนุญาต**
```kql
let approved = dynamic(["TeamViewer"]);   // ใส่ RMM ที่องค์กรใช้จริง
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessVersionInfoProductName has_any ("AnyDesk", "RustDesk", "TeamViewer", "ScreenConnect", "ConnectWise Control", "Atera",
                                               "Splashtop", "MeshCentral", "SimpleHelp", "Action1", "TacticalRMM", "NetSupport", "Zoho Assist")
     or FileName in~ ("anydesk.exe", "rustdesk.exe", "ngrok.exe", "meshagent.exe", "client32.exe")
     or (FileName =~ "code.exe" and ProcessCommandLine has "tunnel")
| where not(ProcessVersionInfoProductName has_any (approved))
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Devices = dcount(DeviceName), DeviceList = make_set(DeviceName, 20)
    by FileName, ProcessVersionInfoProductName
| order by FirstSeen desc
```

**วิธีรับมือ** — ถอนการติดตั้ง, ตรวจ session log ของ RMM (ใครเชื่อมต่อ, โอนไฟล์อะไร), ตรวจว่าติดตั้งมาอย่างไร, block hash และโดเมนของ RMM ที่ไม่อนุญาต

**ป้องกันระยะยาว** — กำหนด RMM ที่อนุญาตเพียงตัวเดียว, WDAC/AppLocker บล็อกตัวอื่น, proxy บล็อกโดเมนของ RMM ที่ไม่ใช้

---

## T1572 Protocol Tunneling / T1090 Proxy

**วิธีทำงาน** — สร้าง tunnel จากเครื่องภายในออกไปข้างนอก (ngrok, `cloudflared`, Chisel, `ssh -R`, `plink -R`) หรือ port forward ภายใน (`netsh interface portproxy`) เพื่อเข้าถึงเครือข่ายภายในจากภายนอกโดยไม่ผ่าน VPN

**KQL**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ngrok.exe", "cloudflared.exe", "chisel.exe", "frpc.exe", "ligolo.exe", "plink.exe", "ngrok", "cloudflared", "chisel", "frpc")
     or (FileName in~ ("ssh.exe", "ssh", "plink.exe") and ProcessCommandLine matches regex @"\s-[RLD]\s*\d")
     or (FileName =~ "netsh.exe" and ProcessCommandLine has "portproxy")
     or ProcessCommandLine has_any ("tunnel run", "tunnel --url", "tcp://0.tcp.ngrok.io")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

**วิธีรับมือ** — kill process และลบ binary, ลบ portproxy (`netsh interface portproxy reset`), ตรวจ inbound connection ที่ผ่าน tunnel, หาบัญชีที่สร้าง tunnel

**ป้องกันระยะยาว** — บล็อกโดเมน tunnel service ที่ proxy/DNS, egress allowlist บน server

---

## T1105 Ingress Tool Transfer

**วิธีทำงาน** — ดาวน์โหลดเครื่องมือเข้าเครื่องผ่าน `certutil -urlcache`, `bitsadmin /transfer`, `curl -o`, `Invoke-WebRequest -OutFile`, `wget`

**KQL**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("-urlcache", "-split", "http"))
     or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any ("/transfer", "/addfile"))
     or (FileName in~ ("curl.exe", "wget.exe") and ProcessCommandLine has_any ("-o ", "--output", "-O "))
     or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has_any ("-OutFile", "DownloadFile", "Start-BitsTransfer"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**วิธีรับมือ** — ระบุไฟล์ที่ดาวน์โหลด (ใช้ `DeviceFileEvents` ช่วงเวลาเดียวกัน), ตรวจ hash, block URL

---

## Checklist ตอบสนองระดับ Tactic

- [ ] ระบุช่องทาง C2 ทั้งหมด (หลัก + สำรอง) จาก memory/config ของ implant
- [ ] Block ทุกช่องทางพร้อมกัน (IP, domain, RMM, tunnel service) แล้วจึง isolate เครื่อง
- [ ] ค้นหาเครื่องอื่นที่ติดต่อ C2 เดียวกัน ย้อนหลังอย่างน้อย 30 วัน
- [ ] ตรวจปริมาณข้อมูลขาออกบนช่องทาง C2 ([Exfiltration](14-exfiltration.md))
