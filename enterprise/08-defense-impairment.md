# 08. Defense Impairment (TA0112) — ใหม่ใน v20

## เป้าหมายของผู้โจมตี

ทำให้ฝ่ายป้องกัน **มองไม่เห็นหรือเชื่อข้อมูลไม่ได้**: ปิดหรือแก้ EDR/AV, หยุดการเก็บ log, ล้าง log, ปิด firewall, ดัดแปลงนโยบาย, ทำลาย trust control
พฤติกรรมเหล่านี้มักเกิด **ทันทีก่อน** ransomware หรือการขโมยข้อมูลครั้งใหญ่ จึงเป็นสัญญาณเตือนสุดท้ายที่ต้องตอบสนองเร็วที่สุด

## ลำดับการทำงานที่พบบ่อย

1. ตรวจว่ามี security software อะไร (T1518.001 ใน [Discovery](10-discovery.md))
2. ปิด/ถอด EDR ด้วยสิทธิ์ admin, ใช้ BYOVD ([T1068](06-privilege-escalation.md#t1068-exploitation-for-privilege-escalation-รวม-byovd)), หรือรีบูตเข้า Safe Mode (T1688)
3. เพิ่ม exclusion, ปิด real-time protection, ปิด tamper protection
4. ปิด/ล้าง Windows Event Log, Linux auditd, cloud log (CloudTrail, Diagnostic settings)
5. ปิด host firewall หรือแก้ security group/NSG ให้เปิดกว้าง

## Log ที่ต้องมี

| สัญญาณ | ตาราง |
|---|---|
| คำสั่งปิด Defender / firewall | `DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceEvents` |
| Sensor หยุดส่งข้อมูล | `DeviceInfo`, `Heartbeat` |
| Log ถูกล้าง | `SecurityEvent` (1102), `Event` (104) |
| Cloud logging / firewall | `AzureActivity`, `AWSCloudTrail` |

> **สำคัญ**: การที่ log หายไปก็เป็นสัญญาณ — ต้องมี detection สำหรับ "ความเงียบ" ด้วย

---

## T1685 Disable or Modify Tools

### T1685.001 / Disable security tools (Defender, EDR)

**วิธีทำงาน** — `Set-MpPreference -DisableRealtimeMonitoring $true`, เพิ่ม exclusion, หยุด/ลบ service ของ EDR, แก้ registry policy `DisableAntiSpyware`, ใช้เครื่องมือ "EDR killer" ที่อาศัย driver

**KQL — คำสั่งปิด/ลดความสามารถ Defender**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection",
                                    "DisableScriptScanning", "Add-MpPreference", "ExclusionPath", "ExclusionProcess",
                                    "Uninstall-WindowsFeature -Name Windows-Defender", "sc stop WinDefend", "sc config WinDefend")
   or (FileName =~ "MpCmdRun.exe" and ProcessCommandLine has "-RemoveDefinitions")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**KQL — ความพยายามแก้ไขที่ถูก Tamper Protection บล็อก**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "TamperingAttempt"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
```

**KQL — เครื่องที่หยุดส่งข้อมูล (Defender XDR)**
```kql
DeviceInfo
| where Timestamp > ago(7d)
| summarize LastSeen = max(Timestamp) by DeviceName, OSPlatform
| where LastSeen between (ago(7d) .. ago(4h))
| order by LastSeen desc
```

**KQL — agent หยุดส่ง heartbeat (Sentinel / AMA)**
```kql
Heartbeat
| where TimeGenerated > ago(2d)
| summarize LastHeartbeat = max(TimeGenerated) by Computer, OSType
| where LastHeartbeat < ago(1h)
```

### T1685.005 Clear Windows Event Logs / T1685.006 Clear Linux or Mac System Logs

**KQL**
```kql
union
  (SecurityEvent | where TimeGenerated > ago(7d) | where EventID == 1102
   | project TimeGenerated, Computer, Detail = "Security log cleared", By = SubjectUserName),
  (Event | where TimeGenerated > ago(7d) | where EventID == 104 and Source == "Microsoft-Windows-Eventlog"
   | project TimeGenerated, Computer, Detail = "Event log cleared: " + RenderedDescription, By = UserName),
  (DeviceProcessEvents | where Timestamp > ago(7d)
   | where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any (" cl ", "clear-log"))
        or ProcessCommandLine has_any ("Clear-EventLog", "Remove-EventLog", "auditctl -D", "> /var/log/", "truncate -s 0 /var/log")
   | project TimeGenerated = Timestamp, Computer = DeviceName, Detail = ProcessCommandLine, By = AccountName)
```

### T1685.002 Disable or Modify Cloud Log

**KQL**
```kql
union
  (AzureActivity
   | where TimeGenerated > ago(7d)
   | where OperationNameValue has_any ("MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE", "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
                                       "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DELETE", "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/DELETE")
   | project TimeGenerated, Actor = Caller, Action = OperationNameValue, Target = _ResourceId),
  (AWSCloudTrail
   | where TimeGenerated > ago(7d)
   | where EventName in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteFlowLogs",
                         "DeleteDetector", "DisableSecurityHub", "DeleteConfigurationRecorder", "StopConfigurationRecorder")
   | project TimeGenerated, Actor = UserIdentityArn, Action = EventName, Target = RequestParameters)
```

**วิธีรับมือ (T1685 ทั้งหมด)**
1. **ตอบสนองทันที (Critical)** — การปิด security tool หรือล้าง log โดยไม่มี change เกือบทุกครั้งคือการเตรียมลงมือขั้นสุดท้าย
2. Isolate เครื่อง (ถ้า sensor ยังติดต่อได้) หรือตัดเครือข่ายที่ switch/firewall (ถ้า sensor ถูกปิดแล้ว)
3. ตรวจบัญชีที่สั่ง → บัญชีนั้นมีสิทธิ์ admin ถือว่าถูกยึด → disable/reset
4. คืนค่าการตั้งค่า/เปิด logging กลับ, ตรวจช่วงเวลาที่ log หายว่าผู้โจมตีทำอะไร (ใช้ network log, log ของเครื่องอื่น)
5. ไล่ตรวจเครื่องอื่นที่ถูกสั่งแบบเดียวกันในช่วงเวลาใกล้กัน (มักทำผ่าน GPO/PsExec หลายเครื่องพร้อมกัน)

**ป้องกันระยะยาว**
- เปิด **Tamper Protection** ทุกเครื่องและจัดการผ่าน Intune/MDE เท่านั้น
- Log forwarding แบบ real-time ไปยัง workspace ที่ผู้ดูแลระบบปกติลบไม่ได้ (M1029), CloudTrail แบบ organization trail + S3 Object Lock
- จำกัดผู้ที่แก้ diagnostic settings / CloudTrail ด้วย Azure Policy / SCP
- Alert เมื่อ sensor เงียบนานเกินเกณฑ์

**False positive** — การถอน agent ตามแผน (decommission เครื่อง), troubleshooting ของทีม IT → ต้องผูกกับ change ticket

---

## T1686 Disable or Modify System Firewall

**วิธีทำงาน** — ปิด Windows Firewall (T1686.003) เพื่อให้ RDP/SMB เข้าได้, เพิ่ม rule อนุญาตพอร์ตของ C2, หรือแก้ NSG/Security Group บนคลาวด์ให้เปิด `0.0.0.0/0` (T1686.001)

**KQL — host firewall**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "netsh.exe" and ProcessCommandLine has_any ("advfirewall set", "state off", "firewall add rule", "portproxy"))
     or ProcessCommandLine has_any ("Set-NetFirewallProfile -Enabled False", "New-NetFirewallRule", "ufw disable", "iptables -F", "systemctl stop firewalld")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**KQL — cloud firewall เปิดกว้าง**
```kql
union
  (AWSCloudTrail
   | where TimeGenerated > ago(7d)
   | where EventName in ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules")
   | where RequestParameters has "0.0.0.0/0" or RequestParameters has "::/0"
   | project TimeGenerated, Actor = UserIdentityArn, Action = EventName, Detail = RequestParameters),
  (AzureActivity
   | where TimeGenerated > ago(7d)
   | where OperationNameValue =~ "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
   | where ActivityStatusValue in ("Success", "Succeeded")
   | project TimeGenerated, Actor = Caller, Action = OperationNameValue, Detail = tostring(Properties))
```

**วิธีรับมือ** — คืนค่า rule, ตรวจ connection ที่เข้ามาระหว่างที่ firewall เปิด (`DeviceNetworkEvents` InboundConnectionAccepted, VPC Flow Logs), ตรวจบัญชีที่แก้

**ป้องกันระยะยาว** — จัดการ firewall ผ่าน GPO/Intune (ผู้ใช้แก้ไม่ได้), Azure Policy / AWS Config rule ที่ห้าม inbound จาก `0.0.0.0/0` บนพอร์ตบริหาร

---

## T1553 Subvert Trust Controls

**วิธีทำงาน** — ติดตั้ง root certificate ของผู้โจมตี (T1553.004) เพื่อดักหรือปลอม TLS, ข้าม Mark-of-the-Web (T1553.005) ด้วยไฟล์ ISO/VHD/7z, ข้าม Gatekeeper บน macOS (T1553.001), sign มัลแวร์ด้วย cert ที่ขโมยมา (T1553.002)

**KQL — root certificate ใหม่**
```kql
union
  (DeviceRegistryEvents
   | where Timestamp > ago(7d)
   | where RegistryKey has_any (@"\SystemCertificates\Root\Certificates\", @"\SystemCertificates\AuthRoot\Certificates\")
   | where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
   | project Timestamp, DeviceName, InitiatingProcessFileName, Detail = RegistryKey),
  (DeviceProcessEvents
   | where Timestamp > ago(7d)
   | where (FileName =~ "certutil.exe" and ProcessCommandLine has "-addstore" and ProcessCommandLine has "root")
        or (ProcessCommandLine has "Import-Certificate" and ProcessCommandLine has @"Cert:\LocalMachine\Root")
   | project Timestamp, DeviceName, InitiatingProcessFileName, Detail = ProcessCommandLine)
```

**วิธีรับมือ** — ลบ certificate, ตรวจ proxy/traffic ที่อาจถูกดัก, ถ้าเป็น code-signing cert ขององค์กรเองที่รั่ว ให้เพิกถอนกับ CA และ re-sign ซอฟต์แวร์

**False positive** — การติดตั้ง cert ขององค์กรผ่าน GPO/Intune, ซอฟต์แวร์ TLS inspection ที่ได้รับอนุญาต

---

## T1688 Safe Mode Boot

**วิธีทำงาน** — ตั้ง `bcdedit /set {current} safeboot minimal` แล้วรีบูต เพราะ EDR/AV หลายตัวไม่ทำงานใน Safe Mode จากนั้นจึงเข้ารหัสไฟล์ (เทคนิคของ ransomware หลายกลุ่ม)

**KQL**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bcdedit.exe" and ProcessCommandLine has "safeboot"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\SYSTEM\CurrentControlSet\Control\SafeBoot\"
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
```

**วิธีรับมือ** — **Critical**: isolate ทันทีก่อนเครื่องรีบูต, ลบค่า safeboot (`bcdedit /deletevalue {current} safeboot`), ตรวจเครื่องอื่นในเครือข่ายเดียวกัน

---

## T1484 Domain or Tenant Policy Modification และ T1556 Modify Authentication Process

ทั้งสองอยู่ใน Defense Impairment ด้วย (ใช้ปิด security policy ทั้งโดเมน/tenant) — ดูรายละเอียดและ KQL ที่
[T1484 ใน Tactic 06](06-privilege-escalation.md#t1484-domain-or-tenant-policy-modification) และ [T1556 ใน Tactic 05](05-persistence.md#t1556-modify-authentication-process)

---

## Checklist ตอบสนองระดับ Tactic

- [ ] จัดเป็น **Critical** เมื่อไม่มี change ticket รองรับ — ตอบสนองภายใน 15 นาที
- [ ] Contain ด้วยวิธีที่ไม่พึ่ง sensor ที่ถูกปิด (network-level isolation, disable บัญชี)
- [ ] เปิดการป้องกันและ logging กลับ, ยืนยันว่าข้อมูลกลับมาไหลเข้า SIEM
- [ ] สร้าง timeline ช่วงที่ "มองไม่เห็น" จากแหล่งอื่น (firewall, DNS, เครื่องข้างเคียง, cloud log)
- [ ] ตรวจหา ransomware precursor: shadow copy deletion, service stop, mass file change ([Tactic 15](15-impact.md))
