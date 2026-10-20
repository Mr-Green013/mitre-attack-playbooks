# Mobile Matrix (Android / iOS) — 12 Tactics

## ภาพรวม

อุปกรณ์มือถือของพนักงานเก็บ OTP/MFA, แชตงาน, อีเมล และแอปธนาคาร ผู้โจมตีจึงมุ่งเป้าเพื่อขโมย credential และข้ามการยืนยันตัวตน
การมองเห็นบนมือถือจำกัดกว่า endpoint มาก — การตรวจจับส่วนใหญ่มาจาก **MDM/UEM (Intune)**, **Mobile Threat Defense (Defender for Endpoint on Android/iOS)** และ **sign-in logs ของ Entra ID**

## Log และเครื่องมือที่ต้องมี

| แหล่งข้อมูล | ใช้ตรวจอะไร |
|---|---|
| Intune compliance + device inventory | jailbreak/root, OS ล้าสมัย, แอปที่ติดตั้ง, sideloading |
| Defender for Endpoint (mobile) | phishing link, แอปอันตราย, network protection |
| `SigninLogs` (DeviceDetail) | การเข้าถึงจากมือถือที่ไม่ compliant, อุปกรณ์ใหม่ |
| `AuditLogs` | ลงทะเบียน device/MFA method ใหม่ (สัญญาณของ SIM swap, linked device) |
| `AlertInfo` / `AlertEvidence` | alert จาก MDE mobile |

## KQL ที่ใช้ได้ทั้ง Domain

**การเข้าถึงทรัพยากรองค์กรจากมือถือที่ไม่ compliant หรือไม่ได้จัดการ**
```kql
SigninLogs
| where TimeGenerated > ago(7d) and ResultType == "0"
| extend OS = tostring(DeviceDetail.operatingSystem), Compliant = tostring(DeviceDetail.isCompliant), Managed = tostring(DeviceDetail.isManaged)
| where OS has_any ("Android", "iOS")
| where Compliant != "true"
| summarize SignIns = count(), Apps = make_set(AppDisplayName, 10), IPs = make_set(IPAddress, 5) by UserPrincipalName, OS, Managed
| order by SignIns desc
```

**การเปลี่ยน MFA method / เบอร์โทร (SIM swap, account takeover)**
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("User registered security info", "User changed default security info", "User deleted security info",
                          "Admin registered security info", "Admin updated security info", "Admin deleted security info")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
         Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Actor, Target, ResultReason
```

**Alert จาก Defender for Endpoint บนมือถือ**
```kql
AlertInfo
| where Timestamp > ago(7d)
| join kind=inner (AlertEvidence | where Timestamp > ago(7d)) on AlertId
| where DeviceName has_any ("iPhone", "iPad", "Android") or EntityType == "MobileApp" or Title has_any ("mobile", "Android", "iOS", "phishing site")
| summarize Alerts = dcount(AlertId), Titles = make_set(Title, 10) by DeviceName, AccountUpn
```

> **สิ่งที่ต้องปรับ** — การระบุอุปกรณ์มือถือใน `AlertEvidence` ต่างกันตาม tenant ให้ตรวจค่าจริงของ `DeviceName` / `EntityType` ก่อนใช้

---

## TA0027 Initial Access

**วิธีทำงาน** — ส่ง SMS/LINE/WhatsApp (smishing, T1660) ให้ติดตั้ง APK นอก Play Store (T1476), แอปที่เคยปลอดภัยแล้วปล่อยอัปเดตอันตราย (T1661), เว็บ exploit (T1456), zero-click exploit (T1664), SIM swap (T1451), แอป/SDK ใน supply chain (T1474)

**วิธีตรวจสอบ** — MDE mobile แจ้งเตือน phishing link และแอปอันตราย; Intune รายงานแอปจาก unknown source; sign-in จากอุปกรณ์ใหม่หลังเปลี่ยนเบอร์โทร

**วิธีรับมือ** — ถอนแอป, เช็กว่าแอปได้สิทธิ์ Accessibility/Device Admin หรือไม่ (ถ้าได้ ถือว่าเครื่องถูกยึด), revoke session ของผู้ใช้, ถ้าสงสัย zero-click ให้ปิดเครื่อง เก็บ sysdiagnose/bugreport และส่งผู้เชี่ยวชาญ

**ป้องกันระยะยาว** — บล็อก unknown sources ผ่าน Intune, Android Work Profile, Lockdown Mode บน iOS สำหรับบุคคลเสี่ยงสูง, ตกลงกับผู้ให้บริการมือถือเรื่อง SIM swap PIN

## TA0041 Execution

**วิธีทำงาน** — ใช้ native code (T1575), shell บน Android ที่ root แล้ว (T1623.001), เปิดช่องโหว่ client (T1658), scheduled job (T1603)

**วิธีตรวจสอบ** — MDE/MTD จับ root/jailbreak และพฤติกรรม; Intune compliance (`Rooted/Jailbroken`)

**วิธีรับมือ** — ตั้งเครื่องเป็น non-compliant อัตโนมัติ → Conditional Access บล็อกการเข้าถึง → ให้ผู้ใช้ reset เครื่อง

## TA0028 Persistence

**วิธีทำงาน** — Broadcast Receiver ที่รันเมื่อบูต (T1624.001), foreground service (T1541), แก้ไขแอปหรือ system binary (T1577, T1645), **Linked Devices** (T1676: ผูก WhatsApp/Signal ของเหยื่อกับเครื่องผู้โจมตีผ่าน QR code)

**วิธีตรวจสอบ** — ตรวจรายการ linked devices ในแอปแชตเป็นรอบ (ไม่มี log ส่งเข้า SIEM); แอปที่ขอ Device Admin

**วิธีรับมือ** — ยกเลิก linked device ทั้งหมด, ถอนแอปที่มี Device Admin (ต้องยกเลิกสิทธิ์ก่อน), factory reset ถ้ายังไม่แน่ใจ

## TA0029 Privilege Escalation

**วิธีทำงาน** — ขอสิทธิ์ Device Administrator (T1626.001), exploit kernel เพื่อ root/jailbreak (T1404), process injection ผ่าน ptrace (T1631)

**วิธีตรวจสอบ / รับมือ** — Intune/MTD แจ้ง jailbreak/root → non-compliant → บล็อก → reset เครื่อง; อัปเดต OS ให้ทันรอบแพตช์ความปลอดภัย

## TA0030 Defense Evasion

**วิธีทำงาน** — ซ่อนไอคอนแอป (T1628.001), ดาวน์โหลดโค้ดหลังติดตั้ง (T1407 — หลบการตรวจของ store), geofencing (T1627.001), ป้องกันการถอนแอป (T1629.001), ซ่อนร่องรอย root (T1630.003), ใช้ virtualization เพื่อหลบ sandbox (T1670)

**วิธีตรวจสอบ** — MDE mobile ตรวจพฤติกรรมของแอป; Intune รายงานแอปที่ไม่มีใน allowlist แม้ไอคอนถูกซ่อน

**วิธีรับมือ** — ถอนผ่าน Intune (ไม่พึ่งผู้ใช้หาไอคอน), ถ้าถอนไม่ได้ให้ wipe work profile หรือทั้งเครื่อง

## TA0031 Credential Access

**วิธีทำงาน** — ใช้ Accessibility (T1453) อ่านหน้าจอและกดปุ่มแทนผู้ใช้, อ่าน notification ที่มี OTP (T1517), หน้าต่าง overlay ปลอมหน้า login (T1417.002), keylogging (T1417.001), ขโมย keychain บน iOS ที่ jailbreak (T1634.001), URI hijacking ขโมย OAuth code (T1635.001)

**วิธีตรวจสอบ** — sign-in สำเร็จจากอุปกรณ์/ประเทศใหม่ทันทีหลังผู้ใช้รายงานว่าติดตั้งแอปแปลก; MTD แจ้งแอปที่ใช้ Accessibility ผิดปกติ

**วิธีรับมือ** — ถือว่า credential และ OTP ทุกตัวบนเครื่องรั่ว: reset password, revoke session, ย้าย MFA ไปเครื่องใหม่ที่สะอาด, แจ้งผู้ใช้เปลี่ยนรหัสบัญชีส่วนตัวที่ใช้บนเครื่องนั้น

**ป้องกันระยะยาว** — Phishing-resistant MFA (passkey ผูกกับอุปกรณ์), number matching, จำกัด Accessibility ผ่าน Android Restricted Settings / MDM, ไม่ใช้ SMS OTP กับบัญชีสำคัญ

## TA0032 Discovery

**วิธีทำงาน** — สำรวจแอปที่ติดตั้งรวมถึงแอปความปลอดภัย (T1418), ไฟล์ (T1420), ตำแหน่ง (T1430), เครือข่าย Wi-Fi (T1422.002), สแกนเครือข่ายภายในจากมือถือที่ต่อ Wi-Fi องค์กร (T1423)

**วิธีตรวจสอบ** — NDR/firewall เห็นการสแกนจาก IP ของ Wi-Fi มือถือ; แยก VLAN ของมือถือเพื่อให้ตรวจง่าย

## TA0033 Lateral Movement

**วิธีทำงาน** — exploit บริการบนเครือข่ายจากมือถือ (T1428), แพร่ผ่าน USB ไปยังคอมพิวเตอร์ (T1458)

**วิธีรับมือ / ป้องกัน** — มือถืออยู่ใน VLAN แยกที่เข้าถึงได้เฉพาะอินเทอร์เน็ตและบริการที่จำเป็น, ปิด USB data transfer จากมือถือบนเครื่ององค์กรผ่าน device control

## TA0035 Collection

**วิธีทำงาน** — อ่าน SMS/contacts/call log/calendar (T1636), บันทึกเสียง (T1429), ถ่ายวิดีโอ (T1512), จับหน้าจอ (T1513), อ่านข้อมูลแอป (T1409), ติดตามตำแหน่ง (T1430) — ลักษณะของ spyware (Pegasus, Predator) และ stalkerware

**วิธีรับมือ** — สำหรับบุคคลเสี่ยงสูง (ผู้บริหาร, นักข่าว, ทีมเจรจา) ใช้เครื่องมือตรวจ forensic (เช่น MVT ของ Amnesty International), เปลี่ยนเครื่อง, ประเมินข้อมูลที่อาจรั่ว

## TA0037 Command and Control

**วิธีทำงาน** — HTTPS (T1437.001), web service เป็น C2 (T1481 — Firebase, Telegram), SSL pinning เพื่อกันการดัก traffic (T1521.003), DGA (T1637.001), SMS/push เป็นช่องทางนอกแบนด์ (T1644), remote access app (T1663)

**วิธีตรวจสอบ** — MDE network protection / DNS filtering บนมือถือ (เช่นผ่าน per-app VPN หรือ Defender) จับโดเมน C2 ที่รู้จัก

## TA0036 Exfiltration

**วิธีทำงาน** — ส่งข้อมูลผ่าน C2 (T1646) หรือโปรโตคอลอื่น (T1639)

**วิธีรับมือ** — block ปลายทาง, wipe เครื่อง, ประเมินข้อมูลที่อยู่บนเครื่อง (อีเมล, ไฟล์ OneDrive ที่ cache, แชต)

## TA0034 Impact

**วิธีทำงาน** — ล็อกเครื่อง/เปลี่ยน PIN (T1629.002, T1640), เข้ารหัสไฟล์ (T1471), ลบข้อมูล (T1662), ควบคุมการโทร/SMS เพื่อขโมย OTP หรือหักเงิน (T1616, T1582), แก้ข้อมูลธุรกรรม (T1641)

**วิธีรับมือ** — remote wipe ผ่าน Intune, กู้คืนจาก backup ของผู้ให้บริการ, แจ้งธนาคาร/ผู้ให้บริการมือถือถ้ามีการหักเงิน

---

## Checklist ตอบสนองเหตุบนมือถือ

- [ ] ระบุผู้ใช้, รุ่น/OS, เครื่องเป็นขององค์กร (corporate) หรือส่วนตัว (BYOD), สถานะ compliance
- [ ] ตั้ง non-compliant / บล็อกการเข้าถึงผ่าน Conditional Access ทันที
- [ ] Revoke session และ reset password; ย้าย MFA ไปเครื่องที่สะอาด
- [ ] BYOD: wipe เฉพาะ work profile / app data (selective wipe) — corporate: full wipe หลังเก็บหลักฐาน
- [ ] ตรวจ linked devices ของแอปแชต และ MFA method ที่ถูกเพิ่ม
- [ ] ทบทวนนโยบาย: unknown sources, OS ขั้นต่ำ, app allowlist
