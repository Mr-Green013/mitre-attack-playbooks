# 🛡️ MITRE ATT&CK® v20.0 All-in-One Interactive Mind Map, Threat Groups, Attack Campaigns & Playbooks Studio

[![MITRE ATT&CK v20.0](https://img.shields.io/badge/MITRE%20ATT%26CK-v20.0%20%28935%20TTPs%29-indigo)](https://attack.mitre.org/)
[![Threat Groups](https://img.shields.io/badge/APT%20Groups-182%20Groups%20%2B%2016%20Deep%20Dossiers-rose)](https://attack.mitre.org/groups/)
[![Campaigns](https://img.shields.io/badge/Campaigns-61%20Official%20Campaigns-cyan)](https://attack.mitre.org/campaigns/)
[![Adversary Comms](https://img.shields.io/badge/Adversary%20Dialogues-Vishing%20%7C%20Teams%20%7C%20Tor%20Ransomware-amber)](https://github.com/Mr-Green013/mitre-attack-playbooks)

คลังฐานข้อมูลและเว็บแอปพลิเคชันแบบโต้ตอบ **MITRE ATT&CK® v20.0** ฉบับสมบูรณ์สำหรับทีม **SOC / Blue Team**, **Red Team / Pentest**, **Cyber Threat Intelligence (CTI)** และ **CISO / Compliance**

## 🚀 โครงสร้างข้อมูลและ 8 โมดูลหลักในระบบ
1. **🌌 Interactive Mind Map (Constellation & Spider View)**: แผนผังโต้ตอบครอบคลุม 3 Domains (`Enterprise`, `Mobile`, `ICS/OT`), **18 Sub-domains**, **39 Tactics**, **383 Techniques** และ **552 Sub-techniques** (รวม **935 TTPs**)
2. **📊 Kill-Chain Matrix**: ตารางยุทธวิธีเรียงตามลำดับขั้นตอนการโจมตี พร้อมตัวกรองเจาะจงราย Sub-domain ทั้ง 18 แพลตฟอร์ม
3. **🕵️ Threat Intelligence & Adversary Operations (`APT & Malware` - 4 หมวดย่อย)**:
   - **กลุ่มผู้โจมตี & รายละเอียดการโจมตี (182 MITRE Groups + 16 Deep Dossiers)**: เจาะลึกลำดับขั้นตอนการโจมตี (Step-by-Step Kill Chain) ของ `APT29 (G0016)`, `APT28 (G0007)`, `Lazarus Group (G0032)`, `Contagious Interview (G1052)`, `Sandworm Team (G0034)`, `Volt Typhoon (G1017)`, `Salt Typhoon (G1045)`, `APT41 (G0096)`, `Mustang Panda (G0129)`, `Kimsuky (G0094)`, `OilRig (G0049)`, `Scattered Spider (G1015)`, `Storm-1811 / Black Basta (G1046)`, `Akira (G1024)`, `LockBit 3.0 (S0002)` และ `TeamPCP (G1056)` พร้อมสารบบครบทั้ง 182 กลุ่ม (`G0001`–`G1059`)
   - **💬 การพูดคุย ล่อลวง & เจรจาต่อรอง (5 ห้องแชตจำลองจากเหตุการณ์จริง)**: บทสนทนา Vishing หลอก IT Helpdesk รีเซ็ต MFA, แชต Microsoft Teams ลวงให้กด `Ctrl+Win+Q` Quick Assist, แชต LinkedIn หลอกนักพัฒนาสัมภาษณ์งาน (`BeaverTail` / `InvisibleFerret`), ห้องแชตเจรจาค่าไถ่บน Tor Dark Web และบอต C2 บน Telegram / ตลาดซื้อขายสิทธิ์ Initial Access Broker
   - **⚔️ ฐานข้อมูลการโจมตี & แคมเปญ (ครบทั้ง 61 MITRE Campaigns: `C0001`–`C0066`)**: รวมถึงแคมเปญปี 2025–2026 ล่าสุด เช่น `C0063` (Poland Wiper), `C0066` (U.S. Water Utilities), `C0064` (AI-Assisted Breach), `C0062` (AI-orchestrated Campaign), `C0054` (Operation Triangulation), `C0046` (ArcaneDoor) และ `C0024` (SolarWinds Compromise)
   - **🧰 วิธีการโจมตี คำสั่ง CLI & มัลแวร์ประจำกลุ่ม (`Attack Methods & Tradecraft`)**: ตัวอย่างคำสั่ง Command-Line จริง (HTML Smuggling, LOLBins, BYOVD, LSASS Dump/DCSync, Netsh Portproxy/Rclone, ESXi & PLC Sabotage) พร้อมแนวทางตรวจจับด้วย SIEM/EDR
4. **📖 Operational Role Playbooks**: คู่มือปฏิบัติการแยกตามบทบาท SOC/Blue Team, Red Team, CTI และ Purple Team
5. **📚 Full Database Explorer (1,690+ Objects)**: ค้นหาและกรอง TTPs, Mitigations (`Mxxxx`), Data Sources (`DSxxxx`), Detection Strategies (`DETxxxx`), ICS Assets (`A0001`–`A0018`), Groups (`Gxxxx`) และ Campaigns (`Cxxxx`)
6. **🗺️ Custom Mapping Studio & Auto-Mapper**: แปลงข้อความ Incident Log หรือส่งลำดับ Kill Chain ของกลุ่มแฮกเกอร์เข้าสู่วาดกราฟ Attack Flow อัตโนมัติ
7. **🛡️ SIEM & Compliance Coverage Heatmap**: แมปความเชื่อมโยงระหว่าง **SIEM Use Cases ↔ MITRE ATT&CK® v20.0 ↔ ISO/IEC 27001:2022 ↔ NIST CSF 2.0 ↔ PDPA Thailand (มาตรา 37)**
8. **🌐 Network Topology & Data Flow Diagram (DFD) Studio**: วาดผังเครือข่าย 5 Security Zones และจำลองรัศมีผลกระทบเมื่อถูกเจาะ (**Blast Radius Simulation**)

## 📘 Playbooks: วิธีการทำงาน / วิธีตรวจสอบ (KQL) / วิธีรับมือ

คู่มือ Markdown แยกราย Tactic สำหรับ SOC / IR: แต่ละ Technique มีวิธีทำงานของผู้โจมตี, สัญญาณที่ต้องดู, KQL สำหรับ Microsoft Sentinel / Defender XDR, ขั้นตอนรับมือ และมาตรการป้องกันระยะยาว

- [วิธีใช้คู่มือ, IR lifecycle, ระดับความรุนแรง, Log ที่ต้องเปิด](docs/00-how-to-use.md)
- [Mobile (Android / iOS) — 12 Tactics](mobile/README.md)
- [ICS / OT — 12 Tactics + ICS Assets A0001–A0018](ics/README.md)
- [แม่แบบสำหรับเพิ่ม Technique ใหม่](templates/tactic-template.md)

| # | Enterprise Tactic | Playbook |
|---|---|---|
| 01 | TA0043 Reconnaissance | [enterprise/01-reconnaissance.md](enterprise/01-reconnaissance.md) |
| 02 | TA0042 Resource Development | [enterprise/02-resource-development.md](enterprise/02-resource-development.md) |
| 03 | TA0001 Initial Access | [enterprise/03-initial-access.md](enterprise/03-initial-access.md) |
| 04 | TA0002 Execution | [enterprise/04-execution.md](enterprise/04-execution.md) |
| 05 | TA0003 Persistence | [enterprise/05-persistence.md](enterprise/05-persistence.md) |
| 06 | TA0004 Privilege Escalation | [enterprise/06-privilege-escalation.md](enterprise/06-privilege-escalation.md) |
| 07 | TA0005 Stealth | [enterprise/07-stealth.md](enterprise/07-stealth.md) |
| 08 | TA0112 Defense Impairment | [enterprise/08-defense-impairment.md](enterprise/08-defense-impairment.md) |
| 09 | TA0006 Credential Access | [enterprise/09-credential-access.md](enterprise/09-credential-access.md) |
| 10 | TA0007 Discovery | [enterprise/10-discovery.md](enterprise/10-discovery.md) |
| 11 | TA0008 Lateral Movement | [enterprise/11-lateral-movement.md](enterprise/11-lateral-movement.md) |
| 12 | TA0009 Collection | [enterprise/12-collection.md](enterprise/12-collection.md) |
| 13 | TA0011 Command and Control | [enterprise/13-command-and-control.md](enterprise/13-command-and-control.md) |
| 14 | TA0010 Exfiltration | [enterprise/14-exfiltration.md](enterprise/14-exfiltration.md) |
| 15 | TA0040 Impact | [enterprise/15-impact.md](enterprise/15-impact.md) |

> KQL ทุกชุดเป็นจุดเริ่มต้นสำหรับ hunting — ทดสอบกับข้อมูลจริงใน tenant และปรับ threshold ก่อนตั้งเป็น Analytics Rule

## 📂 โครงสร้างไฟล์ใน Repository
- `index.html` — เว็บแอปพลิเคชันแบบ All-in-One (เปิดใช้งานผ่าน GitHub Pages ได้ทันที)
- `docs/`, `enterprise/`, `mobile/`, `ics/`, `templates/` — Playbooks ราย Tactic (ตารางด้านบน)
- `playbooks/THREAT_GROUPS_AND_ATTACK_CAMPAIGNS_TH.md` — เอกสารสรุปแฟ้มเจาะลึก 16 กลุ่มผู้โจมตี, ลำดับ Kill Chain และบทสนทนาการล่อลวง/เจรจาค่าไถ่
- `playbooks/mitre_playbooks_v20.json` — ฐานข้อมูล JSON ฉบับสมบูรณ์ (APT Dossiers, Adversary Communications, CLI Tradecraft, 182 Groups, 61 Campaigns)
- `README.md` — คู่มือการใช้งานและการเปิด GitHub Pages

## 🌐 การเปิดใช้งานผ่าน GitHub Pages
1. ไปที่ **Settings → Pages** ของ Repository
2. เลือก **Source: Deploy from a branch**, branch **`main`**, โฟลเดอร์ **`/ (root)`** แล้วกด **Save**
3. รอ 1–2 นาที แล้วเปิด `https://mr-green013.github.io/mitre-attack-playbooks/`

## 🔐 หมายเหตุด้านความปลอดภัย
- ข้อความที่ผู้ใช้กรอก (โน้ต, Mapping Studio, SIEM rule, Network map) และข้อมูลที่เคยบันทึกใน `localStorage` ถูกแปลงอักขระ `< > " ' & \` เป็นตัวอักษรเต็มความกว้างก่อนแสดงผล เพื่อป้องกัน XSS
- ปุ่ม **Push to GitHub** ในหน้าเว็บส่ง Personal Access Token จากเบราว์เซอร์ไปที่ `api.github.com` โดยตรง (ไม่ได้เก็บลงเครื่อง) — ใช้ **fine-grained token** ที่จำกัดเฉพาะ repo นี้ สิทธิ์ *Contents: Read and write* และตั้งวันหมดอายุสั้น
- ปุ่มนี้เขียนทับ `README.md`, `index.html` และ `playbooks/mitre_playbooks_v20.json` ใน repo ทุกครั้งที่กด
- หน้าเว็บโหลด Tailwind (play CDN) และ Google Fonts จากภายนอก
