# 🕵️ ฐานข้อมูลกลุ่มผู้โจมตี (APT Groups), แคมเปญการโจมตี (Campaigns), วิธีการลงมือ และบทสนทนาล่อลวง/เจรจาต่อรอง

เอกสารสรุปข่าวกรองภัยคุกคามจาก **MITRE ATT&CK® v20.0** สำหรับคลัง [Mr-Green013/mitre-attack-playbooks](https://github.com/Mr-Green013/mitre-attack-playbooks)

## 1. แฟ้มเจาะลึก 16 กลุ่มผู้โจมตีและเครือข่ายแรนซัมแวร์สำคัญ (Deep Group Dossiers)

### [G0016] APT29 (Cozy Bear / Midnight Blizzard / NOBELIUM)
- **ต้นสังกัด / ภูมิภาค**: Russia (SVR Foreign Intelligence Service) (2008 – ปัจจุบัน)
- **เป้าหมายหลัก**: หน่วยงานรัฐบาล, กระทรวงการต่างประเทศ, คลังสมอง (Think Tanks), ผู้ให้บริการ Cloud & IT Supply Chain (Microsoft 365 / Entra ID)
- **สรุปพฤติกรรม**: กลุ่มจารกรรมไซเบอร์ระดับสูงของหน่วยข่าวกรองต่างประเทศรัสเซีย (SVR) เชี่ยวชาญการแทรกซึมแบบไร้ร่องรอย (Stealth), การวางยา Supply Chain (C0024 SolarWinds SUNBURST), การปลอมแปลงโทเคนยืนยันตัวตน (Golden SAML / OAuth App Abuse) และการโจมตี Microsoft Teams Vishing
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: แอบอ้างเป็นทีม IT Security ผ่าน Microsoft Teams External Chat ล่อให้เป้าหมายกรอกรหัส Device Code Phishing หรือใช้บัญชีธุรกิจที่ยึดมาส่งลิงก์ OneDrive/PDF ที่ผ่านการเข้ารหัส
- **มัลแวร์และเครื่องมือ**: S0559 SUNBURST, S0560 TEARDROP, S0567 GoldMax, S0154 Cobalt Strike, S0603 EnvyScout
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Initial Access (`T1195.002 / T1566.002`)**: ฝัง Backdoor ในอัปเดตซอฟต์แวร์ (SolarWinds Orion SUNBURST) หรือทำ Password Spraying / Device Code Phishing เข้าสู่ Cloud Tenant
  - **2. Execution & Persistence (`T1098.001 / T1671`)**: เพิ่ม Client Secret/Certificate ใหม่ใน Entra ID Service Principal และผูกสิทธิ์ OAuth App (Mail.ReadWrite) เพื่อคงสิทธิ์ถาวร
  - **3. Credential Access (`T1606.002 / T1003.006`)**: ขโมยใบรับรอง ADFS Token-Signing เพื่อสร้างตั๋ว Golden SAML หรือรัน DCSync ดึงรหัสผ่านทั้งโดเมน
  - **4. Stealth & Defense Impairment (`T1685.002 / T1027`)**: ปิดหรือดัดแปลง Cloud Audit Logs, ตั้งชื่อโปรเซสและโดเมน C2 ให้ตรงกับโครงสร้างพื้นฐานขององค์กรเหยื่อ
  - **5. Collection & Exfiltration (`T1114.002 / T1041`)**: ดึงข้อมูลอีเมลของผู้บริหารและงานวิจัยด้านความมั่นคงผ่าน Microsoft Graph API แล้วส่งออกผ่าน HTTPS C2

### [G0007] APT28 (Fancy Bear / Forest Blizzard / Sofacy / GRU)
- **ต้นสังกัด / ภูมิภาค**: Russia (GRU Unit 26165) (2004 – ปัจจุบัน)
- **เป้าหมายหลัก**: กระทรวงกลาโหม, กองทัพ, รัฐสภา, องค์กรพลังงาน, การบิน, สื่อมวลชน และโครงสร้างพื้นฐานโลจิสติกส์
- **สรุปพฤติกรรม**: หน่วยข่าวกรองทางทหารของรัสเซีย (GRU Unit 26165) มีความเชี่ยวชาญในการส่ง Spearphishing, การใช้ช่องโหว่ Zero-Day บน Webmail/Outlook/Edge Routers และการทำ Nearest Neighbor Wi-Fi Hopping (C0051)
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: ส่งอีเมล Spearphishing ที่อ้างอิงเหตุการณ์ความมั่นคงหรือเอกสารราชการจริง พร้อมแนบลิงก์ Credential Harvesting หรือใช้ช่องโหว่ปฏิทิน Outlook (CVE-2023-23397) ดึง Net-NTLMv2 Hash โดยเหยื่อไม่ต้องคลิก
- **มัลแวร์และเครื่องมือ**: S0045 Zebrocy, S0002 Mimikatz, S0148 X-Agent, S0363 Empire, GooseEgg
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Initial Access (`T1566.001 / T1669`)**: ส่งอีเมล Spearphishing หรือเจาะเครือข่ายองค์กรข้างเคียงแล้วเชื่อมต่อเข้า Wi-Fi ของเป้าหมาย (C0051 Nearest Neighbor)
  - **2. Forced Auth & Creds (`T1187 / T1110.003`)**: บังคับให้เครื่องเหยื่อส่ง NTLM Hash ผ่าน UNC Path ไปยังเซิร์ฟเวอร์ WebDAV/SMB ของผู้โจมตีและทำ Password Spraying
  - **3. Privilege Escalation (`T1068 / T1055`)**: ยกระดับสิทธิ์ด้วยเครื่องมือ GooseEgg (ช่องโหว่ Windows Print Spooler driver) เพื่อขึ้นเป็น SYSTEM
  - **4. Lateral Movement (`T1021.002 / T1053.005`)**: สร้าง Scheduled Tasks และเคลื่อนย้ายข้ามเซิร์ฟเวอร์ผ่าน SMB/WinRM
  - **5. Collection & Exfiltration (`T1114.003 / T1567.002`)**: ตั้งกฎส่งต่ออีเมลและอัปโหลดเอกสารความลับออกไปยัง Cloud Storage

### [G0032] Lazarus Group (Diamond Sleet) & APT38 (G0082)
- **ต้นสังกัด / ภูมิภาค**: North Korea (RGB Reconnaissance General Bureau) (2009 – ปัจจุบัน)
- **เป้าหมายหลัก**: ธนาคารและระบบ SWIFT, ตลาดแลกเปลี่ยน Cryptocurrency, บริษัทพัฒนาซอฟต์แวร์, อุตสาหกรรมป้องกันประเทศและเซมิคอนดักเตอร์
- **สรุปพฤติกรรม**: กลุ่มปฏิบัติการหลักของเกาหลีเหนือที่ควบคู่ทั้งการจารกรรมระดับชาติและการปล้นสินทรัพย์ดิจิทัล/ธนาคาร (APT38) เชี่ยวชาญการหลอกสัมภาษณ์งานสาย Tech (Operation Dream Job C0022) และการโจมตี Software Supply Chain (3CX C0057)
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: สวมรอยเป็น Headhunter / Senior Tech Recruiter บน LinkedIn และ GitHub ทักแชตชวนวิศวกรสัมภาษณ์งานเงินเดือนสูง แล้วส่งไฟล์โจทย์ทดสอบเขียนโค้ด (Trojanized PDF/ZIP/GitHub Repo) ให้รันบนเครื่องทำงาน
- **มัลแวร์และเครื่องมือ**: S1070 APPLEJEUS, S0446 MagicRAT, S0692 BlindingCan, S0139 WannaCry, S0670 Dtrack
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Social Engineering Lure (`T1598.001 / T1566.003`)**: ทักแชตผ่าน LinkedIn/Telegram ในแคมเปญ Operation Dream Job (C0022) ส่งไฟล์งานปลอมหรือซอฟต์แวร์คริปโตฝังโทรจัน (APPLEJEUS)
  - **2. Execution & DLL Sideloading (`T1574.001 / T1218.011`)**: ใช้เทคนิค DLL Search Order Hijacking อาศัยโปรแกรมที่มีใบรับรองถูกต้องโหลดโค้ดอันตรายเข้าสู่หน่วยความจำ
  - **3. Credential Theft (`T1555.003 / T1552.004`)**: ดึงรหัสผ่านจากเบราว์เซอร์, ไฟล์ .env, SSH Private Keys และคุกกี้เข้าถึงระบบ Cloud/Crypto Wallet
  - **4. Lateral Movement (`T1021.001 / T1021.004`)**: เคลื่อนย้ายผ่าน SSH และ RDP เข้าสู่เซิร์ฟเวอร์ Build Pipeline หรือเซิร์ฟเวอร์ธุรกรรมการเงิน
  - **5. Impact / Heist (`T1657 / T1485`)**: โอนถ่ายสินทรัพย์ดิจิทัล/การเงิน (Financial Theft) และปล่อย Wiper ลบข้อมูลเพื่อทำลายหลักฐาน

### [G1052] Contagious Interview (DeceptiveDevelopment / DEV#POPPER)
- **ต้นสังกัด / ภูมิภาค**: North Korea (2023 – ปัจจุบัน)
- **เป้าหมายหลัก**: นักพัฒนาซอฟต์แวร์ Full-Stack, วิศวกร Web3 / Blockchain, DevOps และบริษัทเทคโนโลยีทั่วโลก
- **สรุปพฤติกรรม**: กลุ่มภัยคุกคามเกาหลีเหนือยุคใหม่ที่มุ่งเป้าเจาะเครื่องนักพัฒนาซอฟต์แวร์โดยเฉพาะผ่านการสัมภาษณ์งานออนไลน์ปลอม โดยหลอกให้ git clone และรันโปรเจกต์ Node.js/Python/React ที่ฝังมัลแวร์ BeaverTail และ InvisibleFerret
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: พูดคุยเป็นกันเองเหมือน CTO หรือ Tech Lead ของสตาร์ทอัพ Web3/AI ขอให้ผู้สมัครแก้โจทย์ Bug เล็กๆ ใน GitHub/Bitbucket Repo ภายใน 30 นาที หรือแจ้งว่ากล้อง/ไมค์ในระบบประชุมไม่ทำงานเพื่อให้รันสคริปต์แก้ไข
- **มัลแวร์และเครื่องมือ**: BeaverTail (JS InfoStealer), InvisibleFerret (Python RAT), AnyDesk
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Fake Job Interview (`T1585.001 / T1683.001`)**: สร้างโปรไฟล์บริษัทปลอมบน LinkedIn และทักชวนนักพัฒนาทำแบบทดสอบ Technical Assessment
  - **2. Malicious Repo Execution (`T1204.005 / T1059.007`)**: เหยื่อรัน npm install / npm start บนโปรเจกต์ทดสอบ ซึ่งมีโค้ด JavaScript ที่ถูกพรางตัว (BeaverTail) ทำงานเบื้องหลัง
  - **3. Second-Stage Python RAT (`T1059.006 / T1105`)**: BeaverTail ดาวน์โหลด Python portable environment พร้อมรัน InvisibleFerret backdoor ข้ามแพลตฟอร์ม (Windows/macOS/Linux)
  - **4. Credential & Wallet Harvesting (`T1555.003 / T1552.001`)**: กวาดข้อมูล Browser Login Data, ส่วนขยายกระเป๋าคริปโต (MetaMask/Phantom), macOS Keychain และไฟล์ .env / SSH Keys
  - **5. Remote Persistence (`T1219.002 / T1041`)**: แอบติดตั้งสคริปต์ควบคุมระยะไกลและส่งออกซอร์สโค้ดรวมถึงคีย์ลับทั้งหมดไปยังเซิร์ฟเวอร์ C2

### [G0034] Sandworm Team (APT44 / Seashell Blizzard / Voodoo Bear)
- **ต้นสังกัด / ภูมิภาค**: Russia (GRU Unit 74455) (2009 – ปัจจุบัน)
- **เป้าหมายหลัก**: โรงไฟฟ้าและโครงข่ายพลังงาน (Power Grid), ระบบน้ำประปาและระบบทำความร้อน, โทรคมนาคม, หน่วยงานรัฐ และระบบควบคุมอุตสาหกรรม (ICS/OT)
- **สรุปพฤติกรรม**: หน่วยปฏิบัติการสงครามไซเบอร์เชิงทำลายล้างของ GRU Unit 74455 ผู้อยู่เบื้องหลังการตัดกระแสไฟฟ้าในยูเครน (2015 C0028, 2016 C0025, 2022 C0034), มัลแวร์ล้างโลก NotPetya และแคมเปญ Wiper โจมตีโครงสร้างพื้นฐานในยุโรป
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: เน้นปฏิบัติการทำลายล้างแบบไร้การเจรจา (No-negotiation Wiper / Fake Ransomware) และใช้ช่องทาง Telegram Hacktivist Persona บังหน้าในการประกาศความรับผิดชอบเพื่อสร้างผลกระทบทางจิตวิทยา
- **มัลแวร์และเครื่องมือ**: S0604 Industroyer / Industroyer2, S0368 NotPetya, S0693 CaddyWiper, S0089 BlackEnergy, S0691 AwfulShred
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. IT Perimeter Breach (`T1190 / T1505.003`)**: เจาะช่องโหว่ Edge Appliance หรือวาง Web Shell (Neo-REGEORG) บนเซิร์ฟเวอร์ที่เชื่อมต่ออินเทอร์เน็ต
  - **2. IT-to-OT Pivot (`T1078 / T0886`)**: ขโมยรหัสผ่านจาก Active Directory แล้วกระโดดข้าม Jump Host เข้าสู่โซน OT / SCADA Control Center
  - **3. ICS Protocol Manipulation (`T0836 / T1692.001`)**: ใช้ Industroyer2 ส่งคำสั่งโปรโตคอล IEC 60870-5-104 / Modbus / OPC สั่งเปิดเบรกเกอร์สถานีไฟฟ้าย่อยโดยตรง
  - **4. Inhibit Response Function (`T0878 / T1695.001`)**: ตัดช่องทางสื่อสาร Serial COM / Ethernet และปิดระบบแจ้งเตือนบนหน้าจอ HMI เพื่อถ่วงเวลาการกู้คืนของวิศวกร
  - **5. Multi-Platform Data Wipe (`T1561.002 / T0809`)**: ปล่อย CaddyWiper (Windows) และ AwfulShred (Linux/Solaris) ลบดิสก์เซิร์ฟเวอร์ทั้งหมดพร้อมกันผ่าน GPO

### [G1017] Volt Typhoon (BRONZE SILHOUETTE / Vanguard Panda)
- **ต้นสังกัด / ภูมิภาค**: China (PRC State-Sponsored) (2021 – ปัจจุบัน)
- **เป้าหมายหลัก**: โครงสร้างพื้นฐานสำคัญระดับชาติ (พลังงาน, น้ำประปา, คมนาคม, ท่าเรือ, โทรคมนาคม และฐานทัพ)
- **สรุปพฤติกรรม**: กลุ่มผู้โจมตีที่เน้นการฝังตัวระยะยาวในโครงสร้างพื้นฐานสำคัญโดยแทบไม่ใช้มัลแวร์เลย (100% Living-off-the-Land / LOTL) อาศัยการยึดเราเตอร์ SOHO มาทำเป็นเครือข่าย Proxy (KV Botnet C0035) เพื่อกลืนไปกับทราฟฟิกปกติ
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: ไม่มีการติดต่อสื่อสารกับเหยื่อเลย ทุกคำสั่งรันผ่าน CLI มาตรฐานของระบบ (`wmic`, `ntdsutil`, `netsh`, `powershell`) ผ่านท่อ Proxy ของอุปกรณ์เครือข่ายในประเทศเดียวกัน
- **มัลแวร์และเครื่องมือ**: S0002 Mimikatz, Impacket, FRP (Fast Reverse Proxy), Native Windows LOTL Binaries
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Operational Relay Box (ORB) (`T1584.008 / T1090.003`)**: ยึดเราเตอร์และไฟร์วอลล์ที่หมดอายุการสนับสนุน (KV Botnet) เพื่อใช้เป็น Multi-hop Proxy ซ่อน IP ต้นทาง
  - **2. Edge Appliance Exploit (`T1190 / T1133`)**: เจาะช่องโหว่ Zero-Day บนระบบ VPN/Firewall/SD-WAN (เช่น Fortinet, Ivanti, Citrix, Versa Director)
  - **3. NTDS.dit Credential Extraction (`T1003.003 / T1047`)**: ใช้คำสั่ง `wmic` และ `ntdsutil.exe "ac i ntds" "ifm"` สร้างสำเนาฐานข้อมูล Active Directory เพื่อดึงรหัสผ่านทุกบัญชี
  - **4. Portproxy LOTL Tunneling (`T1090.001 / T1021.001`)**: รันคำสั่ง `netsh interface portproxy add v4tov4` บนเซิร์ฟเวอร์ภายในเพื่อส่งต่อทราฟฟิก RDP/SMB เข้าสู่โซนควบคุม OT
  - **5. Selective Log Clearing (`T1685.005 / T1070.003`)**: ลบเฉพาะบรรทัด Event Log และประวัติคำสั่งที่เกี่ยวข้องกับการล็อกอินของตนเพื่อรักษาการฝังตัวนานหลายปี

### [G1045] Salt Typhoon (GhostEmperor / FamousSparrow Nexus)
- **ต้นสังกัด / ภูมิภาค**: China (PRC State-Sponsored) (2019 – ปัจจุบัน)
- **เป้าหมายหลัก**: ผู้ให้บริการโทรคมนาคมระดับประเทศ (ISP / Telecom Carriers), โครงข่าย Core Router และระบบดักฟังตามกฎหมาย
- **สรุปพฤติกรรม**: กลุ่มจารกรรมระดับสูงที่มุ่งเจาะโครงสร้างพื้นฐานของผู้ให้บริการอินเทอร์เน็ตและโทรคมนาคม โดยเข้าควบคุม Core Routers / Switches เพื่อดักจับข้อมูลทราฟฟิกและเมทาดาทาการสื่อสาร
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: ฝังตัวเงียบในระดับ Firmware/IOS ของเราเตอร์และสวิตช์หลัก ใช้พอร์ตบริหารจัดการและแก้ไขตาราง Routing/SPAN เพื่อคัดลอกทราฟฟิกออกไปโดยไม่กระทบความเร็วเครือข่าย
- **มัลแวร์และเครื่องมือ**: J-magic (cd00r BPF Backdoor), Demodex Rootkit, GhostSpider
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Network Edge Compromise (`T1190 / T1078`)**: เจาะอุปกรณ์เครือข่ายและเซิร์ฟเวอร์บริหารจัดการของค่ายโทรคมนาคม
  - **2. Passive BPF Backdoor (`T1205.002 / T1014`)**: ติดตั้ง Backdoor ที่ใช้ Socket Filters (eBPF / cd00r) รอรับ Magic Packet พิเศษก่อนเปิดเชลล์โดยไม่เปิดพอร์ตค้างไว้
  - **3. TACACS+ / RADIUS Sniffing (`T1040 / T1552.004`)**: ดักฟังข้อมูลรับรองของวิศวกรเครือข่ายและดึงคอนฟิกจากอุปกรณ์ผ่าน SNMP/CLI (T1602.002)
  - **4. System Image Modification (`T1601.001 / T1098.004`)**: แก้ไขไฟล์อิมเมจของอุปกรณ์เครือข่ายและฝังคีย์ SSH เพื่อคงสิทธิ์แม้มีการรีบูต
  - **5. Traffic Duplication Exfil (`T1020.001`)**: ตั้งค่าพอร์ต Mirror / GRE Tunnel เพื่อส่งสำเนาทราฟฟิกเป้าหมายออกไปยังโหนดรวบรวมข้อมูล

### [G0096] APT41 (Wicked Panda / Brass Typhoon / BARIUM)
- **ต้นสังกัด / ภูมิภาค**: China (2012 – ปัจจุบัน)
- **เป้าหมายหลัก**: โทรคมนาคม, ยาและสาธารณสุข, เซมิคอนดักเตอร์, บริษัทพัฒนาเกมออนไลน์, โลจิสติกส์ และการบิน
- **สรุปพฤติกรรม**: กลุ่มภัยคุกคามสองบทบาทที่ทำงานจารกรรมข้อมูลเทคโนโลยีในเวลากลางวัน และปฏิบัติการโจมตีเพื่อผลประโยชน์ทางการเงิน (เช่น ขโมยใบรับรอง Code Signing และสกุลเงินในเกม) ในเวลากลางคืน
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: ส่ง Spearphishing ที่ปรับแต่งเนื้อหาเฉพาะองค์กร หรือแทรกซึมผ่านระบบอัปเดตซอฟต์แวร์พร้อมใช้ใบรับรองดิจิทัลที่ขโมยมาเซ็นกำกับมัลแวร์
- **มัลแวร์และเครื่องมือ**: S0448 ShadowPad, S0154 Cobalt Strike, S0013 PlugX, DustPan, DustTrap
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Public Web App Exploit (`T1190`)**: ใช้ช่องโหว่ SQL Injection, Deserialization หรือ RCE บนเว็บแอปพลิเคชันขององค์กรเพื่อวาง Web Shell
  - **2. Signed Loader & DLL Hijack (`T1553.002 / T1574.001`)**: วางไฟล์ไบนารีถูกต้องที่มีใบรับรองดิจิทัลคู่กับไฟล์ DLL อันตราย (ShadowPad / DustPan) เพื่อโหลดเข้าหน่วยความจำ
  - **3. Kernel Rootkit & Stealth (`T1014 / T1055.012`)**: ติดตั้งไดรเวอร์ระดับ Kernel หรือทำ Process Hollowing ซ่อนตัวใน `svchost.exe`
  - **4. Cloud Web Service C2 (`T1102.002 / T1071.004`)**: ใช้ Google Workspace, Cloudflare Workers และ DNS Tunneling เป็นช่องทางควบคุม C2 (แคมเปญ APT41 DUST C0040)
  - **5. Intellectual Property Theft (`T1560.001 / T1567.002`)**: บีบอัดซอร์สโค้ดและฐานข้อมูลวิจัยแล้วอัปโหลดออกไปยัง Cloud Storage

### [G0129] Mustang Panda ( Earth Preta / Bronze President / Stately Taurus )
- **ต้นสังกัด / ภูมิภาค**: China (2012 – ปัจจุบัน)
- **เป้าหมายหลัก**: หน่วยงานภาครัฐในเอเชียตะวันออกเฉียงใต้ (ASEAN), สถานทูต, องค์กรความร่วมมือระหว่างประเทศ และสถาบันวิจัย
- **สรุปพฤติกรรม**: กลุ่มจารกรรมไซเบอร์ที่เคลื่อนไหวอย่างหนักในภูมิภาคเอเชียตะวันออกเฉียงใต้และยุโรป มีเอกลักษณ์คือการใช้เอกสารล่อเหยื่อเรื่องการประชุมอาเซียน/นโยบายรัฐ ควบคู่กับการแพร่กระจายผ่าน USB Flash Drive และมัลแวร์ตระกูล PlugX / ToneShell
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: ส่งอีเมลแนบลิงก์ Google Drive / Dropbox ที่โหลดไฟล์ `.zip` หรือ `.iso` ข้างในมีไฟล์ทางลัด `.lnk` ตั้งชื่อเป็นวาระการประชุมระดับภูมิภาค เมื่อคลิกจะเปิดเอกสารจริงขึ้นบังหน้าพร้อมแอบรัน PlugX เบื้องหลัง
- **มัลแวร์และเครื่องมือ**: S0013 PlugX (Korplug), S1139 ToneShell, PUBLOAD, SmugX
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Diplomatic Lure & USB Worm (`T1566.002 / T1091`)**: ส่งลิงก์ดาวน์โหลดไฟล์ Archive (`.iso`/`.zip`) หรือแพร่กระจายผ่าน USB Drive ที่ซ่อนไฟล์จริงไว้ในโฟลเดอร์ Hidden
  - **2. DLL Side-Loading (Triad) (`T1574.001 / T1564.001`)**: ใช้ชุดไฟล์ 3 ชิ้น (ไฟล์ `.exe` ที่เซ็นชื่อถูกต้อง + ไฟล์ `.dll` โหลดเดอร์ + ไฟล์ข้อมูลเข้ารหัส `.dat`) เพื่อรัน PlugX หรือ ToneShell
  - **3. Registry Persistence (`T1547.001`)**: สร้างคีย์ใน `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` ให้ทำงานทุกครั้งที่เปิดเครื่อง
  - **4. Automated Document Staging (`T1119 / T1560.001`)**: สแกนหาไฟล์ `.doc`, `.docx`, `.pdf`, `.xls` ทั้งเครื่องและในไดรฟ์แชร์ แล้วบีบอัดด้วย `rar.exe` แบบแบ่งพาร์ต
  - **5. Custom TLS C2 Exfiltration (`T1071.001 / T1573`)**: ส่งไฟล์เอกสารออกผ่านทราฟฟิก HTTPS ที่ปลอมแปลงส่วนหัว (Fake TLS Handshake)

### [G0049] OilRig (APT34 / Hazel Sandstorm) & MuddyWater (G0069)
- **ต้นสังกัด / ภูมิภาค**: Iran (MOIS) (2014 – ปัจจุบัน)
- **เป้าหมายหลัก**: พลังงานและปิโตรเคมี, โทรคมนาคม, ธนาคาร, หน่วยงานรัฐบาล และระบบสาธารณูปโภค
- **สรุปพฤติกรรม**: กลุ่มปฏิบัติการหลักของอิหร่านที่เชี่ยวชาญการเจาะเซิร์ฟเวอร์ Microsoft Exchange, การใช้ DNS Tunneling / อีเมลเป็นช่องทาง C2 และการนำซอฟต์แวร์ RMM สำเร็จรูป (SimpleHelp, Atera, ScreenConnect) มาใช้ควบคุมเครื่องเหยื่อ
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: ส่งอีเมล Phishing แนบลิงก์ OneDrive/SharePoint ที่ชี้ไปยังสคริปต์ติดตั้งโปรแกรมรีโมต RMM ของแท้ เพื่อให้ฝ่าย IT เข้าใจผิดคิดว่าเป็นเครื่องมือช่วยเหลือทางไกลปกติ
- **มัลแวร์และเครื่องมือ**: S0138 POWRUNER, S0252 BONDUPDATER, Mango Backdoor, Atera / SimpleHelp RMM
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Exchange Exploit / Spearphish (`T1190 / T1566.001`)**: เจาะเซิร์ฟเวอร์อีเมลหรือส่งไฟล์แนบที่เรียกใช้งาน PowerShell/VBScript
  - **2. Legitimate RMM Deployment (`T1219.002 / T1053.005`)**: ติดตั้งโปรแกรมรีโมตถูกต้องตามกฎหมาย (SimpleHelp / Atera) หรือตั้ง Scheduled Task รันสคริปต์ทุกไม่กี่นาที
  - **3. Credential Harvesting (`T1003.001 / T1555.003`)**: ดึงรหัสผ่านจากหน่วยความจำ LSASS และฐานข้อมูลรหัสผ่านของเบราว์เซอร์
  - **4. DNS & Email C2 Channel (`T1071.004 / T1071.003`)**: ส่งคำสั่งและรับผลลัพธ์ผ่านระเบียน DNS TXT/A Queries หรือผ่านดราฟต์อีเมลใน Exchange Web Services (EWS)
  - **5. Mailbox & AD Exfiltration (`T1114.002 / T1048`)**: ส่งออกกล่องจดหมายและข้อมูลโครงสร้างเครือข่ายทั้งหมด

### [G1015] Scattered Spider (Octo Tempest / UNC3944 / 0ktapus)
- **ต้นสังกัด / ภูมิภาค**: Native English-Speaking Cybercrime Collective (US/UK) (2022 – ปัจจุบัน)
- **เป้าหมายหลัก**: โทรคมนาคม, BPO/Call Center, คาสิโนและโรงแรมระดับโลก, สถาบันการเงิน, ค้าปลีก และผู้ให้บริการ SaaS/Cloud
- **สรุปพฤติกรรม**: กลุ่มอาชญากรไซเบอร์ที่ใช้ภาษาอังกฤษเป็นภาษาแม่ เชี่ยวชาญการทำ Social Engineering ขั้นสูงสุด (Vishing โทรหลอก IT Helpdesk, SIM Swapping, SMS Phishing) เพื่อยึดครองระบบ Identity (Okta / Entra ID) และเข้ารหัส VMware ESXi (ALPHV/BlackCat & RansomHub)
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: โทรศัพท์สด (Vishing) หรือส่งข้อความผ่าน SMS/Telegram/Teams ด้วยสำเนียงเจ้าของภาษา อ้างอิงข้อมูลส่วนตัวของพนักงานจริง (ชื่อหัวหน้า, รหัสพนักงาน, วันเกิด) เพื่อกดดันให้ IT Helpdesk รีเซ็ตรหัสผ่านและลงทะเบียนอุปกรณ์ MFA ใหม่ให้ทันที
- **มัลแวร์และเครื่องมือ**: AnyDesk / ScreenConnect / Pulseway RMM, ngrok / Tailscale, BlackCat / ALPHV / RansomHub ESXi Locker, LinPEAS / TruffleHog
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Helpdesk Vishing & SIM Swap (`T1598.004 / T1451 / T1621`)**: โทรหลอกแผนก IT Helpdesk สวมรอยเป็นพนักงานระดับสูงเพื่อขอรีเซ็ต MFA หรือทำ SIM Swap / MFA Fatigue Push
  - **2. Rogue MFA & RMM Persistence (`T1098.005 / T1219.002`)**: ลงทะเบียนโทรศัพท์ของผู้โจมตีเข้ากับบัญชี SSO (Okta/Entra ID) และติดตั้งเครื่องมือ RMM หลายตัวพร้อมกัน
  - **3. Internal Wiki & Repo Mining (`T1213.001 / T1213.005`)**: ค้นหาคู่มือสถาปัตยกรรมระบบและรหัสผ่านใน Confluence, SharePoint, Slack, Microsoft Teams และ GitHub
  - **4. Cloud & Hypervisor Pivot (`T1556.007 / T1675`)**: ยึดครอง AWS/Azure Control Plane และล็อกอินเข้าสู่ VMware vCenter / ESXi Hypervisor
  - **5. ESXi Encryption & Live Extortion (`T1486 / T1657`)**: เข้ารหัส Virtual Machines บน ESXi พร้อมส่งข้อความข่มขู่ผู้บริหารโดยตรงผ่าน SMS และ Microsoft Teams

### [G1046] Storm-1811 (Black Basta Ransomware Affiliate)
- **ต้นสังกัด / ภูมิภาค**: Eastern Europe / Russian-Speaking RaaS Affiliate (2024 – ปัจจุบัน)
- **เป้าหมายหลัก**: องค์กรธุรกิจขนาดกลางและใหญ่ที่ใช้ Microsoft 365 และเปิดอนุญาต External Microsoft Teams Chat
- **สรุปพฤติกรรม**: กลุ่มผู้โจมตีที่บุกเบิกเทคนิคการถล่มอีเมลขยะหลายพันฉบับ (Email Bombing T1667) แล้วทักแชตหรือโทรผ่าน Microsoft Teams สวมรอยเป็นฝ่าย IT Helpdesk เพื่อหลอกให้เหยื่อเปิดโปรแกรม Windows Quick Assist
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: ทักแชต Microsoft Teams จากบัญชีภายนอกที่ใช้ชื่อว่า 'Help Desk Manager' หรือ 'IT Security Support' ทันทีที่เหยื่อกำลังตกใจเพราะกล่องอีเมลถูกสแปมถล่ม แล้วบอกว่าจะช่วยบล็อกสแปมให้โดยขอให้กดปุ่ม `Ctrl + Windows + Q` (Quick Assist)
- **มัลแวร์และเครื่องมือ**: Windows Quick Assist, QakBot / Pikabot, Cobalt Strike, SystemBC, Black Basta Ransomware
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Email Bombing Distraction (`T1667`)**: ยิงสคริปต์สมัครรับจดหมายข่าว 3,000+ แห่งใส่อีเมลของเหยื่อภายใน 10 นาทีเพื่อสร้างความโกลาหล
  - **2. Teams Helpdesk Impersonation (`T1566.004 / T1684.001`)**: โทรหรือแชตผ่าน Microsoft Teams อ้างเป็นฝ่าย IT Support ของบริษัท ขอเข้าช่วยเหลือผ่านหน้าจอ
  - **3. Quick Assist Remote Takeover (`T1219.002 / T1059.001`)**: หลอกให้เหยื่อกด `Ctrl+Win+Q` ใส่รหัส Quick Assist 6 หลัก จากนั้นรันสคริปต์ `curl` / `msiexec` ดาวน์โหลด Payload
  - **4. Credential Dump & AD Pivot (`T1003.001 / T1021.002`)**: ดึงรหัสผ่านด้วย Mimikatz, ปิด EDR (T1685) และเคลื่อนย้ายผ่าน SMB/RDP ไปยัง Domain Controller
  - **5. Black Basta Double Extortion (`T1567.002 / T1486`)**: ขโมยข้อมูลด้วย Rclone แล้วปล่อยแรนซัมแวร์ Black Basta เข้ารหัสทั้ง Windows และ VMware ESXi

### [G1024] Akira Ransomware Group (GOLD SAHARA / PUNK SPIDER)
- **ต้นสังกัด / ภูมิภาค**: Eastern Europe (Conti Nexus) (2023 – ปัจจุบัน)
- **เป้าหมายหลัก**: อุตสาหกรรมการผลิต, การเงิน, การศึกษา, โรงพยาบาล และองค์กรที่ใช้ VPN ที่ไม่ได้เปิด MFA
- **สรุปพฤติกรรม**: กลุ่มแรนซัมแวร์ที่ขยายตัวรวดเร็วที่สุดกลุ่มหนึ่ง มุ่งเจาะผ่านช่องโหว่และบัญชี Cisco/Fortinet/SonicWall VPN ที่ไม่มี MFA มีตัวเข้ารหัสที่เขียนด้วย C++ และ Rust สำหรับถล่มทั้งเซิร์ฟเวอร์ Windows และ VMware ESXi
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: หน้าเว็บเจรจาต่อรองบนเครือข่าย Tor ออกแบบเป็นหน้าต่าง Terminal สีเขียวย้อนยุค (Retro CLI Chat) ผู้เจรจาใช้ถ้อยคำเชิงธุรกิจผสมการกดดันเรื่องค่าปรับกฎหมายคุ้มครองข้อมูล (GDPR/PDPA) และเสนอส่วนลดหากจ่ายภายใน 48 ชั่วโมง
- **มัลแวร์และเครื่องมือ**: Akira Windows Locker, Akira_v2 / Megazord Rust ESXi Locker, AnyDesk, Rclone, AdFind, Mimikatz
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Single-Factor VPN Breach (`T1133 / T1078.002`)**: ล็อกอินเข้าเครือข่ายผ่าน VPN ที่ไม่มี MFA โดยใช้รหัสผ่านที่รั่วไหลจาก InfoStealer หรือช่องโหว่ CVE บนอุปกรณ์ VPN
  - **2. BYOVD Defense Impairment (`T1685.001 / T1068`)**: นำไดรเวอร์ที่มีช่องโหว่ (เช่น `rwdrv.sys` / `zemana.sys`) มาโหลดเพื่อสั่งปิดโปรเซสของ EDR/Antivirus จากระดับ Kernel
  - **3. Active Directory Recon & Dump (`T1482 / T1003.001`)**: รัน `nltest`, `AdFind` สำรวจโครงสร้างโดเมน และดัมพ์หน่วยความจำ LSASS ด้วย `comsvcs.dll`
  - **4. Archive & Rclone Exfiltration (`T1560.001 / T1567.002`)**: บีบอัดข้อมูลสำคัญด้วย WinRAR (`rar.exe a -hp`) แล้วอัปโหลดออกไปยัง MEGA.nz ด้วย Rclone
  - **5. ESXi & Windows Encryption (`T1490 / T1486`)**: ลบ Volume Shadow Copies ด้วย PowerShell WMI แล้วเข้ารหัสไฟล์ `.vmdk` บน ESXi และเซิร์ฟเวอร์ทั้งหมด

### [S0002] LockBit 3.0 (LockBit Black) & Modern RaaS Ecosystem
- **ต้นสังกัด / ภูมิภาค**: Global Ransomware-as-a-Service Syndicate (2019 – ปัจจุบัน)
- **เป้าหมายหลัก**: ทุกกลุ่มอุตสาหกรรมทั่วโลก องค์กรขนาดใหญ่ โรงพยาบาล โรงงาน และผู้ให้บริการ MSP
- **สรุปพฤติกรรม**: เครือข่ายแรนซัมแวร์ที่ใช้รูปแบบ Triple Extortion (เข้ารหัสไฟล์ + ขู่เผยแพร่ข้อมูลรั่วไหล + ยิง DDoS กดดัน) เปิดให้ Affiliates นำเครื่องมือ StealBit และตัวเข้ารหัสความเร็วสูงไปใช้โจมตี
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: ใช้ระบบแชตอัตโนมัติบน Tor Negotiation Portal พร้อมนาฬิกานับถอยหลัง (Countdown Timer) ข่มขู่ว่าจะเปิดขายข้อมูลให้คู่แข่งหรือแจ้งหน่วยงานกำกับดูแลหากไม่เริ่มเจรจา
- **มัลแวร์และเครื่องมือ**: LockBit 3.0 / LockBit-NG-Dev, StealBit Exfiltrator, S0002 Mimikatz, S0154 Cobalt Strike, PsExec
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Initial Access Broker (IAB) (`T1133 / T1190`)**: ซื้อสิทธิ์การเข้าถึง RDP/VPN หรือเจาะช่องโหว่เว็บ/ไฟร์วอลล์ขอบข่าย
  - **2. Disable Security & Logs (`T1685.001 / T1685.005`)**: ใช้ GPO ปิด Windows Defender ทั้งโดเมน และรัน `wevtutil cl` ล้าง Event Logs ทั้งหมด
  - **3. Credential Harvesting (`T1003.001 / T1558.003`)**: รัน Mimikatz (S0002) และทำ Kerberoasting เพื่อยึดบัญชี Domain Admin
  - **4. StealBit Automated Exfil (`T1020 / T1567`)**: ใช้เครื่องมือ StealBit ดึงไฟล์เอกสารออกไปยังเซิร์ฟเวอร์ของผู้โจมตีด้วยความเร็วสูง
  - **5. GPO Mass Encryption (`T1490 / T1486`)**: สั่งกระจายตัวเข้ารหัสผ่าน Group Policy และ PsExec ไปยังทุกเครื่องในเครือข่ายพร้อมกัน

### [G0094] Kimsuky (Velvet Chollima / Emerald Sleet / APT43)
- **ต้นสังกัด / ภูมิภาค**: North Korea (2012 – ปัจจุบัน)
- **เป้าหมายหลัก**: นักวิชาการด้านนโยบายต่างประเทศ, นักการทูต, สื่อมวลชน, หน่วยงานความมั่นคง และองค์กรวิจัย
- **สรุปพฤติกรรม**: กลุ่มข่าวกรองเกาหลีเหนือที่ใช้ Generative AI ช่วยร่างอีเมลเชิญสัมภาษณ์หรือขอความเห็นทางวิชาการอย่างแนบเนียน พร้อมใช้ส่วนขยายเบราว์เซอร์อันตราย (Malicious Browser Extensions) ขโมยอีเมลและคุกกี้
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: ส่งอีเมลติดต่อต่อเนื่องหลายฉบับโดยไม่ได้แนบมัลแวร์ในฉบับแรก เพื่อสร้างความไว้วางใจในฐานะนักวิจัยหรือนักข่าว ก่อนส่งลิงก์แบบฟอร์มหรือเอกสารที่ฝังสคริปต์ในภายหลัง
- **มัลแวร์และเครื่องมือ**: BabyShark, GoldDragon, RandomQuery, Malicious Chrome/Edge Extensions
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. AI-Crafted Reconnaissance (`T1682 / T1683.001`)**: ใช้บริการ LLM สาธารณะช่วยค้นคว้าข้อมูลเป้าหมายและร่างอีเมลเทียบเชิญทางวิชาการ
  - **2. Multi-Turn Social Engineering (`T1598.003 / T1566.002`)**: โต้ตอบอีเมลกับเหยื่อจนเหยื่อเชื่อใจ แล้วส่งลิงก์ Google Drive / OneDrive ปลอมเพื่อดักรหัสผ่าน
  - **3. Malicious Browser Extension (`T1176.001 / T1539`)**: หลอกติดตั้งส่วนขยายเบราว์เซอร์เพื่อดักจับ Web Session Cookies และอ่านเนื้อหา Gmail/M365 แบบเงียบๆ
  - **4. Script Proxy Execution (`T1218.005 / T1059.005`)**: รัน BabyShark VBS/HTA script ผ่าน `mshta.exe` เพื่อสำรวจข้อมูลเครื่อง
  - **5. Continuous Mailbox Monitoring (`T1114.003 / T1071.001`)**: ตั้งกฎแอบส่งต่ออีเมลและเฝ้าอ่านการสนทนาของเป้าหมายในระยะยาว

### [G1056] TeamPCP (Cloud-Native & AI Workload Threat Group)
- **ต้นสังกัด / ภูมิภาค**: Cloud-Native Cybercriminal Group (2024 – ปัจจุบัน)
- **เป้าหมายหลัก**: คลัสเตอร์ Kubernetes, Docker API, เซิร์ฟเวอร์ AI/ML (Ray / Jupyter / Ollama), ระบบ CI/CD และ Cloud Storage
- **สรุปพฤติกรรม**: กลุ่มผู้โจมตียุค Cloud-Native ที่มุ่งเป้าสแกนหาคอนเทนเนอร์, ระบบประมวลผล AI และ Cloud APIs ที่ตั้งค่าผิดพลาด เพื่อขโมย Cloud IAM Keys, ฝังตัวใน Kubernetes และรีดไถข้อมูลบนคลาวด์
- **รูปแบบการพูดคุย / ล่อลวง (`การพูดคุย`)**: ทิ้งไฟล์ประกาศเรียกค่าไถ่ (Ransom Note) ไว้ใน S3 Bucket / ฐานข้อมูลที่ถูกลบหรือยึด พร้อมระบุช่องทางติดต่อผ่าน Telegram และ Session ID สำหรับเจรจา
- **มัลแวร์และเครื่องมือ**: TeamPCP Cloud Scripts, Kinsing, TruffleHog, AWS/GCP/Azure CLI
- **ลำดับขั้นตอนการโจมตี (Kill Chain)**:
  - **1. Exposed Cloud/Container API (`T1190 / T1609`)**: สแกนหา Docker Daemon API, Kubernetes Kubelet หรือคลัสเตอร์ AI (Ray) ที่เปิดพอร์ตโดยไม่มีการยืนยันตัวตน
  - **2. Privileged Pod & Host Escape (`T1610 / T1611`)**: สั่งรันคอนเทนเนอร์แบบ `--privileged` และเมาท์ดิสก์ของโฮสต์ (`/mnt/host`) เพื่อยึดเครื่องแม่ข่าย
  - **3. IMDS & Secret Harvesting (`T1552.005 / T1552.007`)**: ดึงโทเคน IAM Role จาก Cloud Metadata API (`169.254.169.254`) และกวาดหาคีย์ใน Kubernetes Secrets
  - **4. Cross-Account Cloud Exfil (`T1530 / T1537`)**: ใช้คีย์ที่ได้คัดลอกข้อมูลจาก S3 / Blob Storage ข้ามไปยังบัญชีคลาวด์ของผู้โจมตีโดยตรง
  - **5. Cloud Bucket Wipe & Extortion (`T1485.001 / T1496.001`)**: ตั้งกฎ Lifecycle ลบข้อมูลหรือรันเหมืองขุดคริปโต/LLM Hijacking บนทรัพยากรคลาวด์ของเหยื่อ

## 2. บทสนทนาการล่อลวงและการเจรจาค่าไถ่ (Adversary Communications & Negotiation Transcripts)

### 1. บทสนทนา Vishing & แชตหลอก IT Helpdesk เพื่อรีเซ็ต MFA (Scattered Spider G1015)
- **ช่องทาง**: 📞 โทรศัพท์สด (Vishing) + 🎫 ระบบ IT Service Desk Chat | **MITRE TTPs**: `T1598.004, T1684.001, T1098.005, T1078.004`
- **บริบท**: ผู้โจมตีค้นหาข้อมูลพนักงานระดับ Senior Engineer จาก LinkedIn และฐานข้อมูลที่รั่วไหล (ชื่อ-นามสกุล, รหัสพนักงาน, วันเกิด, ชื่อหัวหน้างาน) แล้วโทรและทักแชตหาแผนก IT Helpdesk ในช่วงเปลี่ยนกะ โดยอ้างว่าเพิ่งเปลี่ยนโทรศัพท์มือถือใหม่และเข้าแอป Okta Verify / Microsoft Authenticator ไม่ได้
  > **🕵️ ผู้โจมตี (สวมรอยเป็น 'คุณอเล็กซ์ - Senior Cloud Architect') (21:42 น.)**: สวัสดีครับทีม Helpdesk ผมอเล็กซ์จากทีม Cloud Infra นะครับ พอดีโทรศัพท์เครื่องเก่าผมหน้าจอแตกเปิดไม่ติดเลย เพิ่งย้ายซิมมาใส่เครื่องใหม่ ตอนนี้จะล็อกอินเข้า Okta ไปแก้ Incident ด่วนของลูกค้าแต่ติดหน้า MFA Push ครับ ช่วยรีเซ็ต MFA Device ให้ผมหน่อยได้ไหมครับ?
  > *วิเคราะห์ TTP*: T1598.004 / T1684.001: สร้างสถานการณ์เร่งด่วน (Urgency) นอกเวลาทำการปกติเพื่อกดดันเจ้าหน้าที่
  > **👨‍💻 เจ้าหน้าที่ IT Helpdesk (21:43 น.)**: สวัสดีครับคุณอเล็กซ์ เพื่อยืนยันตัวตน รบกวนแจ้งรหัสพนักงาน 6 หลัก วันเดือนปีเกิด และชื่อผู้จัดการโดยตรงของคุณด้วยครับ
  > *วิเคราะห์ TTP*: ช่องโหว่กระบวนการ: ใช้คำถามยืนยันตัวตนแบบ Static Knowledge-Based Authentication (KBA) ซึ่งหาได้จาก OSINT/Breach Data
  > **🕵️ ผู้โจมตี (ใช้ข้อมูลจาก OSINT & Breach Dump) (21:44 น.)**: รหัสพนักงาน EMP-408921 ครับ เกิดวันที่ 14 สิงหาคม 1988 หัวหน้าผมคือคุณเดวิด เฉิน (VP of Engineering) ครับ รบกวนส่งลิงก์ลงทะเบียน QR Code อันใหม่มาที่หน้าจอหรือเปิด Temporary Pass ให้เลยนะครับ ตอนนี้ทีมรอผมเข้า AWS Production อยู่คนเดียวเลย
  > *วิเคราะห์ TTP*: T1589.001/.003: ใช้ข้อมูลที่รวบรวมไว้ในขั้น Reconnaissance ตอบได้อย่างแม่นยำและเร่งรัด
  > **👨‍💻 เจ้าหน้าที่ IT Helpdesk (หลงเชื่อหากไม่มีนโยบาย Out-of-Band Video Check) (21:45 น.)**: ข้อมูลถูกต้องครับ ผมกด Clear Existing MFA Factors และส่งลิงก์ Enroll อุปกรณ์ใหม่ให้เรียบร้อยแล้วครับ ลองสแกน QR Code จากหน้าล็อกอินได้เลยครับ
  > *วิเคราะห์ TTP*: T1098.005 (Device Registration): ทันทีที่ Helpdesk กดรีเซ็ต ผู้โจมตีที่เปิดหน้าล็อกอินรออยู่จะสแกน QR Code ผูกแอป Authenticator ของตนเองสำเร็จทันที!
- **การป้องกัน (Blue Team Counter-Playbook)**: บังคับใช้มาตรการยืนยันตัวตนแบบเปิดกล้องวิดีโอคอลเห็นหน้าจริงพร้อมบัตรพนักงาน (Live Video Verification) และต้องมีการกดอนุมัติในระบบจากหัวหน้างานโดยตรง (Manager Approval Workflow) ก่อนรีเซ็ต MFA ทุกครั้ง

### 2. แชต Microsoft Teams ปลอมเป็นฝ่าย IT ล่อให้เปิด Quick Assist หลังถล่มอีเมล (Storm-1811 / Black Basta G1046)
- **ช่องทาง**: 💬 Microsoft Teams (External Tenant Chat & Audio Call) | **MITRE TTPs**: `T1667, T1566.004, T1219.002, T1059.001`
- **บริบท**: ผู้โจมตีใช้บอตยิงสแปมสมัครจดหมายข่าว 3,500 ฉบับเข้ากล่องอีเมลของพนักงานการเงินภายใน 5 นาที (Email Bombing T1667) จากนั้นทักแชตผ่าน Microsoft Teams โดยใช้ชื่อบัญชีภายนอกว่า 'IT Security Helpdesk' เพื่อเสนอตัวเข้าแก้ไขปัญหา
  > **🕵️ ผู้โจมตี (บัญชี External Teams: 'IT Helpdesk - Security Operations [External]') (10:15 น.)**: ⚠️ แจ้งเตือนด่วนจากแผนก IT Security: ระบบตรวจพบว่ากล่องอีเมลของคุณกำลังถูกโจมตีด้วย Spam Flood (กว่า 3,000 ฉบับ) และมีความเสี่ยงที่มัลแวร์จะแฝงตัวเข้ามา คุณได้รับอีเมลรบกวนจำนวนมากใช่ไหมครับ?
  > *วิเคราะห์ TTP*: T1667 + T1684.001: ผู้โจมตีเป็นผู้สร้างปัญหา Email Bombing เอง แล้วทักเข้ามาสวมบทเป็นผู้ช่วยชีวิตทันที
  > **👩‍💼 พนักงานฝ่ายการเงิน (10:16 น.)**: ใช่ค่ะ! อีเมลเด้งรัวมากจน Outlook ค้างไปหมดแล้ว พอดีกำลังจะโอนจ่ายงวดงานด้วย ช่วยแก้ไขด่วนเลยค่ะ
  > *วิเคราะห์ TTP*: เหยื่อเกิดความตื่นตระหนกและต้องการให้ปัญหาจบเร็วที่สุด
  > **🕵️ ผู้โจมตี (IT Helpdesk ปลอม) (10:17 น.)**: ไม่ต้องกังวลครับ เดี๋ยววิศวกรจะรีเซ็ตตัวกรอง Spam Quarantine บนเครื่องของคุณให้ทันที รบกวนกดปุ่มลัดบนคีย์บอร์ด `Ctrl + Windows + Q` เพื่อเปิดโปรแกรมช่วยเหลือมาตรฐานของ Microsoft (Quick Assist) แล้วกรอกรหัสความปลอดภัย 6 หลักนี้ครับ: `849-204` จากนั้นกด Allow ได้เลยครับ
  > *วิเคราะห์ TTP*: T1219.002 (Remote Desktop Software): ใช้ Windows Quick Assist ที่ติดตั้งมากับ Windows 10/11 ทุกเครื่องเพื่อไม่ต้องหลอกให้ดาวน์โหลดไฟล์ .exe
  > **🕵️ ผู้โจมตี (หลังเข้าควบคุมหน้าจอได้แล้ว) (10:19 น.)**: ตอนนี้ระบบกำลังรันสคริปต์อัปเดตความปลอดภัย หน้าจออาจจะมืดลงประมาณ 1 นาที ห้ามปิดเครื่องนะครับ... (เบื้องหลังแอบเปิด cmd/powershell รัน `curl` ดึงไฟล์ `.msi` / Cobalt Strike Beacon และดัมพ์ LSASS)
  > *วิเคราะห์ TTP*: T1059.001 / T1218.007: ใช้ฟีเจอร์เพิกเฉยหน้าจอเพื่อรันคำสั่งติดตั้ง C2 Beacon และขโมยรหัสผ่านโดเมน
- **การป้องกัน (Blue Team Counter-Playbook)**: ปิดการรับแชตจากโดเมนภายนอกที่ไม่อยู่ใน Allowlist บน Microsoft Teams (`External Access = Blocked/Allowlist Only`), บล็อกการรัน `QuickAssist.exe` ด้วย AppLocker/WDAC และตั้งกฎ SIEM จับ Inbound Email Spike (T1667)

### 3. บทสนทนาหลอกสัมภาษณ์งานสาย Tech & ให้รันโค้ดทดสอบบน GitHub (Lazarus / Contagious Interview G1052)
- **ช่องทาง**: 💼 LinkedIn Messaging + 🐙 GitHub / Telegram | **MITRE TTPs**: `T1585.001, T1598.001, T1204.005, T1059.007, T1555.003`
- **บริบท**: ผู้โจมตีปลอมตัวเป็น Senior Recruiter ของบริษัท Web3/FinTech/AI ระดับโลก ทักหา Senior Developer ชาวไทย/สากล เสนอผลตอบแทนสูง ($180k–$250k Remote) และขอให้ทำ Live Coding Test ด้วยการโคลนโปรเจกต์ Node.js จาก GitHub มารันบนเครื่อง
  > **🕵️ ผู้โจมตี (LinkedIn: 'Sarah Jenkins - Head of Talent @ DeFi-Nexus Labs') (14:10 น.)**: Hi! เราประทับใจผลงานใน GitHub ของคุณมาก ตอนนี้เรากำลังขยายทีม Core Platform (Remote 100%, เงินเดือน $190,000 + Token Bonus) ขั้นตอนแรกไม่มีข้อสอบอัลกอริทึมน่าเบื่อค่ะ เพียงแค่ลองรัน Demo โปรเจกต์ของเราและแก้ Bug หน้า UI เล็กน้อยก่อนคุยกับ CTO พรุ่งนี้ สนใจไหมคะ?
  > *วิเคราะห์ TTP*: T1585.001 / T1683.001: ใช้ข้อเสนอเงินเดือนสูงและขั้นตอนสัมภาษณ์ที่ดูทันสมัยดึงดูดนักพัฒนา
  > **👨‍💻 Senior Full-Stack Developer (14:15 น.)**: สนใจครับ ส่งลิงก์ Repository และรายละเอียดงานมาได้เลยครับ
  > *วิเคราะห์ TTP*: นักพัฒนามักคุ้นชินกับการ git clone และ npm install โค้ดจาก GitHub อยู่แล้ว
  > **🕵️ ผู้โจมตี (ส่งลิงก์ GitHub Repo ฝังมัลแวร์ BeaverTail) (14:16 น.)**: นี่คือลิงก์ Repo ค่ะ: `github.com/defi-nexus-assessment/dex-portal-v2` (รหัสผ่านแตกไฟล์เอกสารบรีฟคือ `Nexus2026!`) ให้รัน `npm install && npm run dev` บนเครื่องของคุณได้เลยนะคะ ถ้าหน้าเว็บขึ้นแล้วแคปหน้าจอมาบอกด้วยค่ะ!
  > *วิเคราะห์ TTP*: T1204.005 (Malicious Library) / T1059.007: ในไฟล์ `package.json` มีสคริปต์ `postinstall` หรือไฟล์ `server/routes/api.js` ที่ยัดโค้ด Obfuscated JS ยาวหลายพันตัวอักษรไว้ด้านขวาสุดของบรรทัด
  > **🤖 สคริปต์ BeaverTail & InvisibleFerret (ทำงานเงียบในพื้นหลังทันทีที่รัน npm) (14:19 น.)**: [Background Telemetry] ดึงไฟล์ Login Data จาก Chrome/Brave, กวาดโฟลเดอร์ส่วนขยายกระเป๋าคริปโต (`nkbihfbeogaeaoehlefnkodbefgpgknn`), อ่านไฟล์ `~/.ssh/id_rsa`, `~/.aws/credentials` และดาวน์โหลด Python RAT `InvisibleFerret` มาฝังตัวเรียบร้อย
  > *วิเคราะห์ TTP*: T1555.003 / T1552.001 / T1041: ขโมยทั้งรหัสผ่านบริษัท คีย์ AWS/GitHub และสินทรัพย์คริปโตภายในไม่กี่วินาที
- **การป้องกัน (Blue Team Counter-Playbook)**: ห้ามรันโปรเจกต์ทดสอบจากภายนอกบนเครื่องทำงานจริงเด็ดขาด (ต้องรันใน Disposable VM / DevContainer ที่แยกขาดจากเครือข่ายและไม่มีคีย์จริง) และใช้ `npm install --ignore-scripts`

### 4. บันทึกห้องแชตเจรจาค่าไถ่บน Tor Portal (LockBit 3.0 / Akira Double-Extortion Negotiation)
- **ช่องทาง**: 🧅 Tor Dark Web Negotiation Chat Portal | **MITRE TTPs**: `T1486, T1567.002, T1657, T1490`
- **บริบท**: หลังผู้โจมตีขโมยข้อมูลขนาด 850 GB ออกไปและเข้ารหัสไฟล์บนเซิร์ฟเวอร์ Windows + VMware ESXi สำเร็จ ทีมตอบสนองเหตุการณ์ (Incident Response) ได้เข้าสู่ห้องแชตบนเครือข่าย Tor ตามลิงก์ในไฟล์ README_RESTORE.txt เพื่อประเมินสถานการณ์และซื้อเวลา
  > **💀 LockBit / Akira Negotiator (Automated + Human Operator) (Day 1 - 09:00)**: ยินดีต้อนรับสู่ระบบช่วยเหลือของเครือข่ายเรา เซิร์ฟเวอร์และ ESXi Hypervisors ของคุณถูกเข้ารหัสด้วยอัลกอริทึม AES-256 + RSA-4096 และเราได้ดาวน์โหลดข้อมูลสำคัญของคุณออกมาแล้ว 850 GB (รวมถึงฐานข้อมูลลูกค้า PDPA, งบการเงิน และสัญญาการค้า) ข้อเสนอในการซื้อตัวถอดรหัส (Decryptor) และลบข้อมูลทั้งหมดคือ $2,500,000 USD ในสกุล Monero (XMR) หรือ Bitcoin หากไม่ติดต่อภายใน 72 ชม. ข้อมูลทั้งหมดจะถูกเผยแพร่บน Leak Blog
  > *วิเคราะห์ TTP*: T1486 + T1657: ใช้กลยุทธ์ Double Extortion กดดันทั้งเรื่องระบบล่มและโทษปรับตามกฎหมายคุ้มครองข้อมูลส่วนบุคคล
  > **🛡️ ทีมเจรจาฝ่ายรับมือเหตุการณ์ (IR Negotiator) (Day 1 - 16:30)**: เราได้รับข้อความของคุณแล้ว ขณะนี้คณะกรรมการบริหารกำลังประเมินผลกระทบ แต่ก่อนจะพูดคุยเรื่องตัวเลข เราต้องการหลักฐานยืนยันว่าคุณมีข้อมูลจริง (File Tree) และขอทดสอบถอดรหัสไฟล์ตัวอย่าง 2 ไฟล์เพื่อพิสูจน์ว่า Decryptor ของคุณใช้งานได้จริงและไม่ทำให้ไฟล์เสียหาย
  > *วิเคราะห์ TTP*: กลยุทธ์ IR: การขอ File Tree ช่วยให้ทีมสืบสวนรู้ขอบเขตโฟลเดอร์ที่รั่วไหล (เพื่อเตรียมแจ้ง สคส./PDPC ภายใน 72 ชม.) และช่วยซื้อเวลาให้ทีมวิศวกรกู้คืนระบบจาก Immutable Backup
  > **💀 RaaS Operator (Day 1 - 17:05)**: นี่คือไฟล์ `file_tree_listing.txt` (420,000 ไฟล์จาก `\\FS01\Finance$` และ `\\SQL01\Backups$`) อัปโหลดไฟล์ที่ถูกเข้ารหัส 2 ไฟล์ (ขนาดไม่เกิน 2MB และไม่ใช่ไฟล์ฐานข้อมูลหลัก) มาในช่อง Attachment ได้เลย ถ้าคุณตัดสินใจจบดีลภายใน 48 ชั่วโมงนี้ เราลดให้เหลือ $1,650,000 USD
  > *วิเคราะห์ TTP*: T1039 / T1560: ผู้โจมตีเปิดเผยชื่อ File Share ต้นทางที่ถูกดูดข้อมูล ซึ่งช่วยให้ทีม DFIR ย้อนกลับไปหาเครื่องต้นตอที่รัน Rclone ได้ตรงจุด
  > **🛡️ ทีม Incident Response (บันทึกภายใน SOC - ไม่ได้ส่งให้คนร้าย) (Day 2 - 11:00)**: [Internal IR Note] ตรวจสอบ `file_tree_listing.txt` แล้วพบว่าข้อมูลถูกดึงออกจากเครื่อง `SRV-APP-04` ผ่าน `rclone.exe` ไปยัง MEGA.nz ขณะนี้ทีมวิศวกรกู้คืน VM ทั้งหมดจาก Immutable Offline Backup (Veeam Hardened Repo) สำเร็จ 100% แล้ว และเตรียมออกหนังสือแจ้งสำนักงานคณะกรรมการคุ้มครองข้อมูลส่วนบุคคล (สคส. / PDPC) ตามมาตรา 37(4) โดยไม่ต้องจ่ายค่าไถ่
  > *วิเคราะห์ TTP*: M1053 (Data Backup): การมี Immutable Backup ที่แยกขาดจาก Active Directory ช่วยให้องค์กรกู้ระบบกลับมาได้โดยไม่ต้องยอมจำนนต่อการข่มขู่
- **การป้องกัน (Blue Team Counter-Playbook)**: แยกเครือข่ายระบบสำรองข้อมูลแบบ Immutable/Air-gapped (M1053), เก็บ NetFlow/Proxy Logs เพื่อระบุขนาดและชื่อไฟล์ที่ถูกส่งออกจริง และปฏิบัติตามขั้นตอนการแจ้งเหตุละเมิดข้อมูลส่วนบุคคลภายใน 72 ชั่วโมง

### 5. การซื้อขายสิทธิ์เข้าถึงองค์กร (Initial Access Broker) & ข้อความแจ้งเตือนจากบอต C2 บน Telegram
- **ช่องทาง**: 🕶️ Dark Web Forum + ✈️ Telegram Bot API C2 (T1102.002) | **MITRE TTPs**: `T1650, T1589.001, T1102.002, T1071.001`
- **บริบท**: แสดงเบื้องหลังห่วงโซ่อุปทานของอาชญากรไซเบอร์: ตั้งแต่บอต InfoStealer/C2 ส่งข้อความแจ้งเตือนเข้า Telegram ของแฮกเกอร์เมื่อมีเหยื่อติดเชื้อ ไปจนถึงนายหน้าขายสิทธิ์ (Initial Access Broker - T1650) นำสิทธิ์ VPN/Domain Admin ไปโพสต์ขายต่อให้กลุ่มแรนซัมแวร์
  > **🤖 Telegram C2 Bot (`@RedLine_Beacon_Bot` -> T1102.002) (02:14 น.)**: 🔔 **[NEW VICTIM INITIALIZED]**
• **Host:** `CORP-FIN-PC09` (`10.20.15.44`)
• **User:** `CORP\somchai.p` (Local Admin: YES)
• **Country:** TH / AS45758
• **Extracted Cookies/Logins:** 48 Saved Passwords (includes `vpn.corp-example.co.th`, `portal.azure.com`)
• **Command Prompt:** Type `/shell_9941 whoami /all` to execute
  > *วิเคราะห์ TTP*: T1102.002 (Web Service Bidirectional C2): มัลแวร์ใช้ `api.telegram.org/bot<token>/sendMessage` ส่งข้อมูลเครื่องเหยื่อออกไปโดยผ่าน Firewall ที่เปิดพอร์ต 443
  > **🕵️ Initial Access Broker (โพสต์ประกาศขายในฟอรัมใต้ดิน - T1650 Acquire Access) (13:00 น.)**: 🔥 **[SELLING CORPORATE ACCESS - MANUFACTURING SECTOR]**
• **Revenue:** $180M USD | **Hosts:** ~1,200 endpoints
• **Access Type:** SSL VPN (Fortinet) + Valid Domain User + Local Admin on Jump Server
• **AV/EDR:** Windows Defender (Default Config)
• **Price:** $4,500 USD (Instant Buy) or 15% Revenue Share for LockBit/Akira Affiliates
  > *วิเคราะห์ TTP*: T1650 (Acquire Access): นายหน้า IAB มักขายสิทธิ์ที่ดึงมาจาก InfoStealer ให้กลุ่มแรนซัมแวร์เข้ามาทำ Lateral Movement ต่อภายในไม่กี่ชั่วโมง
- **การป้องกัน (Blue Team Counter-Playbook)**: บล็อกหรือเฝ้าระวังการเรียก `api.telegram.org` และ `discord.com/api/webhooks` จากเซิร์ฟเวอร์และโปรเซสสคริปต์, ห้ามบันทึกรหัสผ่านสำคัญในเบราว์เซอร์ทั่วไป และเพิกถอน Session Token ทันทีที่พบแจ้งเตือนใน Dark Web Monitoring
