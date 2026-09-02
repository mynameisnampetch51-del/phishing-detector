# Phishing URL Detector

ตรวจสอบ URL ที่สงสัยด้วย heuristic 8 ข้อ — วางลิงก์แล้วเห็นทันทีว่าเข้าเกณฑ์ไหนบ้างพร้อมเหตุผล ไม่ใช่แค่ true/false เสริมด้วยชั้น ML (backend แยก, รัน optional) ที่เช็คเนื้อหาหน้าเว็บจริงเพิ่มเติม

**Demo:** https://mynameisnampetch51-del.github.io/phishing-detector/ (heuristic ล้วน — ชั้น ML ต้องรัน backend เองที่เครื่อง ดู [ML layer](#ml-layer-optional) ด้านล่าง)

## แนวคิด

ระบบจริงอย่าง Google Safe Browsing ใช้หลายชั้นผสมกัน: blocklist (เร็ว, แม่นสำหรับของเก่า) + heuristic (จับ pattern ที่รู้ทันที ไม่ต้องมี dataset) + ML (จับเว็บฟิชชิ่งใหม่ที่ยังไม่เคยเห็น) โปรเจกต์นี้มี 2 ชั้น:

- **Heuristic** (`rules.js`, `app.js`) — รันในเบราว์เซอร์ล้วน ไม่ต้องมี dataset หรือเซิร์ฟเวอร์ นี่คือชั้นหลักที่ demo ใช้งานได้จริงตลอด
- **ML** (`api/`) — โมเดล LogisticRegression เทรนจาก [PhiUSIIL Phishing URL dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (เทรนไว้ที่ [phishing-ml-classifier](../phishing-ml-classifier)) ต้องมี backend เพราะต้อง fetch หน้าเว็บเป้าหมายมาแกะเนื้อหา (นับ `<img>`, `<script>`, favicon ฯลฯ) ซึ่งเบราว์เซอร์ทำเองไม่ได้เพราะติด CORS

## กฎที่ตรวจ (แต่ละข้อถ่วงน้ำหนักคะแนนไม่เท่ากัน)

| กฎ | น้ำหนัก | ตรวจอะไร |
|---|---|---|
| ใช้ IP แทน domain | 3 | hostname เป็นเลข IP ตรงๆ |
| มี `@` ใน URL | 3 | เทคนิคหลอกเบราว์เซอร์คลาสสิก |
| คล้ายโดเมนดังผิดปกติ | 3 | เทียบ hostname กับโดเมนดังด้วย Levenshtein distance (typosquatting) |
| ไม่ใช้ HTTPS | 2 | เช็ค protocol |
| Subdomain เยอะผิดปกติ | 1 | นับจุดใน hostname |
| มีคำต้องสงสัย | 1 | เช่น login, verify, secure, banking |
| URL ยาวผิดปกติ | 1 | เกิน 75 ตัวอักษร |
| ใช้ URL shortener | 1 | เทียบกับ list บริการย่อลิงก์ที่รู้จัก |

คะแนนรวม 0 = ปลอดภัย, 1–3 = น่าสงสัย, 4+ = อันตรายสูง

## เทคนิคที่ใช้

- แยกแต่ละกฎเป็น pure function ใน `rules.js` — เทส/แก้ไขทีละข้อได้อิสระ
- Implement Levenshtein distance เองเพื่อจับ typosquatting (ไม่พึ่ง library)
- `localStorage` เก็บประวัติการตรวจสอบล่าสุด 10 รายการ — คลิกประวัติเพื่อตรวจซ้ำได้
- Styling ด้วย Tailwind CDN ธีมเดียวกับ `to-do/` และ `cube-net/`

## ML layer (optional)

`api/` เป็น FastAPI backend แยกต่างหาก — เมื่อรันอยู่ที่ `localhost:8000` หน้าเว็บจะยิงเช็คเพิ่มโดยอัตโนมัติหลังกด "ตรวจสอบ" ถ้าไม่ได้รันจะขึ้นข้อความบอกเฉยๆ ไม่ทำให้ใช้งานส่วน heuristic ไม่ได้

วิธีรัน: ดู [`api/README.md`](api/README.md)

**ข้อจำกัดของโมเดล ML** (พูดตรงๆ): เทรนด้วย LogisticRegression ธรรมดา บาง feature ที่ dataset ต้นทางไม่เปิดสูตรตายตัว (`CharContinuationRate`, `TLDLegitimateProb` ฯลฯ) ฝั่ง `api/features.py` ใช้การประมาณค่าเอาเอง ผลคือมีเคส false positive กับเว็บจริงที่รูปแบบ URL "เรียบง่ายผิดปกติ" เช่น `google.com` เพราะ weight ของ feature บางตัว (เช่นสัดส่วนตัวอักษรในหลาย URL) แรงมากจากข้อมูลเทรนจริง ไม่ใช่บั๊กของ API — เป็นข้อจำกัดของโมเดล linear ตัวนี้เอง ยังไม่ได้แก้

## ข้อจำกัด

ชั้น heuristic ตรวจได้แค่ pattern ที่รู้ล่วงหน้า จับเว็บฟิชชิ่งรูปแบบใหม่ที่ไม่มีในกฎไม่ได้ — ชั้น ML ช่วยจับ pattern ใหม่ได้บ้างแต่ยังไม่แม่นพอสำหรับ production (ดูหัวข้อ ML layer ด้านบน) ระบบจริงจะต่อด้วย threat intelligence/blocklist เพิ่มเพื่อจับเคสที่สองชั้นนี้เขียนไม่ทัน

## รันเอง

เปิด `index.html` ในเบราว์เซอร์ได้เลย ไม่ต้องติดตั้งอะไรเพิ่ม (ใช้ได้แค่ชั้น heuristic)

อยากได้ชั้น ML ด้วย ให้รัน `api/` ตามคู่มือใน [`api/README.md`](api/README.md) ก่อนเปิด `index.html`
