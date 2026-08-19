# Phishing URL Detector

ตรวจสอบ URL ที่สงสัยด้วย heuristic 8 ข้อ (ไม่ใช้ ML/backend) — วางลิงก์แล้วเห็นทันทีว่าเข้าเกณฑ์ไหนบ้างพร้อมเหตุผล ไม่ใช่แค่ true/false

**Demo:** https://mynameisnampetch51-del.github.io/phishing-detector/

## แนวคิด

ระบบจริงอย่าง Google Safe Browsing ใช้หลายชั้นผสมกัน: blocklist (เร็ว, แม่นสำหรับของเก่า) + heuristic (จับ pattern ที่รู้ทันที ไม่ต้องมี dataset) + ML (จับเว็บฟิชชิ่งใหม่ที่ยังไม่เคยเห็น) โปรเจกต์นี้ทำ **ชั้น heuristic** ซึ่งเป็นชั้นแรกของระบบจริง — เร็ว รันได้ในเบราว์เซอร์ล้วน ไม่ต้องมี dataset หรือเซิร์ฟเวอร์

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

## ข้อจำกัด (พูดตรงๆ)

นี่คือ heuristic ล้วน ไม่ใช่ ML — ตรวจได้แค่ pattern ที่รู้ล่วงหน้า จับเว็บฟิชชิ่งรูปแบบใหม่ที่ไม่มีในกฎไม่ได้ ระบบจริงจะต่อด้วยชั้น ML และ threat intelligence เพิ่มเพื่อจับเคสที่ heuristic เขียนไม่ทัน

## รันเอง

เปิด `index.html` ในเบราว์เซอร์ได้เลย ไม่ต้องติดตั้งอะไรเพิ่ม
