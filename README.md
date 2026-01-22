# 🔐 Kriptografik Algoritmlar Tadqiqoti  
### Python + Tkinter asosidagi interaktiv kriptografiya laboratoriyasi

Ushbu loyiha **kriptografik algoritmlarni o‘rganish, tahlil qilish va test qilish** uchun mo‘ljallangan **to‘liq funksional grafik ilova (GUI)** hisoblanadi. Dastur **Python va Tkinter** yordamida yaratilgan bo‘lib, kriptografiyaning asosiy yo‘nalishlarini qamrab oladi.

---

# 🎯 Loyiha Maqsadi

Ushbu ilovaning asosiy maqsadi:

- Kriptografiya algoritmlarini **vizual muhitda tushunarli qilib ko‘rsatish**
- Murakkab algoritmlarni **amaliy tajriba orqali o‘rganish**
- Talabalar va o‘rganuvchilar uchun **interaktiv laboratoriya yaratish**
- Kriptografiya fanini **sodda va tushunarli shaklda tushuntirish**

---

# 🧩 Ilova Tuzilishi (Asosiy Bo‘limlar)

Ilova **4 ta asosiy bo‘lim**dan tashkil topgan:

---

## 🔏 1) ERI — Elektron Raqamli Imzo

Bu bo‘lim **xabarlarning haqiqiyligini va yaxlitligini tekshirish** uchun ishlatiladigan **raqamli imzo algoritmlarini** o‘z ichiga oladi.

### Mavjud algoritmlar:
- DSA (Digital Signature Algorithm)
- El-Gamal Signature
- RSA Signature

### Imkoniyatlar:
- Kalit generatsiya qilish
- Xabarni imzolash
- Imzoni tekshirish
- Natijalarni vizual ko‘rish

---

## 🎲 2) PTRR — Pseudo Tasodifiy Sonlar Generatorlari (PRNG)

Bu bo‘lim **tasodifiy sonlar generatsiyasi** va **kriptografik kalitlar uchun random manbalar**ni modellashtiradi.

### Generator turlari:

### 🧩 Elementar generatorlar:
- Chiziqli generator
- Nochiziqli generator

### 🧠 Murakkab generatorlar:
- RSA generator
- Blum-Blum-Shub (BBS)
- Blum-Micali

### 📡 Siljitish registrli generatorlar:
- A5/1 algoritmi

### Imkoniyatlar:
- Tasodifiy ketma-ketlik generatsiya qilish
- Parametrlar bilan ishlash
- Natijani tahlil qilish

---

## 🧾 3) SHA — Hash Funksiyalari

Bu bo‘lim **xabarlar uchun xesh qiymat hisoblash** imkonini beradi.

### Mavjud hash algoritmlar:
- MD5
- SHA-1
- SHA-256
- SHA-512

### Imkoniyatlar:
- Matn kiritish
- Hash qiymatni hisoblash
- Natijani nusxalash
- Taqqoslash imkoniyati

---

## 🔑 4) Kalit Generatsiya — Shifrlash va Protokollar

Bu bo‘lim **ma’lumotlarni shifrlash, deshifrlash va autentifikatsiya** jarayonlarini qamrab oladi.

---

### 🧊 Simmetrik shifrlash:
- AES
- Blowfish
- CAST-128

**Imkoniyatlar:**
- Kalit yaratish
- Ma’lumotni shifrlash
- Deshifrlash

---

### 🌊 Oqimli shifrlash:
- RC4
- A5/1

---

### 🛰️ Assimetrik shifrlash:
- RSA
- El-Gamal

---

### 🛡️ Autentifikatsiya protokollari:
- Challenge–Response
- Needham–Schroeder
- Kerberos

---

# 🧭 Ilovadan Foydalanish Tartibi

1. Dasturni ishga tushiring:
   ```bash
   python main.py
