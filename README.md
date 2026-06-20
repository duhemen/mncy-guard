# 🛡️ Mncy-Guard (Gadis Cantik Putri Iklan)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)

Mncy-Guard adalah solusi **Intelligent Network Monitoring** yang dirancang untuk memberikan transparansi dan keamanan pada trafik sistem Anda secara *real-time*.

![Mncy-Guard Banner](baner.png)

---

## 📑 Daftar Isi
- [Fitur Utama](#-fitur-utama)
- [Instalasi](#-instalasi)
- [Lisensi](#-lisensi)
- [Struktur Proyek](#-struktur-proyek)

---

## 🚀 Fitur Utama
* **Real-time Traffic Monitoring:** Visualisasi aliran data jaringan secara langsung.
* **Stateful Behavior Detection:** Analisis mendalam untuk mendeteksi anomali.
* **Smart Filtering Engine:** Membedakan trafik sah vs mencurigakan dengan cerdas.
* **Quarantine Manager:** Isolasi koneksi IP berbahaya dengan satu klik.



## 🛠 Instalasi
1. Pastikan Python telah terinstal di sistem Anda, lalu jalankan perintah berikut di terminal:
2. Clone repository:
   ```Bash:
     git clone [https://github.com/duhemen/mncy-guard.git](https://github.com/duhemen/mncy-guard.git)
     cd mncy-guard
3. Instal dependensi:
   ```Bash:
    pip install -r requirements.txt
4. Jalankan aplikasi:
   ```Bash:
    python main.py
## 📜 Lisensi
Proyek ini dilisensikan di bawah MIT License.
Dibuat dengan dedikasi untuk keamanan jaringan.

## 📂 Struktur Proyek
Proyek ini diorganisir secara modular agar mudah dikembangkan:

```text
mncy-guard/
├── core/         # Mesin deteksi & analisis keamanan
├── ui/           # Antarmuka dasbor (GUI)
├── db/           # Manajemen database ancaman
├── config.py     # Konfigurasi variabel aplikasi
└── main.py       # Titik masuk utama aplikasi
