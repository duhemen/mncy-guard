# 🛡️ Mncy-Guard (Gadis Cantik Putri Iklan)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)

Mncy-Guard adalah solusi **Intelligent Network Monitoring** yang dirancang untuk memberikan transparansi dan keamanan pada trafik sistem Anda secara *real-time*.

![Mncy-Guard Banner](baner.png)

---

## 📑 Daftar Isi
- [Fitur Utama](#-fitur-utama)
- [Struktur Proyek](#-struktur-proyek)
- [Instalasi](#-instalasi)
- [Lisensi](#-lisensi)

---

## 🚀 Fitur Utama
* **Real-time Traffic Monitoring:** Visualisasi aliran data jaringan secara langsung.
* **Stateful Behavior Detection:** Analisis mendalam untuk mendeteksi anomali.
* **Smart Filtering Engine:** Membedakan trafik sah vs mencurigakan dengan cerdas.
* **Quarantine Manager:** Isolasi koneksi IP berbahaya dengan satu klik.

---

## 📂 Struktur Proyek
Proyek ini diorganisir secara modular agar mudah dikembangkan:

```text
mncy-guard/
├── core/         # Mesin deteksi & analisis keamanan
├── ui/           # Antarmuka dasbor (GUI)
├── db/           # Manajemen database ancaman
├── config.py     # Konfigurasi variabel aplikasi
└── main.py       # Titik masuk utama aplikasi

🛠 Instalasi
Pastikan Python telah terinstal di sistem Anda, lalu jalankan perintah berikut di terminal:

Clone repository:

Bash
git clone [https://github.com/duhemen/mncy-guard.git](https://github.com/duhemen/mncy-guard.git)
cd mncy-guard
Instal dependensi:

Bash
pip install -r requirements.txt
Jalankan aplikasi:

Bash
python main.py
📜 Lisensi
Proyek ini dilisensikan di bawah MIT License.

Dibuat dengan dedikasi untuk keamanan jaringan
