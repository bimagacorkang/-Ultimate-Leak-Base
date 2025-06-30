# -Ultimate-Leak-Base
Advanced Web Leak Scanner with Proxy Rotation

✨ Fitur Utama
Deep Scanning - Mencari 100+ path/file sensitif (.env, config.php, backup.zip, dll)

Smart Detection - Mendeteksi:

Credentials (database, API keys, SSH keys)

Email & data sensitif

File backup yang terekspos

High Performance - Multi-threading (50+ threads)

Stealth Mode - Proxy rotation bawaan (10+ premium proxies)

Customizable - Wordlist dan pola deteksi bisa dikustomisasi

🚀 Instalasi
bash
git clone https://github.com/username/ultimate-web-scanner.git
cd ultimate-web-scanner
pip install -r requirements.txt
🛠 Penggunaan
bash
# Scan dasar
python3 scanner.py -u https://target.com

# Scan dengan proxy rotation
python3 scanner.py -u https://target.com -p -t 30

# Scan tanpa proxy
python3 scanner.py -u https://target.com -np
⚙️ Opsi
Parameter	Deskripsi
-u URL	Target URL (wajib)
-t NUM	Jumlah threads (default: 50)
-p	Aktifkan proxy rotation
-np	Nonaktifkan semua proxy
📌 Contoh Output
https://i.imgur.com/fake_output.png

⚠️ Disclaimer
Hanya untuk tujuan pentest legal!
Penggunaan untuk aktivitas ilegal dilarang keras. Developer tidak bertanggung jawab atas penyalahgunaan alat ini.

diff
- PERINGATAN: Selalu dapatkan izin tertulis sebelum melakukan scanning!
🤖 Kontribusi
Pull request dipersilakan. Untuk perubahan besar, buka issue terlebih dahulu.

📄 Lisensi
MIT
