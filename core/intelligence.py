import requests

# URL contoh untuk feed IP jahat (bisa diganti dengan API lain seperti AbuseIPDB)
FEED_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"

def get_threat_intelligence():
    """Mengunduh daftar IP berbahaya dari internet."""
    try:
        response = requests.get(FEED_URL, timeout=10)
        if response.status_code == 200:
            # Membersihkan data: ambil baris yang bukan komentar
            ips = [line for line in response.text.splitlines() if not line.startswith('#') and line.strip()]
            return set(ips)
    except Exception as e:
        print(f"Gagal update intelijen: {e}")
    return set()

# Inisialisasi daftar ancaman di memori
threat_list = get_threat_intelligence()