import psutil
import hashlib
from db.threat_db import THREAT_DATABASE
from .whitelist import is_whitelisted

def get_file_hash(file_path):
    """Menghitung SHA-256 dari file untuk identifikasi unik."""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Membaca file dalam potongan kecil agar tidak membebani RAM
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError):
        # Jika file terkunci oleh sistem atau tidak bisa diakses, abaikan
        return None

def scan_processes():
    threats = []
    # Mengambil informasi proses termasuk path eksekusi (exe)
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info['name']
            exe_path = proc.info['exe']
            
            # 1. Lewati jika ada di whitelist
            if is_whitelisted(name):
                continue
                
            # 2. Cek Hash jika path tersedia
            if exe_path:
                file_hash = get_file_hash(exe_path)
                # Bandingkan hash dengan database ancaman
                if file_hash in THREAT_DATABASE:
                    threats.append(proc.info)
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return threats

def check_file_reputation(file_path):
    """Cek apakah file adalah file sistem resmi (sederhana)."""
    # Contoh sederhana: Cek apakah path mengandung 'Microsoft VS Code'
    if "Microsoft VS Code" in file_path:
        return "Aman (Verified Path)"
    return "Mencurigakan (Perlu Investigasi)"