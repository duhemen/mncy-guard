import json
import os
import socket

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'user_config.json')

def load_config():
    """Membaca konfigurasi dari file JSON."""
    if not os.path.exists(CONFIG_PATH):
        return {"whitelist_ips": [], "whitelist_processes": []}
    try:
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error membaca konfigurasi: {e}")
        return {"whitelist_ips": [], "whitelist_processes": []}

def is_whitelisted(process_name=None, ip_address=None):
    config = load_config()
    
    # 1. CEK OTOMATIS IP LOKAL (Tanpa perlu .add())
    if ip_address:
        # Mendapatkan IP lokal mesin saat ini
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        if ip_address == local_ip or ip_address == "127.0.0.1":
            return True
            
        # Cek dari file JSON
        if ip_address in config.get('whitelist_ips', []):
            return True
            
    # 2. Cek Proses
    if process_name:
        whitelist_procs = [p.lower() for p in config.get('whitelist_processes', [])]
        if process_name.lower() in whitelist_procs:
            return True
            
    return False