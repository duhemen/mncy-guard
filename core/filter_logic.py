# Simpan sebagai: C:\mncy\core\filter_logic.py

TRUSTED_PIDS = [4, 1916, 16072, 8288, 10868]

def should_ignore_alert(pid, ip_address):
    # Cek PID Aman
    if pid in TRUSTED_PIDS:
        return True, "Aktivitas proses sistem yang sah."
    
    # Cek IP infrastruktur cloud (Google/Microsoft/dll)
    trusted_prefixes = ("40.", "52.", "20.", "142.", "216.", "172.217.")
    if ip_address.startswith(trusted_prefixes):
        return True, "Infrastruktur Cloud Terpercaya."
        
    return False, ""