# C:\mncy\core\whitelist.py

# Daftar proses sistem Windows yang krusial
WHITELISTED_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", 
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", 
    "dwm.exe", "taskhostw.exe", "winlogon.exe", "python.exe" # python.exe penting!
}

# Daftar IP yang tidak boleh diblokir (Gateway, Localhost, DNS Server)
WHITELISTED_IPS = {"127.0.0.1", "192.168.1.1", "8.8.8.8"}

def is_whitelisted(process_name=None, ip_address=None):
    """Cek apakah proses atau IP aman untuk diabaikan."""
    if process_name:
        if process_name.lower() in WHITELISTED_PROCESSES:
            return True
    if ip_address:
        if ip_address in WHITELISTED_IPS:
            return True
    return False