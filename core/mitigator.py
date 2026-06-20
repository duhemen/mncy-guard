import psutil
import shutil
import os
import subprocess
from core.whitelist import is_whitelisted

def terminate_process(pid):
    try:
        process = psutil.Process(pid)
        name = process.name()
        
        # --- PENGAMANAN TAMBAHAN ---
        if is_whitelisted(process_name=name):
            return False, f"Proses {name} dilindungi (System Process)."
            
        process.terminate()
        return True, f"Berhasil menghentikan: {name}"
    except Exception as e:
        return False, f"Error: {str(e)}"

def quarantine_process(pid):
    """Menghentikan proses dan memindahkan file ke karantina."""
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe() # Mendapatkan lokasi file
        proc.terminate() # Matikan dulu prosesnya
        
        # Lokasi Karantina
        quarantine_dir = r"C:\mncy\quarantine"
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)
            
        # Pindahkan file
        dest_path = os.path.join(quarantine_dir, f"{proc.name()}_{pid}.quarantine")
        shutil.move(exe_path, dest_path)
        return True, f"Proses {proc.name()} dikarantina ke {dest_path}"
    except Exception as e:
        return False, f"Gagal karantina: {str(e)}"
    
def block_ip(ip_address):
    # --- PENGAMANAN TAMBAHAN ---
    if is_whitelisted(ip_address=ip_address):
        print(f"[PROTECT]: IP {ip_address} terdeteksi di Whitelist. Blokir dibatalkan.")
        return False, "IP dilindungi."
    
    rule_name = f"MNCY_Block_{ip_address}"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
    
    try:
        subprocess.run(command, shell=True, check=True)
        return True, f"Berhasil memblokir IP: {ip_address}"
    except Exception as e:
        return False, f"Gagal memblokir: {str(e)}"