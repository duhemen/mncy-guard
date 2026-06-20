import scapy.all as scapy
import psutil
import json
import os

# --- OTOMATISASI GATEWAY ---
def get_gateway_info():
    try:
        # Mencari IP Gateway dari routing table
        gateway_ip = scapy.conf.route.route("0.0.0.0")[2]
        # Mencari MAC Address Gateway
        gateway_mac = scapy.getmacbyip(gateway_ip)
        print(f"[+] Gateway Terdeteksi: IP={gateway_ip}, MAC={gateway_mac}")
        return gateway_ip, gateway_mac
    except Exception as e:
        print(f"[-] Gagal mendeteksi Gateway: {e}")
        return None, None

# Inisialisasi otomatis saat modul dimuat
GATEWAY_IP, GATEWAY_MAC = get_gateway_info()

def detect_arp_spoofing(packet):
    """Deteksi ARP Spoofing dengan Gateway otomatis."""
    if not hasattr(packet, 'arp'):
        return False, ""

    opcode = getattr(packet.arp, 'opcode', None)
    src_mac = getattr(packet.arp, 'src_hw_mac', None)
    src_ip = getattr(packet.arp, 'src_proto_ipv4', None)

    # Pastikan data terdeteksi
    if not GATEWAY_IP or not GATEWAY_MAC:
        return False, ""

    # Opcode '2' adalah ARP Reply
    if opcode == '2' and src_mac and src_ip:
        # Cek apakah paket datang dari IP Gateway
        if src_ip == GATEWAY_IP:
            # Jika MAC berbeda dengan MAC Gateway asli, itu Spoofing!
            if src_mac.lower() != GATEWAY_MAC.lower():
                msg = f"ALERT: ARP SPOOFING! {src_mac} menyamar jadi Gateway {GATEWAY_IP}."
                print(f"[!!!] {msg}")
                return True, msg
    
    return False, ""

packet_count = {}
def detect_flooding(src_ip):
    # Logika tetap sama, pastikan src_ip valid
    if src_ip == "N/A": return False
    import time
    now = time.time()
    if src_ip not in packet_count: packet_count[src_ip] = []
    packet_count[src_ip].append(now)
    packet_count[src_ip] = [t for t in packet_count[src_ip] if now - t < 1]
    return len(packet_count[src_ip]) > 500

QUARANTINE_FILE = "quarantine_list.json"

def get_quarantine_data():
    if not os.path.exists(QUARANTINE_FILE):
        return {}
    with open(QUARANTINE_FILE, 'r') as f:
        return json.load(f)

def quarantine_process(pid, reason):
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        file_path = proc.exe()
        
        # 1. Suspend proses agar tidak bisa jalan
        proc.suspend()
        
        # 2. Simpan ke database karantina
        data = get_quarantine_data()
        data[str(pid)] = {
            "name": proc_name,
            "path": file_path,
            "reason": reason
        }
        with open(QUARANTINE_FILE, 'w') as f:
            json.dump(data, f)
            
        return True, f"Berhasil mengkarantina {proc_name} (PID: {pid})"
    except Exception as e:
        return False, str(e)

def release_process(pid):
    try:
        proc = psutil.Process(int(pid))
        proc.resume() # Hidupkan kembali
        
        # Hapus dari database
        data = get_quarantine_data()
        if str(pid) in data:
            del data[str(pid)]
            with open(QUARANTINE_FILE, 'w') as f:
                json.dump(data, f)
        return True, "Proses berhasil dikembalikan."
    except Exception as e:
        return False, str(e)