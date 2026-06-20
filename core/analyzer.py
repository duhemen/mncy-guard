import time
from core.filter_logic import should_ignore_alert

port_history = {}
connection_history = {}
last_seen = {}

# Tambahkan variabel untuk mencatat waktu terakhir peringatan (Sistem Cooldown)
last_alert_time = {}

def analyze_nmap(src_ip, dst_port):
    current_time = time.time()
    
    if src_ip not in port_history:
        port_history[src_ip] = set()
        last_seen[src_ip] = current_time
    
    port_history[src_ip].add(dst_port)
    
    if len(port_history[src_ip]) > 15:
        print(f"[!] DETEKSI NMAP: Pemindaian port mencurigakan dari {src_ip}")
        port_history[src_ip] = set()
        return True
    
    if current_time - last_seen[src_ip] > 60:
        port_history[src_ip] = set()
        last_seen[src_ip] = current_time
        
    return False

def analyze_beaconing(src_ip, dst, proto, pid, name):
    """Deteksi beaconing dengan sistem Anti-Spam (Cooldown)."""
    current_time = time.time()

    is_safe, reason = should_ignore_alert(pid, src_ip)
    
    if is_safe:
        return None
    
    # 1. SISTEM COOLDOWN: Jika IP ini baru saja dilaporkan dalam 60 detik terakhir, abaikan!
    if src_ip in last_alert_time and current_time - last_alert_time[src_ip] < 60:
        return False
    
    # 2. ABAIKAN IP LOKAL (Jaringan sendiri)
    if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("127."):
        return False
        
    if src_ip not in connection_history:
        connection_history[src_ip] = []
    
    connection_history[src_ip].append(current_time)
    
    # Bersihkan riwayat yang lebih tua dari 10 detik saja
    connection_history[src_ip] = [t for t in connection_history[src_ip] if current_time - t < 10]
    
    # 3. AMBANG BATAS NYATA (Traffic wajar vs tidak wajar)
    # 100 paket dalam 10 detik baru dianggap peringatan
    if len(connection_history[src_ip]) >= 100:
        last_alert_time[src_ip] = current_time # Kunci IP ini selama 60 detik ke depan
        print(f"[!] DETEKSI BEACONING: Komunikasi berulang dari {src_ip}")
        return True
            
    return False

connection_state = {} 

def analyze_stateful_behavior(src_ip, dst_ip):
    """
    Mendeteksi pola beaconing (komunikasi teratur/berulang)
    yang merupakan ciri khas botnet/C2.
    """
    now = time.time()
    key = f"{src_ip}->{dst_ip}"
    
    if key not in connection_state:
        connection_state[key] = []
        
    # Catat waktu koneksi saat ini
    connection_state[key].append(now)
    
    # Hanya simpan riwayat 60 detik terakhir
    connection_state[key] = [t for t in connection_state[key] if now - t < 60]
    
    # Jika dalam 60 detik terjadi lebih dari 30 koneksi ke satu tujuan
    # Ini adalah indikasi kuat adanya Beaconing (heartbeat malware)
    if len(connection_state[key]) > 30:
        return True, "Potensi Beaconing (C2 Heartbeat Detected)"
    
    return False, ""