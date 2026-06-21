# --- Import Modul & Konfigurasi ---
import threading
import time
import socket
import subprocess
import asyncio
from tkinter import simpledialog
from plyer import notification

# Mengambil konfigurasi dari file config.py
from config import SCAN_INTERVAL, INTERFACE

# Import komponen internal proyek
from ui.dashboard import Dashboard
from core.detector import scan_processes
from core.sniffer import NetworkSniffer
from core.network_manager import get_process_by_port
from db.database import init_db, log_threat
from core.analyzer import analyze_nmap, analyze_beaconing, analyze_stateful_behavior
from core.network_shield import detect_arp_spoofing, detect_flooding, quarantine_process, release_process, get_quarantine_data
from core.mitigator import block_ip
from core.engine import engine
from core.intelligence import check_ip_reputation
from core.whitelist import is_whitelisted
from core.analyzer import calculate_entropy, check_payload
from core.filter_logic import should_ignore_alert
import traceback


# --- Pesan Pembuka Profesional ---
print("========================================")
print("Mncy-Guard v1.0 | Mengaktifkan perlindungan jaringan...")
print(f"Mode Scan: {SCAN_INTERVAL} detik")
print(f"Interface Aktif: {INTERFACE}")
print("========================================")

# Inisialisasi Database
init_db()

# Variabel Global untuk mengelola Thread
sniffer_instance = None
monitor_running = True
packet_count_per_second = 0
total_packets = 0
total_threats = 0

def get_current_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        traceback.print_exc()
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip

# Di dalam main.py
def run_system_monitor(ui):
    global monitor_running
    while monitor_running:
        threats = scan_processes()
        for t in threats:
            # GUNAKAN ui.after agar aman untuk thread UI
            ui.after(0, lambda: ui.add_threat(t['pid'], t['name'], "Suspicious Process"))
            ui.after(0, lambda: log_threat(t['name'], t['pid'], "Detected by scanner"))
        time.sleep(5)

def trigger_alert(threat_msg, ip_target):
    # Definisi fungsi 'show' di dalam agar bisa diakses oleh threading
    def show():
        notification.notify(
            title='Mncy-Guard Alert!',
            message=f'Ancaman Terdeteksi: {threat_msg} dari {ip_target}',
            app_icon=None, 
            timeout=5,
        )
    
    # Jalankan fungsi 'show' tersebut di thread terpisah
    threading.Thread(target=show, daemon=True).start()

def on_packet_captured(packet):
    global packet_count_per_second, total_packets, total_threats
    
    # 1. Ekstraksi Data
    src_ip, dst_ip, proto, pid, proc_name = "N/A", "N/A", "Unknown", "0", "N/A"

    if hasattr(packet, 'arp'):
        src_ip, dst_ip, proto = packet.arp.src_proto_ipv4, packet.arp.dst_proto_ipv4, "ARP"
    elif 'IP' in packet or 'IPV6' in packet:
        ip_layer = packet.ip if 'IP' in packet else packet.ipv6
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        proto = packet.transport_layer if hasattr(packet, 'transport_layer') else "IP"
        if hasattr(packet, 'transport_layer'):
            try:
                src_port = int(packet[packet.transport_layer].srcport)
                pid, proc_name = get_process_by_port(src_port)
            except: pass

    # 2. Statistik
    packet_count_per_second += 1
    total_packets += 1
    update_ui_stats()

    # 3. Analisis Perilaku & Whitelist
    is_beaconing, msg = analyze_stateful_behavior(src_ip, dst_ip, proto, pid, proc_name)
    trusted_processes = ["Code.exe", "msedge.exe", "chrome.exe", "firefox.exe", "svchost.exe", "explorer.exe"]
    is_safe = (is_whitelisted(ip_address=src_ip) or is_whitelisted(ip_address=dst_ip) or proc_name in trusted_processes)

    # 4. Logika Alert
    if is_beaconing and not is_safe:
        total_threats += 1  # <--- WAJIB ADA
        update_ui_stats()   # <--- WAJIB ADA agar angka di dashboard berubah
        app.after(0, app.add_threat, src_ip, dst_ip, proto, pid, proc_name, msg)

    # 5. Analisis Payload (Signature, Entropy, Blacklist, API Reputasi)
    if hasattr(packet, 'data') and hasattr(packet.data, 'data'):
        try:
            raw_data = packet.data.data.replace(':', '')
            payload = bytes.fromhex(raw_data)
            
            # Cek Signature
            threat_sig = check_payload(payload)
            if threat_sig:
                total_threats += 1            # Tambahkan ini
                update_ui_stats()             # Tambahkan ini
                app.add_threat(src_ip, dst_ip, proto, pid, proc_name, threat_sig)

            # Cek Entropy
            if len(payload) > 50 and calculate_entropy(payload) > 7.5:
                total_threats += 1            # Tambahkan ini
                update_ui_stats()             # Tambahkan ini
                app.add_threat(src_ip, dst_ip, proto, pid, proc_name, "High Entropy/Beaconing")

            # Cek Reputasi AbuseIPDB
            if src_ip != "N/A" and not is_safe:
                score = check_ip_reputation(src_ip)
                if score and score > 50:
                    total_threats += 1        # Tambahkan ini
                    update_ui_stats()         # Tambahkan ini
                    app.log(f"ALERT: IP {src_ip} memiliki skor ancaman tinggi: {score}%")
                    app.add_threat(src_ip, dst_ip, proto, pid, proc_name, f"High Reputation Threat ({score}%)")
                    block_ip(src_ip)
                        
        except Exception as e:
            pass # Menghindari crash pada paket malformed

    # 6. Deteksi Flooding & Update GUI
    if src_ip != "N/A" and detect_flooding(src_ip):
        block_ip(src_ip)
    
    app.after(0, app.add_packet_row, src_ip, dst_ip, proto, pid, proc_name)
    app.update_graph(src_ip, dst_ip)

# --- FUNGSI PENDUKUNG ---

def run_system_monitor(ui):
    while monitor_running:
        for t in scan_processes():
            ui.after(0, lambda: ui.add_threat(t['pid'], t['name'], "Suspicious"))
        time.sleep(5)

# --- CALLBACK UNTUK TOMBOL ---

def start_monitor():
    global sniffer_instance, monitor_running
    monitor_running = True
    
    # AKTIFKAN SAKLAR DASHBOARD
    app.is_monitoring = True # <--- TAMBAHKAN INI
    
    # 1. Jalankan Scanner Thread
    threading.Thread(target=run_system_monitor, args=(app,), daemon=True).start()
    
    # 2. Jalankan Sniffer Thread
    sniffer_instance = NetworkSniffer(on_packet_captured)
    sniffer_instance.start()
    
    app.log("System Security Engine Started...")
    app.start_btn.config(state="disabled")
    app.stop_btn.config(state="normal")

def trigger_quarantine(pid):
    global app
    success, msg = quarantine_process(pid, "Security Trigger")
    if success:
        # Panggil fungsi refresh yang ada di app (Dashboard)
        if hasattr(app, 'refresh_quarantine_list'):
            app.refresh_quarantine_list() 
        app.log(msg)

def reset_counter():
    global packet_count_per_second
    while True:
        time.sleep(1) # Tunggu 1 detik
        # Kirim data ke GUI (Emen perlu pastikan app sudah memiliki metode update_graph)
        if 'app' in globals():
            app.after(0, app.update_graph, packet_count_per_second)
        # Reset counter
        packet_count_per_second = 0
def update_ui_stats():
    global total_threats, total_packets
    # Pastikan kita mengirim 'total_threats' (variabel global yang tadi ditambah)
    if 'app' in globals():
        app.update_stats(total_threats, total_packets)

def stop_monitor():
    global sniffer_instance, monitor_running
    monitor_running = False 
    
    if sniffer_instance:
        try:
            # Panggil method yang sudah ada di NetworkSniffer
            sniffer_instance.stop() 
            # Jika ada fungsi close() biasa, panggil itu saja, jangan async
            if hasattr(sniffer_instance, 'close'):
                sniffer_instance.close()
        except Exception as e:
            # Kita tulis info saja, tidak perlu detail error agar tidak menakutkan
            print(f"Info: Sniffer dihentikan.")
        finally:
            sniffer_instance = None
    
    try:
        app.log("System Security Engine Stopped.")
        app.start_btn.config(state="normal")
        app.stop_btn.config(state="disabled")
    except:
        pass

# --- INISIALISASI ---

if __name__ == "__main__":
    # 1. Inisialisasi Dashboard
    app = Dashboard(start_monitor, stop_monitor)

    # Definisi fungsi harus di luar dari alur utama jika ingin dipanggil nanti
    def refresh_ui():
        app.refresh_quarantine_list()
    
    app.refresh_quarantine_list = refresh_ui
    
    # 2. Definisikan on_closing
    def on_closing():
        print("DEBUG: Tombol X ditekan!")
        global sniffer_instance
        stop_monitor()
        app.destroy() # Ini wajib ada agar jendela tertutup
    
    # 3. Hubungkan protokol
    app.protocol("WM_DELETE_WINDOW", on_closing)
    
    # 4. Jalankan thread pendukung
    threading.Thread(target=reset_counter, daemon=True).start()
    
    # 5. Jalankan aplikasi (INI HARUS PALING BAWAH)
    app.mainloop()