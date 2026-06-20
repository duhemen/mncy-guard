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
from core.intelligence import threat_list
from core.whitelist import WHITELISTED_IPS
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
monitor_running = True # Flag untuk menghentikan loop scanner
packet_count_per_second = 0

# Tambahkan ini:
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

# 3. Update Whitelist secara otomatis saat startup
current_ip = get_current_ip()
WHITELISTED_IPS.add(current_ip)
print(f"[SYSTEM]: IP lokal {current_ip} telah ditambahkan ke whitelist.")

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
    total_packets += 1
    
    # 1. INISIALISASI & EKSTRAKSI (Lakukan ini di PALING AWAL)
    src_ip, dst_ip = "N/A", "N/A"
    proto = "Unknown"
    pid, proc_name = "0", "N/A"

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
            except:
                pass

    # 2. UPDATE STATISTIK (Setelah data terekstraksi)
    packet_count_per_second += 1
    total_packets += 1
    update_ui_stats() # Sekarang statistik punya data yang valid

    # 3. ANALISIS PERILAKU
    is_beaconing, msg = analyze_stateful_behavior(src_ip, dst_ip, proto, pid, proc_name)
    trusted_processes = ["Code.exe", "msedge.exe", "chrome.exe", "firefox.exe", "svchost.exe", "explorer.exe"]
    is_safe = (src_ip in WHITELISTED_IPS or dst_ip in WHITELISTED_IPS or proc_name in trusted_processes)

    # 4. KIRIM KE GUI (Tampilkan row & update graph)
    app.after(0, app.add_packet_row, src_ip, dst_ip, proto, pid, proc_name)
    app.update_graph(src_ip, dst_ip)

   # 5. LOGIKA ALERT
    if is_beaconing and not is_safe:
        total_threats += 1
        print(f"DEBUG: Ancaman terdeteksi! Total Threats sekarang: {total_threats}") # <--- TAMBAHKAN INI
        update_ui_stats()
        app.after(0, app.add_threat, src_ip, dst_ip, proto, pid, proc_name, msg)
    
    # 4. Analisis Signature & Blacklist (Tetap jalan)
    if hasattr(packet, 'data') and hasattr(packet.data, 'data'):
        try:
            # Mengakses data dengan aman
            raw_data = packet.data.data.replace(':', '')
            payload = bytes.fromhex(raw_data)
            
            # 1. Cek Signature
            threat_signature = check_payload(payload)
            if threat_signature:
                pid_val = int(pid) if str(pid).isdigit() else 0
                ignore, reason = should_ignore_alert(pid_val, dst_ip)
                if not ignore:
                    app.log(f"ALERT: {threat_signature}")
                    app.add_threat(src_ip, dst_ip, proto, pid, proc_name, threat_signature)

            # 2. Cek Entropy
            if len(payload) > 50:
                entropy = calculate_entropy(payload)
                if entropy > 7.5:
                    pid_val = int(pid) if str(pid).isdigit() else 0
    
                    # 1. TETAP TAMBAHKAN STATISTIK (Ini agar Card Ancaman bergerak)
                    total_threats += 1
                    update_ui_stats()
    
                    # 2. BARU CEK FILTER UNTUK TAMPILAN ALERT
                    ignore, reason = should_ignore_alert(pid_val, dst_ip)
                    if not ignore:
                        app.log(f"ALERT: High Entropy Detected ({entropy:.2f})")
                        app.add_threat(src_ip, dst_ip, proto, pid, proc_name, f"C&C Beaconing ({entropy:.2f})")
                    else:
                        print(f"DEBUG: Alert di-ignore untuk PID {pid_val} (Filter aktif)")
            
            # 3. Cek Blacklist
            if src_ip != "N/A" and src_ip in threat_list and not is_safe:
                app.after(0, app.add_threat, src_ip, dst_ip, proto, pid, proc_name, "Malicious IP Source")
                app.log(f"ALERT: IP {src_ip} dalam database blacklist!")
                block_ip(src_ip)

        except (ValueError, TypeError) as e:
            # Menangani error konversi hex tanpa menghentikan program
            pass
        except Exception as e:
            # Ini akan menangkap error lainnya (seperti variabel yang belum terdefinisi)
            print("--- TERDETEKSI ERROR ---")
            traceback.print_exc() # Ini akan menampilkan detail error + baris kodenya
            print("-----------------------")

    # 5. Deteksi Flooding
    if src_ip != "N/A" and detect_flooding(src_ip):
        app.log(f"ALERT: FLOODING dari {src_ip}!")
        block_ip(src_ip)

        # 3. Analisis Payload/Signature
        if hasattr(packet, 'data'):
            try:
                # Cek apakah 'data' memiliki field 'data' secara aman
                # Kita gunakan getattr dengan default None untuk menghindari AttributeError
                data_field = getattr(packet.data, 'data', None)
        
                if data_field:
                    # Jika ada, baru kita proses
                    raw_data = data_field.replace(':', '')
                    payload = bytes.fromhex(raw_data)
            
                    # ... (Lanjutkan logika pengecekan Signature & Entropy Emen di sini) ...
            
            except Exception as e:
                # Menangkap error jika konversi hex gagal
                pass

        # 4. TAMPILKAN KE GUI
        app.after(0, app.add_packet_row, src_ip, dst_ip, proto, pid, proc_name)
        app.update_graph(src_ip, dst_ip)

        # 5. Deteksi Flooding
        if src_ip != "N/A" and detect_flooding(src_ip):
            msg = f"ALERT: FLOODING dari {src_ip}!"
            app.log(msg)
            block_ip(src_ip)

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
    
    # Karena app adalah instance dari Dashboard, panggil langsung.
    # Kita tetap menggunakan app.after agar thread sniffer tidak 
    # mengganggu thread utama (GUI).
    if 'app' in globals():
        app.after(0, lambda: app.update_stats(total_threats, total_packets))
    else:
        print("DEBUG: Instance app belum tersedia.")

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