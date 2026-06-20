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

def get_current_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
    except Exception:
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
    global packet_count_per_second
    packet_count_per_second += 1
    
    try:
        # 1. Inisialisasi data default
        src_ip, dst_ip, proto = "N/A", "N/A", "N/A"
        pid, proc_name = "N/A", "Unknown"
        
        # 2. Tangkap Data (Tanpa elif, agar semua jenis paket diproses)
        
        # --- Proses ARP ---
        if hasattr(packet, 'arp'):
            src_ip = packet.arp.src_proto_ipv4
            dst_ip = packet.arp.dst_proto_ipv4
            proto = "ARP"
            
            # Cek Spoofing
            is_spoofed, msg = detect_arp_spoofing(packet)
            if is_spoofed:
                app.after(0, app.add_packet_row, src_ip, dst_ip, proto, "N/A", "System (ATTACK!)")
                app.after(0, app.add_threat, src_ip, dst_ip, proto, "N/A", "System", msg)
                app.log(msg)
            else:
                app.after(0, app.add_packet_row, src_ip, dst_ip, proto, "N/A", "System")
            
            # Kirim ke Peta
            app.update_graph(src_ip, dst_ip)

        # --- Proses IP (TCP/UDP/Lainnya) ---
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto = packet.transport_layer if hasattr(packet, 'transport_layer') else "IP"
            
            name = proc_name if 'proc_name' in locals() else "Unknown"
            is_beaconing, msg = analyze_stateful_behavior(src_ip, dst_ip, proto, pid, name)
            if is_beaconing:
                app.after(0, app.add_threat, src_ip, dst_ip, proto, pid, proc_name, msg)
                app.log(f"ALERT: {msg} dari {src_ip}!")

            if src_ip in threat_list:
                app.log(f"ALERT: IP {src_ip} terdeteksi dalam Database Ancaman Global!")
                app.after(0, app.add_threat, src_ip, packet.ip.dst, "UNKNOWN", 0, "N/A", "Malicious IP Source")
                # Kita bisa memicu auto-block juga di sini
                from core.mitigator import block_ip
                block_ip(src_ip)

            if hasattr(packet, 'data'):
                payload = bytes.fromhex(packet.data.data.replace(':', ''))
                threat_name = engine.check_payload(payload)
                if threat_name:
                    app.after(0, app.add_threat, src_ip, dst_ip, proto, pid, proc_name, f"SIGNATURE: {threat_name}")
                    app.log(f"ALERT: Pola {threat_name} terdeteksi dari {src_ip}!")

            # Cari PID/Process jika ada port
            if hasattr(packet, 'transport_layer'):
                try:
                    src_port = int(packet[packet.transport_layer].srcport)
                    pid, proc_name = get_process_by_port(src_port)
                except:
                    pass

                # Analisis Keamanan (hanya untuk paket IP)
                if analyze_nmap(src_ip, int(packet[packet.transport_layer].dstport) if hasattr(packet[packet.transport_layer], 'dstport') else 0):
                    app.after(0, app.add_threat, src_ip, dst_ip, proto, pid, proc_name, "Nmap Scan")
            
            # Update GUI & Peta
            app.after(0, app.add_packet_row, src_ip, dst_ip, proto, pid, proc_name)
            app.update_graph(src_ip, dst_ip)

        # 3. Deteksi Flooding (Global)
        if src_ip != "N/A" and detect_flooding(src_ip):
            msg = f"ALERT: FLOODING dari {src_ip}!"
            app.log(msg)
            block_ip(src_ip)

    except Exception as e:
        # Error diamankan agar sniffer tidak mati
        pass

# --- CALLBACK UNTUK TOMBOL ---

def start_monitor():
    global sniffer_instance, monitor_running
    monitor_running = True
    
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