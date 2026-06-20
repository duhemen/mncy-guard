import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import datetime
import psutil
from core.detector import check_file_reputation
import json
from core.network_shield import release_process, get_quarantine_data, quarantine_process
from core.mitigator import block_ip, terminate_process, quarantine_process
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx
import queue

class Dashboard(ttk.Window):

    def is_threat(self, ip):
        """Memeriksa apakah IP ada di daftar ancaman (bisa dihubungkan ke modul intelligence)."""
        # Kamu bisa mengimpor threat_list dari core.intelligence jika sudah ada
        try:
            from core.intelligence import threat_list
            return ip in threat_list
        except:
            return False

    def __init__(self, start_scan_callback, stop_callback):
        super().__init__(themename="darkly")
        self.title("Mncy-Guard Security Center")
        self.geometry("900x700")
        self.stop_callback = stop_callback

        # 1. Notebook sebagai kontainer utama
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # 2. Tab Monitoring
        self.main_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text="Network Monitor")

        # 3. Filter Combobox (Emen bisa taruh di sini agar terlihat rapi)
        self.filter_var = tk.StringVar(value="All")
        self.filter_combo = ttk.Combobox(self.main_tab, textvariable=self.filter_var, state="readonly")
        self.filter_combo['values'] = ("All", "TCP", "UDP", "ARP", "IP")
        self.filter_combo.pack(fill=X, pady=5)
        self.filter_combo.bind("<<ComboboxSelected>>", self.apply_filter)

        # Tabel Data Capture (Di dalam main_tab)
        cols = ("Time", "Src", "Dst", "Proto", "PID", "Process", "Status")
        self.tree_net = ttk.Treeview(self.main_tab, columns=cols, show="headings", height=10)
        self.tree_net.tag_configure('danger', background='#ffcccc', foreground='black')
        
        self.data_queue = queue.Queue()
        
        # PERBAIKAN: Hapus .root dari sini
        self.after(1000, self.process_queue)

        # --- DISINI Emen MENGHUBUNGKAN SORTIR ---
        for col in cols:
            self.tree_net.heading(col, text=col, command=lambda c=col: self.sort_column(self.tree_net, c, False))
            self.tree_net.column(col, width=100)
        
        self.tree_net.pack(fill=BOTH, expand=True, pady=5)
        self.setup_graph()

        # --- Tabel Threats (Tabel Bawah) ---
        self.tree = ttk.Treeview(self.main_tab, columns=cols, show="headings", height=8)
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        self.tree.pack(fill=BOTH, expand=True, pady=5)

        # --- Frame untuk Tombol Kontrol ---
        btn_frame = ttk.Frame(self.main_tab) # Menggunakan main_tab sebagai parent
        btn_frame.pack(fill=X, pady=5)

        # --- Tombol ---
        ttk.Button(btn_frame, text="Block Selected IP", command=self.manual_block_threat).pack(side=LEFT, padx=5)
        ttk.Button(btn_frame, text="Unblock Selected IP", command=self.manual_unblock_threat).pack(side=LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear Logs", command=self.clear_threats).pack(side=LEFT, padx=5)

        # 3. Tab Quarantine
        self.quarantine_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.quarantine_tab, text="Quarantine Manager")

        self.quarantine_list = tk.Listbox(self.quarantine_tab)
        self.quarantine_list.pack(fill=BOTH, expand=True, pady=5)

        self.btn_release = ttk.Button(self.quarantine_tab, text="Release Selected", command=self.handle_release)
        self.btn_release.pack(fill=X)

        # 4. Panel Tombol Aksi (Tetap di bawah agar selalu terlihat)
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=X, padx=10, pady=10)

        self.start_btn = ttk.Button(btn_frame, text="Start Monitor", bootstyle="success", command=start_scan_callback)
        self.start_btn.pack(side=LEFT, padx=2)

        self.stop_btn = ttk.Button(btn_frame, text="Stop Monitor", bootstyle="danger", command=stop_callback, state=DISABLED)
        self.stop_btn.pack(side=LEFT, padx=2)

        self.kill_btn = ttk.Button(btn_frame, text="Kill Selected", bootstyle="warning", command=self.kill_selected)
        self.kill_btn.pack(side=LEFT, padx=2)

        self.block_btn = ttk.Button(btn_frame, text="Block IP", bootstyle="danger", command=self.block_selected_ip)
        self.block_btn.pack(side=LEFT, padx=2)

        self.unblock_btn = ttk.Button(btn_frame, text="Unblock IP", bootstyle="info", command=self.unblock_selected_ip)
        self.unblock_btn.pack(side=LEFT, padx=2)
        
        self.quarantine_btn = ttk.Button(btn_frame, text="Quarantine", bootstyle="danger", command=self.handle_quarantine)
        self.quarantine_btn.pack(side=LEFT, padx=2)

        # Status Bar
        self.status_label = ttk.Label(self, text="Ready", relief=SUNKEN, anchor=W)
        self.status_label.pack(side=BOTTOM, fill=X)

    # --- FUNGSI FUNGSI ---

    def setup_graph(self):
        import networkx as nx
        self.G = nx.Graph() 
        self.graph_frame = ttk.LabelFrame(self.main_tab, text="Cybernet War Map (Real-time)")
        self.graph_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        self.fig, self.ax = plt.subplots(figsize=(6, 4), dpi=100, facecolor='#2c3e50')
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(fill=BOTH, expand=True)

    def update_graph(self, src_ip, dst_ip=None):
        # Cukup masukkan ke antrean saja
        self.data_queue.put((src_ip, dst_ip))

    def process_queue(self):
        if not self.data_queue.empty():
            while not self.data_queue.empty():
                src_ip, dst_ip = self.data_queue.get()
                target = dst_ip if dst_ip is not None else "Unknown"
                if src_ip != "N/A":
                    # Gunakan self.G (bukan self.graph)
                    if self.is_threat(src_ip):
                        self.G.add_edge(src_ip, target, color='red', weight=2)
                    else:
                        self.G.add_edge(src_ip, target, color='green', weight=1)

            # Render grafik
            try:
                self.ax.clear()
                self.ax.set_facecolor('#2c3e50')
                pos = nx.spring_layout(self.G, k=0.5, seed=42)
            
                # Gambar node dan edge
                nx.draw_networkx_nodes(self.G, pos, ax=self.ax, node_size=300, node_color='cyan')
                nx.draw_networkx_labels(self.G, pos, ax=self.ax, font_size=8, font_color='white')
            
                # Gambar edge dengan warna dinamis
                edges = self.G.edges(data=True)
                for u, v, d in edges:
                    color = d.get('color', 'green')
                    nx.draw_networkx_edges(self.G, pos, ax=self.ax, edgelist=[(u, v)], edge_color=color, width=2)
            
                self.canvas.draw()
            except Exception:
                pass
            
        self.after(1000, self.process_queue)
    
    def apply_filter(self, event=None):
        """Fungsi untuk menyaring paket berdasarkan pilihan filter."""
        selected_filter = self.filter_combo.get()
        print(f"Filtering by: {selected_filter}")
        
        # Logika penyaringan:
        # 1. Hapus semua item di treeview utama
        for item in self.tree.get_children():
            self.tree.delete(item)

    def sort_column(self, tv, col, reverse):
        """Fungsi untuk mengurutkan isi kolom Treeview saat header diklik."""
        # Ambil data dari kolom yang diklik
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        
        # Urutkan list data
        l.sort(reverse=reverse)

        # Pindahkan item di Treeview sesuai urutan baru
        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)

        # Update heading agar klik berikutnya bisa membalikkan urutan (Asc/Desc)
        tv.heading(col, command=lambda: self.sort_column(tv, col, not reverse))
    
    def manual_block_threat(self):
        # Mengambil item yang dipilih di tabel bawah (self.tree)
        selected_item = self.tree.focus()
        if not selected_item:
            print("Pilih baris ancaman terlebih dahulu!")
            return
            
        values = self.tree.item(selected_item)['values']
        ip_to_block = values[1] # Indeks 1 adalah kolom 'Src'
        
        # Panggil fungsi block dari mitigator.py
        success, msg = block_ip(ip_to_block)
        print(msg)

    def manual_unblock_threat(self):
        # 1. Ambil IP dari baris yang diklik
        selected_item = self.tree.focus()
        if not selected_item:
            print("Pilih baris ancaman terlebih dahulu!")
            return
            
        values = self.tree.item(selected_item)['values']
        ip_to_unblock = values[1] # Indeks 1 adalah kolom 'Src'
        
        # 2. Jalankan perintah unblock (menggunakan teknik yang sama dengan block_ip)
        import subprocess
        rule_name = f"MNCY_Block_{ip_to_unblock}"
        command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        
        try:
            subprocess.run(command, shell=True, check=True)
            print(f"Berhasil menghapus blokir untuk IP: {ip_to_unblock}")
        except Exception as e:
            print(f"Gagal unblock: {str(e)}")

    def clear_threats(self):
        # Menghapus semua baris di tabel threats
        for item in self.tree.get_children():
            self.tree.delete(item)

    def kill_selected(self):
        # Perhatikan indentasi di sini, harus menjorok ke dalam!
        selected_item = self.tree_net.selection()
        if not selected_item:
            return 
        
        item_data = self.tree_net.item(selected_item[0])['values']
        pid = item_data[4] 
        
        if pid != "N/A" and pid != "Unknown":
            try:
                process = psutil.Process(int(pid))
                process.terminate()
                self.log(f"Process {pid} terminated.")
                self.tree_net.delete(selected_item)
            except Exception as e:
                self.log(f"Failed to kill: {e}")

    def block_selected_ip(self):
        print("DEBUG: Tombol Block IP ditekan!") # <-- Tambahkan ini
        selected_item = self.tree_net.selection() # Pastikan pakai tree_net (bukan tree)
        
        if not selected_item:
            self.log("Pilih IP dari tabel atas dulu!")
            return
        
        item_data = self.tree_net.item(selected_item[0])['values']
        ip_to_block = item_data[1] # Pastikan indeks 1 adalah kolom Src
        
        print(f"DEBUG: Mencoba memblokir IP: {ip_to_block}") # <-- Tambahkan ini
        
        if ip_to_block != "-" and ip_to_block != "N/A":
            try:
                import subprocess
                rule_name = f"Mncy-Guard-Block-{ip_to_block}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_to_block}'
                
                subprocess.run(cmd, shell=True, check=True)
                self.log(f"SUCCESS: IP {ip_to_block} telah diblokir.")
                print("DEBUG: Perintah netsh berhasil!")
            except Exception as e:
                self.log(f"Gagal: {e}")
                print(f"DEBUG: Error terjadi: {e}")

    def unblock_selected_ip(self):
        # 1. Konfirmasi agar tidak salah hapus
        ip_to_unblock = simpledialog.askstring("Unblock IP", "Masukkan IP yang ingin dibuka aksesnya:")
        
        if not ip_to_unblock:
            return

        confirm = messagebox.askyesno("Konfirmasi", f"Apakah Anda yakin ingin membuka blokir IP {ip_to_unblock}?")
        if not confirm:
            return

        try:
            import subprocess
            rule_name = f"Mncy-Guard-Block-{ip_to_unblock}"
            
            # Perintah untuk menghapus rule
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            
            # Menjalankan perintah
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log(f"SUCCESS: IP {ip_to_unblock} telah di-unblock.")
                messagebox.showinfo("Berhasil", f"IP {ip_to_unblock} berhasil dibuka!")
            else:
                self.log(f"Gagal: Aturan untuk {ip_to_unblock} tidak ditemukan.")
                messagebox.showwarning("Info", "Aturan firewall tidak ditemukan, mungkin IP tidak sedang diblokir.")
                
        except Exception as e:
            self.log(f"Error sistem: {e}")
            messagebox.showerror("Error", f"Terjadi kesalahan: {e}")


    def quarantine_selected(self):
        from core.mitigator import quarantine_process
        selected_item = self.tree_net.selection()
        if not selected_item:
            return
        
        item_data = self.tree_net.item(selected_item[0])['values']
        pid = item_data[4]
    
        if pid != "N/A" and pid != "Unknown":
            success, message = quarantine_process(int(pid))
            # Indentasi ini harus masuk ke dalam IF
            if success:
                self.log(message)
                self.tree_net.delete(selected_item)
            else:
                self.log(f"Error: {message}")

    def handle_quarantine(self):
        selected_item = self.tree_net.selection()
        if selected_item:
            item_data = self.tree_net.item(selected_item[0])['values']
            pid = item_data[4]
            if str(pid).isdigit():
                # Panggil fungsi dari main.py atau lewat callback
                success, msg = quarantine_process(int(pid), "Manual Request")
                if success:
                    self.log(msg)
                    self.refresh_quarantine_list()

    def handle_release(self):
        selection = self.quarantine_list.curselection()
        if selection:
            # Ambil PID dari string "PID: Name"
            pid = self.quarantine_list.get(selection[0]).split(":")[0]
            success, msg = release_process(pid)
            if success:
                self.log(msg)
                self.refresh_quarantine_list()

    def refresh_quarantine_list(self):
        # Bersihkan listbox agar tidak menumpuk
        self.quarantine_list.delete(0, tk.END)
        # Ambil data dari modul shield
        data = get_quarantine_data()
        for pid, info in data.items():
            self.quarantine_list.insert(tk.END, f"{pid}: {info['name']}")


    def check_selected_process(self):
        selected_item = self.tree_net.selection()
        if not selected_item: return
        
        item_data = self.tree_net.item(selected_item[0])['values']
        pid = item_data[4]
        
        if pid != "N/A":
            try:
                proc = psutil.Process(int(pid))
                info = check_file_reputation(proc.exe())
                self.log(f"Reputasi {proc.name()}: {info}")
            except Exception as e:
                self.log(f"Gagal cek: {e}")


    def add_packet_row(self, src, dst, proto, pid, proc_name):
        try:
            time_str = datetime.datetime.now().strftime("%H:%M:%S")
            
            # Masukkan data ke tabel
            item = self.tree_net.insert("", 0, values=(
                time_str, src, dst, proto, pid, proc_name, "Captured"
            ))
            
            # Jika "ATTACK" dalam nama proses, beri warna merah (tag 'danger')
            if "ATTACK" in proc_name:
                self.tree_net.item(item, tags=('danger',))
            
            # Cek filter yang sedang aktif
            # Gunakan getattr agar aplikasi tidak crash jika filter_var belum terdefinisi
            selected_proto = getattr(self, 'filter_var', tk.StringVar(value="All")).get()
            
            if selected_proto != "All" and proto.upper() != selected_proto.upper():
                self.tree_net.detach(item) 
            
            # Logika auto-scroll & batas 100 baris
            self.tree_net.yview_moveto(0)
            children = self.tree_net.get_children()
            if len(children) > 100:
                self.tree_net.delete(children[-1])
                
        except Exception as e:
            print(f"GUI Update Error: {e}")

    def log(self, message):
        self.status_label.config(text=message)
        print(f"[UI LOG]: {message}")
    
    def add_threat(self, src, dst, proto, pid, name, reason):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        # Masukkan ke tree atas dengan tag 'danger'
        self.tree_net.insert("", 0, values=(now, src, dst, proto, pid, name, reason), tags=('danger',))
        # Masukkan juga ke tree bawah (log ancaman)
        self.tree.insert("", 0, values=(now, src, dst, proto, pid, name, reason))

    def on_closing(self):
        """Fungsi ini dipanggil saat tombol X diklik."""
        print("[UI LOG]: Menutup aplikasi...")
        
        # 1. Hentikan pemanggilan update berikutnya
        # Kita perlu cara untuk menghentikan loop after
        # (Jika perlu, tambahkan variabel flag self.running = False)
        
        # 2. Panggil stop_callback yang dikirim dari main.py
        if self.stop_callback:
            self.stop_callback()
            
        # 3. Hancurkan jendela
        self.destroy()
        
        # 4. Paksa keluar agar tidak ada sisa proses di latar belakang
        import sys
        sys.exit(0)