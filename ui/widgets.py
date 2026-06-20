import tkinter as tk
import ttkbootstrap as ttk

class SummaryCard(ttk.Frame):
    """Komponen untuk membuat kartu statistik modern."""
    def __init__(self, parent, title, value, color="info"):
        super().__init__(parent, bootstyle="secondary")
        self.pack(side="left", padx=10, pady=10, fill="x", expand=True)
        
        lbl_title = ttk.Label(self, text=title, font=("Arial", 10, "bold"))
        lbl_title.pack(pady=(10, 0))
        
        self.lbl_value = ttk.Label(self, text=value, font=("Arial", 14, "bold"), bootstyle=color)
        self.lbl_value.pack(pady=(0, 10))

    def update_value(self, new_value):
        self.lbl_value.config(text=new_value)

class HealthCard(SummaryCard):
    """Kartu khusus untuk Health Score yang berubah warna."""
    def update_health(self, score):
        # Update teks skor
        self.lbl_value.config(text=f"{score}%")
        
        # Logika perubahan warna
        if score > 80:
            self.lbl_value.config(bootstyle="success")
        elif score > 50:
            self.lbl_value.config(bootstyle="warning")
        else:
            self.lbl_value.config(bootstyle="danger")