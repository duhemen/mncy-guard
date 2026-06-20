import sqlite3
import logging
from datetime import datetime

DB_PATH = "mncy_security.db"

logging.basicConfig(
    filename='keamanan_mncy.log',
    level=logging.INFO,
    format='%(asctime)s - [MNY-GUARD] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def init_db():
    """Membuat tabel log jika belum ada."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            process_name TEXT,
            pid INTEGER,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_threat(process_name, pid, reason):
    logging.info(f"Ancaman Terdeteksi: {process_name} (PID: {pid}) - Alasan: {reason}")
    """Menyimpan data ancaman ke database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO detection_logs (timestamp, process_name, pid, reason)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, process_name, pid, reason))
    conn.commit()
    conn.close()