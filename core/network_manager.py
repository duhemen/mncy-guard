import psutil

def get_process_by_port(port):
    """Mencari nama proses dan PID berdasarkan port yang digunakan."""
    if not port or port == 0:
        return "N/A", "Unknown"

    try:
        for conn in psutil.net_connections(kind='inet'):
            # Pastikan port cocok dan pid tersedia
            if (conn.laddr and conn.laddr.port == port) or (conn.raddr and conn.raddr.port == port):
                if conn.pid:
                    proc = psutil.Process(conn.pid)
                    return proc.pid, proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    except Exception as e:
        # print(f"DEBUG: Error mencari PID: {e}") # Opsional, aktifkan jika mau debug
        pass
        
    return "N/A", "Unknown"