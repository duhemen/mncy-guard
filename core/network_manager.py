import psutil

def get_process_by_port(port):
    """Mencari nama proses dan PID berdasarkan port yang digunakan."""
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port or (conn.raddr and conn.raddr.port == port):
            try:
                proc = psutil.Process(conn.pid)
                return proc.pid, proc.name()
            except:
                continue
    return "N/A", "Unknown"