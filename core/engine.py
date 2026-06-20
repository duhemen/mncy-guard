# C:\mncy\core\engine.py

class SignatureEngine:
    def __init__(self):
        # Database aturan sederhana (bisa dikembangkan dari file eksternal)
        self.signatures = {
            "nmap_pattern": b"\x00\x4e\x6d\x61\x70",  # Contoh signature hex
            "malicious_cmd": b"cmd.exe /c",
            "exploit_pattern": b"\x90\x90\x90\x90"     # NOP sled
        }

    def check_payload(self, payload):
        """Memeriksa apakah payload mengandung tanda tangan ancaman."""
        if not payload:
            return None
            
        for name, sig in self.signatures.items():
            if sig in payload:
                return name
        return None

# Instansiasi untuk digunakan di sniffer
engine = SignatureEngine()