# core/sniffer.py
import pyshark
import threading
import asyncio

class NetworkSniffer(threading.Thread):
    def __init__(self, callback):
        super().__init__(daemon=True)
        self.callback = callback
        self.running = True
        self.capture = None

    def run(self):
        # MEMAKSA PEMBUATAN EVENT LOOP BARU
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        except Exception:
            loop = asyncio.get_event_loop()

        print("DEBUG: Sniffing di interface: Wi-Fi")
        
        try:
            # Menggunakan mode standar, kita tidak perlu async_mode
            self.capture = pyshark.LiveCapture(interface='Wi-Fi')
            
            # Kita gunakan sniff_continuously
            for packet in self.capture.sniff_continuously():
                if not self.running:
                    break
                self.callback(packet)
                
        except Exception as e:
            print(f"[Sniffer Error]: {e}")
        finally:
            self.stop()
            loop.close()

    def stop(self):
        self.running = False
        if self.capture:
            try:
                self.capture.close()
            except:
                pass