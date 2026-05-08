import asyncio
import logging
from datetime import datetime, timedelta
from scapy.all import sniff, ARP, IP, TCP, UDP, Ether, get_if_hwaddr, conf
from collections import defaultdict, deque
import threading
import time
import socket

logger = logging.getLogger("NetGuard-IDS")

class IDSEngine:
    def __init__(self, alert_callback, gateway_callback=None):
        self.alert_callback = alert_callback # Async function to call for alerts
        self.gateway_callback = gateway_callback # Callback for when gateway is found
        self.running = False
        self._thread = None
        self.interface = None
        
        # Detection State
        self.mac_cache = {} # {ip: mac}
        self.gateway_ip = None
        self.gateway_mac = None
        
        # Port Scan Tracker (Vertical: One source -> Many ports on one target)
        # {src_ip: {dst_ip: set(ports)}}
        self.vertical_scan_cache = defaultdict(lambda: defaultdict(set))
        
        # Host Discovery Tracker (Horizontal: One source -> One port on many targets)
        # {src_ip: {port: set(dst_ips)}}
        self.horizontal_scan_cache = defaultdict(lambda: defaultdict(set))
        
        # Traffic Stats for DoS
        self.traffic_stats = defaultdict(int) # {ip: packet_count}
        
        # Configuration
        self.PORT_SCAN_THRESHOLD = 15 # Unique ports on one host
        self.HOST_DISC_THRESHOLD = 10 # Unique hosts for one port
        self.DOS_THRESHOLD = 1000 # Packets per second from one source
        self.WINDOW_SIZE = 10 # Seconds for window-based detection
        
        # Timestamps for windowing
        self.last_cleanup = time.time()
        self._lock = threading.Lock()
        
        # Bandwidth Monitoring
        # {ip: {"sent": bytes, "recv": bytes, "bps": float, "last_check": timestamp}}
        self.bandwidth_data = defaultdict(lambda: {"sent": 0, "recv": 0, "bps": 0.0, "last_check": time.time(), "prev_total": 0})

    def _packet_handler(self, pkt):
        try:
            now = time.time()
            
            # 1. ARP Spoofing Detection
            if ARP in pkt:
                self._handle_arp(pkt)

            # 2. Port & Host Scanning Detection
            if IP in pkt:
                self._handle_ip_scan(pkt, now)
                self._handle_bandwidth(pkt, now)

            # Periodic cleanup (every 30s to keep memory low)
            if now - self.last_cleanup > 30:
                with self._lock:
                    self.traffic_stats.clear()
                    self.vertical_scan_cache.clear()
                    self.horizontal_scan_cache.clear()
                self.last_cleanup = now

        except Exception as e:
            logger.error(f"IDS Handler Error: {e}")

    def _handle_arp(self, pkt):
        arp = pkt[ARP]
        if arp.op in [1, 2]: # Request or Reply
            src_ip = arp.psrc
            src_mac = arp.hwsrc.upper()
            
            with self._lock:
                # Ignore our own fake MAC used for blocking to prevent alert loops
                if src_mac == "00:0C:29:AB:CD:EF":
                    return
                
                # Check for MAC change for existing IP
                if src_ip in self.mac_cache and self.mac_cache[src_ip] != src_mac:
                    # Possible ARP Spoofing
                    msg = f"ARP Conflict! {src_ip} moved from {self.mac_cache[src_ip]} to {src_mac}"
                    severity = "High"
                    
                    # Critical if it's the gateway being spoofed
                    if src_ip == self.gateway_ip:
                        msg = f"CRITICAL: Gateway ARP Spoofing! {src_ip} is being hijacked by {src_mac}"
                        severity = "Critical"
                    
                    self._emit_alert(severity, "ARP Spoofing", msg, src_ip)
                
                self.mac_cache[src_ip] = src_mac
                
                # Specifically protect gateway if we don't know it yet
                # (Simple heuristic: first .1 or .254 seen is often gateway)
                if not self.gateway_ip and (src_ip.endswith(".1") or src_ip.endswith(".254")):
                    self.gateway_ip = src_ip
                    self.gateway_mac = src_mac
                    logger.info(f"IDS: Identified potential gateway at {src_ip} ({src_mac})")
                    if self.gateway_callback: self.gateway_callback(self.interface, self.gateway_ip)

    def _handle_ip_scan(self, pkt, now):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Ignore traffic to/from self if possible
        # if src_ip == self.my_ip: return

        # Flood / DoS Detection
        with self._lock:
            self.traffic_stats[src_ip] += 1
            if self.traffic_stats[src_ip] > self.DOS_THRESHOLD:
                self._emit_alert("Medium", "Flood Detection", f"High traffic volume from {src_ip}", src_ip)
                self.traffic_stats[src_ip] = 0

        # Scanning Detection
        proto_name = ""
        dport = 0
        
        if TCP in pkt:
            dport = pkt[TCP].dport
            proto_name = "TCP"
        elif UDP in pkt:
            dport = pkt[UDP].dport
            proto_name = "UDP"
        
        if dport:
            with self._lock:
                # Vertical Scan: One source -> Many ports on one target
                self.vertical_scan_cache[src_ip][dst_ip].add(dport)
                if len(self.vertical_scan_cache[src_ip][dst_ip]) > self.PORT_SCAN_THRESHOLD:
                    msg = f"Port Scan detected: {src_ip} scanned {len(self.vertical_scan_cache[src_ip][dst_ip])} {proto_name} ports on {dst_ip}"
                    self._emit_alert("High", "Port Scanning", msg, src_ip)
                    self.vertical_scan_cache[src_ip][dst_ip].clear()

                # Horizontal Scan: One source -> One port on many targets
                self.horizontal_scan_cache[src_ip][dport].add(dst_ip)
                if len(self.horizontal_scan_cache[src_ip][dport]) > self.HOST_DISC_THRESHOLD:
                    msg = f"Host Discovery detected: {src_ip} probing port {dport} across {len(self.horizontal_scan_cache[src_ip][dport])} hosts"
                    self._emit_alert("Medium", "Host Discovery", msg, src_ip)
                    self.horizontal_scan_cache[src_ip][dport].clear()

    def _handle_bandwidth(self, pkt, now):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        pkt_size = len(pkt)
        
        with self._lock:
            # Update sent for source
            self.bandwidth_data[src_ip]["sent"] += pkt_size
            # Update recv for destination
            self.bandwidth_data[dst_ip]["recv"] += pkt_size
            
            # Rate calculation (every ~1s)
            for ip in [src_ip, dst_ip]:
                data = self.bandwidth_data[ip]
                elapsed = now - data["last_check"]
                if elapsed >= 1.0:
                    current_total = data["sent"] + data["recv"]
                    diff = current_total - data["prev_total"]
                    data["bps"] = diff / elapsed
                    data["prev_total"] = current_total
                    data["last_check"] = now

    def get_bandwidth_stats(self):
        """Returns a list of device bandwidth usage sorted by bps."""
        now = time.time()
        with self._lock:
            stats = []
            for ip, data in self.bandwidth_data.items():
                # If no packets seen for > 2s, set bps to 0
                if now - data["last_check"] > 2.0:
                    data["bps"] = 0.0
                
                if data["sent"] > 0 or data["recv"] > 0:
                    stats.append({
                        "ip": ip,
                        "sent": data["sent"],
                        "recv": data["recv"],
                        "bps": round(data["bps"], 2),
                        "kbps": round(data["bps"] * 8 / 1024, 2)
                    })
            return sorted(stats, key=lambda x: x["bps"], reverse=True)

    def _emit_alert(self, sev, type, msg, ip=None):
        alert = {
            "timestamp": datetime.now().isoformat(),
            "sev": sev,
            "type": type,
            "msg": msg,
            "ip": ip
        }
        # Schedule the async callback
        if asyncio.iscoroutinefunction(self.alert_callback):
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.run_coroutine_threadsafe(self.alert_callback(alert), loop)
                else:
                    # Fallback for initialization phase
                    logger.warning("Event loop not running, skipping alert callback")
            except RuntimeError:
                # No event loop in this thread
                pass

    def start(self, interface=None):
        if self.running: return
        self.interface = interface if interface and interface.strip() else None
        self.running = True
        
        # Try to find gateway before starting
        try:
            # conf.route.route("0.0.0.0") returns (iface, gw, psrc)
            res = conf.route.route("0.0.0.0")
            if res:
                self.gateway_ip = res[1]
                logger.info(f"IDS: System gateway detected at {self.gateway_ip}")
                if self.gateway_callback: self.gateway_callback(self.interface, self.gateway_ip)
        except Exception as e:
            logger.warning(f"IDS: Could not auto-detect gateway: {e}")

        def run_sniff():
            logger.info(f"IDS Sniffer started on {self.interface or 'default interface'}")
            try:
                sniff(iface=self.interface, prn=self._packet_handler, store=0, stop_filter=lambda x: not self.running)
            except Exception as e:
                logger.error(f"Sniffer error: {e}")
                self.running = False
            logger.info("IDS Sniffer stopped")

        self._thread = threading.Thread(target=run_sniff, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            # Send a dummy packet to wake up sniff if needed? 
            # Scapy's stop_filter checks after every packet
            self._thread.join(timeout=1)
