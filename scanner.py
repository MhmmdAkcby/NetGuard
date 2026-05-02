# FIXED BUGS:
# BUG 1 - Added missing 'import os' for is_admin() privilege checks.
# BUG 3 - PassiveEngine.start(): Added asyncio.ensure_future() to correctly schedule the background thread.
# BUG 4 - scan_network(): Replaced invalid asyncio.sleep(0, "Unknown") with _unknown_vendor() async helper.
# BUG 8 - MAC Vendor Lookup: Added robust exception handling and string normalization for MAC lookups to prevent crashes on unknown or malformed MACs.

import asyncio
import logging
import ipaddress
import socket
import time
import re
import subprocess
import os
import psutil
from typing import AsyncGenerator, Dict, Any, List, Tuple, Set, Optional
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, UDP, DNS, DNSQR, send, sniff, conf
from mac_vendor_lookup import AsyncMacLookup
from vulnerability_engine import detect_vulnerabilities, calculate_cvss_impact

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Constants
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 137: "NetBIOS", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB", 1900: "SSDP", 3306: "MySQL", 
    3389: "RDP", 5353: "mDNS", 5432: "PostgreSQL", 8080: "HTTP-Proxy"
}

# Netdiscover-style common subnets for auto-discovery
COMMON_SUBNETS = [
    "192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24", "172.16.0.0/24",
    "192.168.100.0/24", "10.10.1.0/24", "172.16.1.0/24"
]

mac_lookup = AsyncMacLookup()
port_semaphore = asyncio.Semaphore(60)
device_semaphore = asyncio.Semaphore(10) # Limit concurrent device analysis

async def _unknown_vendor():
    return "Unknown"

async def get_vendor_safe(mac: str) -> str:
    """FIX: BUG 8 - Robust MAC vendor lookup with exception handling and normalization."""
    if not mac or mac == "Unknown":
        return "Unknown"
    
    # Normalize MAC: Ensure string, uppercase, remove any 'b' prefixes from Scapy raw bytes
    try:
        if isinstance(mac, bytes):
            mac = mac.decode('utf-8', errors='ignore')
        
        # Strip potential 'b' prefix and quotes if it was stringified as repr()
        mac = str(mac).replace("b'", "").replace("'", "").upper().strip()
        
        # Basic MAC format validation (at least some hex and colons/dashes)
        if not re.match(r'^([0-9A-F]{2}[:-]?){5}([0-9A-F]{2})$', mac):
            # Try to format raw hex string if no delimiters
            if len(mac) == 12:
                mac = ":".join(mac[i:i+2] for i in range(0, 12, 2))
            else:
                return "Unknown"

        return await mac_lookup.lookup(mac)
    except Exception as e:
        logger.warning(f"Vendor lookup failed for {mac}: {e}")
        return "Unknown"

class InterfaceManager:
    """Manages network interface enumeration and subnet discovery."""
    
    @staticmethod
    def get_interfaces() -> List[Dict[str, Any]]:
        interfaces = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        
        for name, addr_list in addrs.items():
            if name == "lo" or "loopback" in name.lower(): continue
            if name in stats and not stats[name].isup: continue
            
            iface_info = {"name": name, "ip": None, "mask": None, "cidr": None, "mac": None}
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    iface_info["ip"] = addr.address
                    iface_info["mask"] = addr.netmask
                    try:
                        network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                        iface_info["cidr"] = str(network)
                    except: pass
                elif addr.family == psutil.AF_LINK:
                    iface_info["mac"] = addr.address
            
            if iface_info["ip"] and iface_info["cidr"]:
                interfaces.append(iface_info)
        return interfaces

    @staticmethod
    def is_admin() -> bool:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return os.getuid() == 0 if hasattr(os, 'getuid') else False

class PassiveEngine:
    """
    Netdiscover-style Passive discovery engine.
    Sniffs ARP traffic and tracks packet counts without sending anything.
    """
    def __init__(self, callback):
        self.callback = callback
        self.running = False
        self._loop = None
        self.stats = {} # {ip: {'mac': mac, 'count': n}}

    def _packet_callback(self, pkt):
        try:
            if ARP in pkt:
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                
                # Normalize MAC from packet
                if isinstance(mac, bytes):
                    mac = mac.decode('utf-8', errors='ignore')
                mac = str(mac).upper().strip()

                if ip not in self.stats:
                    self.stats[ip] = {'mac': mac, 'count': 0}
                
                self.stats[ip]['count'] += 1
                
                if self._loop:
                    device_data = {
                        "ip": ip, 
                        "mac": mac, 
                        "method": "Passive (ARP)", 
                        "packets": self.stats[ip]['count']
                    }
                    self._loop.call_soon_threadsafe(self.callback, device_data)
        except: pass

    def start(self, interface: str):
        self.running = True
        self.stats = {}
        self._loop = asyncio.get_event_loop()
        def run_sniff():
            sniff(iface=interface, filter="arp", prn=self._packet_callback, store=0, stop_filter=lambda x: not self.running)
        asyncio.ensure_future(asyncio.to_thread(run_sniff))

    def stop(self):
        self.running = False

class ActiveEngine:
    """Active Scanner with varying intensity levels (Netdiscover style)."""
    def __init__(self, interface: str = None):
        self.interface = interface

    async def arp_sweep(self, cidr: str, speed: str = "Normal") -> List[Dict]:
        discovered = []
        config = {
            "Fast": {"retries": 1, "timeout": 1, "inter": 0.001},
            "Normal": {"retries": 2, "timeout": 2, "inter": 0.01},
            "Deep": {"retries": 4, "timeout": 3, "inter": 0.02}
        }.get(speed, {"retries": 2, "timeout": 2, "inter": 0.01})

        for attempt in range(config["retries"]):
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr)
                ans, _ = await asyncio.to_thread(srp, pkt, timeout=config["timeout"], verbose=False, iface=self.interface, inter=config["inter"])
                for _, rec in ans:
                    # Normalize MAC from packet
                    mac = str(rec.hwsrc).upper().strip()
                    discovered.append({
                        "ip": str(rec.psrc), 
                        "mac": mac, 
                        "method": f"ARP Sweep ({speed})", 
                        "packets": 1
                    })
                if discovered and speed == "Fast": break
            except Exception as e: logger.error(f"ARP Sweep Error: {e}")
        
        unique = {d['ip']: d for d in discovered}
        return list(unique.values())

    async def fallback_probe(self, ip: str) -> Optional[Dict]:
        try:
            resp = await asyncio.to_thread(sr1, IP(dst=ip)/ICMP(), timeout=1.0, verbose=False)
            if resp: return {"ip": ip, "mac": "Unknown", "method": "ICMP Probe", "packets": 1, "ttl": resp.ttl}
        except: pass
        return None

class DiscoveryManager:
    """Orchestrates all discovery engines."""
    def __init__(self):
        self.interface_mgr = InterfaceManager()
        self.active_engine = ActiveEngine()
        self.discovered_ips = set()
        self.passive_engine = None
        self._is_scanning = False

    def validate_input(self, cidr: str, interface: str):
        if cidr:
            try: ipaddress.IPv4Network(cidr, strict=False)
            except ValueError: raise ValueError(f"Invalid CIDR format: {cidr}")
        if interface:
            valid_ifaces = psutil.net_if_addrs().keys()
            if interface not in valid_ifaces: raise ValueError(f"Interface '{interface}' not found.")

    async def update_mac_db(self):
        try: await asyncio.wait_for(mac_lookup.update_vendors(), timeout=15)
        except: pass

    async def get_hostname(self, ip: str) -> str:
        try:
            # FIX: Added timeout to prevent long hangs on slow DNS
            hostname, _, _ = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), timeout=3.0)
            return hostname
        except: return "Unknown"

    async def perform_recon(self, ip: str) -> Dict[str, Any]:
        tasks = [self._probe_port(ip, port) for port in COMMON_PORTS.keys()]
        results = await asyncio.gather(*tasks)
        open_ports, services, vulns = [], {}, []
        for port, info in results:
            if port:
                open_ports.append(port)
                services[port] = info
                v = await detect_vulnerabilities(info['name'], info['banner'])
                if v: vulns.extend(v)
        risk = calculate_cvss_impact(vulns)
        return {"ports": sorted(open_ports), "services": services, "vulnerabilities": vulns, "risk_score": risk}

    async def _probe_port(self, ip, port):
        async with port_semaphore:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=2.0)
                banner = ""
                try: banner = (await asyncio.wait_for(reader.read(1024), timeout=1.5)).decode('utf-8', errors='ignore').strip()
                except: pass
                name = COMMON_PORTS.get(port, f"Unknown-{port}")
                writer.close()
                await writer.wait_closed()
                return port, {"name": name, "banner": banner[:200]}
            except: return None, None

    def detect_os(self, ttl, ports, hostname) -> str:
        h = hostname.lower()
        if "iphone" in h or "ipad" in h: return "iOS Device"
        if "android" in h: return "Android"
        if "windows" in h or 3389 in ports: return "Windows"
        if ttl and ttl <= 64: return "Linux/Unix"
        if ttl and ttl > 200: return "Router/Gateway"
        return "Generic IoT"

    async def scan_network(self, cidr: str, interface: str = None, speed: str = "Normal", passive: bool = False) -> AsyncGenerator[Dict[str, Any], None]:
        try:
            if not cidr and not passive:
                yield {"type": "status", "state": "Auto-Discovery", "message": "No subnet provided. Detecting local ranges...", "progress": 5}
                
                # Dynamic Subnet Detection: Check all active interfaces first
                local_ranges = []
                for iface in self.interface_mgr.get_interfaces():
                    if iface.get("cidr"):
                        local_ranges.append(iface["cidr"])
                
                # Combine detected ranges with common subnets, preserving order
                ranges_to_scan = list(dict.fromkeys(local_ranges + COMMON_SUBNETS))
                
                all_enriched = []
                if not ranges_to_scan:
                    yield {"type": "status", "state": "Error", "message": "No active network interfaces found.", "progress": 100}
                    return

                for i, subnet in enumerate(ranges_to_scan):
                    current_prog = 5 + int((i/len(ranges_to_scan))*90)
                    yield {"type": "status", "state": "Auto-Discovery", "message": f"Scanning {subnet} ({i+1}/{len(ranges_to_scan)})", "progress": current_prog}
                    async for result in self._scan_range(subnet, interface, speed="Fast"):
                        if result["type"] == "final_data":
                            all_enriched.extend(result["data"])
                        elif result["type"] != "status" or result["state"] != "Completed":
                            yield result
                
                yield {"type": "status", "state": "Completed", "message": f"Auto-Discovery finished. Total {len(all_enriched)} devices identified.", "progress": 100}
                yield {"type": "final_data", "data": all_enriched}
                return

            if passive:
                yield {"type": "status", "state": "Passive Monitoring", "message": "Listening for ARP traffic (Passive Mode)...", "progress": 100}
                return

            async for result in self._scan_range(cidr, interface, speed):
                yield result
            
            yield {"type": "status", "state": "Completed", "message": "Scan finished.", "progress": 100}

        except Exception as e:
            logger.error(f"Scan Failure: {e}")
            yield {"type": "error", "message": str(e), "state": "Failed"}

    async def _scan_range(self, cidr, interface, speed):
        self.validate_input(cidr, interface)
        self.discovered_ips.clear() # FIX: Reset discovered IPs for every fresh scan
        
        yield {"type": "status", "state": "ARP Sweep", "message": f"Probing {cidr} for active hosts...", "progress": 10}
        self.active_engine.interface = interface
        active_devices = await self.active_engine.arp_sweep(cidr, speed)
        
        if not active_devices:
            yield {"type": "status", "state": "Completed", "message": "No devices found in this range.", "progress": 100}
            yield {"type": "final_data", "data": []}
            return

        yield {"type": "status", "state": "Enrichment", "message": f"Found {len(active_devices)} hosts. Starting parallel analysis...", "progress": 35}
        
        async def enrich_device(dev, index, total):
            if dev['ip'] in self.discovered_ips: return None
            self.discovered_ips.add(dev['ip'])
            
            async with device_semaphore:
                # Update progress for this specific device start
                prog = 40 + int((index/total)*55)
                # We can't yield from here as it's not a generator, but we can return data
                host_task = self.get_hostname(dev['ip'])
                vendor_task = get_vendor_safe(dev['mac'])
                recon_task = self.perform_recon(dev['ip'])
                
                host, vendor, recon = await asyncio.gather(host_task, vendor_task, recon_task)
                os_name = self.detect_os(dev.get('ttl'), recon['ports'], host)
                return {**dev, "hostname": host, "vendor": vendor, "os": os_name, **recon}

        # Create tasks for all devices
        tasks = [enrich_device(dev, i, len(active_devices)) for i, dev in enumerate(active_devices)]
        
        # We want to yield as they complete to show progress in UI
        enriched_devices = []
        for completed_task in asyncio.as_completed(tasks):
            final_dev = await completed_task
            if final_dev:
                enriched_devices.append(final_dev)
                yield {"type": "device", "data": final_dev}
                # Update progress based on how many have finished
                prog = 40 + int((len(enriched_devices)/len(active_devices))*55)
                yield {"type": "status", "state": "Enrichment", "message": f"Analyzed {final_dev['ip']}...", "progress": prog}

        yield {"type": "final_data", "data": enriched_devices}

discovery_manager = DiscoveryManager()

async def scan_network_stream(cidr: str, interface: str = None, speed: str = "Normal", passive: bool = False) -> AsyncGenerator[Dict[str, Any], None]:
    async for update in discovery_manager.scan_network(cidr, interface, speed, passive):
        yield update

async def update_mac_database():
    await discovery_manager.update_mac_db()

def get_interfaces():
    return InterfaceManager.get_interfaces()
