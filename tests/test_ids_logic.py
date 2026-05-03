import unittest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from scapy.all import ARP, IP, TCP, UDP, Ether
from ids_engine import IDSEngine
import time

class TestIDSLogic(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.alert_mock = AsyncMock()
        self.ids = IDSEngine(self.alert_mock)
        # Manually set gateway for testing
        self.ids.gateway_ip = "192.168.1.1"
        self.ids.gateway_mac = "AA:BB:CC:DD:EE:FF"
        self.ids.mac_cache["192.168.1.1"] = "AA:BB:CC:DD:EE:FF"

    async def test_arp_spoofing_gateway(self):
        # Create a malicious ARP packet
        malicious_pkt = ARP(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55")
        
        self.ids._packet_handler(malicious_pkt)
        
        # Give a tiny bit of time for the task to be scheduled
        await asyncio.sleep(0.1)
        
        self.alert_mock.assert_called()
        args = self.alert_mock.call_args[0][0]
        self.assertEqual(args['type'], "ARP Spoofing")
        self.assertEqual(args['sev'], "Critical")

    async def test_port_scan_detection(self):
        src_ip = "10.0.0.5"
        dst_ip = "10.0.0.10"
        
        for port in range(1, 20):
            pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=port)
            self.ids._packet_handler(pkt)
            
        await asyncio.sleep(0.1)
        self.alert_mock.assert_called()
        alerts = [call[0][0] for call in self.alert_mock.call_args_list]
        self.assertTrue(any(a['type'] == "Port Scanning" for a in alerts))

    async def test_host_discovery_detection(self):
        src_ip = "10.0.0.5"
        port = 445
        
        for i in range(10, 25):
            dst_ip = f"10.0.0.{i}"
            pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=port)
            self.ids._packet_handler(pkt)
            
        await asyncio.sleep(0.1)
        self.alert_mock.assert_called()
        alerts = [call[0][0] for call in self.alert_mock.call_args_list]
        self.assertTrue(any(a['type'] == "Host Discovery" for a in alerts))

    async def test_flood_detection(self):
        src_ip = "192.168.1.50"
        for _ in range(1100):
            pkt = IP(src=src_ip, dst="1.1.1.1")/UDP(dport=53)
            self.ids._packet_handler(pkt)
        await asyncio.sleep(0.1)
        alerts = [call[0][0] for call in self.alert_mock.call_args_list]
        self.assertTrue(any(a['type'] == "Flood Detection" for a in alerts))

    async def test_bandwidth_monitoring(self):
        src_ip = "192.168.1.10"
        # Simulate sending 1000 bytes
        pkt = IP(src=src_ip, dst="1.1.1.1")/TCP(dport=80)/("X"*960) # ~1000 bytes total
        self.ids._packet_handler(pkt)
        stats = self.ids.get_bandwidth_stats()
        device_stats = next(s for s in stats if s['ip'] == src_ip)
        self.assertTrue(device_stats['sent'] >= 1000)

if __name__ == "__main__":
    unittest.main()
