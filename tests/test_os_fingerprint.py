import unittest
from scanner import DiscoveryManager

class TestOSFingerprint(unittest.TestCase):
    def setUp(self):
        self.dm = DiscoveryManager()

    def test_windows_detection(self):
        # Mock TCP Fingerprint for Windows 10/11
        tcp_fp = {
            "win": 64240,
            "ttl": 128,
            "opts": ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK'],
            "mss": 1460,
            "wscale": 8,
            "sack": True
        }
        os_name = self.dm.detect_os(128, [445, 135], "DESKTOP-ABC", tcp_fp)
        self.assertEqual(os_name, "Windows 10/11")

    def test_linux_detection(self):
        # Mock TCP Fingerprint for Linux
        tcp_fp = {
            "win": 29200,
            "ttl": 64,
            "opts": ['MSS', 'SAckOK', 'Timestamp', 'NOP', 'WScale'],
            "mss": 1460,
            "wscale": 7,
            "sack": True
        }
        os_name = self.dm.detect_os(64, [22, 80], "ubuntu-server", tcp_fp)
        self.assertEqual(os_name, "Linux (Modern Kernel)")

    def test_fallback_logic(self):
        # No TCP FP, just TTL and ports
        os_name = self.dm.detect_os(128, [445], "Unknown")
        self.assertEqual(os_name, "Windows")
        
        os_name = self.dm.detect_os(64, [22], "Unknown")
        self.assertEqual(os_name, "Linux/Unix")

if __name__ == "__main__":
    unittest.main()
