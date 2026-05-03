import unittest
from unittest.mock import patch, MagicMock
from security_engine import SecurityEngine
import time

class TestSecurityEngine(unittest.TestCase):
    def setUp(self):
        self.engine = SecurityEngine()
        self.engine.set_config("eth0", "192.168.1.1")

    @patch('security_engine.send')
    def test_start_and_stop_blocking(self, mock_send):
        target_ip = "192.168.1.50"
        target_mac = "AA:BB:CC:DD:EE:FF"
        
        # Test Start
        success = self.engine.start_blocking(target_ip, target_mac)
        self.assertTrue(success)
        self.assertTrue(self.engine.is_blocking(target_ip))
        
        # Give it a moment to run at least one loop
        time.sleep(0.5)
        self.assertTrue(mock_send.called)
        
        # Test Stop
        success = self.engine.stop_blocking(target_ip)
        self.assertTrue(success)
        self.assertFalse(self.engine.is_blocking(target_ip))

    def test_block_without_gateway(self):
        self.engine.gateway_ip = None
        success = self.engine.start_blocking("1.1.1.1", "AA:BB")
        self.assertFalse(success)

if __name__ == "__main__":
    unittest.main()
