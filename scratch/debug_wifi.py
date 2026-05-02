import subprocess
import os

def test_wifi_scan():
    cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, creationflags=0x08000000 if os.name == 'nt' else 0)
        output = output.decode('cp850', errors='ignore')
        print("--- RAW OUTPUT START ---")
        print(output)
        print("--- RAW OUTPUT END ---")
        
        networks = []
        current_net = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith("SSID"):
                if current_net.get("ssid"): networks.append(current_net)
                parts = line.split(":", 1)
                ssid = parts[1].strip() if len(parts) > 1 else "Hidden"
                current_net = {"ssid": ssid or "Hidden", "method": "WiFi Scan"}
                print(f"Found SSID: '{ssid}'")
            elif "BSSID" in line and ":" in line:
                bssid = line.split(":", 1)[1].strip()
                current_net["bssid"] = bssid
                print(f"  Found BSSID: {bssid}")
            elif "Signal" in line and ":" in line:
                current_net["signal"] = line.split(":", 1)[1].strip()
            elif "Authentication" in line and ":" in line:
                current_net["security"] = line.split(":", 1)[1].strip()
            elif "Channel" in line and ":" in line:
                current_net["channel"] = line.split(":", 1)[1].strip()
            elif "Radio type" in line and ":" in line:
                val = line.split(":", 1)[1].strip()
                current_net["band"] = "5 GHz" if "802.11a" in val or "802.11ac" in val or "802.11ax" in val else "2.4 GHz"
        
        if current_net.get("ssid"): networks.append(current_net)
        
        print(f"\nTotal networks found by parser: {len(networks)}")
        for i, net in enumerate(networks):
            print(f"{i+1}. {net.get('ssid')} ({net.get('bssid')})")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_wifi_scan()
