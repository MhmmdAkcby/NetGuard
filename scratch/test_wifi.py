
import subprocess
import os

def test_wifi_scans():
    encodings = ['cp850', 'cp1254', 'utf-8', 'utf-16']
    cmds = [
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        ["netsh", "wlan", "show", "interfaces"],
        ["netsh", "wlan", "show", "all"]
    ]
    
    for cmd in cmds:
        print(f"--- Running: {' '.join(cmd)} ---")
        try:
            raw = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            for enc in encodings:
                try:
                    text = raw.decode(enc)
                    print(f"Successfully decoded with {enc}")
                    print(text[:500]) # Print first 500 chars
                    break
                except:
                    continue
        except Exception as e:
            print(f"Failed: {e}")
        print("\n")

if __name__ == "__main__":
    test_wifi_scans()
