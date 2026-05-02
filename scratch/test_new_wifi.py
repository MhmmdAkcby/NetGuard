import asyncio
import subprocess
import os
import re

async def test_new_logic():
    # Attempt to trigger a scan refresh
    try:
        print("Refreshing scan...")
        subprocess.run(["netsh", "wlan", "show", "networks"], capture_output=True, creationflags=0x08000000 if os.name == 'nt' else 0)
        await asyncio.sleep(1)
    except: pass

    cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, creationflags=0x08000000 if os.name == 'nt' else 0)
        output = output.decode('cp850', errors='ignore')
    except Exception as e:
        print(f"Error: {e}")
        return
    
    networks = []
    current_ssid = None
    current_net = None
    
    ssid_re = re.compile(r"^SSID\s+\d+\s+:\s+(.*)$", re.IGNORECASE)
    bssid_re = re.compile(r"^\s*BSSID\s+\d+\s+:\s+([0-9a-fA-F:]{17})$", re.IGNORECASE)
    signal_re = re.compile(r"^\s*Signal\s+:\s+(\d+%)", re.IGNORECASE)
    
    for line in output.split('\n'):
        line_clean = line.strip()
        if not line_clean: continue
        
        ssid_match = ssid_re.match(line_clean)
        if ssid_match:
            if current_net: networks.append(current_net)
            current_ssid = ssid_match.group(1).strip() or "Hidden"
            current_net = None
            continue
        
        bssid_match = bssid_re.match(line_clean)
        if bssid_match:
            if current_net: networks.append(current_net)
            current_net = {"ssid": current_ssid, "bssid": bssid_match.group(1).upper(), "signal": "0%"}
            continue
        
        if current_net:
            sig_match = signal_re.match(line_clean)
            if sig_match: current_net["signal"] = sig_match.group(1)

    if current_net: networks.append(current_net)
    
    print(f"\nFound {len(networks)} BSSIDs:")
    for n in networks:
        print(f"- {n['ssid']} ({n['bssid']}) Signal: {n['signal']}")

if __name__ == "__main__":
    asyncio.run(test_new_logic())
