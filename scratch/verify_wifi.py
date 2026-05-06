import sys
import os
sys.path.append(os.getcwd())

from scanner import InterfaceManager
import json

def verify_wifi_detection():
    print("Enumerating interfaces...")
    ifaces = InterfaceManager.get_interfaces()
    
    wifi_found = False
    for iface in ifaces:
        name = iface.get('name')
        is_wifi = iface.get('is_wifi', False)
        ip = iface.get('ip')
        
        status = "UP" if iface.get('is_up') else "DOWN"
        wifi_mark = "[WIFI]" if is_wifi else "[ETH/OTHER]"
        
        print(f"{wifi_mark} {name} ({status}): {ip}")
        
        if is_wifi:
            wifi_found = True
            details = iface.get('details', {})
            print(f"  - Description: {details.get('description')}")
            print(f"  - SSID: {details.get('ssid')}")
            print(f"  - Band: {details.get('band')}")
            print(f"  - Supported Radios: {details.get('supported_radios')}")
            
    if wifi_found:
        print("\nSUCCESS: WiFi interfaces detected with rich properties.")
    else:
        print("\nWARNING: No WiFi interfaces detected. (If this is a VM, this is expected).")

if __name__ == "__main__":
    verify_wifi_detection()
