import subprocess
import json
import os

def test_powershell_wifi():
    # This script uses WinRT via PowerShell to get a fresh WiFi scan
    ps_script = """
    $ErrorActionPreference = 'Stop'
    try {
        # Check if the assembly is available
        Add-Type -AssemblyName "Windows.Devices.WiFi" -ErrorAction SilentlyContinue
        
        $adapterSelector = [Windows.Devices.WiFi.WiFiAdapter]::GetDeviceSelector()
        $devices = [Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync($adapterSelector).GetAwaiter().GetResult()
        
        if ($devices.Count -eq 0) {
            Write-Output "[]"
            exit
        }
        
        $wifiAdapter = [Windows.Devices.WiFi.WiFiAdapter]::FromIdAsync($devices[0].Id).GetAwaiter().GetResult()
        
        # Trigger a fresh scan
        $wifiAdapter.ScanAsync().GetAwaiter().GetResult()
        
        $networks = $wifiAdapter.NetworkReport.AvailableNetworks
        $results = @()
        foreach ($net in $networks) {
            $results += @{
                ssid = $net.Ssid
                bssid = $net.Bssid
                signal = $net.SignalBars
                rssi = $net.NetworkRssiInDecibels
                security = $net.SecuritySettings.NetworkAuthenticationType.ToString()
            }
        }
        $results | ConvertTo-Json
    } catch {
        # Fallback to netsh if WinRT fails
        Write-Error $_.Exception.Message
        exit 1
    }
    """
    
    try:
        cmd = ["powershell", "-Command", ps_script]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        if stderr:
            print(f"PS Error: {stderr}")
        
        if stdout:
            print("--- POWERSHELL OUTPUT ---")
            print(stdout)
            try:
                data = json.loads(stdout)
                print(f"\nFound {len(data) if isinstance(data, list) else 1} networks via PowerShell.")
            except:
                print("Could not parse JSON output.")
        else:
            print("No output from PowerShell.")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_powershell_wifi()
