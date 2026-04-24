import asyncio
import logging
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import AsyncMacLookup

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MAC lookup
mac_lookup = AsyncMacLookup()

async def get_vendor(mac_address: str) -> str:
    """
    Attempts to look up the vendor/manufacturer for a given MAC address.
    """
    try:
        # Update lookup table if necessary
        # Note: In a production app, you might want to handle this update differently
        # as it can be slow on first run.
        return await mac_lookup.lookup(mac_address)
    except Exception:
        return "Unknown Vendor"

async def scan_network(ip_range: str):
    """
    Performs an ARP scan on the local network to identify connected devices.
    Returns a list of dictionaries containing IP, MAC, and Vendor.
    """
    logger.info(f"Starting ARP scan on {ip_range}")
    
    # Create ARP request packet
    # pdst is the destination IP range
    arp = ARP(pdst=ip_range)
    
    # Create Ethernet broadcast packet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Stack the packets
    packet = ether/arp

    try:
        # Run srp in a thread to avoid blocking the event loop
        # srp sends and receives packets at layer 2
        result = await asyncio.to_thread(srp, packet, timeout=3, verbose=False)
        
        answered_list = result[0]
        devices = []

        for sent, received in answered_list:
            ip = received.psrc
            mac = received.hwsrc
            vendor = await get_vendor(mac)
            
            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor
            })

        logger.info(f"Scan completed. Found {len(devices)} devices.")
        return devices

    except PermissionError:
        logger.error("Administrative privileges (root/sudo) are required to run Scapy.")
        raise PermissionError("Access denied. Please run the application as Administrator/root.")
    except Exception as e:
        logger.error(f"An error occurred during scanning: {e}")
        raise e
