from scapy.all import IP, TCP, send
import time
import sys

def simulate_port_scan(target_ip, num_ports=25):
    print(f"Simulating port scan from this machine to {target_ip}...")
    for port in range(1000, 1000 + num_ports):
        # We send a single SYN packet to each port
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        if port % 5 == 0:
            print(f"Sent {port - 1000 + 1} packets...")
        time.sleep(0.01) # Small delay to not overwhelm but fast enough for detection
    print("Done.")

if __name__ == "__main__":
    target = "127.0.0.1"
    if len(sys.argv) > 1:
        target = sys.argv[1]
    simulate_port_scan(target)
