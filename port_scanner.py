import socket
import threading

def scan_port(target, port):
    """Attempts to connect to a specific port on the target IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            print(f"✅ Port {port} is OPEN")
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

def scan_ports(target, ports):
    """Scans multiple ports using threading for speed."""
    print(f"\n🔍 Scanning {target} for open ports...\n")
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    target_ip = input("Enter target IP address: ")
    ports_to_scan = range(1, 1024)  # Scan first 1023 ports
    scan_ports(target_ip, ports_to_scan)
