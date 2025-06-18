import socket

def scan_open_ports(url):
    host = url.split("://")[-1].split("/")[0]
    open_ports = []
    for port in range(20, 9000):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    if open_ports:
        print(f"[!] Open ports detected: {open_ports}")
        return True
    print("[+] No open ports detected.")
    return False
