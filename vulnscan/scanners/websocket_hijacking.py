import requests

def scan_websocket_hijacking(url):
    response = requests.get(url)
    if "WebSocket" in response.headers.get('Upgrade', ''):
        print("[!] Potential WebSocket hijacking vulnerability detected.")
        return True
    print("[+] No WebSocket hijacking vulnerabilities detected.")
    return False
