import requests

def scan_reflected_input(url):
    try:
        test_payload = "reflecttest123"
        response = requests.get(f"{url}?test={test_payload}")
        if test_payload in response.text:
            print("[!] Reflected input detected!")
            return True
        print("[+] No reflected input found.")
        return False
    except requests.RequestException as e:
        print(f"Error scanning for reflected input: {e}")
        return False
