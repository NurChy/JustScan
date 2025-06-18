import requests

def scan_http_methods(url):
    try:
        response = requests.options(url)
        if any(method in response.headers.get("Allow", "") for method in ["PUT", "DELETE", "TRACE"]):
            print("[!] Insecure HTTP methods enabled!")
            return True
        print("[+] Safe HTTP methods in use.")
        return False
    except requests.RequestException as e:
        print(f"Error scanning HTTP methods: {e}")
        return False
