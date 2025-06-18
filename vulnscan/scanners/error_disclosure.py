import requests

def scan_error_disclosure(url):
    try:
        response = requests.get(f"{url}?error_test='")
        error_keywords = ["error", "exception", "traceback", "warning"]
        if any(keyword in response.text.lower() for keyword in error_keywords):
            print("[!] Server error messages disclosed!")
            return True
        print("[+] No error messages disclosed.")
        return False
    except requests.RequestException as e:
        print(f"Error scanning for error disclosure: {e}")
        return False
