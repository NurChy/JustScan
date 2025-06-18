import requests

def scan_unrestricted_file_upload(url):
    files = {'file': ('test.php', '<?php echo "Hacked"; ?>', 'application/x-php')}
    response = requests.post(url, files=files)
    if response.status_code == 200 and "Hacked" in response.text:
        print("[!] Unrestricted file upload vulnerability detected.")
        return True
    print("[+] No unrestricted file upload vulnerabilities detected.")
    return False
