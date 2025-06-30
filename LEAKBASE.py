import requests
import re
import threading
from queue import Queue
from colorama import Fore, init
from urllib.parse import urlparse
import argparse

# Inisialisasi
init(autoreset=True)
print_lock = threading.Lock()

# Banner Eliteclea
BANNER = f"""
{Fore.RED}╦ ╦╔═╗╔╦╗╔═╗╔╗╔╔╦╗  ╔═╗╔═╗╔╦╗╔═╗╦═╗╔═╗╔═╗
{Fore.YELLOW}╠═╣║ ║║║║║╣ ║║║ ║   ╠═╝║ ║ ║ ║ ║╠╦╝║╣ ╚═╗
{Fore.GREEN}╩ ╩╚═╝╩ ╩╚═╝╝╚╝ ╩   ╩  ╚═╝ ╩ ╚═╝╩╚═╚═╝╚═╝
{Fore.CYAN}  [ Elite Web Deep Scanner ] | {Fore.MAGENTA}Dev: Petrus4Sec | {Fore.BLUE}v4.20
{Fore.RESET}{'-'*65}
{Fore.YELLOW}Features:
{Fore.CYAN}- Multi-threading (50x Faster)  - Auto-Exploit Basic
{Fore.CYAN}- TOR/Proxy Support           - Smart Pattern Detection
{Fore.CYAN}- Full Color Output           - Advanced Error Handling
{Fore.RED}\nWARNING: For authorized penetration testing only!
{'-'*65}
"""

print(BANNER)

# Konfigurasi Default
THREADS = 5
TIMEOUT = 50
TOR_PROXY = 'socks5://127.0.0.1:9050'

# Wordlists Lengkap
DIR_WORDLIST = [
    '/', '/admin/', '/administrator/', '/backup/', '/backups/', '/tmp/', '/temp/',
    '/logs/', '/log/', '/error_log/', '/access_log/', '/config/', '/configuration/',
    '/wp-admin/', '/wp-content/', '/wp-includes/', '/wordpress/', '/joomla/',
    '/phpmyadmin/', '/mysql/', '/dbadmin/', '/sql/', '/database/', '/db/',
    '/.git/', '/.svn/', '/.hg/', '/.DS_Store/', '/.env/', '/.htaccess/',
    '/cgi-bin/', '/shell/', '/upload/', '/uploads/', '/images/', '/img/',
    '/assets/', '/static/', '/media/', '/files/', '/downloads/', '/private/',
    '/secret/', '/hidden/', '/secure/', '/v1/', '/api/', '/rest/', '/graphql/',
    '/debug/', '/console/', '/_debug/', '/phpinfo/', '/test/', '/demo/',
    '/old/', '/new/', '/2019/', '/2020/', '/2021/', '/2022/', '/2023/',
    '/archive/', '/dev/', '/development/', '/staging/', '/production/',
    '/.well-known/', '/.aws/', '/.ssh/', '/.npm/', '/.cache/', '/.local/',
    '/vendor/', '/composer/', '/node_modules/', '/bower_components/',
    '/storage/', '/var/www/', '/wwwroot/', '/public_html/', '/webroot/'
]

FILE_WORDLIST = [
    '.env', 'config.php', 'configuration.php', 'settings.py', 'config.json',
    'config.yml', 'config.yaml', 'secrets.json', 'credentials.json',
    'wp-config.php', 'local-config.php', 'database.php', 'db.php',
    'config.inc.php', 'configuration.ini', 'appsettings.json',
    'web.config', '.htpasswd', '.htaccess', 'robots.txt',
    'backup.zip', 'backup.tar', 'backup.tar.gz', 'backup.sql',
    'dump.sql', 'database.sql', 'db.sql', 'backup.db', 'data.db',
    'users.db', 'backup.rdb', 'dump.rdb', 'backup.mdb',
    'error.log', 'access.log', 'debug.log', 'server.log',
    'phpinfo.php', 'test.php', 'info.php', 'debug.php',
    'composer.json', 'package.json', 'bower.json',
    'index.php.bak', 'index.html.bak', 'index.bak',
    'backup.txt', 'passwords.txt', 'credentials.txt',
    'admin.zip', 'www.zip', 'site.zip', 'project.zip',
    'backup_2023.zip', 'backup_2022.zip', 'backup_2021.zip',
    'backup2023.rar', 'backup2022.rar', 'backup2021.rar',
    'backup.7z', 'backup2023.7z', 'backup2022.7z',
    'users.csv', 'customers.csv', 'clients.csv',
    'employees.xlsx', 'salaries.xlsx', 'financials.xlsx',
    'private.pdf', 'confidential.pdf', 'secret.pdf'
]

# Pola Deteksi Lengkap
CRITICAL_PATTERNS = {
    'Database Credentials': r"(?i)(db|database|mysql|pgsql)_?(user|name|pass|host|port)\s*[=:]\s*['\"].+?['\"]",
    'Private Keys': r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----",
    'AWS Keys': r"(?i)aws_(access_key_id|secret_access_key|session_token)\s*=\s*['\"].+?['\"]",
    'API Keys': r"(?i)(api|google|youtube|twitter|facebook)_?(key|token|secret)\s*=\s*['\"].+?['\"]",
    'Email Credentials': r"(?i)(email|smtp)_?(user|pass|host|port)\s*=\s*['\"].+?['\"]",
    'JWT Tokens': r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    'OAuth Tokens': r"(?i)oauth_?(token|secret|key)\s*=\s*['\"].+?['\"]",
    'Cryptocurrency Wallets': r"(?i)(bitcoin|ethereum|ltc|monero)_?(address|wallet|key)\s*=\s*['\"].+?['\"]",
    'SSH Credentials': r"(?i)ssh_?(user|pass|host|port)\s*=\s*['\"].+?['\"]",
    'FTP Credentials': r"(?i)ftp_?(user|pass|host|port)\s*=\s*['\"].+?['\"]"
}

MEDIUM_PATTERNS = {
    'Email Addresses': r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}",
    'Phone Numbers': r"(\+?\d{1,3}[-\.\s]?)?\(?\d{3}\)?[-\.\s]?\d{3}[-\.\s]?\d{4}",
    'Credit Card Numbers': r"\b(?:\d[ -]*?){13,16}\b",
    'Personal IDs': r"\b\d{3}-\d{2}-\d{4}\b",  # SSN pattern
    'Basic Auth': r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+"
}

LOW_PATTERNS = {
    'Comments': r"<!--.*?-->|\/\*.*?\*\/|//.*?$",
    'Debug Info': r"console\.log\(.*?\)|var_dump\(.*?\)|print_r\(.*?\)",
    'IP Addresses': r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    'User Agents': r"User-Agent:\s*.+"
}

# Exploit DB
EXPLOIT_DB = {
    'phpinfo.php': 'PHPInfo Exposure (LFI/RFI Potential)',
    '.git/HEAD': 'Git Repository Exposure',
    '.env': 'Environment File Exposure',
    'wp-config.php': 'WordPress Config Exposure',
    'config.php': 'PHP Config Exposure',
    'backup.sql': 'Database Dump Exposure',
    'error_log': 'Error Log Exposure',
    'admin.php': 'Admin Panel Found',
    'debug.php': 'Debug Panel Found',
    'cgi-bin/': 'CGI-BIN Directory Listing'
}

# Thread-safe Queue
url_queue = Queue()
results = []

import http.client

def scan_url(url):
    try:
        session = requests.Session()
        if USE_PROXY:
            session.proxies = proxies

        resp = session.get(url, timeout=TIMEOUT, verify=False)
        
        # Critical Data Scanning
        for desc, pattern in CRITICAL_PATTERNS.items():
            matches = re.findall(pattern, resp.text)
            if matches:
                with print_lock:
                    print(f"{Fore.RED}[!] CRITICAL: {desc} found at {url}")
                    print(f"{Fore.YELLOW}    Matches: {matches[:3]}... (truncated)")
                    results.append({'type': 'CRITICAL', 'url': url, 'desc': desc, 'matches': matches[:3]})

        # Medium Risk Data
        for desc, pattern in MEDIUM_PATTERNS.items():
            matches = re.findall(pattern, resp.text)
            if matches:
                with print_lock:
                    print(f"{Fore.YELLOW}[!] MEDIUM: {desc} found at {url}")
                    results.append({'type': 'MEDIUM', 'url': url, 'desc': desc, 'matches': matches[:3]})

        # Low Risk Data
        for desc, pattern in LOW_PATTERNS.items():
            matches = re.findall(pattern, resp.text)
            if matches:
                with print_lock:
                    print(f"{Fore.BLUE}[*] LOW: {desc} found at {url}")
                    results.append({'type': 'LOW', 'url': url, 'desc': desc, 'matches': matches[:3]})

        # Check Common Exploits
        for path, desc in EXPLOIT_DB.items():
            if path in url:
                with print_lock:
                    print(f"{Fore.MAGENTA}[!] EXPLOIT: {desc} at {url}")
                    results.append({'type': 'EXPLOIT', 'url': url, 'desc': desc})

    except http.client.RemoteDisconnected as e:
        with print_lock:
            print(f"{Fore.RED}[x] RemoteDisconnected scanning {url}: {str(e)}")
    except requests.exceptions.RequestException as e:
        with print_lock:
            print(f"{Fore.RED}[x] Network error scanning {url}: {str(e)}")
    except Exception as e:
        with print_lock:
            print(f"{Fore.RED}[x] Error scanning {url}: {str(e)}")
            print(f"{Fore.RED}[x] Network error scanning {url}: {str(e)}")
    except Exception as e:
        with print_lock:
            print(f"{Fore.RED}[x] Error scanning {url}: {str(e)}")

def worker():
    while True:
        url = url_queue.get()
        scan_url(url)
        url_queue.task_done()

def main():
    global USE_PROXY, proxies

    parser = argparse.ArgumentParser(description='Elite Web Deep Scanner')
    parser.add_argument('-u', '--url', help='Target URL', required=True)
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('-p', '--proxy', help='Proxy to use (e.g. socks5://127.0.0.1:9050)')
    args = parser.parse_args()

    TARGET = args.url
    if not TARGET.startswith('http'):
        TARGET = 'http://' + TARGET

    THREADS = args.threads
    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
        USE_PROXY = True

    # Setup threads
    for _ in range(THREADS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    # Build target URLs
    base_domain = urlparse(TARGET).netloc
    print(f"{Fore.GREEN}[*] Starting scan on {base_domain} with {THREADS} threads...")

    # Add directory targets
    for path in DIR_WORDLIST:
        url_queue.put(TARGET.rstrip('/') + path)

    # Add file targets
    for file in FILE_WORDLIST:
        url_queue.put(TARGET.rstrip('/') + '/' + file)

    url_queue.join()
    print(f"\n{Fore.GREEN}[+] Scan completed! Found {len(results)} interesting items.")

    # Summary
    print(f"\n{Fore.CYAN}=== SCAN SUMMARY ===")
    print(f"{Fore.RED}CRITICAL: {len([r for r in results if r['type'] == 'CRITICAL'])}")
    print(f"{Fore.YELLOW}MEDIUM: {len([r for r in results if r['type'] == 'MEDIUM'])}")
    print(f"{Fore.BLUE}LOW: {len([r for r in results if r['type'] == 'LOW'])}")
    print(f"{Fore.MAGENTA}EXPLOITS: {len([r for r in results if r['type'] == 'EXPLOIT'])}")

    # Save results
    with open('scan_results.txt', 'w') as f:
        for item in results:
            f.write(f"[{item['type']}] {item['url']}\n")
            f.write(f"Description: {item['desc']}\n")
            f.write(f"Matches: {item['matches']}\n\n")

    print(f"\n{Fore.GREEN}[*] Results saved to scan_results.txt")

if __name__ == "__main__":
    main()