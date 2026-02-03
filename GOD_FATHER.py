import requests
import re
import argparse
import urllib3
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from colorama import Fore, init, Style

# Settings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

stats = {"ep": 0, "ky": 0, "or": 0, "bp": 0, "sf": 0, "scanned": 0, "total": 0, "live": 0}
seen_secrets = set() 
seen_files = set()
processed_urls = set()

EXCLUDED_EXTENSIONS = ('.css', '.png', '.jpg', '.jpeg', '.gif', '.woff', '.woff2', '.ttf', '.svg', '.eot', '.ico', '.mp4')
SENSITIVE_PATHS = ['/.env', '/.git/config', '/.aws/credentials', '/config.php.bak']
SENS_KEYWORDS = ["AWS_ACCESS_KEY", "AWS_SECRET", "DB_PASSWORD", "SECRET_KEY", "repositoryformatversion", "[default]"]

def print_banner():
    banner = f"""
{Fore.RED}    ██████╗  ██████╗ ██████╗ ███████╗ █████╗ ████████╗██╗  ██╗███████╗██████╗ 
{Fore.RED}    ██╔════╝ ██╔═══██╗██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║  ██║██╔════╝██╔══██╗
{Fore.RED}    ██║  ███╗██║   ██║██║  ██║█████╗  ███████║   ██║   ███████║█████╗  ██████╔╝
{Fore.RED}    ██║   ██║██║   ██║██║  ██║██╔══╝  ██╔══██║   ██║   ██╔══██║██╔══╝  ██╔══██╗
{Fore.RED}    ╚██████╔╝╚██████╔╝██████╔╝██║     ██║  ██║   ██║   ██║  ██║███████╗██║  ██║
{Fore.WHITE}    -----------------------------------------------------------------------
{Fore.YELLOW}      SENSITIVE DATA CAN HIDE, BUT IT CAN'T ESCAPE THE GODFATHER.
{Fore.CYAN}                 MADE BY DHARMVEER | GODFATHER V16.0
    """
    print(banner)

PATTERNS = {
    "CLOUD_KEY": r"(AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43})",
    "ENDPOINT": r'["\'](/(?:api|v[0-9]|graphql|admin|auth|checkout)/[a-zA-Z0-9\-_/.]+)["\']'
}

PAYLOAD = "https://www.bing.com"
OR_PARAMS = ['url', 'next', 'dest', 'destination', 'callback', 'redirect', 'goto']

def update_status():
    perc = (stats['scanned'] / stats['total']) * 100 if stats['total'] > 0 else 0
    status_line = f"\r\033[K{Fore.BLUE}[{stats['scanned']}/{stats['total']}] {perc:.1f}% - {Fore.GREEN}Live:{stats['live']} {Fore.CYAN}EP:{stats['ep']} {Fore.RED}KY:{stats['ky']} {Fore.MAGENTA}OR:{stats['or']} {Fore.YELLOW}BP:{stats['bp']} {Fore.GREEN}SF:{stats['sf']}"
    sys.stdout.write(status_line)
    sys.stdout.flush()

def log_result(text, color=Fore.WHITE):
    sys.stdout.write(f"\r\033[K{color}{text}\n")
    update_status()

def save_to_file(output_file, data_type, value, source):
    if not output_file: return
    mode = 'a' if os.path.exists(output_file) else 'w'
    with open(output_file, mode, encoding='utf-8') as f:
        if output_file.endswith(".html"):
            if mode == 'w': f.write("<html><body style='background:#111;color:#eee;font-family:monospace;'><h1>GodFather Report</h1><hr>")
            f.write(f"<p><b style='color:yellow'>[{data_type}]</b> {value} <br><small>Source: {source}</small></p><hr>\n")
        else:
            f.write(f"[{data_type}] {value} in {source}\n")
        f.flush()

def test_403_bypass(url, output_file):
    headers = [{'X-Forwarded-For': '127.0.0.1'}, {'X-Original-URL': '/'}]
    for header in headers:
        try:
            r = requests.get(url, headers=header, timeout=4, verify=False, allow_redirects=False)
            if r.status_code == 200 and any(key in r.text.upper() for key in SENS_KEYWORDS):
                log_result(f"!!! [403-BYPASS] {url} with {header} !!!", Fore.YELLOW + Style.BRIGHT)
                stats["bp"] += 1
                save_to_file(output_file, "403-BYPASS", str(header), url)
        except: pass

def hunt_sensitive_files(base_url, output_file):
    parsed = urlparse(base_url)
    root_url = f"{parsed.scheme}://{parsed.netloc}"
    if root_url in seen_files: return
    seen_files.add(root_url)
    for path in SENSITIVE_PATHS:
        try:
            target = root_url + path
            r = requests.get(target, timeout=4, verify=False, allow_redirects=False)
            if r.status_code == 200 and any(key in r.text.upper() for key in SENS_KEYWORDS):
                log_result(f"[CONFIRMED-FILE] {target}", Fore.GREEN + Style.BRIGHT)
                stats["sf"] += 1
                save_to_file(output_file, "SENSITIVE-FILE", target, "File Hunt")
        except: pass

def scan_logic(content, source_url, output_file, args):
    # Secret/Key Hunting (-ky)
    if args.ky or args.all:
        for name, pat in [("CLOUD_KEY", PATTERNS["CLOUD_KEY"])]:
            matches = re.findall(pat, content)
            for val in matches:
                if len(str(val)) < 6 or str(val) in seen_secrets: continue
                log_result(f"[CLOUD_KEY] {val} in {source_url}", Fore.RED + Style.BRIGHT)
                stats["ky"] += 1
                seen_secrets.add(str(val))
                save_to_file(output_file, "CLOUD_KEY", val, source_url)

    # Endpoint Hunting (-ep)
    if args.ep or args.all:
        matches = re.findall(PATTERNS["ENDPOINT"], content)
        for val in matches:
            if len(str(val)) < 6 or str(val) in seen_secrets: continue
            log_result(f"[ENDPOINT] {val} in {source_url}", Fore.CYAN)
            stats["ep"] += 1
            seen_secrets.add(str(val))
            save_to_file(output_file, "ENDPOINT", val, source_url)
    
    # Open Redirect (-poc)
    if args.poc or args.all:
        for p in OR_PARAMS:
            if f"{p}=" in source_url.lower():
                try:
                    test_url = f"{source_url.split('?')[0]}?{p}={PAYLOAD}"
                    r = requests.get(test_url, timeout=4, verify=False, allow_redirects=False)
                    if r.status_code in [301, 302, 307, 308] and PAYLOAD in r.headers.get('Location', ''):
                        log_result(f"!!! [VULNERABLE-OR] {test_url} !!!", Fore.MAGENTA + Style.BRIGHT)
                        stats["or"] += 1
                        save_to_file(output_file, "OPEN-REDIRECT", test_url, "OR Hunt")
                except: pass

def process_url(url, args):
    if url in processed_urls: return
    processed_urls.add(url)
    if len(url) > 400 or url.lower().endswith(EXCLUDED_EXTENSIONS):
        stats["scanned"] += 1
        return
    try:
        target_url = url if url.startswith('http') else urljoin(args.domain or "", url)
        
        # Sensitive File Hunt (-sf)
        if args.sf or args.all:
            hunt_sensitive_files(target_url, args.output)
            
        r = requests.get(target_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=6, verify=False)
        
        if r.status_code == 200:
            if args.verify: stats["live"] += 1
            scan_logic(r.text, target_url, args.output, args)
        elif r.status_code == 403 and (args.poc or args.all):
            test_403_bypass(target_url, args.output)
            
    except: pass
    stats["scanned"] += 1
    if stats["scanned"] % 10 == 0: update_status()

def main():
    print_banner()
    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.RawTextHelpFormatter(prog, max_help_position=40, width=110), add_help=False)
    
    parser.add_argument("-h", "--help", action="help", help="Show this help message")
    
    req = parser.add_argument_group(f'{Fore.RED}REQUIRED')
    req.add_argument("-i", "--input", required=True, help="Input URL/Path list")

    config = parser.add_argument_group(f'{Fore.CYAN}SETTINGS')
    config.add_argument("-d", "--domain", help="Base domain for partial paths")
    config.add_argument("-t", "--threads", type=int, default=100, help="Threads (Default: 100)")
    config.add_argument("-o", "--output", default=None, help="Output file (.txt/.html)")

    modes = parser.add_argument_group(f'{Fore.GREEN}SCAN MODES (Manual Selection)')
    modes.add_argument("-ky", action="store_true", help="Hunt for Secrets/Keys")
    modes.add_argument("-ep", action="store_true", help="Hunt for API Endpoints")
    modes.add_argument("-sf", action="store_true", help="Hunt for Sensitive Files (.env, etc.)")
    modes.add_argument("-poc", action="store_true", help="Test for OR & 403 Bypass")
    modes.add_argument("-v", "--verify", action="store_true", help="Verify Live status (200 OK)")
    modes.add_argument("-all", action="store_true", help="Run ALL scans together")

    args = parser.parse_args()
    
    if not (args.ky or args.ep or args.sf or args.poc or args.all):
        print(f"{Fore.YELLOW}[!] No scan mode selected. Use -ky, -ep, -sf, -poc or -all")
        return

    if args.output:
        with open(args.output, 'w') as f: f.write("")

    if not os.path.exists(args.input):
        print(f"{Fore.RED}[!] Error: File '{args.input}' not found!")
        return

    with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    stats["total"] = len(urls)
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            for url in urls: executor.submit(process_url, url, args)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Stopped by user.")
    
    print(f"\n\n{Fore.GREEN}--- HUNTING COMPLETE | MADE BY DHARMVEER ---")

if __name__ == "__main__":
    main()
