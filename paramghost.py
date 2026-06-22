#!/usr/bin/env python3
# ParamGhost - Hidden/unused parameter detector
# Improved version

import requests
import re
import argparse
import urllib3
import concurrent.futures
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl
from bs4 import BeautifulSoup
import difflib
import json
import sys
import time
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

def print_info(msg):
    print(f"[{Colors.BLUE}*{Colors.RESET}] {msg}")

def print_success(msg):
    print(f"[{Colors.GREEN}+{Colors.RESET}] {msg}")

def print_warning(msg):
    print(f"[{Colors.YELLOW}!{Colors.RESET}] {msg}")

def print_error(msg):
    print(f"[{Colors.RED}-{Colors.RESET}] {msg}")

COMMON_JS_KEYWORDS = {
    "abstract", "arguments", "await", "boolean", "break", "byte", "case", "catch", "char",
    "class", "const", "continue", "debugger", "default", "delete", "do", "double", "else",
    "enum", "eval", "export", "extends", "false", "final", "finally", "float", "for",
    "function", "goto", "if", "implements", "import", "in", "instanceof", "int", "interface",
    "let", "long", "native", "new", "null", "package", "private", "protected", "public",
    "return", "short", "static", "super", "switch", "synchronized", "this", "throw",
    "throws", "transient", "true", "try", "typeof", "var", "void", "volatile", "while", "with",
    "yield", "length", "type", "value", "name", "id", "key", "data", "index", "result", "error", "message",
    "width", "height", "top", "left", "right", "bottom", "color", "background", "margin", "padding",
    "undefined", "NaN", "Infinity", "Math", "Date", "String", "Number", "Boolean", "Object", "Array", "JSON"
}

class ParamGhost:
    def __init__(self, target_url, workers=10, timeout=10, headers=None, cookies=None, proxy=None, delay=0):
        self.target_url = self.normalize_url(target_url)
        self.workers = workers
        self.timeout = timeout
        self.delay = delay
        
        self.headers = {
            'User-Agent': 'ParamGhost/2.0 (Security Testing)'
        }
        if headers:
            for h in headers:
                if ':' in h:
                    k, v = h.split(':', 1)
                    self.headers[k.strip()] = v.strip()
                    
        self.cookies = {}
        if cookies:
            for c in cookies.split(';'):
                if '=' in c:
                    k, v = c.split('=', 1)
                    self.cookies[k.strip()] = v.strip()
                    
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        
        self.session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    @staticmethod
    def normalize_url(url):
        if not url.startswith('http://') and not url.startswith('https://'):
            return 'http://' + url
        return url

    def fetch_url(self, url):
        if self.delay > 0:
            time.sleep(self.delay)
        try:
            return self.session.get(
                url, 
                headers=self.headers, 
                cookies=self.cookies, 
                proxies=self.proxies, 
                timeout=self.timeout, 
                verify=False, 
                allow_redirects=True
            )
        except requests.exceptions.RequestException as e:
            return None

    def get_js_files(self):
        print_info(f"Fetching base URL: {self.target_url}")
        response = self.fetch_url(self.target_url)
        if not response:
            print_error(f"Error fetching base URL: {self.target_url}")
            return [], ""
        
        js_urls = set()
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            js_url = urljoin(self.target_url, script['src'])
            js_urls.add(js_url)
            
        print_success(f"Found {len(js_urls)} JS files to analyze.")
        return list(js_urls), response.text

    def process_js_url(self, url):
        params = set()
        param_pattern = re.compile(r'[\?\&]([a-zA-Z0-9_-]+)=')
        json_key_pattern = re.compile(r'["\']([a-zA-Z0-9_-]+)["\']\s*:')
        append_pattern = re.compile(r'\.append\(\s*["\']([a-zA-Z0-9_-]+)["\']')
        form_data_pattern = re.compile(r'FormData\(\)\.set\(\s*["\']([a-zA-Z0-9_-]+)["\']')
        
        resp = self.fetch_url(url)
        if not resp:
            return params
            
        text = resp.text
        for pattern in [param_pattern, json_key_pattern, append_pattern, form_data_pattern]:
            for m in pattern.findall(text):
                params.add(m)
            
        return params

    def extract_params_from_js(self, js_urls):
        params = set()
        print_info(f"Extracting parameters from {len(js_urls)} JS files...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(self.process_js_url, url): url for url in js_urls}
            for future in concurrent.futures.as_completed(futures):
                try:
                    res = future.result()
                    params.update(res)
                except Exception:
                    pass
                    
        filtered_params = set()
        for p in params:
            p_lower = p.lower()
            if 1 < len(p) < 32 and p_lower not in COMMON_JS_KEYWORDS:
                filtered_params.add(p)
                
        return list(filtered_params)

    @staticmethod
    def compare_responses(base_text, fuzz_text):
        if abs(len(base_text) - len(fuzz_text)) == 0 and base_text == fuzz_text:
             return 1.0
        return difflib.SequenceMatcher(None, base_text, fuzz_text).quick_ratio()

    def build_test_url(self, param, value):
        parsed = urlparse(self.target_url)
        qs = parse_qsl(parsed.query)
        qs.append((param, value))
        new_query = urlencode(qs)
        return parsed._replace(query=new_query).geturl()

    def fuzz_single_param(self, param, dummy_value, base_text, baseline_ratio):
        test_url = self.build_test_url(param, dummy_value)
        resp = self.fetch_url(test_url)
        if not resp:
            return None
            
        ratio = self.compare_responses(base_text, resp.text)
        
        if ratio < (baseline_ratio - 0.05):
            return {
                "param": param, 
                "ratio": ratio, 
                "url": test_url,
                "status": resp.status_code,
                "length": len(resp.text),
                "words": len(resp.text.split()),
                "lines": len(resp.text.splitlines())
            }
        return None

    def fuzz_params(self, params, base_text):
        results = []
        dummy_value = "test_fuzz_1337"
        
        print_info("Establishing baseline similarity...")
        baseline_url = self.build_test_url("pg_baseline_test_1337", dummy_value)
        baseline_resp = self.fetch_url(baseline_url)
        
        if baseline_resp:
            baseline_ratio = self.compare_responses(base_text, baseline_resp.text)
            print_success(f"Baseline similarity ratio established at {baseline_ratio:.4f}")
        else:
            baseline_ratio = 1.0
            print_warning("Could not establish baseline. Using 1.0 as default.")

        print_info(f"Fuzzing {len(params)} parameters using {self.workers} workers...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(self.fuzz_single_param, p, dummy_value, base_text, baseline_ratio): p for p in params}
            
            completed = 0
            total = len(params)
            
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                if completed % max(1, total // 10) == 0 or completed == total:
                    sys.stdout.write(f"\r[{Colors.CYAN}~{Colors.RESET}] Progress: {completed}/{total} ({(completed/total)*100:.1f}%)")
                    sys.stdout.flush()
                    
                try:
                    res = future.result()
                    if res:
                        results.append(res)
                except Exception:
                    pass
                    
        print() # New line after progress
        return results

def main():
    parser = argparse.ArgumentParser(
        description="ParamGhost 2.0 - Hidden/unused parameter detector via JS source + response diff correlation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="HTTP request timeout in seconds")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("-H", "--header", action='append', help="Custom header (e.g. 'Authorization: Bearer token')")
    parser.add_argument("-c", "--cookie", help="Custom cookies (e.g. 'session=123; user=admin')")
    parser.add_argument("-x", "--proxy", help="HTTP/HTTPS proxy (e.g. 'http://127.0.0.1:8080')")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    
    args = parser.parse_args()

    print(fr"""{Colors.CYAN}
    ____                           ________               __ 
   / __ \____ __________ _____ ___/ ____/ /_  ____  _____/ /_
  / /_/ / __ `/ ___/ __ `/ __ `__ \/ __/ __ \/ __ \/ ___/ __/
 / ____/ /_/ / /  / /_/ / / / / / / /_/ / / / /_/ (__  ) /_  
/_/    \__,_/_/   \__,_/_/ /_/ /_/\____/_/ /_/\____/____/\__/
                                                             
    v2.0 - Parameter Discovery & Fuzzing Tool
{Colors.RESET}""")

    ghost = ParamGhost(
        target_url=args.url,
        workers=args.workers,
        timeout=args.timeout,
        headers=args.header,
        cookies=args.cookie,
        proxy=args.proxy,
        delay=args.delay
    )
    
    js_urls, base_text = ghost.get_js_files()
    if not base_text:
        sys.exit(1)
        
    params = ghost.extract_params_from_js(js_urls)
    
    # Common potential hidden parameters to always include
    common_params = [
        'debug', 'admin', 'test', 'dir', 'file', 'cmd', 'exec', 'url', 'path', 
        'config', 'mode', 'dev', 'api', 'env', 'token', 'key', 'id'
    ]
    for cp in common_params:
        if cp not in params:
            params.append(cp)
            
    print_success(f"Extracted {len(params)} unique potential parameters.")
    
    results = ghost.fuzz_params(params, base_text)
    
    if results:
        results.sort(key=lambda x: x['ratio'])
        print("\n" + "="*70)
        print(f" {Colors.GREEN}[+] FOUND {len(results)} POTENTIAL HIDDEN PARAMETERS!{Colors.RESET}")
        print("="*70)
        
        for r in results:
            print(f" {Colors.MAGENTA}► Parameter :{Colors.RESET} {r['param']}")
            print(f"   {Colors.CYAN}Similarity:{Colors.RESET} {r['ratio']:.4f}")
            print(f"   {Colors.CYAN}Status    :{Colors.RESET} {r['status']}")
            print(f"   {Colors.CYAN}Length    :{Colors.RESET} {r['length']} bytes (W: {r['words']}, L: {r['lines']})")
            print(f"   {Colors.CYAN}Test URL  :{Colors.RESET} {r['url']}")
            print("-" * 70)
            
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
            print_success(f"Results saved to {args.output}")
    else:
        print_warning("No significant response changes detected with any parameter.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user.{Colors.RESET}")
        sys.exit(0)
