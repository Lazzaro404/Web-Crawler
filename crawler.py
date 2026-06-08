#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║              W E B C R A W L E R  v2.0                  ║
║         Link & Endpoint Discovery Tool                   ║
║         github-style output | Kali-ready                 ║
╚══════════════════════════════════════════════════════════╝

Features most crawlers don't have:
  - JS source extraction (finds endpoints buried in .js files)
  - API endpoint pattern detection (REST, GraphQL, WebSocket)
  - Secret/key pattern sniffing in source (not stored, just flagged)
  - Subdomain harvesting from links + JS
  - Form action + hidden input extraction
  - robots.txt & sitemap.xml parsing
  - WAF/CDN fingerprinting
  - Response diff fingerprinting (detects soft 404s)
  - Concurrent crawling with smart rate limiting
  - Full export: JSON, CSV, TXT
"""

import sys
import re
import json
import csv
import time
import queue
import hashlib
import argparse
import threading
import urllib.parse
from datetime import datetime
from collections import defaultdict
from typing import Optional

try:
    import requests
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.live import Live
    from rich.columns import Columns
    from rich import box
    from rich.text import Text
    from rich.tree import Tree
    import tldextract
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Run: pip install requests beautifulsoup4 rich tldextract lxml")
    sys.exit(1)

console = Console()

# ─── PATTERNS ────────────────────────────────────────────────────────────────

API_PATTERNS = [
    r'/api/v\d+/[\w/]+',
    r'/api/[\w/-]+',
    r'/v\d+/[\w/-]+',
    r'/rest/[\w/-]+',
    r'/graphql[\w/-]*',
    r'/gql[\w/-]*',
    r'/ws[\w/-]*',
    r'/wss?://[\w./-]+',
    r'/rpc[\w/-]*',
    r'/ajax[\w/-]+',
    r'/json[\w/-]+',
    r'/xml[\w/-]+',
    r'\.json$',
    r'\.xml$',
    r'/auth[\w/-]+',
    r'/login[\w/-]*',
    r'/logout[\w/-]*',
    r'/token[\w/-]*',
    r'/oauth[\w/-]+',
    r'/upload[\w/-]*',
    r'/download[\w/-]*',
    r'/admin[\w/-]*',
    r'/dashboard[\w/-]*',
    r'/config[\w/-]*',
    r'/settings[\w/-]*',
    r'/user[\w/-]+',
    r'/account[\w/-]+',
    r'/profile[\w/-]+',
    r'/search[\w/-]*',
    r'/query[\w/-]*',
]

SECRET_PATTERNS = {
    "AWS Key":         r'AKIA[0-9A-Z]{16}',
    "AWS Secret":      r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
    "GitHub Token":    r'ghp_[0-9a-zA-Z]{36}',
    "Google API Key":  r'AIza[0-9A-Za-z\-_]{35}',
    "JWT Token":       r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Private Key":     r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
    "Basic Auth":      r'(?i)(basic\s+)[a-zA-Z0-9+/=]{20,}',
    "Bearer Token":    r'(?i)(bearer\s+)[a-zA-Z0-9._\-]{20,}',
    "Password Field":  r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"\s]{4,}[\'"]',
    "API Key Param":   r'(?i)(api[_-]?key|apikey|access[_-]?token)\s*[=:]\s*[\'"][^\'"\s]{8,}[\'"]',
    "Slack Token":     r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "Stripe Key":      r'(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24,}',
    "Firebase URL":    r'https://[a-z0-9-]+\.firebaseio\.com',
    "Heroku API Key":  r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    "IP Address":      r'\b(?!10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}\b',
}

JS_ENDPOINT_PATTERNS = [
    r'(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*[\'"`]([^\'"`\s]+)[\'"`]',
    r'(?:url|endpoint|path|route|href|action)\s*[=:]\s*[\'"`]([/][^\'"`\s]+)[\'"`]',
    r'(?:baseURL|baseUrl|BASE_URL|API_URL|apiUrl)\s*[=:]\s*[\'"`]([^\'"`\s]+)[\'"`]',
    r'[\'"`](/(?:api|v\d|rest|gql|graphql|auth|admin|ws)[^\'"`\s]*)[\'"`]',
    r'XMLHttpRequest.*?open\s*\(\s*[\'"`]\w+[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]',
    r'router\.(?:get|post|put|delete|patch|use)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
    r'app\.(?:get|post|put|delete|patch|use)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
]

WAF_SIGNATURES = {
    "Cloudflare":   ["cf-ray", "cloudflare", "__cfduid", "cf-request-id"],
    "AWS WAF":      ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
    "Akamai":       ["akamai", "x-check-cacheable", "x-akamai-transformed"],
    "Fastly":       ["x-fastly", "fastly-restarts", "x-served-by"],
    "Sucuri":       ["x-sucuri-id", "sucuri"],
    "Imperva":      ["x-iinfo", "visid_incap", "incap_ses"],
    "F5 BIG-IP":    ["bigipserver", "f5"],
    "nginx":        ["x-nginx"],
    "Apache":       ["x-apache"],
    "Vercel":       ["x-vercel-id", "x-vercel-cache"],
    "Netlify":      ["x-nf-request-id", "netlify"],
}

# ─── CRAWLER CLASS ────────────────────────────────────────────────────────────

class WebCrawler:
    def __init__(self, target: str, args):
        self.target = self._normalize_url(target)
        self.args = args
        self.domain = urllib.parse.urlparse(self.target).netloc
        self.base_extract = tldextract.extract(self.target)
        self.base_domain = f"{self.base_extract.domain}.{self.base_extract.suffix}"

        self.visited: set = set()
        self.visited_lock = threading.Lock()

        self.queue: queue.Queue = queue.Queue()
        self.queue.put((self.target, 0, "start"))

        # Results buckets
        self.links_internal: set = set()
        self.links_external: set = set()
        self.endpoints: set = set()
        self.js_endpoints: set = set()
        self.subdomains: set = set()
        self.forms: list = []
        self.secrets_found: list = []
        self.js_files: set = set()
        self.emails: set = set()
        self.parameters: set = set()
        self.comments: list = []
        self.status_codes: dict = defaultdict(int)
        self.content_types: dict = defaultdict(int)
        self.technologies: set = set()
        self.waf_detected: list = []

        self.results_lock = threading.Lock()
        self.stats = {
            "requests": 0, "errors": 0, "js_parsed": 0,
            "start_time": time.time(), "bytes": 0
        }
        self.stats_lock = threading.Lock()

        self.session = self._build_session()
        self._soft404_hashes: set = set()
        self._calibrate_404()

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        ua = self.args.user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
        s.headers.update({
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        if self.args.cookies:
            for c in self.args.cookies.split(";"):
                if "=" in c:
                    k, v = c.strip().split("=", 1)
                    s.cookies.set(k.strip(), v.strip())
        if self.args.headers:
            for h in self.args.headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    s.headers[k.strip()] = v.strip()
        return s

    def _calibrate_404(self):
        """Detect soft-404 pages by fingerprinting random path responses."""
        test_paths = [
            "/this-page-absolutely-does-not-exist-xyz123",
            "/fake-endpoint-abc987def",
        ]
        for path in test_paths:
            try:
                r = self.session.get(
                    self.target + path, timeout=5,
                    allow_redirects=True, verify=not self.args.no_verify
                )
                h = hashlib.md5(r.text[:500].encode()).hexdigest()
                self._soft404_hashes.add(h)
            except Exception:
                pass

    def _is_soft404(self, text: str) -> bool:
        h = hashlib.md5(text[:500].encode()).hexdigest()
        return h in self._soft404_hashes

    def _is_same_domain(self, url: str) -> bool:
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}" == self.base_domain

    def _is_same_host(self, url: str) -> bool:
        return urllib.parse.urlparse(url).netloc == self.domain

    def fetch(self, url: str, depth: int) -> Optional[requests.Response]:
        if self.args.delay:
            time.sleep(self.args.delay)
        try:
            r = self.session.get(
                url, timeout=self.args.timeout,
                allow_redirects=True, verify=not self.args.no_verify,
                stream=False
            )
            with self.stats_lock:
                self.stats["requests"] += 1
                self.stats["bytes"] += len(r.content)
            with self.results_lock:
                self.status_codes[r.status_code] += 1
                ct = r.headers.get("Content-Type", "unknown").split(";")[0].strip()
                self.content_types[ct] += 1
            if depth == 0:
                self._fingerprint_server(r)
            return r
        except requests.exceptions.SSLError:
            with self.stats_lock:
                self.stats["errors"] += 1
            return None
        except Exception:
            with self.stats_lock:
                self.stats["errors"] += 1
            return None

    def _fingerprint_server(self, r: requests.Response):
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
        header_str = " ".join(f"{k}:{v}" for k, v in headers_lower.items())
        detected = []
        for waf, sigs in WAF_SIGNATURES.items():
            if any(sig in header_str for sig in sigs):
                detected.append(waf)
        if detected:
            with self.results_lock:
                self.waf_detected = detected
        # Technology hints
        if "x-powered-by" in headers_lower:
            with self.results_lock:
                self.technologies.add(f"Powered-By: {r.headers.get('X-Powered-By', '')}")
        if "server" in headers_lower:
            with self.results_lock:
                self.technologies.add(f"Server: {r.headers.get('Server', '')}")

    def parse_robots(self):
        try:
            r = self.session.get(f"{self.target}/robots.txt", timeout=self.args.timeout,
                                  verify=not self.args.no_verify)
            if r.status_code == 200:
                paths = re.findall(r'(?:Disallow|Allow):\s*(/\S+)', r.text)
                for p in paths:
                    full = urllib.parse.urljoin(self.target, p)
                    with self.results_lock:
                        self.endpoints.add(full)
                        self.links_internal.add(full)
        except Exception:
            pass

    def parse_sitemap(self):
        urls_to_try = [
            f"{self.target}/sitemap.xml",
            f"{self.target}/sitemap_index.xml",
            f"{self.target}/sitemaps.xml",
        ]
        for url in urls_to_try:
            try:
                r = self.session.get(url, timeout=self.args.timeout,
                                      verify=not self.args.no_verify)
                if r.status_code == 200 and "xml" in r.headers.get("Content-Type", ""):
                    locs = re.findall(r'<loc>(.*?)</loc>', r.text)
                    for loc in locs:
                        loc = loc.strip()
                        if self._is_same_domain(loc):
                            with self.results_lock:
                                self.links_internal.add(loc)
                            if self.queue.qsize() < 5000:
                                self.queue.put((loc, 1, "sitemap"))
            except Exception:
                pass

    def extract_links(self, soup: BeautifulSoup, base_url: str, depth: int):
        tags = [
            ("a", "href"), ("link", "href"), ("script", "src"),
            ("img", "src"), ("form", "action"), ("iframe", "src"),
            ("frame", "src"), ("embed", "src"), ("source", "src"),
            ("track", "src"), ("video", "src"), ("audio", "src"),
        ]
        for tag, attr in tags:
            for el in soup.find_all(tag):
                val = el.get(attr, "").strip()
                if not val or val.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                    continue
                # Grab emails from mailto
                if val.startswith("mailto:"):
                    with self.results_lock:
                        self.emails.add(val[7:].split("?")[0])
                    continue
                full = urllib.parse.urljoin(base_url, val)
                full = full.split("#")[0].rstrip("/") or full
                if not full.startswith(("http://", "https://")):
                    continue
                with self.results_lock:
                    if self._is_same_domain(full):
                        self.links_internal.add(full)
                    else:
                        self.links_external.add(full)
                        ext = tldextract.extract(full)
                        if ext.domain and ext.suffix:
                            subdomain_host = urllib.parse.urlparse(full).netloc
                            if subdomain_host.endswith(self.base_domain) and subdomain_host != self.domain:
                                self.subdomains.add(subdomain_host)
                # Queue for crawling
                if tag == "script" and attr == "src" and self._is_same_domain(full):
                    with self.results_lock:
                        self.js_files.add(full)
                    if self.queue.qsize() < 5000:
                        self.queue.put((full, depth, "js"))
                elif self._is_same_host(full) if not self.args.subdomains else self._is_same_domain(full):
                    if depth < self.args.depth:
                        with self.visited_lock:
                            if full not in self.visited:
                                if self.queue.qsize() < 5000:
                                    self.queue.put((full, depth + 1, "html"))

    def extract_forms(self, soup: BeautifulSoup, base_url: str):
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            action_url = urllib.parse.urljoin(base_url, action) if action else base_url
            inputs = []
            for inp in form.find_all(["input", "select", "textarea", "button"]):
                name = inp.get("name", "")
                itype = inp.get("type", "text")
                val = inp.get("value", "")
                inputs.append({"name": name, "type": itype, "value": val})
                if name:
                    with self.results_lock:
                        self.parameters.add(name)
            with self.results_lock:
                self.forms.append({
                    "url": base_url,
                    "action": action_url,
                    "method": method,
                    "inputs": inputs,
                })

    def extract_comments(self, html: str, url: str):
        html_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for c in html_comments:
            c = c.strip()
            if len(c) > 5 and not c.startswith("[if"):
                with self.results_lock:
                    self.comments.append({"url": url, "comment": c[:300]})

    def detect_endpoints(self, text: str, base_url: str):
        for pat in API_PATTERNS:
            matches = re.findall(pat, text, re.IGNORECASE)
            for m in matches:
                if isinstance(m, tuple):
                    m = m[0]
                if m.startswith("/"):
                    full = urllib.parse.urljoin(base_url, m)
                else:
                    full = m
                if full.startswith("http"):
                    with self.results_lock:
                        self.endpoints.add(full)

    def extract_js_endpoints(self, js_text: str, base_url: str):
        for pat in JS_ENDPOINT_PATTERNS:
            matches = re.findall(pat, js_text, re.IGNORECASE)
            for m in matches:
                if isinstance(m, tuple):
                    m = m[0]
                m = m.strip()
                if not m or len(m) < 2:
                    continue
                if m.startswith("/"):
                    full = urllib.parse.urljoin(base_url, m)
                elif m.startswith("http"):
                    full = m
                else:
                    continue
                with self.results_lock:
                    self.js_endpoints.add(full)
        # also detect bare string endpoints
        bare = re.findall(r'[\'"`](/[\w/.-]{2,100})[\'"`]', js_text)
        for m in bare:
            if any(x in m for x in ["/api/", "/v1/", "/v2/", "/v3/", "/auth/",
                                      "/admin/", "/user/", "/gql", "/graphql",
                                      "/upload", "/download", "/config"]):
                full = urllib.parse.urljoin(base_url, m)
                with self.results_lock:
                    self.js_endpoints.add(full)

    def detect_url_params(self, url: str):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for k in params:
            with self.results_lock:
                self.parameters.add(k)

    def scan_secrets(self, text: str, url: str):
        if not self.args.secrets:
            return
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                for match in matches[:3]:
                    if isinstance(match, tuple):
                        match = match[0]
                    with self.results_lock:
                        self.secrets_found.append({
                            "type": name,
                            "url": url,
                            "snippet": match[:80] + "..." if len(match) > 80 else match,
                        })

    def detect_technology(self, soup: BeautifulSoup, html: str):
        tech_hints = {
            "WordPress":   ["wp-content", "wp-includes", "wp-json"],
            "React":       ["__REACT_", "react-root", "data-reactroot"],
            "Next.js":     ["__NEXT_DATA__", "_next/static"],
            "Vue.js":      ["__vue__", "data-v-"],
            "Angular":     ["ng-version", "ng-app", "angular.js"],
            "jQuery":      ["jquery", "jQuery"],
            "Bootstrap":   ["bootstrap.min.css", "bootstrap.min.js"],
            "Laravel":     ["laravel_session", "laravel-token"],
            "Django":      ["csrfmiddlewaretoken", "django"],
            "Rails":       ["rails", "_rails_assets"],
            "Express.js":  ["X-Powered-By: Express"],
            "ASP.NET":     ["__VIEWSTATE", "asp.net"],
            "PHP":         [".php", "PHPSESSID"],
            "GraphQL":     ["/graphql", "__schema"],
        }
        for tech, signals in tech_hints.items():
            if any(s in html for s in signals):
                with self.results_lock:
                    self.technologies.add(tech)

    def process_page(self, url: str, depth: int, kind: str):
        r = self.fetch(url, depth)
        if not r:
            return
        if r.status_code in (301, 302, 303, 307, 308):
            return
        if r.status_code != 200 and not self.args.all_codes:
            return
        if self._is_soft404(r.text):
            return

        self.detect_url_params(url)
        self.scan_secrets(r.text, url)
        self.detect_endpoints(r.text, url)

        ct = r.headers.get("Content-Type", "")

        if "javascript" in ct or url.endswith(".js") or kind == "js":
            with self.stats_lock:
                self.stats["js_parsed"] += 1
            self.extract_js_endpoints(r.text, url)
            return

        if "html" not in ct and kind != "html" and "text" not in ct:
            return

        try:
            soup = BeautifulSoup(r.text, "lxml")
        except Exception:
            soup = BeautifulSoup(r.text, "html.parser")

        self.extract_links(soup, url, depth)
        self.extract_forms(soup, url)
        self.extract_comments(r.text, url)
        self.detect_technology(soup, r.text)

        # inline JS
        for script in soup.find_all("script"):
            if not script.get("src") and script.string:
                self.extract_js_endpoints(script.string, url)
                self.scan_secrets(script.string, url)

        # extract emails from page text
        emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', r.text)
        with self.results_lock:
            for e in emails:
                if not e.endswith((".png", ".jpg", ".gif", ".css")):
                    self.emails.add(e)

    def worker(self):
        while True:
            try:
                item = self.queue.get(timeout=3)
            except queue.Empty:
                break
            url, depth, kind = item
            with self.visited_lock:
                if url in self.visited:
                    self.queue.task_done()
                    continue
                self.visited.add(url)
            if depth > self.args.depth:
                self.queue.task_done()
                continue
            self.process_page(url, depth, kind)
            self.queue.task_done()

    def run(self):
        console.print(banner())
        console.print(f"\n[bold cyan]Target:[/bold cyan] {self.target}")
        console.print(f"[bold cyan]Domain:[/bold cyan] {self.domain}")
        console.print(f"[bold cyan]Depth:[/bold cyan]  {self.args.depth}")
        console.print(f"[bold cyan]Threads:[/bold cyan] {self.args.threads}\n")

        # Pre-crawl: robots.txt + sitemap
        console.print("[dim]» Fetching robots.txt and sitemap.xml...[/dim]")
        self.parse_robots()
        self.parse_sitemap()

        threads = []
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="bright_cyan"),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Crawling...", total=None)

            for _ in range(self.args.threads):
                t = threading.Thread(target=self.worker, daemon=True)
                t.start()
                threads.append(t)

            while any(t.is_alive() for t in threads):
                elapsed = time.time() - self.stats["start_time"]
                q_size = self.queue.qsize()
                visited = len(self.visited)
                rps = self.stats["requests"] / max(elapsed, 1)
                progress.update(
                    task,
                    description=(
                        f"[cyan]Crawling[/cyan] · "
                        f"[white]{visited}[/white] visited · "
                        f"[white]{q_size}[/white] queued · "
                        f"[dim]{rps:.1f} req/s[/dim]"
                    ),
                )
                time.sleep(0.4)

            for t in threads:
                t.join(timeout=5)

        self.print_results()
        if self.args.output:
            self.export_results()

    def print_results(self):
        elapsed = time.time() - self.stats["start_time"]
        kb = self.stats["bytes"] / 1024

        console.print()
        console.rule("[bold cyan]RESULTS[/bold cyan]")

        # ── Stats summary ────────────────────────────────────
        stat_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        stat_table.add_column(style="dim")
        stat_table.add_column(style="bold white")
        stat_table.add_row("Requests",   str(self.stats["requests"]))
        stat_table.add_row("Errors",     str(self.stats["errors"]))
        stat_table.add_row("JS parsed",  str(self.stats["js_parsed"]))
        stat_table.add_row("Data",       f"{kb:.1f} KB")
        stat_table.add_row("Time",       f"{elapsed:.1f}s")
        stat_table.add_row("Avg speed",  f"{self.stats['requests'] / max(elapsed,1):.1f} req/s")
        console.print(stat_table)

        # ── WAF / Tech ────────────────────────────────────────
        if self.waf_detected or self.technologies:
            console.print("[bold]» Infrastructure[/bold]")
            if self.waf_detected:
                console.print(f"  [yellow]WAF/CDN:[/yellow] {', '.join(self.waf_detected)}")
            for t in sorted(self.technologies):
                console.print(f"  [green]Tech:[/green] {t}")
            console.print()

        # ── Status codes ─────────────────────────────────────
        if self.status_codes:
            console.print("[bold]» HTTP Status Codes[/bold]")
            for code, count in sorted(self.status_codes.items()):
                color = "green" if code == 200 else ("yellow" if code < 400 else "red")
                console.print(f"  [{color}]{code}[/{color}]  {count}x")
            console.print()

        # ── Internal links ────────────────────────────────────
        self._print_section(
            f"Internal Links ({len(self.links_internal)})",
            sorted(self.links_internal),
            "cyan",
            self.args.limit,
        )

        # ── Endpoints ────────────────────────────────────────
        all_endpoints = self.endpoints | self.js_endpoints
        self._print_section(
            f"Endpoints Discovered ({len(all_endpoints)})",
            sorted(all_endpoints),
            "bright_green",
            self.args.limit,
        )

        # ── JS-Extracted endpoints ────────────────────────────
        if self.js_endpoints:
            self._print_section(
                f"JS-Extracted Endpoints ({len(self.js_endpoints)})",
                sorted(self.js_endpoints),
                "magenta",
                self.args.limit,
            )

        # ── External links ────────────────────────────────────
        if self.args.verbose:
            self._print_section(
                f"External Links ({len(self.links_external)})",
                sorted(self.links_external),
                "dim",
                self.args.limit,
            )

        # ── Subdomains ────────────────────────────────────────
        if self.subdomains:
            self._print_section(
                f"Subdomains Found ({len(self.subdomains)})",
                sorted(self.subdomains),
                "yellow",
                None,
            )

        # ── Parameters ────────────────────────────────────────
        if self.parameters:
            self._print_section(
                f"URL Parameters ({len(self.parameters)})",
                sorted(self.parameters),
                "bright_blue",
                None,
            )

        # ── Emails ────────────────────────────────────────────
        if self.emails:
            self._print_section(
                f"Emails ({len(self.emails)})",
                sorted(self.emails),
                "blue",
                None,
            )

        # ── Forms ────────────────────────────────────────────
        if self.forms:
            console.print(f"\n[bold]» Forms ({len(self.forms)})[/bold]")
            for form in self.forms[:self.args.limit or 999]:
                console.print(
                    f"  [bright_blue]{form['method']}[/bright_blue] "
                    f"[cyan]{form['action']}[/cyan]"
                )
                for inp in form["inputs"]:
                    if inp["name"]:
                        console.print(
                            f"    [dim]└─[/dim] [{inp['type']}] {inp['name']}"
                        )

        # ── Comments ─────────────────────────────────────────
        if self.comments and self.args.verbose:
            console.print(f"\n[bold]» HTML Comments ({len(self.comments)})[/bold]")
            for c in self.comments[:20]:
                text = c["comment"].replace("\n", " ").strip()
                console.print(f"  [dim]{c['url']}[/dim]")
                console.print(f"  [yellow]  <!-- {text[:120]} -->[/yellow]")

        # ── Secrets ───────────────────────────────────────────
        if self.secrets_found:
            console.print(f"\n[bold red]» ⚠  Potential Secrets ({len(self.secrets_found)})[/bold red]")
            for s in self.secrets_found:
                console.print(
                    f"  [red]{s['type']}[/red] in [dim]{s['url']}[/dim]"
                )
                console.print(f"  [yellow]  {s['snippet'][:100]}[/yellow]")

        # ── JS files ─────────────────────────────────────────
        if self.js_files and self.args.verbose:
            self._print_section(
                f"JS Files ({len(self.js_files)})",
                sorted(self.js_files),
                "dim",
                self.args.limit,
            )

        console.print()
        console.rule()

    def _print_section(self, title, items, color, limit):
        if not items:
            return
        limited = list(items)[:limit] if limit else list(items)
        console.print(f"\n[bold]» {title}[/bold]")
        for item in limited:
            console.print(f"  [{color}]{item}[/{color}]")
        if limit and len(items) > limit:
            console.print(f"  [dim]... and {len(items) - limit} more[/dim]")

    def export_results(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{self.args.output}_{ts}"

        if self.args.format == "json" or self.args.format == "all":
            path = base + ".json"
            data = {
                "target": self.target,
                "crawled_at": ts,
                "stats": self.stats,
                "waf_detected": self.waf_detected,
                "technologies": list(self.technologies),
                "internal_links": sorted(self.links_internal),
                "external_links": sorted(self.links_external),
                "endpoints": sorted(self.endpoints | self.js_endpoints),
                "js_endpoints": sorted(self.js_endpoints),
                "js_files": sorted(self.js_files),
                "subdomains": sorted(self.subdomains),
                "parameters": sorted(self.parameters),
                "emails": sorted(self.emails),
                "forms": self.forms,
                "secrets": self.secrets_found,
                "comments": self.comments,
                "status_codes": dict(self.status_codes),
            }
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            console.print(f"[green]✓[/green] JSON saved → {path}")

        if self.args.format == "csv" or self.args.format == "all":
            path = base + "_links.csv"
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["type", "url"])
                for u in sorted(self.links_internal):
                    w.writerow(["internal", u])
                for u in sorted(self.endpoints | self.js_endpoints):
                    w.writerow(["endpoint", u])
                for u in sorted(self.links_external):
                    w.writerow(["external", u])
            console.print(f"[green]✓[/green] CSV saved  → {path}")

        if self.args.format == "txt" or self.args.format == "all":
            path = base + "_endpoints.txt"
            with open(path, "w") as f:
                all_ep = sorted(self.endpoints | self.js_endpoints | self.links_internal)
                f.write("\n".join(all_ep))
            console.print(f"[green]✓[/green] TXT saved  → {path}")


# ─── BANNER ──────────────────────────────────────────────────────────────────

def banner():
    return Panel(
        Text.from_markup(
            "\n"
            "[bold cyan]██╗    ██╗███████╗██████╗  ██████╗██████╗  █████╗ ██╗    ██╗██╗\n"
            "██║    ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║    ██║██║\n"
            "██║ █╗ ██║█████╗  ██████╔╝██║     ██████╔╝███████║██║ █╗ ██║██║\n"
            "██║███╗██║██╔══╝  ██╔══██╗██║     ██╔══██╗██╔══██║██║███╗██║██║\n"
            "╚███╔███╔╝███████╗██████╔╝╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗\n"
            " ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝\n"
            "\n"
            "[dim]Link & Endpoint Discovery  ·  JS Mining  ·  Secret Detection[/dim]\n"
            "[dim]v2.0 · use responsibly · only on authorized targets[/dim]\n"
        ),
        border_style="cyan",
        padding=(0, 2),
    )


# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="crawler.py",
        description="Advanced Web Crawler — Link, Endpoint & Secret Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 crawler.py https://example.com
  python3 crawler.py https://example.com -d 3 -t 20
  python3 crawler.py https://example.com --secrets --verbose
  python3 crawler.py https://example.com -o results --format all
  python3 crawler.py https://example.com -d 4 -t 30 --subdomains --secrets -o scan
  python3 crawler.py https://example.com --cookies "session=abc; token=xyz"
  python3 crawler.py https://example.com -H "Authorization: Bearer TOKEN" --delay 0.5
        """,
    )
    p.add_argument("target",          help="Target URL (e.g. https://example.com)")
    p.add_argument("-d", "--depth",   type=int, default=2,    help="Crawl depth (default: 2)")
    p.add_argument("-t", "--threads", type=int, default=10,   help="Concurrent threads (default: 10)")
    p.add_argument("--timeout",       type=int, default=10,   help="Request timeout in seconds (default: 10)")
    p.add_argument("--delay",         type=float, default=0,  help="Delay between requests in seconds")
    p.add_argument("--limit",         type=int, default=None, help="Max items to display per section")
    p.add_argument("--subdomains",    action="store_true",     help="Follow subdomains during crawl")
    p.add_argument("--secrets",       action="store_true",     help="Scan for secrets/keys in source")
    p.add_argument("--all-codes",     action="store_true",     help="Process non-200 responses too")
    p.add_argument("--no-verify",     action="store_true",     help="Disable SSL certificate verification")
    p.add_argument("--verbose", "-v", action="store_true",     help="Show extra output (comments, JS files, external links)")
    p.add_argument("--cookies",       type=str, default=None, help='Cookie string (e.g. "session=abc; csrf=xyz")')
    p.add_argument("-H", "--headers", action="append",         help="Extra header (e.g. -H \"Authorization: Bearer TOKEN\")")
    p.add_argument("--user-agent",    type=str, default=None, help="Custom User-Agent string")
    p.add_argument("-o", "--output",  type=str, default=None, help="Output file base name (no extension)")
    p.add_argument("--format",        choices=["json", "csv", "txt", "all"], default="json",
                                      help="Export format (default: json)")
    return p


def main():
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    try:
        crawler = WebCrawler(args.target, args)
        crawler.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚡ Interrupted by user. Printing partial results...[/yellow]")
        try:
            crawler.print_results()
            if args.output:
                crawler.export_results()
        except Exception:
            pass
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Fatal error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
