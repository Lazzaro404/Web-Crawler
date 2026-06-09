# WebCrawl — Advanced Link & Endpoint Discovery

> A fast, multi-threaded web crawler built for security researchers and penetration testers. Goes beyond simple link extraction — mines JavaScript source, detects API endpoints, sniffs exposed secrets, fingerprints WAFs, and exports clean output ready to pipe into other tools.

---

## Features

| Feature | Description |
|---|---|
| **JS Mining** | Fetches every `.js` file and extracts endpoints from `fetch()`, `axios`, `XMLHttpRequest`, `router.get()`, and raw string paths |
| **API Endpoint Detection** | Identifies REST, GraphQL, WebSocket, and RPC routes from both HTML and JS source |
| **Secret Detection** | Scans source for AWS keys, GitHub tokens, JWTs, Stripe keys, Firebase URLs, hardcoded passwords, and more |
| **Soft-404 Fingerprinting** | Calibrates against random paths before crawling to ignore fake 200 pages |
| **WAF / CDN Fingerprinting** | Detects Cloudflare, Akamai, Fastly, Imperva, F5, Vercel, Netlify from response headers |
| **Technology Detection** | Identifies WordPress, React, Next.js, Vue, Angular, Laravel, Django, Rails, GraphQL, PHP, ASP.NET |
| **Form Extraction** | Finds every `<form>`, its action URL, method, and all named inputs including hidden fields |
| **Subdomain Harvesting** | Collects subdomains from links, JS files, and external references |
| **HTML Comment Mining** | Extracts developer comments left in page source |
| **Email Extraction** | Collects email addresses from both `mailto:` links and page text |
| **URL Parameter Harvesting** | Builds a unique list of all query parameter names across the entire site |
| **robots.txt & sitemap.xml** | Parsed automatically before crawling begins |
| **Concurrent Crawling** | Configurable thread count with smart rate limiting |
| **Flexible Export** | JSON, CSV, plain TXT — or all three at once |

---

## Requirements

- Python 3.8+
- Kali Linux (or any Linux distro)

Install dependencies:

```bash
pip install -r requirements.txt
```

`requirements.txt`:
```
requests>=2.28.0
beautifulsoup4>=4.11.0
lxml>=4.9.0
rich>=13.0.0
tldextract>=3.4.0
```

---

## Installation

```bash
git clone https://github.com/yourusername/webcrawl.git
cd webcrawl
pip install -r requirements.txt
chmod +x crawler.py
```

---

## Usage

```bash
python3 crawler.py <target> [options]
```

### Quick Examples

```bash
# Basic crawl
python3 crawler.py https://example.com

# Deeper crawl with more threads
python3 crawler.py https://example.com -d 4 -t 30

# Full recon — secrets, verbose output, save everything
python3 crawler.py https://example.com -d 3 --secrets --verbose -o results --format all

# Authenticated session
python3 crawler.py https://example.com --cookies "session=abc123; csrf=xyz"

# With auth header
python3 crawler.py https://example.com -H "Authorization: Bearer YOUR_TOKEN"

# Stealthy — slow requests, single thread
python3 crawler.py https://example.com -t 1 --delay 2.0

# Skip SSL (self-signed certs, internal targets)
python3 crawler.py https://192.168.1.1 --no-verify -d 3

# Also crawl discovered subdomains
python3 crawler.py https://example.com --subdomains -d 3
```

---

## Options

```
positional arguments:
  target                Target URL (e.g. https://example.com)

crawl control:
  -d, --depth           Crawl depth (default: 2)
  -t, --threads         Concurrent threads (default: 10)
  --timeout             Request timeout in seconds (default: 10)
  --delay               Delay between requests in seconds (default: 0)
  --subdomains          Follow and crawl subdomains too
  --all-codes           Process non-200 responses as well

detection:
  --secrets             Scan for API keys, tokens, and passwords in source
  --no-verify           Disable SSL certificate verification

authentication:
  --cookies             Cookie string  e.g. "session=abc; csrf=xyz"
  -H, --headers         Extra request header (repeatable)
                        e.g. -H "Authorization: Bearer TOKEN"
  --user-agent          Custom User-Agent string

output:
  -v, --verbose         Show HTML comments, JS files, external links
  --limit N             Max items displayed per section
  -o, --output          Output file base name (no extension)
  --format              Export format: json | csv | txt | all  (default: json)
```

---

## Output

### Terminal

Results are printed in organized sections directly to the terminal:

- Infrastructure (WAF, CDN, server tech)
- HTTP status code breakdown
- Internal links
- Discovered endpoints
- JS-extracted endpoints
- Subdomains
- URL parameters
- Emails
- Forms and inputs
- Secrets (if `--secrets` is enabled)
- HTML comments (if `--verbose` is enabled)

### File Export

When using `-o <name> --format all`, three files are created:

| File | Contents |
|---|---|
| `name_TIMESTAMP.json` | Full structured output — all data in one file |
| `name_TIMESTAMP_links.csv` | All URLs tagged by type: `internal`, `endpoint`, `external` |
| `name_TIMESTAMP_endpoints.txt` | Clean endpoint list, one per line — ready to pipe into other tools |

---

## Piping into Other Tools

The `.txt` output is designed to feed directly into the rest of your recon pipeline:

```bash
# Feed into ffuf for fuzzing
python3 crawler.py https://target.com -o scan --format txt
cat scan_*.txt | ffuf -u FUZZ -w -

# Feed into httpx for probing
cat scan_*.txt | httpx -status-code -title -tech-detect

# Feed into nuclei for vulnerability scanning
cat scan_*.txt | nuclei -t nuclei-templates/

# Feed into waybackurls for historical comparison
cat scan_*.txt | waybackurls
```

---

## Secret Detection

When `--secrets` is enabled, the crawler scans all HTML, JS, and inline source for:

| Pattern | Example |
|---|---|
| AWS Access Key | `AKIA...` |
| AWS Secret | `aws_secret_access_key = "..."` |
| GitHub Token | `ghp_...` |
| Google API Key | `AIza...` |
| JWT Token | `eyJ...` |
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| Stripe Key | `sk_live_...` / `rk_live_...` |
| Slack Token | `xoxb-...` |
| Firebase URL | `https://project.firebaseio.com` |
| Bearer Token | `Authorization: Bearer ...` |
| Hardcoded Password | `password = "..."` |
| API Key Param | `api_key = "..."` |

> **Note:** Secret detection flags patterns that *look* like credentials. Always verify manually before reporting.

---

## WAF & Technology Fingerprinting

Detected automatically on the first request, before crawling begins.

**WAF / CDN detection:**
Cloudflare, AWS WAF, Akamai, Fastly, Sucuri, Imperva, F5 BIG-IP, Vercel, Netlify

**Technology stack detection:**
WordPress, React, Next.js, Vue.js, Angular, jQuery, Bootstrap, Laravel, Django, Ruby on Rails, Express.js, ASP.NET, PHP, GraphQL

---

## How Soft-404 Detection Works

Many sites return HTTP `200` for pages that don't exist, breaking naive crawlers. Before crawling starts, WebCrawl fetches two random paths and hashes the first 500 bytes of each response. Any page that matches those hashes during the crawl is silently skipped — eliminating false-positive links.

---

## Legal & Ethics

This tool is intended for use on systems you own or have explicit written permission to test.

Unauthorized scanning may violate computer fraud laws including the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation in your country. The author is not responsible for misuse.

**Always get written authorization before running any security tool against a target.**

---

## Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.
