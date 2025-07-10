# CSP Subdomain Extractor 🔍
A Python tool to extract subdomains from Content Security Policy (CSP) headers of websites (domain/subdomain/IP)

## Tool Demo
https://medium.com/legionhunters/cspsub-extract-subdomains-from-csp-headers-4d0772f43603

## Features ✨
- Extract subdomains from CSP headers
- Supports single URL or file input with multiple domains
- Input as domain/subdomains/IPs

## Installation 📦

1. Clone the repository:
```bash
git clone https://github.com/legionhunter/csp-subdomain-extractor.git
cd csp-subdomain-extractor
```

2. Download requirements
```
pip3 install -r requirements.txt
```

## How To Run ⛏️

Linux/WSL : python3
Windows : python

Single Input
```
python3 csp_sub.py -u example.com
```

Multiple Domain or subdomains
```
python3 csp_sub.py -f filename.txt
```

Multiple IPs
```
python3 csp_sub.py -f ips.txt -m domain-to-match.tld
```

Save the results
```
python3 csp_sub.py -f filename.txt -o output.txt
python3 csp_sub.py -f ips.txt -m domain-to-match.tld -o output.txt
```


## Features Pending 🚧
- [ ] **User-Agent Randomization** — Rotate User-Agent headers to mimic real browsers and avoid detection
- [ ]  **Multi-threading Support** — Improve performance by analyzing multiple targets concurrently
- [ ] **Automatic Retries** — Retry failed requests up to a configurable number of times
- [ ] **Request Throttling** — Add configurable delay between requests to reduce server load and avoid rate-limiting


## ⚠️ Disclaimer
This tool is intended for **educational, research, and authorized security testing purposes only**.  
**Do not use it on systems or domains you do not own or have explicit permission to test.**  
The author is **not responsible for any misuse or damage** caused by this tool.
