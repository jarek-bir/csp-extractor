# CSP Subdomain Extractor 🔍
A Python tool to extract subdomains from Content Security Policy (CSP) headers of websites (domain/subdomain/IP)


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


## How To Run ⛏️

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
