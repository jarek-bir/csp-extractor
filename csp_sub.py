import requests
import tldextract
import re
import argparse
from urllib.parse import urlparse
from colorama import Fore, init, Style

# Initialize colorama
init(autoreset=True)

def print_banner():
    print(rf"""{Fore.RED}

  ______    ________  _______        ________  ____  ____  _______   
 /" _  "\  /"       )|   __ "\      /"       )("  _||_ " ||   _  "\  
(: ( \___)(:   \___/ (. |__) :)    (:   \___/ |   (  ) : |(. |_)  :) 
 \/ \      \___  \   |:  ____/      \___  \   (:  |  | . )|:     \/  
 //  \ _    __/  \\  (|  /           __/  \\   \\ \__/ // (|  _  \\  
(:   _) \  /" \   :)/|__/ \         /" \   :)  /\\ __ //\ |: |_)  :) 
 \_______)(_______/(_______)       (_______/  (__________)(_______/  

 CSP Subdomain Extractor
 Author: medium.com/@abhirupkonwar04                                          
    """)


def get_csp_headers(url):
    """Fetch CSP headers from both HTTP and HTTPS"""
    headers_collected = []

    # Strip scheme if present
    if url.startswith('http://') or url.startswith('https://'):
        base_url = url.split('://', 1)[1]
    else:
        base_url = url

    protocols = ['http://', 'https://']

    for protocol in protocols:
        full_url = protocol + base_url
        try:
            response = requests.get(full_url, timeout=10, allow_redirects=True)
            if response.ok:
                for header in response.headers:
                    if 'content-security-policy' in header.lower():
                        headers_collected.append(response.headers[header])
        except Exception:
            continue

    return headers_collected if headers_collected else None

def extract_domains_from_csp(csp_policies):
    domains = set()
    if not csp_policies:
        return domains

    domain_pattern = re.compile(
        r'(?:https?://)?(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?',
        re.IGNORECASE
    )

    for policy in csp_policies:
        directives = policy.split(';')
        for directive in directives:
            directive = directive.strip()
            if not directive:
                continue

            parts = directive.split(' ', 1)
            if len(parts) == 1:
                continue

            _, values = parts
            found_domains = domain_pattern.findall(values)
            for domain in found_domains:
                domain = domain.replace('http://', '').replace('https://', '')
                domain = domain.split(':')[0].split('/')[0]
                if domain.startswith('*.'):
                    domain = domain[2:]
                domains.add(domain.lower())

    return domains

def is_subdomain(domain, main_domain):
    if domain == main_domain:
        return False

    domain_parts = domain.split('.')
    main_parts = main_domain.split('.')

    if len(domain_parts) <= len(main_parts):
        return False

    return domain.endswith('.' + main_domain)

def analyze_target(target, match_domain=None, verbose=False, output_file=None):
    """Analyze CSP headers from a target (URL or IP)"""
    csp_headers = get_csp_headers(target)
    if not csp_headers:
        if verbose:
            print(f"{Fore.YELLOW}No CSP headers found for {target}")
        return None  # Return None instead of empty set when no CSP headers

    ext = tldextract.extract(target)
    main_domain = f"{ext.domain}.{ext.suffix}"

    if verbose:    
        print(f"{Fore.MAGENTA}CSP Headers:")
        for i, header in enumerate(csp_headers, 1):
            print(f"{i}. {header}")

    all_domains = extract_domains_from_csp(csp_headers)

    if match_domain:
        subdomains = {domain for domain in all_domains if is_subdomain(domain, match_domain)}
    else:
        subdomains = {domain for domain in all_domains if is_subdomain(domain, main_domain)}

    return subdomains

def process_file(input_file, match_domain=None, verbose=False, output_file=None):
    """Process multiple targets from a file"""
    try:
        with open(input_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

        all_subdomains = set()
        for target in targets:
            if target:
                if verbose:
                    print(f"\n{Fore.BLUE}Analyzing: {target}")

                subdomains = analyze_target(target, match_domain, verbose, output_file)

                if subdomains is None:
                    # No CSP headers found, message already printed inside analyze_target
                    continue

                if subdomains:
                    output = [Fore.GREEN + subdomain for subdomain in sorted(subdomains)]
                    print('\n'.join(output))
                    all_subdomains.update(subdomains)
                elif verbose:
                    print(f"{Fore.YELLOW}No subdomains found")

        if output_file and all_subdomains:
            with open(output_file, 'w') as f:
                f.write('\n'.join(sorted(all_subdomains)))

    except FileNotFoundError:
        print(f"{Fore.RED}Error: Input file '{input_file}' not found.")
    except Exception as e:
        print(f"{Fore.RED}Error processing file: {e}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="CSP Subdomain Extractor - Fetch subdomains from CSP headers",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('-u', '--url', help="Single Domain to analyze (e.g., example.com)")
    parser.add_argument('-f', '--file', help="File containing list of targets (URLs/IPs, one per line)")
    parser.add_argument('-m', '--match', help="Domain to match subdomains against (e.g., domain-to-match-subdomains-from.com)")
    parser.add_argument('-o', '--output', help="Output file to save results")
    parser.add_argument('-v', '--verbose', action='store_true', help="Show verbose output including CSP headers")
    parser.add_argument('--version', action='version', version='CSP Subdomain Extractor 2.3')

    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        return

    if args.file:
        process_file(args.file, args.match, args.verbose, args.output)
    else:
        subdomains = analyze_target(args.url, args.match, args.verbose, args.output)
        if subdomains is None:
            # No CSP headers found, message already printed
            return

        if subdomains:
            output = [Fore.GREEN + subdomain for subdomain in sorted(subdomains)]
            if args.output:
                with open(args.output, 'a') as f:
                    f.write('\n'.join([subdomain.replace(Fore.GREEN, '') for subdomain in output]) + '\n')
            print('\n'.join(output))
        elif args.verbose:
            print(f"{Fore.YELLOW}No subdomains found in CSP headers")

if __name__ == "__main__":
    main()
