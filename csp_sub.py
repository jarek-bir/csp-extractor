#!/usr/bin/env python3
"""
CSP Subdomain Extractor

A tool for extracting subdomains from Content Security Policy (CSP) headers.
Supports both single target analysis and batch processing from files.

Author: medium.com/@abhirupkonwar04
Version: 2.4
"""

import argparse
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Union
from urllib.parse import urlparse

import requests
import tldextract
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


# Configuration constants
class Config:
    VERSION = "2.4"
    TIMEOUT = 10
    DEFAULT_PROTOCOLS = ["http://", "https://"]
    CSP_HEADER_NAMES = [
        "content-security-policy",
        "content-security-policy-report-only",
    ]
    DOMAIN_PATTERN = re.compile(
        r"(?:https?://)?(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?", re.IGNORECASE
    )


@dataclass
class CSPAnalysisResult:
    """Results from CSP header analysis"""

    target: str
    subdomains: Set[str]
    csp_headers: List[str]
    main_domain: str
    success: bool
    error_message: Optional[str] = None


class Logger:
    """Centralized logging and output handling"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._setup_logging()

    def _setup_logging(self):
        """Setup logging configuration"""
        level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler(sys.stderr)],
        )
        self.logger = logging.getLogger(__name__)

    def info(self, message: str, color: str = Fore.WHITE):
        """Log info message with color"""
        print(f"{color}{message}")
        self.logger.info(message)

    def error(self, message: str):
        """Log error message"""
        print(f"{Fore.RED}Error: {message}")
        self.logger.error(message)

    def warning(self, message: str):
        """Log warning message"""
        print(f"{Fore.YELLOW}Warning: {message}")
        self.logger.warning(message)

    def success(self, message: str):
        """Log success message"""
        print(f"{Fore.GREEN}{message}")
        self.logger.info(message)

    def debug(self, message: str):
        """Log debug message"""
        if self.verbose:
            print(f"{Fore.CYAN}Debug: {message}")
        self.logger.debug(message)


def print_banner():
    """Print the application banner"""
    banner = rf"""{Fore.RED}

  ______    ________  _______        ________  ____  ____  _______   
 /" _  "\  /"       )|   __ "\      /"       )("  _||_ " ||   _  "\  
(: ( \___)(:   \___/ (. |__) :)    (:   \___/ |   (  ) : |(. |_)  :) 
 \/ \      \___  \   |:  ____/      \___  \   (:  |  | . )|:     \/  
 //  \ _    __/  \\  (|  /           __/  \\   \\ \__/ // (|  _  \\  
(:   _) \  /" \   :)/|__/ \         /" \   :)  /\\ __ //\ |: |_)  :) 
 \_______)(_______/(_______)       (_______/  (__________)(_______/  

 CSP Subdomain Extractor v{Config.VERSION}
 Author: medium.com/@abhirupkonwar04                                          
    """
    print(banner)


class URLHelper:
    """Helper class for URL operations"""

    @staticmethod
    def normalize_url(url: str) -> str:
        """Remove protocol from URL if present"""
        if url.startswith("http://") or url.startswith("https://"):
            return url.split("://", 1)[1]
        return url

    @staticmethod
    def extract_main_domain(url: str) -> str:
        """Extract main domain from URL using tldextract"""
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}"


class CSPHeaderFetcher:
    """Handles fetching CSP headers from URLs"""

    def __init__(self, logger: Logger, timeout: int = Config.TIMEOUT):
        self.logger = logger
        self.timeout = timeout

    def get_csp_headers(self, url: str) -> Optional[List[str]]:
        """
        Fetch CSP headers from both HTTP and HTTPS protocols

        Args:
            url: Target URL to fetch headers from

        Returns:
            List of CSP header values or None if no headers found
        """
        headers_collected = []
        base_url = URLHelper.normalize_url(url)

        for protocol in Config.DEFAULT_PROTOCOLS:
            full_url = protocol + base_url
            try:
                self.logger.debug(f"Trying to fetch CSP headers from {full_url}")
                response = requests.get(
                    full_url, timeout=self.timeout, allow_redirects=True
                )

                if response.ok:
                    for header_name in Config.CSP_HEADER_NAMES:
                        if header_name in response.headers:
                            headers_collected.append(response.headers[header_name])
                        # Also check case-insensitive
                        for header in response.headers:
                            if header.lower() == header_name:
                                headers_collected.append(response.headers[header])

            except requests.exceptions.RequestException as e:
                self.logger.debug(f"Failed to fetch from {full_url}: {e}")
                continue
            except Exception as e:
                self.logger.debug(f"Unexpected error fetching from {full_url}: {e}")
                continue

        return headers_collected if headers_collected else None


class DomainExtractor:
    """Handles domain extraction from CSP policies"""

    def __init__(self, logger: Logger):
        self.logger = logger

    def extract_domains_from_csp(self, csp_policies: List[str]) -> Set[str]:
        """
        Extract all domains from CSP policy headers

        Args:
            csp_policies: List of CSP policy strings

        Returns:
            Set of extracted domains
        """
        domains = set()
        if not csp_policies:
            return domains

        for policy in csp_policies:
            domains.update(self._extract_domains_from_policy(policy))

        return domains

    def _extract_domains_from_policy(self, policy: str) -> Set[str]:
        """Extract domains from a single CSP policy"""
        domains = set()
        directives = policy.split(";")

        for directive in directives:
            directive = directive.strip()
            if not directive:
                continue

            parts = directive.split(" ", 1)
            if len(parts) == 1:
                continue

            _, values = parts
            found_domains = Config.DOMAIN_PATTERN.findall(values)

            for domain in found_domains:
                cleaned_domain = self._clean_domain(domain)
                if cleaned_domain:
                    domains.add(cleaned_domain.lower())

        return domains

    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize domain string"""
        # Remove protocol
        domain = domain.replace("http://", "").replace("https://", "")
        # Remove port and path
        domain = domain.split(":")[0].split("/")[0]
        # Handle wildcard subdomains
        if domain.startswith("*."):
            domain = domain[2:]
        return domain

    @staticmethod
    def is_subdomain(domain: str, main_domain: str) -> bool:
        """
        Check if domain is a subdomain of main_domain

        Args:
            domain: Domain to check
            main_domain: Main domain to compare against

        Returns:
            True if domain is a subdomain of main_domain
        """
        if domain == main_domain:
            return False

        domain_parts = domain.split(".")
        main_parts = main_domain.split(".")

        if len(domain_parts) <= len(main_parts):
            return False

        return domain.endswith("." + main_domain)


class CSPAnalyzer:
    """Main analyzer for CSP headers and subdomain extraction"""

    def __init__(self, logger: Logger):
        self.logger = logger
        self.header_fetcher = CSPHeaderFetcher(logger)
        self.domain_extractor = DomainExtractor(logger)

    def analyze_target(
        self, target: str, match_domain: Optional[str] = None
    ) -> CSPAnalysisResult:
        """
        Analyze CSP headers from a target (URL or IP)

        Args:
            target: URL or IP to analyze
            match_domain: Optional domain to match subdomains against

        Returns:
            CSPAnalysisResult object with analysis results
        """
        try:
            self.logger.debug(f"Analyzing target: {target}")

            # Fetch CSP headers
            csp_headers = self.header_fetcher.get_csp_headers(target)
            if not csp_headers:
                self.logger.warning(f"No CSP headers found for {target}")
                return CSPAnalysisResult(
                    target=target,
                    subdomains=set(),
                    csp_headers=[],
                    main_domain="",
                    success=False,
                    error_message="No CSP headers found",
                )

            # Extract main domain
            main_domain = URLHelper.extract_main_domain(target)

            if self.logger.verbose:
                self.logger.info(f"CSP Headers for {target}:", Fore.MAGENTA)
                for i, header in enumerate(csp_headers, 1):
                    self.logger.info(f"{i}. {header}")

            # Extract all domains from CSP
            all_domains = self.domain_extractor.extract_domains_from_csp(csp_headers)

            # Filter subdomains
            target_domain = match_domain if match_domain else main_domain
            subdomains = {
                domain
                for domain in all_domains
                if DomainExtractor.is_subdomain(domain, target_domain)
            }

            return CSPAnalysisResult(
                target=target,
                subdomains=subdomains,
                csp_headers=csp_headers,
                main_domain=main_domain,
                success=True,
            )

        except Exception as e:
            error_msg = f"Error analyzing {target}: {e}"
            self.logger.error(error_msg)
            return CSPAnalysisResult(
                target=target,
                subdomains=set(),
                csp_headers=[],
                main_domain="",
                success=False,
                error_message=error_msg,
            )


class FileProcessor:
    """Handles processing multiple targets from files"""

    def __init__(self, logger: Logger, analyzer: CSPAnalyzer):
        self.logger = logger
        self.analyzer = analyzer

    def process_file(
        self,
        input_file: str,
        match_domain: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> Set[str]:
        """
        Process multiple targets from a file

        Args:
            input_file: Path to input file containing targets
            match_domain: Optional domain to match subdomains against
            output_file: Optional output file to save results

        Returns:
            Set of all found subdomains
        """
        try:
            input_path = Path(input_file)
            if not input_path.exists():
                raise FileNotFoundError(f"Input file '{input_file}' not found")

            # Read targets from file
            targets = self._read_targets_from_file(input_path)
            if not targets:
                self.logger.warning("No valid targets found in input file")
                return set()

            # Process each target
            all_subdomains = set()
            for target in targets:
                if not target.strip():
                    continue

                self.logger.info(f"Analyzing: {target}", Fore.BLUE)
                result = self.analyzer.analyze_target(target, match_domain)

                if not result.success:
                    continue

                if result.subdomains:
                    for subdomain in sorted(result.subdomains):
                        self.logger.success(subdomain)
                    all_subdomains.update(result.subdomains)
                else:
                    self.logger.warning("No subdomains found")

            # Save results to file if specified
            if output_file and all_subdomains:
                self._save_results_to_file(all_subdomains, output_file)

            return all_subdomains

        except FileNotFoundError as e:
            self.logger.error(str(e))
            return set()
        except Exception as e:
            self.logger.error(f"Error processing file: {e}")
            return set()

    def _read_targets_from_file(self, file_path: Path) -> List[str]:
        """Read and validate targets from input file"""
        try:
            with file_path.open("r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]
            return targets
        except Exception as e:
            raise Exception(f"Failed to read file {file_path}: {e}")

    def _save_results_to_file(self, subdomains: Set[str], output_file: str):
        """Save results to output file"""
        try:
            output_path = Path(output_file)
            with output_path.open("w", encoding="utf-8") as f:
                f.write("\n".join(sorted(subdomains)))
            self.logger.info(f"Results saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to save results to {output_file}: {e}")


class CSPSubdomainExtractor:
    """Main application class"""

    def __init__(self, verbose: bool = False):
        self.logger = Logger(verbose)
        self.analyzer = CSPAnalyzer(self.logger)
        self.file_processor = FileProcessor(self.logger, self.analyzer)

    def run_single_target(
        self,
        url: str,
        match_domain: Optional[str] = None,
        output_file: Optional[str] = None,
    ):
        """Process a single target URL"""
        result = self.analyzer.analyze_target(url, match_domain)

        if not result.success:
            return

        if result.subdomains:
            for subdomain in sorted(result.subdomains):
                self.logger.success(subdomain)

            # Save to file if specified
            if output_file:
                self._save_single_result(result.subdomains, output_file)
        else:
            self.logger.warning("No subdomains found in CSP headers")

    def run_file_processing(
        self,
        input_file: str,
        match_domain: Optional[str] = None,
        output_file: Optional[str] = None,
    ):
        """Process multiple targets from file"""
        self.file_processor.process_file(input_file, match_domain, output_file)

    def _save_single_result(self, subdomains: Set[str], output_file: str):
        """Save single target results to file"""
        try:
            output_path = Path(output_file)
            with output_path.open("a", encoding="utf-8") as f:
                clean_subdomains = [sub for sub in sorted(subdomains)]
                f.write("\n".join(clean_subdomains) + "\n")
            self.logger.info(f"Results appended to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser"""
    parser = argparse.ArgumentParser(
        description="CSP Subdomain Extractor - Fetch subdomains from CSP headers",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-u", "--url", help="Single Domain to analyze (e.g., example.com)"
    )
    parser.add_argument(
        "-f", "--file", help="File containing list of targets (URLs/IPs, one per line)"
    )
    parser.add_argument(
        "-m",
        "--match",
        help="Domain to match subdomains against (e.g., domain-to-match-subdomains-from.com)",
    )
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show verbose output including CSP headers",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"CSP Subdomain Extractor {Config.VERSION}",
    )

    return parser


def main():
    """Main entry point"""
    print_banner()

    parser = create_argument_parser()
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        return

    # Initialize the application
    app = CSPSubdomainExtractor(verbose=args.verbose)

    try:
        if args.file:
            app.run_file_processing(args.file, args.match, args.output)
        else:
            app.run_single_target(args.url, args.match, args.output)
    except KeyboardInterrupt:
        app.logger.warning("Operation interrupted by user")
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
