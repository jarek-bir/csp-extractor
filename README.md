# CSP Subdomain Extractor 🔍

A Python tool to extract subdomains from Content Security Policy (CSP) headers of websites. This refactored version provides improved code structure, better error handling, and enhanced maintainability.

![CSP Subdomain Extractor](https://github.com/user-attachments/assets/dffa58bd-a6da-4a5f-95c1-d47d619f5f7e)

## Features ✨

- 🌐 Extract subdomains from CSP headers
- 📁 Supports single URL or batch file processing
- 🎯 Custom domain matching capability
- 📊 Verbose output with detailed CSP header information
- 💾 Save results to output files
- 🔧 Robust error handling and logging
- 📦 Object-oriented architecture for better maintainability
- 🐍 Type hints and modern Python practices

## Installation 📦

### Requirements
- Python 3.7+
- pip

### Setup

1. Clone the repository:
```bash
git clone https://github.com/legionhunter/csp-subdomain-extractor.git
cd csp-subdomain-extractor
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage 🚀

### Basic Commands

**Single URL analysis:**
```bash
python3 csp_sub.py -u example.com
```

**Batch processing from file:**
```bash
python3 csp_sub.py -f domains.txt
```

**Verbose output with CSP headers:**
```bash
python3 csp_sub.py -u example.com -v
```

**Save results to file:**
```bash
python3 csp_sub.py -f domains.txt -o results.txt
```

**Match against specific domain:**
```bash
python3 csp_sub.py -f ips.txt -m target-domain.com
```

### Command Line Options

```
-u, --url        Single domain/URL to analyze
-f, --file       File containing list of targets (one per line)
-m, --match      Domain to match subdomains against
-o, --output     Output file to save results
-v, --verbose    Show verbose output including CSP headers
--version        Show version information
```

### Input File Format

Create a text file with one target per line:
```
example.com
subdomain.example.com
https://another-domain.com
192.168.1.1
```

## Architecture 🏗️

The refactored code follows object-oriented principles with clear separation of concerns:

- **`Config`**: Configuration constants and settings
- **`Logger`**: Centralized logging and output handling
- **`URLHelper`**: URL normalization and domain extraction utilities
- **`CSPHeaderFetcher`**: HTTP request handling and CSP header retrieval
- **`DomainExtractor`**: CSP policy parsing and domain extraction
- **`CSPAnalyzer`**: Main analysis logic coordination
- **`FileProcessor`**: Batch file processing capabilities
- **`CSPSubdomainExtractor`**: Main application controller

## Code Quality Improvements 📈

This refactored version includes:

- ✅ Type hints for better IDE support and code clarity
- ✅ Dataclasses for structured data handling
- ✅ Comprehensive error handling with specific exception types
- ✅ Logging system instead of scattered print statements
- ✅ Modular design for easier testing and maintenance
- ✅ Improved documentation and docstrings
- ✅ Constants extracted to configuration class
- ✅ Better separation of concerns

## Error Handling 🛡️

The tool now provides comprehensive error handling for:

- Network connectivity issues
- Invalid URLs or domains
- File I/O errors
- Malformed CSP headers
- Timeout scenarios

## Contributing 🤝

Contributions are welcome! Please ensure your code follows the established patterns:

1. Use type hints
2. Add appropriate docstrings
3. Handle exceptions properly
4. Follow the existing class structure
5. Update tests if applicable

## Tool Demo 📖

For a detailed walkthrough, check out: [CSP Subdomain Extraction Tutorial](https://medium.com/legionhunters/cspsub-extract-subdomains-from-csp-headers-4d0772f43603)

## Future Enhancements 🚧

- [ ] **User-Agent Randomization** — Rotate User-Agent headers to avoid detection
- [ ] **Multi-threading Support** — Concurrent processing for better performance
- [ ] **Automatic Retries** — Configurable retry logic for failed requests
- [ ] **Request Throttling** — Rate limiting to prevent server overload
- [ ] **JSON/CSV Output** — Additional output formats
- [ ] **Unit Tests** — Comprehensive test coverage
- [ ] **Docker Support** — Containerized deployment option

## ⚠️ Disclaimer

This tool is intended for **educational, research, and authorized security testing purposes only**.

**Do not use it on systems or domains you do not own or have explicit permission to test.**

The author is **not responsible for any misuse or damage** caused by this tool.

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author 👨‍💻

- **Original Author**: [@abhirupkonwar04](https://medium.com/@abhirupkonwar04)
- **Refactored Version**: Enhanced for better maintainability and code quality
