#!/bin/bash

# CSP Subdomain Extractor - Usage Examples
echo "🔍 CSP Subdomain Extractor - Usage Examples"
echo "==========================================="

echo
echo "1. 📍 Single domain analysis:"
echo "python3 csp_sub.py -u github.com"
echo

echo "2. 📊 Verbose output with CSP headers:"
echo "python3 csp_sub.py -u stackoverflow.com -v"
echo

echo "3. 📁 Batch processing from file:"
echo "python3 csp_sub.py -f example_domains.txt"
echo

echo "4. 💾 Save results to file:"
echo "python3 csp_sub.py -f example_domains.txt -o results.txt"
echo

echo "5. 🎯 Match against specific domain:"
echo "python3 csp_sub.py -f example_domains.txt -m github.com"
echo

echo "6. 🔍 Comprehensive analysis with verbose output and save:"
echo "python3 csp_sub.py -f example_domains.txt -v -o detailed_results.txt"
echo

echo "7. 🌐 Analyze IP addresses with domain matching:"
echo "echo '192.168.1.1' | python3 csp_sub.py -f /dev/stdin -m example.com"
echo

echo "📖 For more information, run: python3 csp_sub.py --help"
