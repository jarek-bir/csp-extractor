# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2025-07-26

### 🚀 Major Refactor - Object-Oriented Architecture

### Added
- **Object-oriented architecture** with clear separation of concerns
- **Type hints** throughout the codebase for better IDE support
- **Dataclass-based result structures** (`CSPAnalysisResult`)
- **Centralized logging system** with color-coded output
- **Enhanced error handling** with specific exception types
- **Configuration class** for better maintainability
- **Verbose mode improvements** with detailed CSP header display
- **Professional project structure** with proper documentation

### Changed
- **Complete code restructure** into logical classes:
  - `CSPHeaderFetcher`: HTTP request handling
  - `DomainExtractor`: CSP policy parsing
  - `CSPAnalyzer`: Main analysis coordination
  - `FileProcessor`: Batch file processing
  - `Logger`: Centralized logging and output
- **Improved error messages** with better user feedback
- **Enhanced documentation** with comprehensive README
- **Better URL handling** and normalization
- **Robust CSP header detection** (case-insensitive)

### Fixed
- **Network timeout handling** with proper error recovery
- **File I/O error handling** with informative messages
- **URL parsing edge cases** and malformed inputs
- **Domain extraction accuracy** with better regex patterns

### Technical Improvements
- **Python 3.7+** compatibility with modern features
- **Logging instead of print statements** for better debugging
- **Modular design** for easier testing and maintenance
- **Professional code organization** following best practices
- **Comprehensive docstrings** with parameter documentation

## [2.3.0] - Previous Version

### Features
- Basic CSP subdomain extraction
- File and single URL processing
- Domain matching capability
- Output file support
- Basic error handling

---

## Legend
- 🚀 Major features
- ✨ New features
- 🔧 Improvements
- 🐛 Bug fixes
- 📚 Documentation
- ⚠️ Breaking changes
