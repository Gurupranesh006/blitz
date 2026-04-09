# ⚡ blitz ⚡

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)](https://github.com/)

**blitz** is a high-performance, multi-threaded reconnaissance engine designed for speed and reliability. Built to replace traditional, slow bash scripts, it orchestrates a powerful toolchain to deliver comprehensive recon results in seconds.

---

## 🚀 Interactive Quick Start

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/blitz.git
cd blitz

# Run a full recon scan with a visual dependency check
python3 blitz.py example.com -s

# Skip the dependency check for maximum speed
python3 blitz.py example.com -k
```

---

## 🛠️ Features & Toolchain

**blitz** uses a highly concurrent architecture to run independent tasks in parallel:

| Phase | Tool(s) Used | Speed Advantage |
| :--- | :--- | :--- |
| **Subdomains** | `Assetfinder`, `Subfinder` | Parallel discovery + 100 threads |
| **Probing** | `Httprobe`, `Httpx` | High-speed alive verification |
| **Takeovers** | `Subjack` | 200 parallel fingerprint checks |
| **Scanning** | `Nmap` | Aggressive `-T5` & `--min-rate 1000` |
| **Wayback** | `Waybackurls` | Concurrent URL scraping & filtering |
| **Screenshots** | `Gowitness`, `Eyewitness` | Multi-threaded browser rendering |

---

## 📖 Usage Guide

### 📥 Prerequisites
**blitz** will automatically verify these for you, but for best results, ensure they are in your `$PATH`:
- [x] Assetfinder / Subfinder
- [x] Httprobe / Httpx
- [x] Subjack
- [x] Nmap / Waybackurls
- [x] Gowitness or EyeWitness (optional)

### 🎮 Command Options

```text
Options:
  -h, --help            Show this beautiful help menu
  -k, --skip-check      ⏩ Skip the tool dependency check to save time
  -s, --screenshot      📸 Enable automated screenshotting
  -t TOOL, --tool=TOOL  🛠️  Screenshot tool (gowitness/eyewitness)
  -v, --verbose         🔍 Enable verbose output for debugging
```

---

## 🛡️ Smart Dependency Management
No more guessing if your environment is ready. **blitz** features an intelligent verification system:

- **Visual Status Table:** Prints a clear report of all required and optional tools before launching.
- **Fail-Safe Abort:** Prevents wasted time by alerting you if a critical tool is missing.
- **Silent Optimization:** Even when skipping the check (`-k`), **blitz** silently detects high-speed optional tools like `httpx` to ensure you always get the best performance.

---

## 📂 Output Structure
Every scan creates a structured `recon/` directory:
```bash
domain.com/
└── recon/
    ├── final.txt              # Unified unique subdomains
    ├── httprobe/
    │   ├── alive.txt          # Verified active domains
    │   └── httpx_detailed.txt # Full HTTP response data
    ├── scans/                 # Nmap scan results (all formats)
    ├── wayback/               # URL data & extension-sorted lists
    └── screenshots/           # Visual snapshots of all alive targets
```

---

## 🤝 Contribution & Feedback
We love contributors! If you have a speed optimization or a new tool integration, feel free to open a PR.

---
*Created with ❤️ for the security community.*
