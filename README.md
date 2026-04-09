# ⚡ blitz ⚡ ⚡

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)](https://github.com/)

An advanced, high-performance reconnaissance tool rewritten from Bash to Python. This tool leverages **concurrency** to perform subdomain discovery, alive probing, port scanning, and screenshotting at blazing speeds.

---

## 🚀 Interactive Quick Start

> **Wait!** Before you run, ensure you have the required tools installed.

```bash
# Clone the repository (if you haven't already)
git clone <your-repo-url>
cd blitz

# Run your first recon scan
python3 blitz.py example.com -s
```

---

## 🛠️ Features & Toolchain

This tool orchestrates the best-in-class security tools for a comprehensive recon pipeline:

| Phase | Tool(s) Used | Why it's faster? |
| :--- | :--- | :--- |
| **Subdomains** | `Assetfinder`, `Subfinder` | Parallel execution + 100 threads |
| **Probing** | `Httprobe`, `Httpx` | Native HTTP concurrency |
| **Takeovers** | `Subjack` | 200 parallel fingerprints checks |
| **Scanning** | `Nmap` | Aggressive `-T5` & `--min-rate` |
| **Wayback** | `Waybackurls` | Multi-threaded extension sorting |
| **Visuals** | `Gowitness`, `Eyewitness` | Concurrent browser rendering |

---

## 📖 Detailed Instructions

### 📥 Prerequisites
Ensure the following tools are in your `$PATH`:
- [x] Assetfinder / Subfinder
- [x] Httprobe / Httpx
- [x] Subjack
- [x] Nmap
- [x] Waybackurls
- [x] Gowitness or EyeWitness (optional for screenshots)

### 🎮 Command Options

```text
Options:
  -h, --help            Show this beautiful menu
  -s, --screenshot      📸 Enable automated screenshotting
  -t TOOL, --tool=TOOL  🛠️  Screenshot tool (gowitness/eyewitness)
  -v, --verbose         🔍 Debug mode for deep inspection
```

### 📂 Directory Structure Created
```bash
example.com/
└── recon/
    ├── final.txt              # All unique subdomains
    ├── httprobe/
    │   └── alive.txt          # Active web targets
    ├── scans/                 # Nmap output (XML/Grep/Normal)
    ├── wayback/               # URL data & filtered extensions
    └── screenshots/           # Visual proof of findings
```

---

## 🛡️ Exception Handling & Speed
- **Fail-Safe:** Pre-checks all dependencies and alerts you if a tool is missing.
- **Robust:** Gracefully handles keyboard interrupts (`Ctrl+C`) and network timeouts.
- **Aggressive:** Optimized for high-bandwidth environments to get results in seconds, not minutes.

---

## 🤝 Contribution
Found a bug or have a feature request? Open an issue or submit a pull request!

---
*Created with ❤️ for the security community.*
