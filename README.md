# ZPentaSuite
All the red teaming wrapper tools are here, starting from JTR, Hydra, Nmap, SQLmap, BurpSuite and Maltego

---

### ZPentaSuite - Advanced Penetration Testing Toolkit 🚀

What is ZPentaSuite?

ZPentaSuite is a comprehensive penetration testing framework written in Go, consisting of 6 advanced security tools for bug bounty hunters, penetration testers, and security researchers. All tools are highly optimized, multi-threaded, and zero dependency (single binary each).

---

### 📦 Components

1. ZBurpSuite - Advanced Web Security Scanner

· Function: BurpSuite-like CLI tool for web vulnerability testing
· Features:
  · IDOR (Insecure Direct Object Reference) scanning
  · SSRF (Server-Side Request Forgery) testing
  · SQL Injection detection (error-based, union-based, time-based)
  · XSS (Cross-Site Scripting) scanner
  · CORS misconfiguration checker
  · JWT vulnerability testing
  · Endpoint discovery
  · Request bridge (capture and replay HTTP requests)
· Generates: captured_requests/, zsqlmap_results/, reports/

2. ZHydra - Smart Brute Force Engine

· Function: Next-gen brute force tool with AI-powered pattern generation
· Features:
  · NO WORDLIST NEEDED! (generates passwords on-the-fly)
  · Smart pattern generation (leet speak, capitalization, numbers)
  · Context-aware attacks (use company names, dates)
  · Multi-protocol support (SSH, FTP, HTTP, MySQL, Telnet)
  · Connection pooling for speed
  · Rate limiting to avoid blocking
· Generates: zhydra_results/, zhydra_advanced.log, session files

3. ZJohnTheRipper - Hybrid Password Cracker

· Function: Modern password cracking with CPU + GPU acceleration
· Features:
  · 15+ hash formats (MD5, SHA1, SHA256, SHA512, bcrypt, NTLM, MySQL, etc.)
  · GPU acceleration (auto-detects NVIDIA/AMD)
  · Multi-threaded CPU cracking
  · Wordlist mode with rules
  · Incremental brute force
  · Real-time statistics and progress bar
  · Multiple report formats (JSON, CSV, Markdown)
· Generates: hashes.txt (input), cracked.txt (output), reports/, session files

4. ZMaltego - OSINT & Reconnaissance Tool

· Function: Maltego-like CLI for open-source intelligence gathering
· Features:
  · Domain reconnaissance (WHOIS, DNS records)
  · Subdomain enumeration
  · Email discovery
  · IP intelligence (Shodan, VirusTotal)
  · Technology fingerprinting
  · Social media discovery
  · Graph visualization
· Requires API Keys: Shodan, VirusTotal, Hunter.io, BuiltWith, Censys
· Generates: results/, entities/, graphs/, cache/

5. ZNmap - Advanced Network Scanner

· Function: Nmap-like network discovery with custom packet scanner
· Features:
  · Native packet scanner (no Nmap required!)
  · ICMP ping sweep
  · TCP connect scanning
  · Service fingerprinting
  · OS detection
  · Vulnerability detection
  · Concurrent scanning
· Generates: scan_results/, nmap_output/, reports/

6. ZSQLmap - SQL Injection Automation

· Function: Automated SQL injection testing tool
· Features:
  · 50+ SQL injection payloads
  · Database fingerprinting
  · Data extraction (dump databases/tables)
  · WAF bypass techniques
  · Time-based blind testing
  · Second-order injection
  · Out-of-band (OOB) testing
  · Tamper scripts
· Generates: captured_requests/, zsqlmap_results/, audit.db, reports/

---

### 🚀 Quick Start Guide

1. Clone & Enter Directory

```bash
git clone https://github.com/yourusername/ZPentaSuite.git
cd ZPentaSuite
```

2. Initialize Go Modules

```bash
# Initialize root module (optional)
go mod init zpentasuite
go mod tidy

# Initialize each tool (if you want to build individually)
cd Zburpsuite && go mod init && go mod tidy && cd ..
cd Zhydra && go mod init && go mod tidy && cd ..
cd Zjohn_the_ripper && go mod init && go mod tidy && cd ..
cd ZMaltego && go mod init && go mod tidy && cd ..
cd Znmap && go mod init && go mod tidy && cd ..
cd Zsqlmap && go mod init && go mod tidy && cd ..
```

3. Build All Tools

```bash
# Build everything from root
go build -o bin/zburbsuite Zburpsuite/*.go
go build -o bin/zhydra Zhydra/*.go
go build -o bin/zjohn Zjohn_the_ripper/*.go
go build -o bin/zmaltego ZMaltego/*.go
go build -o bin/znmap Znmap/*.go
go build -o bin/zsqlmap Zsqlmap/*.go

# Or build individually
cd Zburpsuite && go build -o zburpsuite && cd ..
```

4. Run Tools

```bash
# ZBurpSuite
./Zburpsuite/zburpsuite -u https://target.com --scan all

# ZHydra
./Zhydra/zhydra -u https://target.com --smart-brute

# ZJohnTheRipper
./Zjohn_the_ripper/zjohn --load hashes.txt --wordlist wordlist.txt

# ZMaltego (requires config.json with API keys)
./ZMaltego/zmaltego -d target.com --recon all

# ZNmap
./Znmap/znmap -t 192.168.1.1 --scan quick

# ZSQLmap
./Zsqlmap/zsqlmap -u "http://target.com/page?id=1" --sqlmap
```

---

### 📁 Generated Files & Folders

After running the tools, you'll find:

```
📁 ZPentaSuite/
├── 📄 config.json              # API keys for ZMaltego (optional)
├── 📁 Zburpsuite/
│   ├── 📁 captured_requests/   # HTTP requests/responses
│   ├── 📁 zsqlmap_results/     # SQL scan results
│   ├── 📁 reports/             # JSON/CSV/Markdown reports
│   └── 📄 zsqlmap_audit.db     # SQLite database
├── 📁 Zhydra/
│   ├── 📁 zhydra_results/      # Brute force results
│   ├── 📄 zhydra_advanced.log  # Log file
│   └── 📄 zhydra_session.json  # Session save
├── 📁 Zjohn_the_ripper/
│   ├── 📄 hashes.txt           # Input hashes (you create)
│   ├── 📄 wordlist.txt         # Wordlist (optional)
│   ├── 📄 cracked.txt          # Cracked passwords
│   ├── 📁 reports/             # Cracking reports
│   └── 📄 zjohn_*.json         # Session files
├── 📁 ZMaltego/
│   ├── 📁 results/             # OSINT results
│   ├── 📁 entities/            # Found entities
│   ├── 📁 graphs/              # Graph visualizations
│   └── 📁 cache/               # API cache
├── 📁 Znmap/
│   ├── 📁 scan_results/        # Nmap results
│   ├── 📁 nmap_output/         # Raw output
│   └── 📁 reports/             # Scan reports
└── 📁 Zsqlmap/
    ├── 📁 captured_requests/   # Request files
    ├── 📁 zsqlmap_results/     # SQL injection results
    ├── 📄 zsqlmap_audit.db     # Audit database
    └── 📁 reports/             # SQL reports
```

---

### ⚡ Performance Features

Tool Multi-threaded GPU Real-time Auto-generated
ZBurpSuite ✅ ❌ ✅ ✅
ZHydra ✅ ❌ ✅ ✅ (no wordlist!)
ZJohn ✅ ✅ ✅ ❌ (needs hash file)
ZMaltego ✅ ❌ ✅ ✅ (with API)
ZNmap ✅ ❌ ✅ ✅
ZSQLmap ✅ ❌ ✅ ✅

---

### 🎯 Why ZPentaSuite?

1. All-in-One: 6 advanced tools in 1 suite
2. Zero Dependencies: Single binary each, no installation needed
3. High Performance: Multi-threaded, concurrent, optimized
4. No Placeholders: 100% real implementations
5. Termux Compatible: Works on Android without root
6. Modern Architecture: Go language, efficient memory usage
7. Professional Reports: JSON, CSV, Markdown formats
8. Active Development: Constantly updated

---

📝 Notes

· ZMaltego requires API keys in config.json
· ZJohnTheRipper needs hash file input
· Other tools generate everything automatically
· All tools work on Linux, macOS and Termux
