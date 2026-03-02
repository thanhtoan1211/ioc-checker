# IOC Checker

> **Threat Intelligence Lookup CLI** — Check IPs, domains, and file hashes against VirusTotal and AbuseIPDB in seconds.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20v3-394EFF?logo=virustotal)](https://virustotal.com)
[![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-API%20v2-DC143C)](https://abuseipdb.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Features

| Feature | Description |
|---------|-------------|
| **Auto-classify** | Detects IPv4, MD5/SHA1/SHA256 hashes, and domain names automatically |
| **Dual-source** | Cross-references VirusTotal + AbuseIPDB for higher confidence verdicts |
| **Rich output** | Color-coded terminal tables with CLEAN / SUSPICIOUS / MALICIOUS verdicts |
| **Bulk mode** | Process an entire file of IOCs with `--file` flag |
| **Export** | Save results as JSON or CSV for further analysis |
| **Rate-safe** | Built-in 250ms delay between API calls to respect free-tier limits |

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/thanhtoan1211/ioc-checker.git
cd ioc-checker

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API keys
cp .env.example .env
# Edit .env with your VirusTotal and AbuseIPDB keys

# 4. Run a check
python ioc_checker.py -i 8.8.8.8
```

---

## Usage

```
usage: ioc_checker [-h] (-i IP | -d DOMAIN | -H HASH | -f FILE)
                   [--export-json PATH] [--export-csv PATH]
                   [--quiet] [--no-banner]
```

### Examples

```bash
# Check a single IP
python ioc_checker.py -i 185.220.101.45

# Check a domain
python ioc_checker.py -d malware-c2.example.com

# Check a file hash (MD5 / SHA1 / SHA256)
python ioc_checker.py -H 44d88612fea8a8f36de82e1278abb02f

# Bulk check from a file + export results
python ioc_checker.py -f sample_iocs.txt --export-json results.json --export-csv results.csv

# Quiet mode (summary table only, no per-IOC details)
python ioc_checker.py -f sample_iocs.txt --quiet
```

---

## Sample Output

```
╭─────────────────────────────────────────╮
│  IOC Checker  |  Threat Intelligence    │
│  VirusTotal + AbuseIPDB  |  Bui Thanh Toan │
╰─────────────────────────────────────────╯

Checking: 185.220.101.45

╭── IOC Report ──────────────────────────╮
│  IOC    : 185.220.101.45               │
│  Type   : IP                           │
│  Verdict: MALICIOUS                    │
╰────────────────────────────────────────╯

╭── VirusTotal ──────────────────────────╮
│ Field       │ Value                    │
│─────────────│──────────────────────────│
│ Verdict     │ MALICIOUS                │
│ Malicious   │ 12                       │
│ Suspicious  │ 2                        │
│ Harmless    │ 56                       │
│ Total       │ 90                       │
│ Country     │ DE                       │
│ ASN         │ 396507                   │
│ AS Owner    │ Emerald Onion            │
╰────────────────────────────────────────╯

╭── AbuseIPDB ───────────────────────────╮
│ Field          │ Value                 │
│────────────────│───────────────────────│
│ Verdict        │ MALICIOUS             │
│ Abuse Score    │ 100%                  │
│ Total Reports  │ 2847                  │
│ Country        │ DE                    │
│ ISP            │ Emerald Onion         │
│ Usage Type     │ Tor Exit Node         │
╰────────────────────────────────────────╯
```

---

## Verdict Logic

| Source | MALICIOUS | SUSPICIOUS | CLEAN |
|--------|-----------|------------|-------|
| **VirusTotal** | ≥ 3 malicious engines | ≥ 1 malicious/suspicious | 0 detections |
| **AbuseIPDB** | Confidence ≥ 80% | Confidence ≥ 25% | Confidence < 25% |
| **Overall** | Either source = MALICIOUS | Either source = SUSPICIOUS | Both = CLEAN |

---

## API Keys

Get free API keys:
- **VirusTotal** — [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) (4 lookups/min, 500/day)
- **AbuseIPDB** — [abuseipdb.com/register](https://www.abuseipdb.com/register) (1,000 lookups/day)

Set them in `.env`:

```env
VIRUSTOTAL_API_KEY=your_vt_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

Both keys are optional — the tool runs with whichever is available.

---

## Supported IOC Types

| Type | Examples |
|------|---------|
| **IPv4** | `8.8.8.8`, `185.220.101.45` |
| **MD5** | `44d88612fea8a8f36de82e1278abb02f` |
| **SHA1** | `3395856ce81f2b7382dee72602f798b642f14d0` |
| **SHA256** | `24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c` |
| **Domain** | `malware-c2.example.com` |

---

## Project Structure

```
ioc-checker/
├── ioc_checker.py     # Main CLI tool
├── requirements.txt   # Python dependencies
├── .env.example       # API key template
├── sample_iocs.txt    # Sample IOCs for testing
└── README.md
```

---

## Author

**Bui Thanh Toan** — Security Engineer
[buithanhtoan.vercel.app](https://buithanhtoan.vercel.app) · [github.com/thanhtoan1211](https://github.com/thanhtoan1211) · btoan123123@gmail.com
