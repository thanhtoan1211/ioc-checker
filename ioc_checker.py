#!/usr/bin/env python3
"""
IOC Checker - Indicator of Compromise Analysis Tool
====================================================
Check IPs, domains, and file hashes against VirusTotal and AbuseIPDB.

Author : Bui Thanh Toan
Email  : btoan123123@gmail.com
Web    : https://buithanhtoan.vercel.app
GitHub : https://github.com/thanhtoan1211
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests
from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

console = Console()

# ── API base URLs ─────────────────────────────────────────────────────────────
VT_BASE    = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"

# ── Regex patterns ────────────────────────────────────────────────────────────
RE_IPV4   = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}$")

# VirusTotal free tier: 4 requests/min → 15s between calls
VT_SLEEP = 15
RE_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")

VERDICT_COLORS = {"CLEAN": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "red", "ERROR": "dim", "UNKNOWN": "cyan"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def classify(ioc: str) -> Optional[str]:
    v = ioc.strip()
    if RE_IPV4.match(v):   return "ip"
    if RE_MD5.match(v) or RE_SHA1.match(v) or RE_SHA256.match(v): return "hash"
    if RE_DOMAIN.match(v): return "domain"
    return None


def to_verdict(malicious: int, suspicious: int) -> str:
    if malicious >= 3:  return "MALICIOUS"
    if malicious >= 1 or suspicious >= 1: return "SUSPICIOUS"
    return "CLEAN"


# ── VirusTotal client ─────────────────────────────────────────────────────────

class VTClient:
    def __init__(self, key: str):
        self.session = requests.Session()
        self.session.headers["x-apikey"] = key

    def get(self, path: str) -> Dict:
        for attempt in range(3):
            r = self.session.get(f"{VT_BASE}/{path}", timeout=15)
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 60))
                console.print(f"[yellow]VT rate limit — waiting {wait}s...[/yellow]")
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError("VirusTotal rate limit exceeded after 3 retries")

    def check_ip(self, ip):     return self.get(f"ip_addresses/{ip}")
    def check_domain(self, d):  return self.get(f"domains/{d}")
    def check_hash(self, h):    return self.get(f"files/{h}")


# ── AbuseIPDB client ──────────────────────────────────────────────────────────

class AbuseClient:
    def __init__(self, key: str):
        self.session = requests.Session()
        self.session.headers.update({"Key": key, "Accept": "application/json"})

    def check_ip(self, ip: str) -> Dict:
        r = self.session.get(f"{ABUSE_BASE}/check",
                             params={"ipAddress": ip, "maxAgeInDays": 90},
                             timeout=15)
        r.raise_for_status()
        return r.json()


# ── Result parsers ────────────────────────────────────────────────────────────

def parse_vt(data: Dict, ioc_type: str) -> Dict:
    attrs = data.get("data", {}).get("attributes", {})
    s     = attrs.get("last_analysis_stats", {})
    mal, sus = s.get("malicious", 0), s.get("suspicious", 0)
    total = sum(s.values())
    result = {
        "source": "VirusTotal", "verdict": to_verdict(mal, sus),
        "malicious": mal, "suspicious": sus,
        "harmless": s.get("harmless", 0), "total": total, "details": {}
    }
    if ioc_type == "ip":
        result["details"] = {
            "Country": attrs.get("country", "N/A"),
            "ASN": attrs.get("asn", "N/A"),
            "AS Owner": attrs.get("as_owner", "N/A"),
            "Reputation": attrs.get("reputation", "N/A"),
        }
    elif ioc_type == "domain":
        result["details"] = {
            "Registrar": attrs.get("registrar", "N/A"),
            "Reputation": attrs.get("reputation", "N/A"),
            "Categories": ", ".join(attrs.get("categories", {}).values()) or "N/A",
        }
    elif ioc_type == "hash":
        result["details"] = {
            "Name": attrs.get("meaningful_name", "N/A"),
            "Type": attrs.get("type_description", "N/A"),
            "Size (bytes)": attrs.get("size", "N/A"),
        }
    return result


def parse_abuse(data: Dict) -> Dict:
    d     = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    verdict = "MALICIOUS" if score >= 80 else "SUSPICIOUS" if score >= 25 else "CLEAN"
    return {
        "source": "AbuseIPDB", "verdict": verdict,
        "details": {
            "Abuse Score": f"{score}%",
            "Total Reports": d.get("totalReports", 0),
            "Country": d.get("countryCode", "N/A"),
            "ISP": d.get("isp", "N/A"),
            "Usage Type": d.get("usageType", "N/A"),
            "Last Reported": d.get("lastReportedAt", "N/A"),
            "Whitelisted": "Yes" if d.get("isWhitelisted") else "No",
        }
    }


def err_result(source: str, exc: Exception) -> Dict:
    return {"source": source, "verdict": "ERROR", "error": str(exc), "details": {}}


# ── Core checker ──────────────────────────────────────────────────────────────

class IOCChecker:
    def __init__(self, vt_key: Optional[str], abuse_key: Optional[str]):
        self.vt    = VTClient(vt_key)       if vt_key    else None
        self.abuse = AbuseClient(abuse_key) if abuse_key else None

    def check(self, ioc: str) -> Dict:
        ioc      = ioc.strip()
        ioc_type = classify(ioc)
        record   = {"ioc": ioc, "type": ioc_type or "unknown",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "sources": [], "overall": "UNKNOWN"}
        if not ioc_type:
            record["error"] = f"Cannot classify: {ioc!r}"
            return record

        if ioc_type == "ip":
            if self.vt:
                try:    record["sources"].append(parse_vt(self.vt.check_ip(ioc), "ip"))
                except Exception as e: record["sources"].append(err_result("VirusTotal", e))
                time.sleep(VT_SLEEP)
            if self.abuse:
                try:    record["sources"].append(parse_abuse(self.abuse.check_ip(ioc)))
                except Exception as e: record["sources"].append(err_result("AbuseIPDB", e))
                time.sleep(0.5)

        elif ioc_type == "domain":
            if self.vt:
                try:    record["sources"].append(parse_vt(self.vt.check_domain(ioc), "domain"))
                except Exception as e: record["sources"].append(err_result("VirusTotal", e))
                time.sleep(VT_SLEEP)

        elif ioc_type == "hash":
            if self.vt:
                try:    record["sources"].append(parse_vt(self.vt.check_hash(ioc), "hash"))
                except Exception as e: record["sources"].append(err_result("VirusTotal", e))
                time.sleep(VT_SLEEP)

        verdicts = [s.get("verdict") for s in record["sources"]]
        record["overall"] = (
            "MALICIOUS"  if "MALICIOUS"  in verdicts else
            "SUSPICIOUS" if "SUSPICIOUS" in verdicts else
            "CLEAN"      if "CLEAN"      in verdicts else "UNKNOWN"
        )
        return record


# ── Rendering ─────────────────────────────────────────────────────────────────

def print_banner():
    console.print(Panel(
        "[bold cyan]IOC Checker[/bold cyan]  [dim]|[/dim]  "
        "[dim]Threat Intelligence Analysis Tool[/dim]\n"
        "[dim]VirusTotal + AbuseIPDB  |  Author: Bui Thanh Toan[/dim]",
        border_style="bright_blue", expand=False
    ))


def render_record(rec: Dict):
    overall = rec.get("overall", "UNKNOWN")
    color   = VERDICT_COLORS.get(overall, "white")

    hdr = Text()
    hdr.append("  IOC    : ", style="bold white"); hdr.append(f"{rec['ioc']}\n", style="bold yellow")
    hdr.append("  Type   : ", style="bold white"); hdr.append(f"{rec['type'].upper()}\n", style="cyan")
    hdr.append("  Verdict: ", style="bold white"); hdr.append(overall, style=f"bold {color}")
    console.print(Panel(hdr, title="[bold]IOC Report[/bold]", border_style=color, expand=False))

    if rec.get("error") and not rec.get("sources"):
        console.print(f"  [red]Error:[/red] {rec['error']}\n")
        return

    for src in rec.get("sources", []):
        t = Table(title=f"[bold]{src['source']}[/bold]", box=box.ROUNDED,
                  border_style=VERDICT_COLORS.get(src.get("verdict","UNKNOWN"), "white"),
                  show_header=True, header_style="bold magenta", min_width=50)
        t.add_column("Field", style="bold white", no_wrap=True)
        t.add_column("Value")
        v = src.get("verdict","UNKNOWN")
        t.add_row("Verdict", Text(v, style=f"bold {VERDICT_COLORS.get(v,'white')}"))
        if v == "ERROR":
            t.add_row("Error", src.get("error",""))
        else:
            for field in ("malicious","suspicious","harmless","total"):
                if field in src:
                    t.add_row(field.title(), str(src[field]))
            for k, val in src.get("details", {}).items():
                t.add_row(k, str(val))
        console.print(t)
    console.print()


def render_summary(records: List[Dict]):
    t = Table(title="[bold]IOC Summary[/bold]", box=box.DOUBLE_EDGE,
              border_style="bright_blue", show_header=True, header_style="bold magenta")
    t.add_column("#", style="dim", width=4)
    t.add_column("IOC", style="cyan", min_width=30)
    t.add_column("Type", width=8)
    t.add_column("Verdict", width=12)
    t.add_column("Sources", style="dim")
    for i, rec in enumerate(records, 1):
        v     = rec.get("overall","UNKNOWN")
        color = VERDICT_COLORS.get(v,"white")
        srcs  = ", ".join(s.get("source","?") for s in rec.get("sources",[]))
        t.add_row(str(i), rec["ioc"], rec["type"].upper(),
                  Text(v, style=f"bold {color}"), srcs or "N/A")
    console.print(t)


# ── Exports ───────────────────────────────────────────────────────────────────

def export_json(records, path):
    with open(path, "w") as f: json.dump(records, f, indent=2, default=str)
    console.print(f"\n[green]JSON saved:[/green] {path}")

def export_csv(records, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ioc","type","overall","timestamp","sources"])
        w.writeheader()
        for r in records:
            w.writerow({"ioc": r["ioc"], "type": r["type"], "overall": r.get("overall"),
                        "timestamp": r.get("timestamp"),
                        "sources": "; ".join(f"{s.get('source')}:{s.get('verdict')}" for s in r.get("sources",[]))})
    console.print(f"[green]CSV saved:[/green] {path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="ioc_checker",
        description="IOC Checker — VirusTotal + AbuseIPDB threat intel lookup",
        epilog=(
            "Examples:\n"
            "  python ioc_checker.py -i 8.8.8.8\n"
            "  python ioc_checker.py -d malicious.example.com\n"
            "  python ioc_checker.py -H 44d88612fea8a8f36de82e1278abb02f\n"
            "  python ioc_checker.py -f sample_iocs.txt --export-json out.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mx = p.add_mutually_exclusive_group(required=True)
    mx.add_argument("-i","--ip",     metavar="IP",     help="Single IP address")
    mx.add_argument("-d","--domain", metavar="DOMAIN", help="Domain name")
    mx.add_argument("-H","--hash",   metavar="HASH",   help="File hash (MD5/SHA1/SHA256)")
    mx.add_argument("-f","--file",   metavar="FILE",   help="Text file of IOCs, one per line")
    p.add_argument("--export-json", metavar="PATH")
    p.add_argument("--export-csv",  metavar="PATH")
    p.add_argument("--quiet",  action="store_true", help="Summary table only")
    p.add_argument("--no-banner", action="store_true")
    args = p.parse_args()

    if not args.no_banner: print_banner()

    vt_key    = os.getenv("VIRUSTOTAL_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    if not vt_key and not abuse_key:
        console.print("[red]No API keys found.[/red] Copy .env.example → .env and add your keys.")
        sys.exit(1)
    if not vt_key:    console.print("[yellow]VIRUSTOTAL_API_KEY not set — VT checks skipped.[/yellow]")
    if not abuse_key: console.print("[yellow]ABUSEIPDB_API_KEY not set — AbuseIPDB checks skipped.[/yellow]")
    if vt_key:        console.print(f"[dim]VT free tier: {VT_SLEEP}s delay between lookups (4 req/min limit)[/dim]")

    checker = IOCChecker(vt_key, abuse_key)

    iocs = []
    if args.ip:     iocs = [args.ip]
    elif args.domain: iocs = [args.domain]
    elif args.hash: iocs = [args.hash]
    elif args.file:
        fp = Path(args.file)
        if not fp.is_file():
            console.print(f"[red]File not found:[/red] {args.file}"); sys.exit(1)
        iocs = [l.strip() for l in fp.read_text().splitlines()
                if l.strip() and not l.strip().startswith("#")]
        console.print(f"[cyan]Loaded {len(iocs)} IOC(s) from[/cyan] {args.file}\n")

    results = []
    for ioc in iocs:
        console.print(f"[dim]Checking:[/dim] [bold cyan]{ioc}[/bold cyan]")
        rec = checker.check(ioc)
        results.append(rec)
        if not args.quiet: render_record(rec)

    if len(results) > 1 or args.quiet:
        render_summary(results)

    if args.export_json: export_json(results, args.export_json)
    if args.export_csv:  export_csv(results, args.export_csv)


if __name__ == "__main__":
    main()
