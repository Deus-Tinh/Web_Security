"""
Smoke test nhanh — chay khi Flask app dang bat (python app.py).
"""

import sys
import urllib.error
import urllib.request
from urllib.parse import urlencode

BASE = "http://127.0.0.1:5000"


def get(path: str, params: dict | None = None) -> tuple[int, str]:
    url = BASE + path
    if params:
        url += "?" + urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        print(f"[FAIL] Khong ket noi {url}: {e}")
        print("       Hay chay: python app.py")
        sys.exit(1)


def main():
    tests = [
        ("/", 200, None),
        ("/search?q=test", 200, "test"),
        ("/category?name=Phones", 200, "Phones"),
        ("safe_category", 200, None),
    ]

    print("[*] Smoke test lab_appsec\n")
    passed = 0

    for path, expect_status, must_contain in tests:
        if path == "safe_category":
            status, body = get("/safe/category", {"name": "' OR '1'='1"})
        else:
            status, body = get(path)
        ok = status == expect_status
        if must_contain and must_contain not in body:
            ok = False
        label = "PASS" if ok else "FAIL"
        print(f"  [{label}] GET {path} -> {status}")
        if ok:
            passed += 1

    # Safe category khong dump toan bo DB (so luong san pham hop ly)
    _, safe_body = get("/safe/category", {"name": "' OR '1'='1"})
    product_cards = safe_body.count("card-title")
    if product_cards > 5:
        print(f"  [FAIL] /safe/category co the bi SQLi (tim thay {product_cards} san pham)")
    else:
        print(f"  [PASS] /safe/category khong dump toan bo data ({product_cards} item)")
        passed += 1

    print(f"\n[*] Ket qua: {passed}/{len(tests)+1} kiem tra thanh cong")

    print("\n[*] Goi y quet scanner:")
    print("    python web_scanner.py --url http://localhost:5000 --report scan_report.txt --json scan_report.json")

    if passed < len(tests) + 1:
        sys.exit(1)


if __name__ == "__main__":
    main()
