"""
Dependency-free vulnerable lab for local scanner demos.

Run:
    python vulnerable_lab_stdlib.py

Endpoints:
    /search?q=test          intentionally vulnerable reflected XSS
    /safe-search?q=test     fixed escaped output
    /products?id=1          intentionally vulnerable SQL injection
    /safe-products?id=1     fixed parameterized query
"""

from __future__ import annotations

import html
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


DB_PATH = Path(__file__).resolve().parent / "vulnerable_lab_stdlib.db"


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS products;
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price INTEGER NOT NULL
        );
        INSERT INTO products (name, category, price) VALUES
        ('Laptop Pro 14', 'computer', 1200),
        ('Security Camera', 'iot', 180),
        ('Wireless Router', 'network', 95),
        ('Security Training Kit', 'training', 45);
        """
    )
    db.commit()
    db.close()


def layout(content: str) -> bytes:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Vulnerable Security Lab</title>
  <style>
    body {{ margin:0; font-family:Arial,sans-serif; background:#071018; color:#e8f7ff; }}
    main {{ max-width:960px; margin:0 auto; padding:40px 20px; }}
    .card {{ border:1px solid #1f4052; background:#0d1a26; border-radius:8px; padding:20px; margin:16px 0; }}
    a {{ color:#43e8ff; }}
    code {{ background:#020812; border:1px solid #1f4052; border-radius:6px; padding:3px 6px; }}
    input,button {{ padding:10px; border-radius:6px; border:1px solid #2b5268; background:#020812; color:white; }}
    table {{ border-collapse:collapse; width:100%; margin-top:16px; }}
    th,td {{ border-bottom:1px solid #1f4052; padding:10px; text-align:left; }}
    .danger {{ color:#ff6b81; }} .safe {{ color:#9dff57; }}
  </style>
</head>
<body><main>{content}</main></body></html>""".encode()


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        routes = {
            "/": self.home,
            "/search": lambda: self.search(params, safe=False),
            "/safe-search": lambda: self.search(params, safe=True),
            "/products": lambda: self.products(params, safe=False),
            "/safe-products": lambda: self.products(params, safe=True),
        }
        handler = routes.get(parsed.path)
        if handler is None:
            self.respond(layout("<h1>404</h1><p>Not found</p>"), status=404)
            return
        self.respond(handler())

    def home(self) -> bytes:
        return layout(
            """
            <h1>Vulnerable Security Lab</h1>
            <p>Local lab intentionally containing SQL Injection and XSS for SentinelAI scanner testing.</p>
            <div class="card">
              <h2 class="danger">Vulnerable XSS</h2>
              <p><a href="/search?q=test">/search?q=test</a></p>
              <form action="/search" method="get">
                <input name="q" placeholder="Search text">
                <button>Search vulnerable</button>
              </form>
            </div>
            <div class="card">
              <h2 class="danger">Vulnerable SQL Injection</h2>
              <p><a href="/products?id=1">/products?id=1</a></p>
              <form action="/products" method="get">
                <input name="id" placeholder="Product id">
                <button>Find vulnerable</button>
              </form>
            </div>
            <div class="card">
              <h2 class="safe">Fixed Endpoints</h2>
              <p><a href="/safe-search?q=test">/safe-search?q=test</a></p>
              <p><a href="/safe-products?id=1">/safe-products?id=1</a></p>
            </div>
            """
        )

    def search(self, params: dict[str, list[str]], safe: bool) -> bytes:
        value = params.get("q", [""])[0]
        rendered = html.escape(value) if safe else value
        title = "Safe Search" if safe else "Vulnerable Search"
        css = "safe" if safe else "danger"
        return layout(
            f"""
            <h1 class="{css}">{title}</h1>
            <div class="card">Search result for: {rendered}</div>
            <p><a href="/">Back</a></p>
            """
        )

    def products(self, params: dict[str, list[str]], safe: bool) -> bytes:
        product_id = params.get("id", ["1"])[0]
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        if safe:
            query = "SELECT id, name, category, price FROM products WHERE id = ?"
            rows = db.execute(query, (product_id,)).fetchall()
            evidence = "Parameterized query used"
        else:
            query = f"SELECT id, name, category, price FROM products WHERE id = {product_id}"
            try:
                rows = db.execute(query).fetchall()
            except sqlite3.Error as exc:
                db.close()
                return layout(
                    f"""
                    <h1 class="danger">SQLite database error</h1>
                    <p>This intentionally leaks database error details for scanner training.</p>
                    <div class="card"><code>{html.escape(str(exc))}</code></div>
                    <p>Query: <code>{html.escape(query)}</code></p>
                    <p><a href="/">Back</a></p>
                    """
                )
            evidence = query
        db.close()
        body = "".join(
            f"<tr><td>{row['id']}</td><td>{html.escape(row['name'])}</td><td>{html.escape(row['category'])}</td><td>${row['price']}</td></tr>"
            for row in rows
        )
        css = "safe" if safe else "danger"
        return layout(
            f"""
            <h1 class="{css}">{'Safe' if safe else 'Vulnerable'} Products</h1>
            <p><code>{html.escape(evidence)}</code></p>
            <table>
              <thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Price</th></tr></thead>
              <tbody>{body}</tbody>
            </table>
            <p><a href="/">Back</a></p>
            """
        )

    def respond(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", 5000), LabHandler)
    print("Vulnerable lab running at http://localhost:5000")
    server.serve_forever()
