"""
Vulnerable Web Security Lab

Run:
    python vulnerable_lab_app.py

Open:
    http://localhost:5000

Purpose:
    Local educational lab for testing your SentinelAI scanner.
    This app intentionally contains SQL Injection and XSS examples.
    Do not deploy this file to the internet.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, g, render_template_string, request
from markupsafe import escape


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vulnerable_lab.db"

app = Flask(__name__)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_: object) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


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
        ('USB Rubber Duck Demo', 'training', 45);
        """
    )
    db.commit()
    db.close()


PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vulnerable Security Lab</title>
  <style>
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #071018;
      color: #e8f7ff;
    }
    main {
      max-width: 960px;
      margin: 0 auto;
      padding: 40px 20px;
    }
    .card {
      border: 1px solid #1f4052;
      background: #0d1a26;
      border-radius: 8px;
      padding: 20px;
      margin: 16px 0;
    }
    a { color: #43e8ff; }
    code {
      background: #020812;
      border: 1px solid #1f4052;
      border-radius: 6px;
      padding: 3px 6px;
    }
    input, button {
      padding: 10px;
      border-radius: 6px;
      border: 1px solid #2b5268;
      background: #020812;
      color: white;
    }
    button { cursor: pointer; }
    table {
      border-collapse: collapse;
      width: 100%;
      margin-top: 16px;
    }
    th, td {
      border-bottom: 1px solid #1f4052;
      padding: 10px;
      text-align: left;
    }
    .danger { color: #ff6b81; }
    .safe { color: #9dff57; }
  </style>
</head>
<body>
<main>
  {{ content|safe }}
</main>
</body>
</html>
"""


def page(content: str) -> str:
    return render_template_string(PAGE, content=content)


@app.get("/")
def home() -> str:
    return page(
        """
        <h1>Vulnerable Security Lab</h1>
        <p>This local lab intentionally contains SQL Injection and XSS for scanner testing.</p>

        <div class="card">
          <h2 class="danger">Vulnerable XSS</h2>
          <p>Try:</p>
          <p><a href="/search?q=test">/search?q=test</a></p>
          <p><code>/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
          <form action="/search" method="get">
            <input name="q" placeholder="Search text">
            <button>Search vulnerable</button>
          </form>
        </div>

        <div class="card">
          <h2 class="danger">Vulnerable SQL Injection</h2>
          <p>Try:</p>
          <p><a href="/products?id=1">/products?id=1</a></p>
          <p><code>/products?id=1 OR 1=1</code></p>
          <form action="/products" method="get">
            <input name="id" placeholder="Product id">
            <button>Find vulnerable</button>
          </form>
        </div>

        <div class="card">
          <h2 class="safe">Fixed Versions</h2>
          <p><a href="/safe-search?q=test">/safe-search?q=test</a></p>
          <p><a href="/safe-products?id=1">/safe-products?id=1</a></p>
        </div>
        """
    )


@app.get("/search")
def vulnerable_search() -> str:
    q = request.args.get("q", "")
    return page(
        f"""
        <h1 class="danger">Vulnerable Search</h1>
        <p>The input below is rendered without escaping.</p>
        <div class="card">Search result for: {q}</div>
        <p><a href="/">Back</a></p>
        """
    )


@app.get("/safe-search")
def safe_search() -> str:
    q = request.args.get("q", "")
    return page(
        f"""
        <h1 class="safe">Safe Search</h1>
        <p>The input below is escaped before rendering.</p>
        <div class="card">Search result for: {escape(q)}</div>
        <p><a href="/">Back</a></p>
        """
    )


@app.get("/products")
def vulnerable_products() -> str:
    product_id = request.args.get("id", "1")
    query = f"SELECT id, name, category, price FROM products WHERE id = {product_id}"
    rows = get_db().execute(query).fetchall()
    return render_products("Vulnerable Products", query, rows, safe=False)


@app.get("/safe-products")
def safe_products() -> str:
    product_id = request.args.get("id", "1")
    rows = get_db().execute(
        "SELECT id, name, category, price FROM products WHERE id = ?",
        (product_id,),
    ).fetchall()
    return render_products("Safe Products", "Parameterized query used", rows, safe=True)


def render_products(title: str, query: str, rows: list[sqlite3.Row], safe: bool) -> str:
    css_class = "safe" if safe else "danger"
    table_rows = "".join(
        f"<tr><td>{row['id']}</td><td>{escape(row['name'])}</td><td>{escape(row['category'])}</td><td>${row['price']}</td></tr>"
        for row in rows
    )
    return page(
        f"""
        <h1 class="{css_class}">{title}</h1>
        <p>Query evidence:</p>
        <p><code>{escape(query)}</code></p>
        <table>
          <thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Price</th></tr></thead>
          <tbody>{table_rows}</tbody>
        </table>
        <p><a href="/">Back</a></p>
        """
    )


if __name__ == "__main__":
    if not DB_PATH.exists():
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)

