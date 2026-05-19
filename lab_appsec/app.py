"""
Flask lab app — cố ý có lỗ hổng XSS và SQLi cho mục đích giáo dục AppSec.
Bản chính của đồ án nằm trong thư mục lab_appsec/.
"""

import os
import sqlite3
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request
from markupsafe import Markup

BASE_DIR = Path(__file__).resolve().parent
DATABASE = str(BASE_DIR / "shop.db")

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def _render(products, **kwargs):
    defaults = {
        "products": products,
        "search_query": None,
        "category": None,
        "demo_mode": None,
        "endpoint_type": None,
        "search_banner": None,
        "sql_error": None,
    }
    defaults.update(kwargs)
    return render_template("index.html", **defaults)


@app.route("/")
def index():
    db = get_db()
    products = db.execute("SELECT * FROM products LIMIT 6").fetchall()
    return _render(products)


# ── Vulnerable Demo: Reflected XSS ───────────────────────────
@app.route("/search")
def search_vulnerable():
    q = request.args.get("q", "")
    db = get_db()
    results = db.execute(
        "SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",)
    ).fetchall()

    # Cố ý không escape — phản chiếu input thẳng vào HTML
    search_banner = Markup(
        '<div class="alert alert-info mt-3">'
        f'Kết quả tìm kiếm cho: <strong>{q}</strong>'
        f'&nbsp;—&nbsp; Tìm thấy {len(results)} sản phẩm.'
        "</div>"
    )

    return _render(
        results,
        search_query=q,
        demo_mode="vulnerable",
        endpoint_type="xss",
        search_banner=search_banner,
    )


# ── Fixed Demo: XSS đã vá (Jinja2 autoescape) ────────────────
@app.route("/safe/search")
def search_safe():
    q = request.args.get("q", "")
    db = get_db()
    results = db.execute(
        "SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",)
    ).fetchall()

    return _render(
        results,
        search_query=q,
        demo_mode="fixed",
        endpoint_type="xss",
    )


# ── Vulnerable Demo: SQL Injection ───────────────────────────
@app.route("/category")
def category_vulnerable():
    name = request.args.get("name", "")
    db = get_db()

    raw_query = f"SELECT * FROM products WHERE category = '{name}'"
    try:
        results = db.execute(raw_query).fetchall()
        error_msg = None
    except Exception as e:
        results = []
        error_msg = str(e)

    return _render(
        results,
        category=name,
        demo_mode="vulnerable",
        endpoint_type="sqli",
        sql_error=error_msg,
    )


# ── Fixed Demo: SQLi đã vá (parameterized query) ─────────────
@app.route("/safe/category")
def category_safe():
    name = request.args.get("name", "")
    db = get_db()
    results = db.execute(
        "SELECT * FROM products WHERE category = ?", (name,)
    ).fetchall()

    return _render(
        results,
        category=name,
        demo_mode="fixed",
        endpoint_type="sqli",
    )


@app.route("/api/products")
def api_products():
    db = get_db()
    rows = db.execute("SELECT * FROM products").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0").strip() in ("1", "true", "True")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    print(f"[*] Database : {DATABASE}")
    print(f"[*] Templates: {BASE_DIR / 'templates'}")
    print(f"[*] Debug mode: {debug}")
    app.run(debug=debug, host="0.0.0.0", port=port)
