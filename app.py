
from flask import Flask, request, render_template_string, g
import sqlite3
import os

app = Flask(__name__, static_folder="static")
DATABASE = "shop.db"

# ──────────────────────────────────────────────
# Helper: kết nối SQLite
# ──────────────────────────────────────────────
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

# ──────────────────────────────────────────────
# TRANG CHỦ
# ──────────────────────────────────────────────
@app.route("/")
def index():
    db = get_db()
    products = db.execute("SELECT * FROM products LIMIT 6").fetchall()
    return render_template_string(
        open("templates/index.html").read(),
        products=products,
        search_query=None,
        search_results=None,
        category=None,
        category_results=None,
    )

# ──────────────────────────────────────────────
# 🔴 LỖ HỔNG #1: REFLECTED XSS
#    Endpoint: /search?q=<input>
#    Vấn đề:   Input từ người dùng được nhúng THẲNG
#              vào HTML mà không qua escape/sanitize.
#    Payload:  <script>alert('XSS')</script>
# ──────────────────────────────────────────────
@app.route("/search")
def search():
    q = request.args.get("q", "")

    db = get_db()
    # Query an toàn (dùng parameterized) — lỗi chỉ ở phần render
    results = db.execute(
        "SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",)
    ).fetchall()

    # ❌ LỖI: render_template_string dùng Markup thô — KHÔNG escape q
    # Kẻ tấn công truyền: ?q=<script>alert(1)</script>
    # → script được phản chiếu lại trong HTML → XSS
    html_snippet = f"""
    <div class="alert alert-info mt-3">
        Kết quả tìm kiếm cho: <strong>{q}</strong>
        &nbsp;—&nbsp; Tìm thấy {len(results)} sản phẩm.
    </div>
    """

    return render_template_string(
        open("templates/index.html").read(),
        products=results,
        search_query=q,
        search_results=results,
        search_banner=html_snippet,   # ← inject thẳng vào template (không escape)
        category=None,
        category_results=None,
    )

# ──────────────────────────────────────────────
# 🔴 LỖ HỔNG #2: SQL INJECTION
#    Endpoint: /category?name=<category>
#    Vấn đề:   Tên category được nối chuỗi TRỰC TIẾP
#              vào câu SQL → attacker kiểm soát query.
#    Payload:  ' OR '1'='1   (dump toàn bộ bảng)
#              ' UNION SELECT 1,2,3,4,5,6 --  (UNION-based)
#              '; DROP TABLE products; --      (destructive)
# ──────────────────────────────────────────────
@app.route("/category")
def category():
    name = request.args.get("name", "")
    db = get_db()

    # ❌ LỖI: nối chuỗi trực tiếp — KHÔNG dùng parameterized query
    raw_query = f"SELECT * FROM products WHERE category = '{name}'"
    
    try:
        results = db.execute(raw_query).fetchall()
        error_msg = None
    except Exception as e:
        results = []
        # Trả về lỗi DB để dễ nhận dạng qua scanner (SQL error-based detection)
        error_msg = str(e)

    return render_template_string(
        open("templates/index.html").read(),
        products=results,
        search_query=None,
        search_results=None,
        search_banner=None,
        category=name,
        category_results=results,
        sql_error=error_msg,          # ← lộ lỗi SQL ra ngoài
    )

# ──────────────────────────────────────────────
# API JSON (dùng cho scanner)
# ──────────────────────────────────────────────
@app.route("/api/products")
def api_products():
    from flask import jsonify
    db = get_db()
    rows = db.execute("SELECT * FROM products").fetchall()
    return jsonify([dict(r) for r in rows])

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
