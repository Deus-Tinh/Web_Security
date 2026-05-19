"""
Khởi tạo SQLite shop.db trong thư mục lab_appsec (cùng thư mục với script).
"""

import os
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "shop.db"


def init():
    if DB_PATH.exists():
        os.remove(DB_PATH)
        print(f"[*] Da xoa database cu: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            category    TEXT    NOT NULL,
            price       REAL    NOT NULL,
            rating      REAL    DEFAULT 4.0,
            image       TEXT    DEFAULT 'default.jpg',
            description TEXT
        )
    """)

    seed = [
        ("iPhone 16 Pro Max 256GB", "Phones", 1199.0, 4.8, "iphone16.jpg",
         "A18 Pro chip, 48MP camera, titanium design."),
        ("Samsung Galaxy S25 Ultra", "Phones", 1099.0, 4.7, "s25ultra.jpg",
         "Snapdragon 8 Elite, 200MP camera, S-Pen included."),
        ("Xiaomi 15 Ultra", "Phones", 899.0, 4.5, "xiaomi15.jpg",
         "Snapdragon 8 Gen 4, Leica camera system."),
        ("Google Pixel 9 Pro", "Phones", 999.0, 4.6, "pixel9.jpg",
         "Tensor G4, AI photography, 7 years updates."),

        ("Apple MacBook Air M3 16GB/1TB", "Laptops", 1299.0, 4.9, "macbook_m3.jpg",
         "M3 chip, 18-hour battery, fanless design."),
        ("Dell XPS 15 OLED 2025", "Laptops", 1599.0, 4.6, "dell_xps15.jpg",
         "Intel Core Ultra 9, RTX 4070, 3.5K OLED."),
        ("Asus ROG Zephyrus G16", "Laptops", 1799.0, 4.7, "rog_g16.jpg",
         "AMD Ryzen 9, RTX 4090, 240Hz QHD display."),
        ("Lenovo ThinkPad X1 Carbon", "Laptops", 1499.0, 4.5, "thinkpad_x1.jpg",
         "Intel Core Ultra 7, 32GB RAM, military-grade durability."),

        ("Apple Mac Mini M4 Pro", "Desktop", 1399.0, 4.8, "macmini_m4.jpg",
         "M4 Pro, 24GB RAM, Thunderbolt 5."),
        ("ASUS ProArt Station PD5", "Desktop", 2199.0, 4.5, "proart_pd5.jpg",
         "Intel i9, RTX 4080, 64GB DDR5."),

        ("Noctua NH-D15 G2", "Fans", 109.0, 4.9, "noctua_nhd15.jpg",
         "Dual-tower air cooler, 300W TDP support."),
        ("Corsair iCUE H150i Elite", "Fans", 199.0, 4.6, "corsair_h150.jpg",
         "360mm AIO liquid cooler, RGB."),

        ("Samsung QLED 8K 75\" 2025", "Tivi", 3499.0, 4.7, "samsung_qled.jpg",
         "8K 120Hz, AI upscaling, Dolby Atmos."),
        ("LG OLED evo C4 65\"", "Tivi", 2199.0, 4.8, "lg_oled_c4.jpg",
         "4K 120Hz, G-Sync, webOS 24."),

        ("Apple AirPods Pro 2nd Gen", "Accessories", 249.0, 4.7, "airpods_pro2.jpg",
         "Active noise cancellation, Spatial Audio."),
        ("Logitech MX Master 3S", "Accessories", 99.0, 4.8, "mx_master3s.jpg",
         "8K DPI, MagSpeed scroll, quiet clicks."),
        ("Keychron Q1 Pro", "Accessories", 199.0, 4.6, "keychron_q1.jpg",
         "75% wireless mechanical keyboard, Gateron Pro switches."),
    ]

    cur.executemany(
        "INSERT INTO products(name,category,price,rating,image,description) "
        "VALUES(?,?,?,?,?,?)",
        seed,
    )

    cur.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email    TEXT,
            role     TEXT DEFAULT 'user'
        )
    """)
    cur.executemany(
        "INSERT INTO users(username,password,email,role) VALUES(?,?,?,?)",
        [
            ("admin", "S3cur3P@ss!", "admin@shop.local", "admin"),
            ("alice", "alice1234", "alice@shop.local", "user"),
            ("bob", "bobpassword", "bob@shop.local", "user"),
        ],
    )

    conn.commit()
    conn.close()

    print(f"[OK] Database da tao: {DB_PATH.resolve()}")
    print(f"[OK] Da insert {len(seed)} san pham, 3 users.")
    print("\n[!] Cau truc bang:")
    print("    products: id, name, category, price, rating, image, description")
    print("    users:    id, username, password, email, role")
    print("\n[!] Buoc tiep theo:")
    print("    1. python app.py")
    print("    2. Mo http://localhost:5000")
    print("    3. Demo XSS : /search?q=<script>alert('XSS')</script>")
    print("    4. Demo SQLi: /category?name=' OR '1'='1' --")
    print("    5. Quet     : python web_scanner.py --url http://localhost:5000 --report scan_report.txt")


if __name__ == "__main__":
    init()
