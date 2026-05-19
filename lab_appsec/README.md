# Web Security Scanner — Phát hiện XSS và SQL Injection

**Đồ án cuối kỳ | Lab giáo dục AppSec**

> Thư mục chính: `lab_appsec/` — chạy mọi lệnh từ đây.  
> Repo gốc `DEMO/` chỉ chứa `.venv` và README trỏ về đây.

---

## 1. Tên đề tài

**Xây dựng công cụ Web Security Scanner phát hiện lỗ hổng Reflected XSS và SQL Injection trên ứng dụng web Flask (lab cố ý lỗ hổng).**

## 2. Mục tiêu

- Xây dựng website demo (Online Shopping Mall) có endpoint **cố ý lỗ hổng** và endpoint **đã vá** để so sánh khi bảo vệ.
- Xây dựng scanner tự động: crawl form/link → fuzz payload XSS/SQLi → báo cáo có severity, evidence, khuyến nghị fix.
- Trình bày được nguyên nhân, cách khai thác (lab), và biện pháp phòng chống.

## 3. Kiến trúc hệ thống

```
┌─────────────────┐     HTTP      ┌──────────────────────┐
│  web_scanner.py │ ────────────► │  app.py (Flask)      │
│  - Crawler      │               │  - /search (XSS)     │
│  - XSS detect   │               │  - /category (SQLi)  │
│  - SQLi detect  │               │  - /safe/* (fixed)   │
│  - Report       │               └──────────┬───────────┘
└─────────────────┘                          │
                                             ▼
                                    ┌─────────────────┐
                                    │  shop.db (SQLite)│
                                    └─────────────────┘
```

## 4. Công nghệ

| Thành phần | Công nghệ |
|------------|-----------|
| Web lab | Python, Flask, Jinja2, Bootstrap |
| Database | SQLite |
| Scanner | Requests, BeautifulSoup, Colorama |
| Báo cáo | TXT, JSON |

## 5. Cài đặt

```powershell
cd lab_appsec
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 6. Tạo database

```powershell
python init_db.py
```

Tạo file `shop.db` **cùng thư mục** `lab_appsec/` (đường dẫn tuyệt đối theo `Path(__file__)`).

## 7. Chạy web lab

```powershell
python app.py
```

Mở trình duyệt: http://localhost:5000

Debug (tùy chọn):

```powershell
$env:FLASK_DEBUG="1"
python app.py
```

## 8. Chạy scanner

```powershell
python web_scanner.py --url http://localhost:5000 --report scan_report.txt --json scan_report.json
```

Tùy chọn:

| Flag | Mô tả |
|------|--------|
| `--report FILE` | Xuất báo cáo TXT |
| `--json FILE` | Xuất báo cáo JSON |
| `--verbose` | In chi tiết từng payload |
| `--dangerous` | Bật payload phá hoại (DROP TABLE) — **mặc định TẮT** |

## 9. Payload demo (lab)

| Loại | Payload | Endpoint |
|------|---------|----------|
| XSS | `<script>alert('XSS')</script>` | `/search?q=` |
| SQLi | `' OR '1'='1' --` | `/category?name=` |

Endpoint đã vá:

- `/safe/search?q=` — autoescape
- `/safe/category?name=` — parameterized query

## 10. Kết quả mong đợi

Scanner phát hiện ít nhất:

1. **Reflected XSS** tại `GET /search` — parameter `q`
2. **SQL Injection** tại `GET /category` — parameter `name` (error-based, boolean, hoặc union)

Báo cáo gồm: severity, evidence, recommendation.

## 11. Giải thích lỗ hổng

### Reflected XSS (`/search`)

Input `q` được nhúng vào HTML qua `Markup` / `| safe` **không escape** → script phản chiếu trong trang.

### SQL Injection (`/category`)

Tham số `name` được **nối chuỗi** vào SQL → attacker điều khiển câu query (`' OR '1'='1`, UNION, …).

## 12. Cách phòng chống

| Lỗ hổng | Biện pháp (xem `/safe/*`) |
|---------|---------------------------|
| XSS | Jinja2 autoescape, không dùng `\| safe` với input user |
| SQLi | Parameterized query: `WHERE category = ?`, tuple `(name,)` |

## 13. Giới hạn scanner

- Chỉ phát hiện **reflected** XSS (không stored/DOM).
- SQLi heuristic: error/length/union — có thể false positive/negative.
- Không dùng headless browser để xác nhận XSS thực thi JS.
- Crawler chỉ quét trang chủ + form/link (không spider sâu).

## 14. Đạo đức sử dụng

- **Chỉ** quét `localhost` hoặc hệ thống bạn **sở hữu** / được **ủy quyền**.
- Payload phá hoại (`DROP TABLE`) chỉ bật với `--dangerous` trong lab cô lập.
- Không dùng công cụ để tấn công website bên thứ ba.

## 15. Kiểm tra nhanh

```powershell
python smoke_test.py
```

(Yêu cầu `python app.py` đang chạy.)

## 16. Tài liệu bảo vệ

- [DEFENSE_NOTES.md](DEFENSE_NOTES.md) — ghi chú thuyết trình
- [sample_report.md](sample_report.md) — báo cáo quét mẫu

## 17. Cấu trúc thư mục

```
lab_appsec/
├── app.py              # Flask lab (vulnerable + safe)
├── init_db.py          # Tạo shop.db
├── web_scanner.py      # Scanner
├── smoke_test.py       # Kiểm tra nhanh
├── requirements.txt
├── templates/
│   └── index.html
├── README.md
├── DEFENSE_NOTES.md
├── sample_report.md
└── shop.db             # (sau init_db.py)
```
