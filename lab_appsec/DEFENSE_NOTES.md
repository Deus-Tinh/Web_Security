# Ghi chú bảo vệ đồ án — Web Security Scanner

## 1. Vì sao chọn đề tài

- XSS và SQL Injection vẫn nằm trong **OWASP Top 10**, phù hợp môn An toàn ứng dụng web.
- Kết hợp **lab thực hành** (Flask) + **công cụ tự động** (scanner) → dễ demo trực quan trước hội đồng.
- Có cả bản **lỗ hổng** và **đã vá** (`/safe/*`) để chứng minh hiểu biệt phòng thủ.

## 2. Luồng hoạt động scanner

```
START → Crawl trang chủ → Thu thập form + link có query
     → Với mỗi (endpoint, param):
           → Fuzz XSS payloads → Kiểm tra reflection
           → Fuzz SQLi payloads → Error / boolean / union
     → Dedupe findings → Xuất TXT/JSON → END
```

## 3. Crawler tìm endpoint

- Parse HTML bằng **BeautifulSoup**.
- Tìm `<form>` → `action`, `method`, danh sách `input[name]`.
- Tìm `<a href="...?param=...">` → extract path + tên parameter.
- Bỏ qua `/safe/*` (chỉ demo fix, không phải mục tiêu quét).
- Fallback: thêm thủ công `/search?q` và `/category?name` nếu crawl rỗng.

## 4. Phát hiện XSS

- Gửi payload vào từng parameter (GET/POST).
- Nếu **payload xuất hiện nguyên vẹn** trong response body → Reflected XSS.
- Ghi **evidence**: đoạn HTML quanh vị trí payload.
- Severity: **HIGH**.

## 5. Phát hiện SQLi (3 kiểu)

| Kiểu | Cách nhận biết |
|------|----------------|
| **Error-based** | Chuỗi lỗi SQLite/SQL trong response (`syntax error`, `near`, …) |
| **Boolean/length** | Payload TRUE (`' OR '1'='1`) → response dài hơn baseline; FALSE ngắn hơn |
| **Union/response** | Payload UNION → thay đổi nội dung/độ dài bất thường, có thể lộ bảng `users` |

Biến `more_data` dùng so sánh độ dài response TRUE vs baseline và FALSE.

## 6. Demo live — 5 bước

1. `python init_db.py` → hiện `shop.db` đã tạo.
2. `python app.py` → mở http://localhost:5000, chỉ sidebar **VULNERABLE DEMO**.
3. XSS: `/search?q=<script>alert('XSS')</script>` → script trong trang.
4. SQLi: `/category?name=' OR '1'='1' --` → hiện nhiều sản phẩm / lỗi SQL.
5. Scanner: `python web_scanner.py --url http://localhost:5000 --report scan_report.txt` → mở báo cáo, so sánh với `/safe/*`.

## 7. Điểm mạnh

- Lab + scanner trong **một repo**, chạy local không phụ thuộc CWD.
- UI có nhãn **Vulnerable Demo** / **Fixed Demo**.
- Scanner có dedupe, severity, evidence, recommendation.
- Payload phá hoại tách riêng (`--dangerous` mặc định tắt).
- Có smoke test, sample report, README đầy đủ.

## 8. Hạn chế

- Không quét stored XSS, CSRF, auth bypass.
- XSS chỉ kiểm tra reflection, không chạy JS thật (headless).
- SQLi heuristic có thể báo nhầm trên app phức tạp.
- Crawler một tầng (trang chủ).

## 9. Hướng phát triển

- [ ] Thêm **CSRF** scan (thiếu token trên form state-changing)
- [ ] Thêm **stored XSS** (POST comment → kiểm tra persistence)
- [ ] Thêm **login/auth** scan (brute force, session fixation)
- [ ] Export báo cáo **HTML** có biểu đồ
- [ ] Tích hợp **headless browser** (Playwright) xác nhận XSS thực thi

## 10. Câu hỏi hội đồng thường gặp

**Q: Tại sao không xóa hết lỗ hổng?**  
A: Đây là lab giáo dục; cần endpoint vulnerable để scanner và demo hoạt động. Đã có `/safe/*` chứng minh cách vá.

**Q: Scanner có thay Burp/ZAP không?**  
A: Không — đây là công cụ học tập, minh họa tư duy DAST cơ bản.

**Q: DROP TABLE có chạy mặc định không?**  
A: Không — chỉ khi `--dangerous` và chỉ nên dùng trên lab local.
