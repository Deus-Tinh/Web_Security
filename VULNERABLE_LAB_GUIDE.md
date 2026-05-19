# Vulnerable Web Security Lab

File lab: `vulnerable_lab_app.py`

Lab này cố ý có lỗi SQL Injection và XSS để bạn đưa vào scanner kiểm thử.

## Chạy Lab

```powershell
pip install flask
python vulnerable_lab_app.py
```

Mở:

```text
http://localhost:5000
```

## Link Để Test XSS

Vulnerable:

```text
http://localhost:5000/search?q=test
```

Payload demo:

```html
<script>alert(1)</script>
```

Fixed:

```text
http://localhost:5000/safe-search?q=test
```

## Link Để Test SQL Injection

Vulnerable:

```text
http://localhost:5000/products?id=1
```

Payload demo:

```text
1 OR 1=1
```

Fixed:

```text
http://localhost:5000/safe-products?id=1
```

## Dùng Với SentinelAI Scanner

Nếu backend scanner chạy trực tiếp trên máy:

```text
http://localhost:5000/search?q=test
http://localhost:5000/products?id=1
```

Nếu backend scanner chạy trong Docker, thường cần dùng:

```text
http://host.docker.internal:5000/search?q=test
http://host.docker.internal:5000/products?id=1
```

Và thêm `host.docker.internal` vào `ALLOWED_TARGET_HOSTS`.

## Lưu Ý

Lab này chỉ dùng local để học bảo mật. Không deploy file này lên internet.
