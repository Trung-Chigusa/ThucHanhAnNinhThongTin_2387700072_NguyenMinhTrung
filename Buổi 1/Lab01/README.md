# Lab 01 – SecureValidator & Git Pre-commit Security Hook

**Sinh viên:** Nguyễn Minh Trung — MSSV: 2387700072
**Buổi:** 1 — Bài 1: Cơ sở lập trình bảo mật, kiểm tra đầu vào
**Phạm vi:** Mục 1.1 → 1.4 của tài liệu thực hành (cài đặt môi trường, xây dựng thư viện `SecureValidator`, Git Security & Pre-commit Hooks).

## 1. Mục tiêu

- Cài đặt môi trường lập trình bảo mật với VS Code + Git + GitHub.
- Xây dựng thư viện Python **SecureValidator** để kiểm tra/làm sạch dữ liệu đầu vào: email, URL (chống SSRF cơ bản), tên file (chống path traversal), chuỗi SQL (chống SQL Injection), chuỗi HTML (chống XSS).
- Xây dựng giao diện web Flask để nhập và kiểm thử trực quan các hàm trên.
- Viết Unit Test cho toàn bộ thư viện `SecureValidator`.
- Triển khai (deploy) ứng dụng lên Render.
- Xây dựng hệ thống **GitSecure** — một pre-commit hook tự viết bằng Python để tự động quét mã nguồn trước khi `git commit`, nhằm phát hiện và ngăn chặn thông tin nhạy cảm (API key, mật khẩu, token…) và quyền file không an toàn (world-writable) lọt vào repository.

## 2. Cấu trúc thư mục

```
secure-validator-lab/
├── app.py                      # Flask app - trang chủ kiểm tra validator
├── requirements.txt            # Flask, gunicorn
├── requirements-dev.txt        # bandit (phục vụ pre-commit hook)
├── render.yaml                 # Cấu hình deploy tự động lên Render
├── .gitignore
├── securevalidator/
│   ├── __init__.py
│   └── core.py                 # Toàn bộ logic validate/sanitize
├── templates/
│   └── index.html              # Giao diện web (Pico.css)
├── tests/
│   └── test_validators.py      # Unit test (unittest)
├── .githooks/
│   └── pre-commit              # Script GitSecure - chặn commit không an toàn
└── pre-commit-hook-test/
    └── bad.py                  # File demo chứa "password = 123456" để test hook
```

## 3. Thư viện `securevalidator/core.py`

| Hàm | Chức năng | Kỹ thuật phòng chống |
|---|---|---|
| `validate_email(email)` | Kiểm tra định dạng email bằng regex `^[\w\.-]+@[\w\.-]+\.\w+$` | Input validation |
| `validate_url(url)` | Parse URL bằng `urllib.parse`, chỉ chấp nhận scheme `http`/`https` và bắt buộc có `netloc` | Chống SSRF cơ bản |
| `validate_filename(filename)` | Từ chối filename chứa `..`, `/`, `\`; so sánh với `os.path.basename` | Chống Path Traversal |
| `sanitize_sql_input(input_str)` | Loại bỏ ký tự đặc biệt (`-- ; ' " #`) và các từ khoá SQL (`OR, AND, SELECT, INSERT, DELETE, UPDATE, DROP, UNION, WHERE`) | Chống SQL Injection |
| `sanitize_html_input(html_str)` | Escape ký tự HTML bằng `html.escape()` | Chống XSS |

## 4. Cài đặt & chạy ứng dụng

```bash
cd secure-validator-lab
pip install -r requirements.txt
python app.py
```

Sau đó mở trình duyệt tại `http://127.0.0.1:5000/`, nhập dữ liệu vào các trường Email, URL, Filename, SQL Input, HTML Input và bấm **Xác thực ngay**.

**Kết quả kiểm thử thủ công trên giao diện:**

| Trường | Giá trị nhập | Kết quả |
|---|---|---|
| Email | `hongphuoc@gmail.com` | Email hợp lệ |
| URL | `https://www.hutech.edu.vn` | URL hợp lệ |
| Filename | `../../etc/passwd` | Tên file không hợp lệ (chặn path traversal) |
| SQL Input | `' OR 1=1 --` | Đã lọc còn lại: `1=1` |
| HTML Input | `<script>alert("XSS")</script>` | Đã mã hóa: `&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;` |

## 5. Unit Test

```bash
python -m unittest discover tests
```

Bộ test gồm 10 test case bao phủ cả trường hợp hợp lệ và không hợp lệ cho từng hàm (`test_validators.py`). Kết quả mong đợi: `Ran 10 tests ... OK`.

## 6. Triển khai lên Render

1. Push code lên GitHub (branch `main`).
2. Vào [dashboard.render.com](https://dashboard.render.com/) → đăng nhập bằng GitHub → **New + → Web Service** → chọn repo vừa push.
3. Cấu hình:

| Field | Value |
|---|---|
| Name | `securevalidator` |
| Runtime | Python |
| Root Directory | `secure-validator-lab` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `gunicorn app:app` |
| Environment | Python 3 |

4. Có thể tự động hoá bước trên bằng file `render.yaml` đặt ở thư mục gốc.
5. Sau khi deploy, Render cấp URL dạng `https://securevalidator.onrender.com/`.

## 7. Git Security & Pre-commit Hook — GitSecure

### 7.1 Lý thuyết

- **Pre-commit hook** là script tự động chạy trước khi `git commit`, giúp phát hiện lỗi bảo mật và ngăn mã không an toàn lọt vào repository. Lợi ích: ngăn lỗ hổng sớm, tự động hoá kiểm tra, giáo dục ý thức bảo mật cho lập trình viên.
- Rò rỉ thông tin nhạy cảm (mật khẩu, API key, token) trong mã nguồn là lỗi nghiêm trọng, dẫn đến lộ key hệ thống, bị hacker khai thác từ kho mã công khai, vi phạm chính sách bảo mật. Có thể dùng các công cụ hỗ trợ như GitLeaks, detect-secrets, TruffleHog, git-secrets để quét mã và lịch sử git.
- Kiểm tra bảo mật tự động hoá giúp tiết kiệm thời gian, phát hiện liên tục ở nhiều giai đoạn (commit → build → deploy) và duy trì chất lượng bảo mật xuyên suốt vòng đời phần mềm.

### 7.2 Yêu cầu hệ thống GitSecure

Hook `.githooks/pre-commit` tích hợp:
- **Quét thông tin nhạy cảm**: phát hiện API key, mật khẩu, token bị hardcode bằng regex (`apikey=`, `secret=`, `password=`, `token=`, khoá AWS `AKIA/ASIA...`).
- **Quét lỗ hổng cơ bản**: chạy `bandit -r .` để phân tích mã nguồn Python.
- **Kiểm tra quyền truy cập file**: phát hiện file world-writable (bỏ qua trên Windows do không hỗ trợ `os.stat` mode kiểu Unix).
- **Ghi log**: mọi phát hiện được ghi vào `gitsecure.log` kèm timestamp.
- Nếu có bất kỳ finding nào → **chặn commit** (`sys.exit(1)`), in ra danh sách lỗi.

### 7.3 Cài đặt hook

```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit          # chạy trong Git Bash
pip install -r requirements-dev.txt    # cài bandit
```

### 7.4 Kiểm thử hook

Tạo file `pre-commit-hook-test/bad.py` chứa `password = "123456"`, sau đó:

```bash
git add pre-commit-hook-test/bad.py
git commit -m "test"
```

**Kết quả:**
```
COMMIT BLOCKED by GitSecure:
 - Sensitive info found in pre-commit-hook-test/bad.py: pattern password\s*=\s*['\"][^'\"]{4,}['\"]
 - File pre-commit-hook-test/bad.py is world-writable!
```

Toàn bộ finding được ghi lại vào `gitsecure.log`. File log này sau đó được thêm vào `.gitignore` để không commit ngược lại vào repo. Sau khi xoá thông tin nhạy cảm khỏi file, commit sẽ được chấp nhận với thông báo `GitSecure: All checks passed.`

Nếu bị chặn vì lỗi "world-writable" trên môi trường Unix/Git Bash, có thể hạ quyền ghi bằng `chmod 644 <tên_file>`.

## 8. Kết luận

Lab 01 xây dựng thành công một thư viện kiểm tra/làm sạch dữ liệu đầu vào (`SecureValidator`) tích hợp giao diện Flask, có unit test đầy đủ và được triển khai thực tế lên Render. Đồng thời, hệ thống pre-commit hook `GitSecure` chứng minh khả năng tự động ngăn chặn rò rỉ thông tin nhạy cảm và cấu hình quyền file không an toàn ngay tại thời điểm commit — một lớp phòng thủ "shift-left" quan trọng trong quy trình phát triển phần mềm an toàn.

> Ảnh chụp tài liệu gốc và các bước thao tác chi tiết được lưu tại [`../tai-lieu-goc`](../tai-lieu-goc).
