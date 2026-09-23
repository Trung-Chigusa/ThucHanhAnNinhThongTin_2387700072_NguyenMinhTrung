# Lab 03 – SecureLogger: Ghi nhật ký ưu tiên bảo mật

**Sinh viên:** Nguyễn Minh Trung — MSSV: 2387700072
**Buổi:** 1 — Bài 1: Cơ sở lập trình bảo mật, kiểm tra đầu vào
**Phạm vi:** Mục 1.6 của tài liệu thực hành — *Thực hành: Ghi nhật ký ưu tiên bảo mật*.

## 1. Mục tiêu

Xây dựng hệ thống ghi nhật ký **SecureLogger**, tích hợp với thư viện `SecureValidator` (Lab 01) và áp dụng các nguyên tắc bảo mật log đã học ở Lab 02 (mục 1.5), với các tính năng:

- Hỗ trợ đa cấp độ log: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.
- Tự động phát hiện và che dấu thông tin định danh cá nhân (PII) trước khi ghi log.
- Quản lý luân phiên log (log rotation) kèm nén dữ liệu (gzip) khi file vượt quá `MAX_LOG_SIZE`.
- Phát hiện thay đổi trái phép trên tập tin nhật ký (tamper detection) bằng chữ ký băm SHA-256.
- Ghi nhật ký theo cấu trúc JSON cố định (chống Log Injection).
- Tích hợp với `SecureValidator` để ghi lại toàn bộ các lần kiểm tra validation qua API `/validate`.

## 2. Cấu trúc thư mục

```
secure_logger_lab/
├── app.py                       # Flask API /validate, có tích hợp secure_logger
├── requirements.txt             # Flask
├── .gitignore
├── securevalidator/             # Sao chép nguyên trạng từ Lab 01
│   ├── __init__.py
│   └── core.py
└── securelogger/
    ├── __init__.py
    └── logger.py                 # Toàn bộ logic SecureLogger
```

Thư mục `securevalidator/` được sao chép nguyên trạng từ `Lab01/secure-validator-lab/securevalidator` sang, tái sử dụng thư viện đã xây dựng ở Lab 01.

## 3. Module `securelogger/logger.py`

| Thành phần | Vai trò |
|---|---|
| `PII_PATTERNS` | Regex phát hiện email và các trường `token/apikey/key/password` |
| `mask_pii(text)` | Thay thế các đoạn PII tìm được bằng nhãn `<email_masked>`, `<token_masked>` — áp dụng nguyên tắc "ghi log có chọn lọc" ở mục 1.5.2 |
| `hash_line(line)` | Băm SHA-256 một dòng log |
| `append_signature(line)` | Ghi chữ ký băm của dòng log vào `secure.log.sig` — phục vụ tamper detection |
| `JSONFormatter` | Định dạng mỗi bản ghi log thành một dòng JSON (`timestamp`, `level`, `message`, `data`, `results` — đã che PII) — áp dụng nguyên tắc "định dạng log cố định" ở mục 1.5.3 |
| `GZipRotator` | Nén file log cũ thành `.gz` khi log rotation xảy ra, xoá file gốc |
| `SecureRotatingFileHandler` | Kế thừa `RotatingFileHandler`; sau khi ghi log (`emit`) sẽ tự động gọi `append_signature` |
| `get_secure_logger()` | Khởi tạo/singleton logger `secure_logger`, giới hạn `MAX_LOG_SIZE = 1MB`, `BACKUP_COUNT = 2` |

## 4. API `/validate` (`app.py`)

```
POST /validate
Content-Type: application/json
```

- Nếu body không phải JSON hợp lệ → ghi log mức `WARNING` ("Invalid JSON received") và trả về lỗi `400`.
- Nếu hợp lệ → gọi lại các hàm của `SecureValidator` (`validate_email`, `validate_url`, `validate_filename`, `sanitize_sql_input`, `sanitize_html_input`), ghi log mức `INFO` ("Validation check performed") kèm `data` gửi lên và `results` trả về (đều đã được `mask_pii` khi ghi vào log), rồi trả JSON kết quả cho client.

## 5. Cài đặt & chạy thử

```bash
cd secure_logger_lab
pip install -r requirements.txt
python app.py
# Server chạy tại http://127.0.0.1:5000/
```

### Kiểm thử bằng Postman

Request mẫu:

```
POST http://localhost:5000/validate
Content-Type: application/json

{
  "email": "phuoc@example.com",
  "url": "https://secure.com",
  "filename": "report.pdf",
  "sql": "' OR 1=1 --",
  "html": "<script>alert(1)</script>"
}
```

Response nhận được:

```json
{
  "email": true,
  "filename": true,
  "html": "&lt;script&gt;alert(1)&lt;/script&gt;",
  "sql": "1=1",
  "url": true
}
```

### Kiểm tra file `secure.log`

Sau khi gọi API, `secure.log` ghi lại một dòng JSON, trong đó email đã được thay bằng `<email_masked>`:

```json
{"timestamp": "2025-06-10T06:56:26.197056Z", "level": "INFO", "message": "Validation check performed", "data": "{'email': '<email_masked>', 'url': 'https://secure.com', 'filename': 'report.pdf', ...}", "results": "{'email': True, 'url': True, ...}"}
```

### Kiểm tra file `secure.log.sig`

File này chứa chuỗi băm SHA-256 tương ứng với từng dòng đã ghi trong `secure.log`, dùng để xác thực dữ liệu log có bị chỉnh sửa hay không (nếu ai đó sửa tay `secure.log`, hash tính lại sẽ không khớp với `secure.log.sig`).

## 6. Liên hệ với lý thuyết Lab 02 (mục 1.5)

| Nguyên tắc (Lab 02) | Cài đặt cụ thể trong SecureLogger |
|---|---|
| Không ghi thô PII vào log | `mask_pii()` che email/token/password/apikey trước khi `JSONFormatter` xuất ra |
| Dùng định dạng log cố định, không chèn động nội dung nguy hiểm | `JSONFormatter` luôn xuất một object JSON có schema cố định (`timestamp, level, message, data, results`) |
| Bảo vệ tính toàn vẹn dữ liệu log | `SecureRotatingFileHandler` + `append_signature()` tạo chữ ký băm SHA-256 cho mỗi dòng log |
| Giám sát log định kỳ, phát hiện bất thường | Log rotation nén (`GZipRotator`) giúp lưu trữ log lịch sử có kiểm soát dung lượng để phục vụ giám sát |

## 7. Kết luận

Lab 03 hoàn thiện chuỗi bài thực hành Buổi 1: dữ liệu đầu vào được kiểm tra/làm sạch bởi `SecureValidator` (Lab 01), các nguyên tắc bảo mật log được học ở Lab 02, và cuối cùng được áp dụng vào một module ghi log thực tế — `SecureLogger` — có khả năng che PII tự động, chống Log Injection bằng định dạng JSON cố định, và đảm bảo tính toàn vẹn nhật ký bằng chữ ký băm.

> Ảnh chụp tài liệu gốc được lưu tại [`../tai-lieu-goc`](../tai-lieu-goc).
