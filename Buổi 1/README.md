# Buổi 1 — Bài 1: Cơ sở lập trình bảo mật, kiểm tra đầu vào

Buổi thực hành gồm 3 lab, bám theo cấu trúc mục lục tài liệu (ảnh chụp gốc tại [`tai-lieu-goc/`](tai-lieu-goc)):

| Lab | Phạm vi tài liệu | Nội dung | README |
|---|---|---|---|
| **Lab 01** | 1.1 → 1.4 | Thư viện `SecureValidator` (validate email/URL/filename, sanitize SQL/HTML), giao diện Flask, unit test, deploy Render, Git pre-commit hook `GitSecure` | [Lab01/README.md](Lab01/README.md) |
| **Lab 02** | 1.5 | Lý thuyết: làm sạch dữ liệu, xử lý PII, phòng chống chèn mã vào nhật ký (Log Injection) | [Lab02/README.md](Lab02/README.md) |
| **Lab 03** | 1.6 | Module `SecureLogger`: ghi log JSON có che PII, log rotation nén gzip, chữ ký băm chống giả mạo log, tích hợp với `SecureValidator` qua API `/validate` | [Lab03/README.md](Lab03/README.md) |

## Mã nguồn

- [`Lab01/secure-validator-lab`](Lab01/secure-validator-lab) — dự án Flask + thư viện SecureValidator + pre-commit hook.
- [`Lab03/secure_logger_lab`](Lab03/secure_logger_lab) — dự án Flask API + thư viện SecureLogger.

Lab 02 không có mã nguồn riêng (là phần lý thuyết nối giữa Lab 01 và Lab 03), nội dung được trình bày đầy đủ trong README.
