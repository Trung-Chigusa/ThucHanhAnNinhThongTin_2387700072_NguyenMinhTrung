# Lab 02 – Làm sạch dữ liệu & Bảo mật ghi nhật ký (lý thuyết)

**Sinh viên:** Nguyễn Minh Trung — MSSV: 2387700072
**Buổi:** 1 — Bài 1: Cơ sở lập trình bảo mật, kiểm tra đầu vào
**Phạm vi:** Mục 1.5 của tài liệu thực hành — *Làm sạch dữ liệu, bảo mật ghi nhật ký*.

Mục 1.5 là phần lý thuyết nền tảng, làm cầu nối giữa Lab 01 (`SecureValidator`) và Lab 03 (`SecureLogger`): các nguyên tắc dưới đây được áp dụng trực tiếp khi cài đặt module ghi log an toàn ở Lab 03.

## 1.5.1 Kỹ thuật làm sạch dữ liệu (Data Sanitization)

**Định nghĩa:** Làm sạch dữ liệu là quá trình loại bỏ hoặc vô hiệu hóa các thành phần nguy hiểm trong dữ liệu đầu vào nhằm ngăn chặn các tấn công như XSS, SQL Injection hay Command Injection.

**Nguyên tắc cơ bản:**
- Không tin tưởng dữ liệu đầu vào (Never trust user input).
- Làm sạch càng sớm càng tốt — xử lý ngay tại điểm nhận dữ liệu.
- Ưu tiên whitelist thay vì blacklist (chỉ cho phép những gì biết chắc là an toàn, thay vì cố liệt kê mọi thứ nguy hiểm).
- Làm sạch theo đúng ngữ cảnh sử dụng (dữ liệu hiển thị trong HTML, dùng trong câu SQL, hay ghi vào log... cần kỹ thuật làm sạch khác nhau).

**Kỹ thuật phổ biến:**
- **Escaping & Encoding:** vô hiệu hóa ký tự đặc biệt (`<`, `>`, `'`, `"`,...) — ví dụ `html.escape()` trong Python (đã áp dụng ở `sanitize_html_input` của Lab 01).
- **Lọc theo whitelist:** chỉ cho phép ký tự hợp lệ (regex whitelist).
- **Sử dụng thư viện chuyên dụng:** `bleach`, `DOMPurify`...
- **Chuẩn hóa dữ liệu:** kiểm tra định dạng đầu vào trước khi xử lý tiếp (email, URL, filename...).

## 1.5.2 Xử lý thông tin định danh cá nhân (PII)

**Định nghĩa:** Personally Identifiable Information (PII) là các dữ liệu có thể dùng để nhận diện một cá nhân cụ thể: họ tên, số CCCD, email, địa chỉ IP, thông tin tài chính...

**Nguy cơ nếu PII bị rò rỉ:**
- Vi phạm pháp lý (theo các luật bảo vệ dữ liệu như GDPR, PDP...).
- Gây mất uy tín hệ thống.
- Dễ bị lợi dụng cho các cuộc tấn công lừa đảo, chiếm đoạt danh tính.

**Nguyên tắc xử lý PII:**
- **Thu thập tối thiểu:** chỉ lưu trữ thông tin thực sự cần thiết.
- **Ẩn hoặc mã hóa:** sử dụng kỹ thuật như hashing, encryption, masking.
- **Kiểm soát truy cập:** giới hạn quyền truy xuất thông tin PII.
- **Ghi log có chọn lọc:** tuyệt đối không ghi thô dữ liệu nhạy cảm vào log.

Nguyên tắc "ghi log có chọn lọc" chính là lý do Lab 03 (`SecureLogger`) cài đặt hàm `mask_pii()` để tự động che (`<email_masked>`, `<token_masked>`...) các trường email/token/password/apikey trước khi ghi log.

## 1.5.3 Phòng chống chèn mã vào nhật ký (Log Injection)

**Định nghĩa:** Log Injection là kỹ thuật tấn công khi kẻ xấu lợi dụng việc ghi log không an toàn để chèn các đoạn mã độc hoặc lệnh đặc biệt, gây ảnh hưởng đến hệ thống phân tích log hoặc tạo lỗi.

**Rủi ro:**
- Làm sai lệch dữ liệu log, khó phát hiện sự cố thật.
- Gây lỗi hoặc khai thác lỗ hổng qua công cụ phân tích log.
- Tiết lộ thông tin nhạy cảm hoặc gây tấn công chuỗi lệnh.

**Nguyên tắc phòng chống:**
- Lọc và mã hóa dữ liệu đầu vào trước khi ghi log, loại bỏ ký tự đặc biệt (newline, tab, escape sequence).
- Dùng định dạng log cố định (ví dụ JSON), không cho phép chèn động nội dung nguy hiểm.
- Giới hạn quyền truy cập log, bảo vệ tính toàn vẹn dữ liệu.
- Kiểm tra và giám sát log định kỳ để phát hiện dấu hiệu bất thường.

Lab 03 áp dụng nguyên tắc này bằng cách ghi log dưới dạng **JSON có cấu trúc** (`JSONFormatter`) thay vì nối chuỗi tự do, đồng thời ký (hash SHA-256) từng dòng log vào file `secure.log.sig` để phát hiện log bị chỉnh sửa trái phép (tamper detection).

## Kết luận

Ba nguyên tắc của mục 1.5 — làm sạch dữ liệu, bảo vệ PII, và chống log injection — là nền tảng lý thuyết trực tiếp cho việc thiết kế hệ thống `SecureLogger` ở Lab 03: mọi dữ liệu trước khi được ghi vào log đều phải đi qua bước làm sạch, che PII, và được ghi theo định dạng JSON cố định, có ký xác thực toàn vẹn.

> Ảnh chụp tài liệu gốc được lưu tại [`../tai-lieu-goc`](../tai-lieu-goc).
