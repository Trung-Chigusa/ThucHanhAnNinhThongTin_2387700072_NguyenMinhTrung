# WebVulnScanner - Lab 04

WebVulnScanner là phần 4.2 của Lab 04. Dự án gồm bốn bộ kiểm tra XSS, SQLi, CSRF, SSRF, bộ tạo báo cáo JSON, CLI và giao diện Flask cục bộ.

## Cài đặt trên Windows

Mở PowerShell trong thư mục `web-vuln-scanner`:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Chạy demo an toàn

Mở ba cửa sổ PowerShell tại thư mục dự án.

1. Cửa sổ thứ nhất chạy fixture cố ý phản hồi HTML chưa mã hóa. Fixture chỉ lắng nghe loopback:

   ```powershell
   .\.venv\Scripts\python.exe demo_target.py
   ```

2. Cửa sổ thứ hai chạy Web UI tại `http://127.0.0.1:5000`:

   ```powershell
   .\.venv\Scripts\python.exe -m ui.app
   ```

3. Mở `http://127.0.0.1:5000` trong trình duyệt. Form được điền sẵn URL của fixture `127.0.0.1:5001`; chọn các kiểm tra và bấm **Bắt đầu kiểm thử cục bộ**.

Có thể chạy cùng bộ kiểm tra từ CLI:

```powershell
.\.venv\Scripts\python.exe main.py --demo
```

Hoặc chỉ định một mục tiêu loopback:

```powershell
.\.venv\Scripts\python.exe main.py --target "http://127.0.0.1:5001/search" --check xss --check csrf
```

CLI in báo cáo JSON. Báo cáo bỏ các giá trị query để tránh ghi nhầm token hoặc dữ liệu riêng tư; findings chỉ giữ tên tham số và mô tả dấu hiệu.

## Cách đọc kết quả

- **XSS:** gửi một custom-element marker vô hại, không có JavaScript. Marker phản hồi không mã hóa được ghi là candidate XSS.
- **SQLi:** so khớp query parameters với một tập pattern phổ biến. Không gửi SQL đến cơ sở dữ liệu và không khẳng định có thể khai thác.
- **CSRF:** đọc các form state-changing và tìm hidden token không rỗng. Form không có token là candidate cần kiểm tra thủ công.
- **SSRF:** nhận diện tham số có chỉ dấu localhost, loopback, private hoặc link-local. Scanner không truy cập URL nằm trong tham số.

Mọi kết quả là dấu hiệu cần xác minh thủ công, không phải xác nhận lỗ hổng. Các request HTTP chỉ tới địa chỉ loopback đã được phân giải và ghim vào IP; target ngoài loopback, redirect và proxy môi trường đều không được dùng.

## Ảnh minh chứng

`minh-chung/` chứa ảnh chụp từ lần chạy thực tế và `test-output.txt` lưu output unittest thô. Ảnh thể hiện test pass, JSON report từ CLI và kết quả trên Web UI.

## Giới hạn

Đây là fixture học tập dành cho máy cục bộ. Không dùng cho website public hoặc môi trường production. Fixture có chủ ý phản hồi HTML chưa mã hóa để minh họa; nó không kết nối cơ sở dữ liệu, không truy cập địa chỉ SSRF và không lưu dữ liệu người dùng.
