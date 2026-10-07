# SecureChat — Lab 03

**Sinh viên:** Nguyễn Minh Trung

**MSSV:** 2387700072

SecureChat là ứng dụng chat dòng lệnh chạy trong máy cá nhân để thực hành TLS hai chiều, quản lý phòng và mã hóa đầu-cuối. Relay chỉ chuyển tiếp các gói tin đã mã hóa.

## 1. Chuẩn bị

Các lệnh bên dưới dùng PowerShell. Mở terminal ở gốc repository rồi chạy `Set-Location` để vào thư mục `Buổi 3\secure-chat`. Trong phần chạy thử, mỗi cửa sổ PowerShell mới cũng bắt đầu ở gốc repository.

```powershell
Set-Location '.\Buổi 3\secure-chat'
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
```

Tạo CA cục bộ cùng chứng thư server, Alice và Bob:

```powershell
.\make-certs.bat
```

Script tìm OpenSSL trong `PATH` hoặc các thư mục OpenSSL phổ biến của Git for Windows. Script dừng nếu bộ chứng thư đã tồn tại để tránh ghi đè CA key.

## 2. Chạy server và hai client

Mở ba cửa sổ PowerShell. Trong cửa sổ thứ nhất, khởi động relay:

```powershell
Set-Location '.\Buổi 3\secure-chat'
.\.venv\Scripts\python.exe .\server.py
```

Mặc định server chỉ lắng nghe trên `127.0.0.1:8443`.

Trong cửa sổ thứ hai, kết nối Alice vào phòng `general`:

```powershell
Set-Location '.\Buổi 3\secure-chat'
.\.venv\Scripts\python.exe .\client.py --host 127.0.0.1 --port 8443 --room general --cert .\certs\alice.pem --key .\certs\alice.key --ca .\certs\ca.pem
```

Trong cửa sổ thứ ba, kết nối Bob vào cùng phòng:

```powershell
Set-Location '.\Buổi 3\secure-chat'
.\.venv\Scripts\python.exe .\client.py --host 127.0.0.1 --port 8443 --room general --cert .\certs\bob.pem --key .\certs\bob.key --ca .\certs\ca.pem
```

Khi client báo đã kết nối, nhập lệnh sau tại cửa sổ Alice:

```text
@bob Xin chào Bob, đây là tin nhắn thử nghiệm.
```

Bob sẽ thấy nội dung trong cửa sổ của mình. Lệnh `@tên_người_dùng nội_dung` gửi riêng cho một người trong cùng phòng. Nhập `/help` để xem lệnh hoặc `exit` để rời phòng.

### Thử cách ly phòng

Giữ Alice trong `general`. Thoát client Bob bằng `exit`, rồi chạy lại Bob với `--room private`:

```powershell
.\.venv\Scripts\python.exe .\client.py --host 127.0.0.1 --port 8443 --room private --cert .\certs\bob.pem --key .\certs\bob.key --ca .\certs\ca.pem
```

Từ Alice, thử gửi `@bob Tin nhắn khác phòng`. Vì Bob không còn trong danh sách phòng `general`, Alice sẽ được báo Bob không kết nối ở phòng đó; Bob không nhận được tin nhắn. Relay cũng từ chối các yêu cầu định tuyến chéo phòng. Đóng server bằng `Ctrl+C` sau khi thoát các client.

## 3. Thiết kế bảo mật

- Server yêu cầu chứng thư client do CA cục bộ cấp. Client xác minh chuỗi chứng thư server và hostname; TLS tối thiểu là 1.2.
- Username lấy từ Common Name trong chứng thư client. Mỗi client tạo khóa X25519 tạm thời và ký thông báo khóa bằng private key RSA của chứng thư.
- Client kiểm tra chữ ký, danh tính, thời hạn và mục đích `clientAuth` của chứng thư peer trước khi dùng khóa.
- Hai client dẫn xuất khóa AES-256 bằng X25519 và HKDF-SHA256. Mỗi tin nhắn được mã hóa riêng bằng AES-GCM; phòng, người gửi và người nhận được xác thực cùng ciphertext.
- Giao thức dùng JSON theo từng dòng, giới hạn mỗi frame ở 64 KiB. Server kiểm tra danh tính và phòng rồi chỉ chuyển ciphertext đến đúng người nhận. Server không lưu lịch sử hoặc ghi nội dung chat vào log.

Server vẫn nhìn thấy username, phòng, thời điểm và kích thước gói tin; server cũng có thể trì hoãn hoặc bỏ gói. TLS bảo vệ đường truyền client-server, còn AES-GCM bảo vệ nội dung chat khỏi relay.

## 4. Kiểm thử

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Các kiểm thử bao gồm giới hạn frame, xác minh chứng thư/chữ ký, mã hóa và phát hiện sửa đổi, từ chối client không tin cậy, định tuyến riêng, cách ly phòng, và trao đổi thật qua TLS trên loopback.

## 5. Giới hạn và lưu ý

Đây là bài thực hành cục bộ, không phải dịch vụ triển khai Internet. Không mở cổng ra Internet, không tái sử dụng CA/client key cho hệ thống thật, và không commit thư mục `certs/`. Các khóa riêng, chứng thư và log cục bộ đã được Git bỏ qua.

Trong PDF đề bài có một chuỗi trông giống mật khẩu ứng dụng SMTP. Giá trị đó không liên quan đến SecureChat và không được đưa vào mã nguồn hay repository; nếu đó là thông tin thật, hãy thu hồi/đổi mật khẩu.
