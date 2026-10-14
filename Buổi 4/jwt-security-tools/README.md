# JWT Security Tools — Lab 04

Bộ công cụ minh họa xác thực JWT và quản lý vòng đời token chạy hoàn toàn cục bộ, phục vụ thực hành trên hệ thống do người học kiểm soát.

## Cài đặt và kiểm thử

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
```

## Gateway demo

Khởi chạy giao diện hướng dẫn trên loopback:

```powershell
.\.venv\Scripts\python.exe main.py --demo
```

Mở `http://127.0.0.1:5000/`. Gateway chỉ bind loopback, tắt debug/reloader và dùng secret ngẫu nhiên trong bộ nhớ. Lệnh demo in access token dùng một lần trong terminal, hết hạn sau 5 phút; không chụp hoặc chia sẻ token này. Gửi token đó tới tuyến `GET /protected` qua header `Authorization: Bearer <token>`.

Chạy demo vòng đời token không in token/secret:

```powershell
.\.venv\Scripts\python.exe main.py --demo-check
```

Demo xác nhận truy cập hợp lệ, thiếu bearer bị từ chối, refresh token được xoay vòng và phát hiện phát lại sẽ thu hồi cả họ token. Trạng thái refresh chỉ tồn tại trong bộ nhớ.

## Các module

- `jwt_validator`: chỉ chấp nhận chữ ký HS256, bắt buộc `exp`, tùy chọn kiểm tra `iss` và `aud`; lỗi trả về thông báo chung, không chứa token hoặc secret.
- `jwt_cracker`: kiểm tra tuần tự wordlist do người dùng cung cấp, tối đa 1.000 dòng và 1 MiB; không có chức năng mạng.
- `oauth_client`: dựng Authorization Code với `state` và PKCE S256; đổi code chỉ thông qua transport do caller truyền vào. Không cấu hình provider trực tiếp.
- `token_manager`: access token HS256 và refresh token ngẫu nhiên opaque; replay thu hồi cả family.
- `api_gateway`: Flask route bảo vệ bằng JWT; dùng test client để kiểm thử cục bộ.

Các kết quả heuristic/demo chỉ nhằm học tập, không thay cho kiểm thử bảo mật chuyên nghiệp. Không dùng lên hệ thống không thuộc quyền kiểm soát.

Bằng chứng chạy thật nằm trong `minh-chung/`.
