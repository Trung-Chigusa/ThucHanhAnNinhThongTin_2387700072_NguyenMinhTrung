# DAST Tool — Lab 05

Bộ demo kiểm thử động cục bộ với Flask: quan sát thông tin tiến trình, lấy mẫu bộ nhớ, đọc bộ đếm giao diện mạng, ghi nhận hành vi và chạy một tác vụ echo giới hạn.

## Cài đặt và chạy

Yêu cầu Python 3.10 trở lên.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

API chạy tại `http://127.0.0.1:5000/`; trang PoC minh họa tự động gửi chuỗi echo ở `/demo`. Có thể khởi động Flask API bằng `python app.py`.

| Endpoint | Kết quả |
|---|---|
| `GET /api/monitor` | CPU, RSS và tên cơ sở của file đang mở của tiến trình API |
| `GET /api/memory` | Một mẫu cấp phát và xu hướng heuristic |
| `GET /api/network` | Bộ đếm tổng hợp của card mạng, không thu thập payload |
| `GET /api/security` | Các sự kiện demo được ghi nhận |
| `POST /api/sandbox` | Nhận JSON `{"message":"hello"}` và trả kết quả echo |

## Kiểm thử

```powershell
python -m unittest discover -s tests -v
```

## Giới hạn an toàn

Sandbox chỉ chấp nhận dạng `echo` với chuỗi tối đa 256 ký tự; tiến trình con dùng argv cố định, `shell=False`, thư mục tạm riêng và timeout ngắn. Đây là wrapper minh họa, không phải sandbox hệ điều hành chống mã độc. API chỉ bind vào loopback khi chạy trực tiếp. Bộ phân tích mạng chỉ báo số byte/gói tổng hợp của các giao diện, không giải mã hay lưu lượng mạng thô. Xu hướng bộ nhớ là heuristic đơn giản, không phải kết luận rò rỉ.

Ảnh PoC và file SARIF mẫu được lưu trong `minh-chung/`.
