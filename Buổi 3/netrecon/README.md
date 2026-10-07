# NetRecon — Lab 03

**Sinh viên:** Nguyễn Minh Trung
**MSSV:** 2387700072

NetRecon là công cụ thực hành kiểm tra dịch vụ trong private lab. Mỗi lần quét chỉ nhận **một địa chỉ IP literal** thuộc loopback hoặc mạng riêng được cấu hình trong allowlist. Công cụ không phân giải hostname, không quét subnet/range và kiểm tra blocklist trước khi mở socket.

## Cài đặt trên Windows

Mở PowerShell tại thư mục `Buổi 3/netrecon`:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Mặc định chỉ cho phép máy cục bộ:

```dotenv
NETRECON_ALLOWLIST=127.0.0.1/32,::1/128
NETRECON_BLOCKLIST=
NETRECON_RATE_PER_SECOND=2
NETRECON_TIMEOUT_SECONDS=1.5
NETRECON_MAX_CONCURRENCY=4
```

Chỉ thêm mạng RFC1918 hoặc IPv6 ULA khi đó là lab bạn được phép kiểm tra. Ví dụ mẫu bên dưới cần được thay bằng dải lab riêng của bạn:

```dotenv
NETRECON_ALLOWLIST=127.0.0.1/32,::1/128,10.10.20.0/24
```

Allowlist rỗng, sai định dạng, public hoặc vượt khỏi dải loopback/RFC1918/ULA sẽ bị từ chối. Blocklist luôn có ưu tiên cao hơn allowlist. Các biến môi trường của Windows có thể ghi đè giá trị trong `.env`.

## Dùng CLI

```powershell
.\.venv\Scripts\python.exe cli.py scan --target 127.0.0.1 --ports 22,80,443 --protocol both
.\.venv\Scripts\python.exe cli.py neighbors
.\.venv\Scripts\python.exe cli.py serve
```

- `scan` nhận danh sách cổng hoặc khoảng cổng; tối đa 128 cổng phân biệt.
- `--protocol` nhận `tcp`, `udp` hoặc `both`.
- `neighbors` chỉ đọc cache ARP/neighbor hiện có trên Windows, không dò các địa chỉ trong cache.
- JSON được lưu trong `reports/`; log xoay vòng nằm trong `logs/`. Hai thư mục, `.env` và `.venv/` được Git bỏ qua.

## Giao diện web

Chạy `cli.py serve`, sau đó mở [http://127.0.0.1:5000](http://127.0.0.1:5000). Flask chỉ bind loopback, tắt debug và reloader. Form dùng CSRF token; web không cho sửa allowlist hoặc giới hạn quét. JSON tải về dùng ID ngẫu nhiên trong bộ nhớ tiến trình và tối đa 20 report gần nhất được giữ lại.

## Cách đọc kết quả

- TCP connect thành công là `open`; bị từ chối là `closed`; hết thời gian chờ là `filtered`.
- UDP bị từ chối/không thể tới host là `closed`. Không có phản hồi được ghi là `open|filtered`, vì UDP im lặng không chứng minh cổng đóng.
- Khi TCP mở, NetRecon có thể đọc tối đa 512 byte banner, không gửi payload ứng dụng và loại bỏ ký tự điều khiển.
- Tên dịch vụ và ghi chú plaintext là gợi ý cục bộ để học tập. Chúng không xác nhận phần mềm, phiên bản hay lỗ hổng.

Giới hạn mặc định là 2 probe/giây, tối đa 4 probe đồng thời và timeout 1.5 giây. Có thể cấu hình rate trong khoảng 1–10, concurrency 1–4 và timeout 0.2–3 giây. NetRecon không có quét stealth/evasion, raw packet, SMTP, gửi email, credential check hay đánh giá CVE.

## Chạy kiểm thử

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```
