# SAST Tool — Lab 05

Công cụ SAST minh họa cho mã Python: phân tích AST, áp dụng rule/pattern, kiểm tra một số chỉ số chất lượng và xuất SARIF 2.1.0.

## Cài đặt và chạy

Yêu cầu Python 3.10 trở lên.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m sast_tool examples\vulnerable_01.py --output report.sarif
```

Có thể chỉ định bộ rule JSON riêng bằng `--rules path\to\rules.json`. Quy tắc mặc định ở `rules/default_rules.json`.

## Kiểm thử

```powershell
python -m unittest discover -s tests -v
```

## Thành phần

- `ASTAnalyzer`: phát hiện các lời gọi và cấu trúc Python đáng rà soát.
- `VulnPatternMatcher`: đối chiếu mã nguồn với pattern trong JSON.
- `SecurityRuleEngine`: chuẩn hóa và kết hợp kết quả theo mức độ.
- `CodeQualityChecker`: đo độ phức tạp, độ dài hàm, độ lồng nhau và dùng Flake8 nếu đã cài.
- `SarifReporter`: ghi kết quả có thể đọc bằng công cụ hỗ trợ SARIF.

Các rule là ví dụ phục vụ học tập, có thể phát hiện nhầm và không thay thế review hay scanner chuyên dụng. Hai file `examples/vulnerable_*.py` cố ý chứa mẫu không an toàn để kiểm chứng đầu ra.

Ảnh kết quả và file SARIF mẫu được lưu trong `minh-chung/`.
