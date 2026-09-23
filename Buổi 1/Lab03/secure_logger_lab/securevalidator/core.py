import re, html, urllib.parse, os

def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.fullmatch(pattern, email) is not None

def validate_url(url: str) -> bool:
    """Validate URL and prevent basic SSRF vectors."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)
    except Exception:
        return False

def validate_filename(filename: str) -> bool:
    """Prevent path traversal attacks."""
    if ".." in filename or "/" in filename or "\\" in filename:
        return False
    return os.path.basename(filename) == filename

def sanitize_sql_input(input_str: str) -> str:
    """Sanitize SQL input to prevent SQL injection."""
    sanitized = re.sub(r"(--|;|'|\"|#)", "", input_str)
    sanitized = re.sub(r"\b(OR|AND|SELECT|INSERT|DELETE|UPDATE|DROP|UNION|WHERE)\b",
                        "", sanitized, flags=re.IGNORECASE)
    return sanitized.strip()

def sanitize_html_input(html_str: str) -> str:
    """Escape HTML input to prevent XSS."""
    return html.escape(html_str)
