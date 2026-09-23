from flask import Flask, request, jsonify
from securevalidator.core import (
    validate_email, validate_url, validate_filename,
    sanitize_sql_input, sanitize_html_input
)
from securelogger.logger import get_secure_logger

app = Flask(__name__)
secure_logger = get_secure_logger()

@app.route("/validate", methods=["POST"])
def validate():
    try:
        data = request.get_json(force=True)
    except Exception as e:
        secure_logger.warning("Invalid JSON received",
                               extra={"data": str(request.data)})
        return jsonify({"error": "Invalid JSON format"}), 400

    results = {
        "email": validate_email(data.get("email", "")),
        "url": validate_url(data.get("url", "")),
        "filename": validate_filename(data.get("filename", "")),
        "sql": sanitize_sql_input(data.get("sql", "")),
        "html": sanitize_html_input(data.get("html", "")),
    }

    secure_logger.info("Validation check performed",
                        extra={"data": data, "results": results})
    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
