import os
from flask import Flask, jsonify, render_template

from .db import get_db_security_status, get_live_telemetry
from .routes_secure import secure_bp
from .routes_vulnerable import vulnerable_bp


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")

    app.register_blueprint(vulnerable_bp)
    app.register_blueprint(secure_bp)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.route("/")
    def home():
        db_status = {}
        telemetry = {}
        db_error = None
        try:
            db_status = get_db_security_status()
            telemetry = get_live_telemetry()
        except Exception as exc:
            db_error = str(exc)

        return render_template(
            "index.html",
            waf_mode=os.environ.get("WAF_MODE_INFO", "On"),
            crs_paranoia=os.environ.get("CRS_PARANOIA_INFO", "1"),
            db_status=db_status,
            telemetry=telemetry,
            db_error=db_error,
        )

    @app.route("/api/telemetry")
    def api_telemetry():
        try:
            db_status = get_db_security_status()
            telemetry = get_live_telemetry()
            return (
                jsonify(
                    {
                        "waf_mode": os.environ.get("WAF_MODE_INFO", "On"),
                        "crs_paranoia": os.environ.get("CRS_PARANOIA_INFO", "1"),
                        "db_status": db_status,
                        "telemetry": telemetry,
                    }
                ),
                200,
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 503

    @app.route("/health")
    def health():
        try:
            db_status = get_db_security_status()
            return (
                jsonify(
                    {
                        "status": "healthy",
                        "waf_mode_configured": os.environ.get("WAF_MODE_INFO", "On"),
                        "db_user": db_status.get("db_user"),
                        "db_is_superuser": db_status.get("is_superuser"),
                    }
                ),
                200,
            )
        except Exception as exc:
            return jsonify({"status": "unhealthy", "error": str(exc)}), 503

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
