from flask import Blueprint, jsonify, make_response, redirect, render_template, request, url_for
import psycopg2

from .db import get_db_connection

secure_bp = Blueprint("secure", __name__, url_prefix="/secure")

MAX_INPUT_LENGTH = 100


def _wants_json():
    return (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in request.headers.get("Accept", "")
    )


def _serialize_rows(rows):
    result = []
    for row in rows:
        item = dict(row)
        if "price" in item and item["price"] is not None:
            item["price"] = float(item["price"])
        result.append(item)
    return result


@secure_bp.route("/")
def index():
    return redirect(url_for("secure.products"))


@secure_bp.route("/login", methods=["GET", "POST"])
def login():
    user = None
    error = None
    executed_query = None
    username = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "Username dan password wajib diisi."
        elif len(username) > MAX_INPUT_LENGTH or len(password) > MAX_INPUT_LENGTH:
            error = f"Panjang input melebihi batas maksimum ({MAX_INPUT_LENGTH} karakter)."
        else:
            # AMAN (LAYER 3): Parameterized Query - memisahkan struktur SQL dari data input
            sql_template = (
                "SELECT id, username, role, email FROM users "
                "WHERE username = %s AND password = %s"
            )
            executed_query = f"{sql_template}  -- params: (%s='{username}', %s='***')"

            conn = None
            try:
                conn = get_db_connection()
                with conn.cursor() as cur:
                    cur.execute(sql_template, (username, password))
                    user = cur.fetchone()
                if not user:
                    # Pesan error generik (tidak membocorkan detail SQL/database)
                    error = "Username atau password tidak valid."
            except psycopg2.Error:
                error = "Terjadi kesalahan layanan. Silakan coba beberapa saat lagi."
            finally:
                if conn:
                    conn.close()

    if request.method == "POST" and _wants_json():
        resp = make_response(
            jsonify(
                {
                    "mode": "secure",
                    "action": "login",
                    "outcome": "authenticated" if user else "blocked_layer3",
                    "defense_layer": "App-Parameterized-Query",
                    "user": dict(user) if user else None,
                    "error": error,
                    "defense_blocked": None,
                    "executed_query": executed_query,
                }
            )
        )
    else:
        resp = make_response(
            render_template(
                "login.html",
                mode="secure",
                username=username,
                user=user,
                error=error,
                defense_blocked=None,
                executed_query=executed_query,
            )
        )

    resp.headers["X-Defense-Layer"] = "App-Parameterized-Query"
    return resp


@secure_bp.route("/products", methods=["GET"])
def products():
    q = request.args.get("q", "").strip()
    items = []
    error = None
    executed_query = None

    if len(q) > MAX_INPUT_LENGTH:
        error = f"Kata kunci pencarian melebihi batas maksimum ({MAX_INPUT_LENGTH} karakter)."
    else:
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as cur:
                if q:
                    # Catat pencarian secara sah (app_user memiliki hak INSERT)
                    cur.execute(
                        "INSERT INTO search_logs (endpoint_mode, query_text) VALUES (%s, %s)",
                        ("secure", q),
                    )
                    conn.commit()

                    # AMAN (LAYER 3): Parameterized Query dengan placeholder %s
                    sql_template = (
                        "SELECT id, name, category, price, stock, description FROM products "
                        "WHERE name ILIKE %s OR category ILIKE %s ORDER BY id"
                    )
                    pattern = f"%{q}%"
                    executed_query = f"{sql_template}  -- params: ('{pattern}', '{pattern}')"
                    cur.execute(sql_template, (pattern, pattern))
                else:
                    sql_template = (
                        "SELECT id, name, category, price, stock, description "
                        "FROM products ORDER BY id"
                    )
                    executed_query = sql_template
                    cur.execute(sql_template)

                items = cur.fetchall()
        except psycopg2.Error:
            error = "Gagal memuat katalog produk. Silakan coba beberapa saat lagi."
        finally:
            if conn:
                conn.close()

    if _wants_json():
        serialized = _serialize_rows(items)
        resp = make_response(
            jsonify(
                {
                    "mode": "secure",
                    "action": "products",
                    "outcome": "blocked_layer3" if (q and len(serialized) == 0) else "ok",
                    "defense_layer": "App-Parameterized-Query",
                    "count": len(serialized),
                    "products": serialized,
                    "error": error,
                    "defense_blocked": None,
                    "executed_query": executed_query,
                }
            )
        )
    else:
        resp = make_response(
            render_template(
                "products.html",
                mode="secure",
                q=q,
                products=items,
                error=error,
                defense_blocked=None,
                executed_query=executed_query,
            )
        )

    resp.headers["X-Defense-Layer"] = "App-Parameterized-Query"
    return resp
