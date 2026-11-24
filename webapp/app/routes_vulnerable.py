from flask import Blueprint, make_response, redirect, render_template, request, url_for
import psycopg2
from psycopg2 import errors as pg_errors

from .db import get_db_connection

vulnerable_bp = Blueprint("vulnerable", __name__, url_prefix="/vulnerable")


@vulnerable_bp.route("/")
def index():
    return redirect(url_for("vulnerable.products"))


@vulnerable_bp.route("/login", methods=["GET", "POST"])
def login():
    user = None
    error = None
    defense_blocked = None
    executed_query = None
    username = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # SENGAJA RENTAN (DEMO UAS): String concatenation langsung ke SQL
        executed_query = (
            "SELECT id, username, role, email FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )

        conn = None
        try:
            conn = get_db_connection()
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(executed_query)
                if cur.description is not None:
                    user = cur.fetchone()
                if not user:
                    error = "Login gagal: kombinasi username dan password tidak ditemukan."
        except pg_errors.InsufficientPrivilege as exc:
            defense_blocked = (
                "Layer 4 (Database Least Privilege) memblokir perintah destruktif! "
                f"PostgreSQL Error [{exc.pgcode}]: {str(exc).strip()}"
            )
        except psycopg2.Error as exc:
            # Sengaja menampilkan pesan error SQL (verbose error leakage pada mode vulnerable)
            error = f"Database Error [{exc.pgcode}]: {str(exc).strip()}"
        finally:
            if conn:
                conn.close()

    resp = make_response(
        render_template(
            "login.html",
            mode="vulnerable",
            username=username,
            user=user,
            error=error,
            defense_blocked=defense_blocked,
            executed_query=executed_query,
        )
    )
    if defense_blocked:
        resp.headers["X-Defense-Layer"] = "DB-Least-Privilege"
    return resp


@vulnerable_bp.route("/products", methods=["GET"])
def products():
    q = request.args.get("q", "")
    items = []
    error = None
    defense_blocked = None

    # SENGAJA RENTAN (DEMO UAS): String concatenation langsung ke klausa WHERE
    if q:
        executed_query = (
            "SELECT id, name, category, price, stock, description FROM products "
            f"WHERE name ILIKE '%{q}%' OR category ILIKE '%{q}%' ORDER BY id"
        )
    else:
        executed_query = (
            "SELECT id, name, category, price, stock, description "
            "FROM products ORDER BY id"
        )

    conn = None
    try:
        conn = get_db_connection()
        conn.autocommit = True
        with conn.cursor() as cur:
            # Demonstrasi operasi INSERT sah oleh app_user (Least Privilege)
            if q:
                try:
                    cur.execute(
                        "INSERT INTO search_logs (endpoint_mode, query_text) VALUES (%s, %s)",
                        ("vulnerable", q[:500]),
                    )
                except psycopg2.Error:
                    pass

            cur.execute(executed_query)
            if cur.description is not None:
                items = cur.fetchall()
    except pg_errors.InsufficientPrivilege as exc:
        defense_blocked = (
            "Layer 4 (Database Least Privilege) memblokir aksi destruktif terhadap database! "
            f"PostgreSQL Error [{exc.pgcode}]: {str(exc).strip()}"
        )
    except psycopg2.Error as exc:
        error = f"Database Error [{exc.pgcode}]: {str(exc).strip()}"
    finally:
        if conn:
            conn.close()

    resp = make_response(
        render_template(
            "products.html",
            mode="vulnerable",
            q=q,
            products=items,
            error=error,
            defense_blocked=defense_blocked,
            executed_query=executed_query,
        )
    )
    if defense_blocked:
        resp.headers["X-Defense-Layer"] = "DB-Least-Privilege"
    return resp
