import os
import psycopg2
from psycopg2.extras import RealDictCursor


def get_db_connection():
    """Membuka koneksi ke PostgreSQL menggunakan kredensial app_user (Least Privilege)."""
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "db"),
        port=int(os.environ.get("DB_PORT", "5432")),
        dbname=os.environ.get("DB_NAME", "cloudshop_db"),
        user=os.environ.get("DB_USER", "app_user"),
        password=os.environ.get("DB_PASSWORD", ""),
        connect_timeout=5,
        cursor_factory=RealDictCursor,
    )


def get_db_security_status():
    """Mengambil informasi live mengenai role aktif dan hak akses Least Privilege di DB."""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    current_user AS db_user,
                    current_database() AS db_name,
                    (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_superuser,
                    has_table_privilege(current_user, 'products', 'SELECT') AS can_select,
                    has_table_privilege(current_user, 'products', 'INSERT') AS can_insert,
                    has_table_privilege(current_user, 'products', 'UPDATE') AS can_update,
                    has_table_privilege(current_user, 'products', 'DELETE') AS can_delete,
                    has_schema_privilege(current_user, 'public', 'CREATE') AS can_create_schema
                """
            )
            row = cur.fetchone()
            return dict(row) if row else {}
    finally:
        if conn:
            conn.close()
