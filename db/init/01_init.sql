-- =============================================================================
-- Defense-in-Depth Layer 4: Database Schema, Seed Data & Least Privilege RBAC
-- Dieksekusi sekali saat inisialisasi PostgreSQL sebagai superuser (postgres_admin)
-- =============================================================================

-- 1. Bersihkan izin default PUBLIC pada database & schema public (Hardening)
REVOKE ALL ON DATABASE cloudshop_db FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- 2. Buat tabel aplikasi (dimiliki oleh superuser postgres_admin, BUKAN app_user)
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(64)  NOT NULL UNIQUE,
    password    VARCHAR(128) NOT NULL,
    role        VARCHAR(32)  NOT NULL DEFAULT 'customer',
    email       VARCHAR(128) NOT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(120)   NOT NULL,
    category    VARCHAR(64)    NOT NULL,
    price       NUMERIC(12, 2) NOT NULL,
    stock       INTEGER        NOT NULL DEFAULT 0,
    description TEXT           NOT NULL
);

CREATE TABLE IF NOT EXISTS search_logs (
    id            SERIAL PRIMARY KEY,
    endpoint_mode VARCHAR(32) NOT NULL,
    query_text    TEXT        NOT NULL,
    created_at    TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Seed Data Pengguna (untuk simulasi Login & uji dampak ekstraksi data SQLi)
INSERT INTO users (username, password, role, email) VALUES
    ('admin', 'AdminCloud#2026', 'administrator', 'admin@cloudshop.local'),
    ('budi',  'BudiPass123!',    'customer',      'budi@cloudshop.local'),
    ('sinta', 'SintaSec456!',    'sec_analyst',   'sinta@cloudshop.local')
ON CONFLICT (username) DO NOTHING;

-- 4. Seed Data Produk Cloud & Keamanan Siber
INSERT INTO products (name, category, price, stock, description) VALUES
    ('Cloud WAF Enterprise',      'Network Security', 450.00, 25, 'Managed Web Application Firewall berbasis OWASP CRS dengan proteksi SQLi dan XSS.'),
    ('VPC Zero-Trust Gateway',    'Cloud Networking', 320.00, 40, 'Segmentasi subnet private/public otomatis dengan inspeksi trafik east-west.'),
    ('Managed PostgreSQL Shield', 'Database',         280.00, 30, 'Database terkelola dengan enkripsi at-rest, audit logging, dan RBAC ketat.'),
    ('SIEM Log Analyzer Pro',     'Monitoring',       510.00, 15, 'Korelasi log real-time untuk deteksi anomali serangan aplikasi web.'),
    ('Cloud HSM Key Vault',       'Cryptography',     690.00, 10, 'Hardware Security Module terdedikasi untuk manajemen kunci enkripsi cloud.'),
    ('DDoS Mitigation Edge',      'Network Security', 390.00, 50, 'Proteksi L3/L4/L7 di tepi jaringan dengan rate limiting adaptif.');

-- 5. Prinsip Least Privilege: Buat role aplikasi terbatas (app_user)
-- Password ini selaras dengan APP_DB_USER & APP_DB_PASSWORD pada .env
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user WITH
            LOGIN
            PASSWORD 'AppUserSecurePass!2026'
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOREPLICATION;
    END IF;
END
$$;

-- Proteksi tambahan terhadap Time-Based Blind SQLi (misal pg_sleep)
ALTER ROLE app_user SET statement_timeout = '5s';

-- 6. Berikan HANYA hak minimum yang diperlukan aplikasi:
--    - CONNECT ke database aplikasi
--    - USAGE pada schema public (TANPA CREATE, sehingga tidak bisa buat/hapus objek)
--    - SELECT, INSERT, UPDATE pada tabel aplikasi (TANPA DELETE, TRUNCATE, DROP, ALTER)
--    - USAGE, SELECT pada sequence untuk mendukung operasi INSERT SERIAL
GRANT CONNECT ON DATABASE cloudshop_db TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;

GRANT SELECT, INSERT, UPDATE ON TABLE users       TO app_user;
GRANT SELECT, INSERT, UPDATE ON TABLE products    TO app_user;
GRANT SELECT, INSERT, UPDATE ON TABLE search_logs TO app_user;

GRANT USAGE, SELECT ON SEQUENCE users_id_seq       TO app_user;
GRANT USAGE, SELECT ON SEQUENCE products_id_seq    TO app_user;
GRANT USAGE, SELECT ON SEQUENCE search_logs_id_seq TO app_user;

-- Eksplisit memastikan hak destruktif tidak dimiliki oleh app_user
REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE users, products, search_logs FROM app_user;
REVOKE CREATE ON SCHEMA public FROM app_user;
