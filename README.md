# Defense-in-Depth: Mitigasi Serangan SQL Injection pada Arsitektur Cloud VPC

Proyek UAS **Komputasi Awan & Keamanan Siber** yang mensimulasikan arsitektur cloud lokal berbasis **Docker Compose** dengan pendekatan **Defense-in-Depth (4 Lapisan Pertahanan)** untuk memitigasi serangan **SQL Injection (SQLi)**.

---

## Arsitektur 4 Lapisan *Defense-in-Depth*

1. **Layer 1 — Network Segmentation (Simulasi VPC `172.20.0.0/16`)**
   - `public_net` (`172.20.1.0/24`): Subnet DMZ publik, hanya menghubungkan `waf` ke luar (port `8080`).
   - `private_app_net` (`172.20.2.0/24`, `internal: true`): Hanya menghubungkan `waf` <-> `webapp`.
   - `private_db_net` (`172.20.3.0/24`, `internal: true`): Hanya menghubungkan `webapp` <-> `db`. Database tidak terekspos ke host maupun ke kontainer WAF.
2. **Layer 2 — Perimeter / WAF (`owasp/modsecurity-crs:nginx-alpine`)**
   - Nginx + ModSecurity v3 + OWASP Core Rule Set (CRS).
   - Mode WAF dapat diubah melalui environment variable `MODSEC_RULE_ENGINE` (`On` / `DetectionOnly` / `Off`) pada file `.env`.
   - Audit log berformat JSON tersimpan di `logs/waf/audit.log`.
3. **Layer 3 — Application Security (`webapp` Flask + Gunicorn)**
   - `/vulnerable/login` & `/vulnerable/products`: Menggunakan *raw SQL string concatenation* (sengaja rentan untuk demonstrasi).
   - `/secure/login` & `/secure/products`: Menggunakan **Parameterized Queries** (`psycopg2` `%s`), validasi panjang input, serta *safe error handling*.
4. **Layer 4 — Database Least Privilege (`postgres:16-alpine`)**
   - Aplikasi berjalan menggunakan role `app_user` (bukan superuser & bukan pemilik tabel).
   - Hak akses dibatasi hanya `SELECT`, `INSERT`, `UPDATE` pada tabel aplikasi (`users`, `products`, `search_logs`) + `USAGE, SELECT` pada sequence.
   - Operasi destruktif (`DROP`, `ALTER`, `CREATE`, `DELETE`, `TRUNCATE`) otomatis ditolak oleh PostgreSQL.

---

## Cara Menjalankan Proyek

### 1. Siapkan Environment
```powershell
Copy-Item .env.example .env
```

### 2. Jalankan Seluruh Stack (Default: WAF Blocking Mode `On`)
```powershell
docker compose up -d --build
```
Akses aplikasi melalui browser di: **http://localhost:8080**

### 3. Mengganti Mode WAF (`On` / `DetectionOnly` / `Off`)
Ubah nilai `MODSEC_RULE_ENGINE` di `.env` atau jalankan langsung lewat environment variable PowerShell:

```powershell
# Mode DetectionOnly (mencatat SQLi di logs/waf/audit.log tanpa memblokir)
$env:MODSEC_RULE_ENGINE="DetectionOnly"; docker compose up -d --force-recreate waf webapp

# Mode Off (menguji Layer 3 & Layer 4 tanpa proteksi WAF)
$env:MODSEC_RULE_ENGINE="Off"; docker compose up -d --force-recreate waf webapp

# Kembali ke Mode Blocking (On)
$env:MODSEC_RULE_ENGINE="On"; docker compose up -d --force-recreate waf webapp
```

---

## Skenario Pengujian Otomatis (Demo UAS)

### A. Uji Isolasi Jaringan VPC (Layer 1)
```powershell
.\scripts\test_network_isolation.ps1
```

### B. Uji Matriks Serangan SQL Injection (Layer 2, 3, dan 4)
```powershell
.\scripts\test_sqli_scenarios.ps1
```

### C. Melihat Audit Log ModSecurity (WAF)
```powershell
Get-Content .\logs\waf\audit.log -Tail 20
```

---

## Ringkasan Matriks Bukti Pertahanan

| Mode WAF (`MODSEC_RULE_ENGINE`) | Target Endpoint | Payload Uji | Hasil yang Diharapkan | Lapisan Penahan |
| :--- | :--- | :--- | :--- | :--- |
| `On` | `/vulnerable/login` | `' OR '1'='1' --` | HTTP `403 Forbidden` | **Layer 2 (WAF)** |
| `DetectionOnly` | `/vulnerable/login` | `' OR '1'='1' --` | Bypass berhasil, tetapi tercatat di `logs/waf/audit.log` (`ruleId 942xxx`) | **Layer 2 (Deteksi)** |
| `DetectionOnly` / `Off` | `/secure/login` | `' OR '1'='1' --` | Login gagal (dianggap teks literal) | **Layer 3 (Parameterized Query)** |
| `DetectionOnly` / `Off` | `/secure/products` | `' UNION SELECT ... FROM users --` | 0 hasil, tidak ada kebocoran data | **Layer 3 (Parameterized Query)** |
| `DetectionOnly` / `Off` | `/vulnerable/products` | `'; DROP TABLE products; --` | Error `must be owner of table products`, tabel tetap utuh | **Layer 4 (DB Least Privilege)** |
| `DetectionOnly` / `Off` | `/vulnerable/products` | `'; DELETE FROM users; --` | Error `permission denied for table users`, data tetap utuh | **Layer 4 (DB Least Privilege)** |
