# Product Requirements Document (PRD)

## Automated External Attack Surface & Brand Threat Intelligence Monitor

| Metadata Dokumen | Keterangan | 
| ----- | ----- | 
| **Nama Proyek** | Automated External Attack Surface & Brand Threat Intelligence Monitor | 
| **Versi Dokumen** | 1.0.0 (Development-Ready) | 
| **Kategori** | Cybersecurity / Cyber Threat Intelligence (CTI) / OSINT Automation | 
| **Target Deployment** | CLI Worker + Containerized Service (Docker) + SQL Database | 
| **Tech Stack Utama** | Python 3.11+, SQLite / PostgreSQL, Docker, AsyncIO, Jinja2 | 

## 1. Ringkasan Eksekutif & Visi Produk

### 1.1 Latar Belakang Masalah

Organisasi modern memiliki aset digital yang terus berkembang (subdomain baru, layanan *cloud*, sertifikat SSL/TLS). Aset yang dibuat tanpa pencatatan terpusat (*shadow IT*) sering kali luput dari pemantauan tim keamanan dan menjadi titik masuk awal serangan. Di sisi lain, pelaku ancaman kerap mendaftarkan domain tiruan (*typosquatting*) untuk melancarkan kampanye *phishing* terhadap pelanggan maupun karyawan organisasi. Pemeriksaan manual memakan waktu lama dan gagal mendeteksi perubahan secara berkala.

### 1.2 Solusi yang Dibangun

Sistem ini adalah mesin intelijen sumber terbuka (*OSINT engine*) otomatis berbasis Python yang melakukan pemantauan pasif secara terjadwal terhadap dua vektor utama:

1. **External Attack Surface Monitoring (EASM):** Menginventarisasi subdomain, catatan DNS, dan sertifikat publik milik domain target, lalu memperkaya data alamat IP dengan informasi layanan terbuka serta kerentanan (*CVE*) menggunakan sumber data pasif tanpa melakukan pemindaian intrusif.

2. **Typosquatting & Phishing Infrastructure Detection:** Menghasilkan permutasi nama domain yang menyerupai target, memeriksa status registrasi DNS/WHOIS-nya, dan mendeteksi domain tiruan aktif yang berpotensi digunakan untuk *phishing*.

Sistem ini menyimpan setiap hasil pemindaian ke dalam basis data relasional untuk membandingkan perubahan antarwaktu (*state diffing*) dan mengirimkan peringatan otomatis (*real-time alert*) apabila ditemukan aset baru atau perubahan berisiko tinggi.

### 1.3 Nilai Tambah Portofolio

Projek ini dirancang untuk mendemonstrasikan kompetensi inti yang dicari pada posisi **SOC Analyst, Threat Intelligence Analyst, dan Security Engineer**:

* Kemampuan mengintegrasikan beragam API dan sumber OSINT menjadi satu alur kerja otomatis (*data pipeline*).

* Penerapan prinsip *passive reconnaissance* yang patuh terhadap batas legalitas dan etika.

* Kemampuan *data modeling* (SQL), deteksi anomali berbasis perubahan (*delta/diff detection*), serta penyusunan laporan intelijen yang siap ditindaklanjuti (*actionable reporting*).

## 2. Batasan Etika, Legalitas & Rules of Engagement (RoE)

Seluruh pengembangan dan pengujian sistem **wajib** mematuhi aturan berikut:

1. **100% Passive Reconnaissance:** Sistem dilarang mengirimkan paket pemindaian port aktif (seperti *SYN scan* Nmap) atau melakukan *brute-force* direktori/kredensial ke server target. Seluruh informasi port dan kerentanan diambil dari repositori intelijen pasif (contoh: Shodan InternetDB, Certificate Transparency logs).

2. **Authorized Scope Only:** Pengujian hanya boleh dilakukan terhadap domain milik pribadi pengembang, infrastruktur lab pengujian, atau domain yang terdaftar dalam program *Bug Bounty* publik dengan cakupan (*scope*) yang secara eksplisit mengizinkan *passive OSINT*.

3. **Rate Limiting & Respectful Scraping:** Setiap permintaan ke API eksternal wajib menerapkan pembatasan laju (*rate limiting*) dan mekanisme *exponential backoff* agar tidak membebani layanan pihak ketiga.

4. **Data Privacy & PII Redaction:** Jika hasil kueri WHOIS atau catatan publik menampilkan informasi identitas pribadi (*Personally Identifiable Information* / PII), sistem harus menyamarkannya (*redaction*) sebelum disimpan atau dipublikasikan pada laporan portofolio.

## 3. Target Pengguna & User Stories

### 3.1 Persona Pengguna

* **Cyber Threat Intelligence (CTI) / SOC Analyst:** Membutuhkan visibilitas harian atas aset eksternal perusahaan yang baru terekspos dan peringatan dini jika muncul domain tiruan yang berpotensi dipakai untuk kampanye *phishing*.

### 3.2 User Stories & Acceptance Criteria

| ID | User Story | Acceptance Criteria (Kriteria Penerimaan) | 
| ----- | ----- | ----- | 
| **US-01** | Sebagai Analis, saya ingin mendaftarkan domain target beserta konfigurasi pemindaian melalui file konfigurasi agar cakupan pemantauan terkendali. | • Sistem membaca daftar domain dari `config.yaml`.  • Sistem memvalidasi format domain dan menolak input di luar *authorized scope* jika daftar pengecualian (*exclude_subdomains*) dikonfigurasi. | 
| **US-02** | Sebagai Analis, saya ingin sistem mengumpulkan subdomain secara pasif dari sumber publik agar seluruh permukaan serangan eksternal terinventarisasi. | • Sistem menarik data dari *Certificate Transparency logs* (`crt.sh`) dan sumber pasif pendukung.  • Hasil deduplikasi subdomain disimpan ke tabel basis data beserta catatan DNS (`A`, `AAAA`, `CNAME`, `MX`). | 
| **US-03** | Sebagai Analis, saya ingin memperkaya setiap alamat IP aktif dengan data port terbuka dan CVE pasif agar aset berisiko tinggi segera teridentifikasi. | • Sistem mengkueri API pasif (seperti Shodan InternetDB) untuk setiap IP unik.  • Sistem menyimpan daftar port, *CPE*, dan *CVE* terkait tanpa mengirim paket langsung ke server target. | 
| **US-04** | Sebagai Analis, saya ingin mendeteksi domain *typosquatting* yang baru aktif agar potensi kampanye *phishing* dapat dimitigasi lebih awal. | • Sistem menghasilkan permutasi domain (omission, homoglyph, transposition, TLD swap).  • Sistem memverifikasi resolusi DNS dan tanggal registrasi domain tiruan.  • Domain yang memiliki catatan `A` atau `MX` aktif ditandai sebagai *High Risk*. | 
| **US-05** | Sebagai Analis, saya ingin sistem membandingkan hasil pemindaian terbaru dengan pemindaian sebelumnya (*diffing*) agar saya hanya fokus pada perubahan baru. | • Sistem mendeteksi subdomain baru, perubahan alamat IP, pembukaan port baru, atau munculnya CVE baru dibanding `scan_run` sebelumnya.  • Perubahan diklasifikasikan berdasarkan tingkat keparahan (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). | 
| **US-06** | Sebagai Analis, saya ingin menerima notifikasi otomatis ketika temuan berisiko tinggi muncul agar respons insiden berjalan cepat. | • Sistem mengirim payload peringatan terstruktur ke Telegram Bot / Discord / Slack Webhook saat ditemukan temuan dengan tingkat keparahan di atas ambang batas (*threshold*). | 
| **US-07** | Sebagai Analis, saya ingin mengekspor laporan ringkasan eksekutif dan *Indicators of Compromise* (IoC) agar mudah dibagikan ke tim teknis maupun manajemen. | • Sistem menghasilkan laporan HTML/Markdown otomatis menggunakan Jinja2.  • Sistem mengekspor feed IoC dalam format JSON dan CSV standar. | 

## 4. Arsitektur Sistem & Alur Kerja Data

### 4.1 Diagram Arsitektur Pipeline

```
+-------------------+      +-------------------------------------------+
|   config.yaml     | ---> |           Orchestrator (main.py)          |
|  & .env Secrets   |      +-------------------------------------------+
+-------------------+                            |
                                                 v
                    +----------------------------+----------------------------+
                    |                                                         |
                    v                                                         v
    +-------------------------------+                         +-------------------------------+
    |    Module 1: EASM Collector   |                         | Module 2: Typosquat Collector |
    | - crt.sh (CT Logs)            |                         | - Permutasi Nama Domain       |
    | - Passive DNS Enumeration     |                         | - Async DNS Resolution        |
    | - Async DNS (A, CNAME, MX)    |                         | - RDAP / WHOIS Metadata       |
    +-------------------------------+                         +-------------------------------+
                    |                                                         |
                    +----------------------------+----------------------------+
                                                 |
                                                 v
                    +---------------------------------------------------------+
                    |              Module 3: Enrichment Engine                |
                    | - Shodan InternetDB (Passive Ports, Tags, CPEs, CVEs)   |
                    | - ASN & Geolocation Lookup                              |
                    | - PII Redaction Filter                                  |
                    +---------------------------------------------------------+
                                                 |
                                                 v
                    +---------------------------------------------------------+
                    |           Module 4: Storage & State Diff Engine         |
                    | - SQLite / PostgreSQL (SQLAlchemy ORM)                  |
                    | - Delta Comparison (New Subdomain / Port / CVE / Spoof) |
                    | - Risk Scoring Engine (LOW -> CRITICAL)                 |
                    +---------------------------------------------------------+
                                                 |
                                                 v
                    +---------------------------------------------------------+
                    |          Module 5: Alerting & Reporting Engine          |
                    | - Real-Time Webhook (Telegram / Slack / Discord)        |
                    | - Jinja2 Executive Summary Report (HTML / Markdown)     |
                    | - Structured IoC Export (JSON / CSV)                    |
                    +---------------------------------------------------------+

```

### 4.2 Struktur Direktori Proyek

```
passive-easm-threat-monitor/
├── config/
│   └── config.yaml              # Konfigurasi target domain, threshold alert, & modul aktif
├── src/
│   ├── __init__.py
│   ├── main.py                  # Entry point CLI & orkestrator pipeline
│   ├── config_loader.py         # Validasi schema konfigurasi (Pydantic)
│   ├── collectors/
│   │   ├── crtsh_collector.py   # Pengambil subdomain dari Certificate Transparency
│   │   ├── dns_resolver.py      # Async DNS resolver (dnspython / aiodns)
│   │   └── typosquat.py         # Generator & verifikator domain tiruan
│   ├── enrichment/
│   │   ├── internetdb.py        # Klien pasif Shodan InternetDB API
│   │   └── sanitizer.py         # Penyaring & penyamar PII (redaction)
│   ├── core/
│   │   ├── database.py          # Model SQLAlchemy & manajemen sesi DB
│   │   ├── diff_engine.py       # Komparasi state antar scan_run
│   │   └── risk_scorer.py       # Kalkulasi skor & severity temuan
│   └── outputs/
│       ├── notifier.py          # Pengirim alert Webhook (Telegram/Slack)
│       └── reporter.py          # Generator laporan Jinja2 & export IoC
├── templates/
│   └── executive_report.md.j2   # Template laporan intelijen
├── tests/
│   ├── test_diff_engine.py
│   ├── test_typosquat.py
│   └── test_sanitizer.py
├── .env.example                 # Template environment variables
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md

```

## 5. Spesifikasi Fungsional per Modul

### 5.1 EASM Collector (`collectors/crtsh_collector.py` & `dns_resolver.py`)

* **Input:** Root domain dari `config.yaml` (contoh: `example.com`).

* **Proses:**

  1. Mengirim permintaan HTTP GET asinkron ke `https://crt.sh/?q=%25.{domain}&output=json`.

  2. Membersihkan entri wildcard (`*.example.com`), menghapus duplikat, dan memfilter subdomain yang masuk daftar pengecualian.

  3. Melakukan resolusi DNS secara asinkron menggunakan `dnspython` (`dns.asyncresolver`) dengan batas konkurensi (*semaphore*) maksimal 20 kueri/detik untuk mengambil catatan `A`, `AAAA`, `CNAME`, dan `MX`.

* **Error Handling:** Jika `crt.sh` mengembalikan HTTP 429 atau 503, sistem menerapkan *retry* maksimal 3 kali dengan jeda eksponensial (2s, 4s, 8s).

### 5.2 Typosquatting Collector (`collectors/typosquat.py`)

* **Input:** Root domain target.

* **Proses:**

  1. Menghasilkan variasi domain menggunakan algoritma permutasi dasar:

     * *Character omission* (`exmple.com`)

     * *Character repetition* (`exampple.com`)

     * *Adjacent character transposition* (`examlpe.com`)

     * *Hyphenation* (`ex-ample.com`)

     * *Common TLD swap* (`.net`, `.org`, `.co`, `.id`, `.xyz`)

  2. Melakukan pengecekan DNS `A` dan `MX` pada seluruh kandidat permutasi.

  3. Hanya menyimpan kandidat yang memiliki catatan DNS aktif (*registered & resolving*) untuk menghindari penumpukan data sampah.

  4. Mengambil metadata registrasi dasar melalui protokol **RDAP** publik dan menjalankan filter penyamaran PII pada kontak pendaftar.

### 5.3 Passive Enrichment Engine (`enrichment/internetdb.py`)

* **Input:** Daftar alamat IPv4 unik hasil resolusi DNS subdomain.

* **Proses:**

  1. Mengkueri endpoint pasif `https://internetdb.shodan.io/{ip}`.

  2. Mengekstrak daftar `ports`, `hostnames`, `cpes`, `tags`, dan `vulns` (daftar ID CVE).

  3. Menyimpan hasil pengayaan ke tabel `ip_enrichments` dengan penanda waktu (*timestamp*).

### 5.4 State Diff & Risk Scoring Engine (`core/diff_engine.py` & `risk_scorer.py`)

* **Logika Perbandingan (*Diffing*):** Membandingkan `scan_run` saat ini ($T_n$) dengan `scan_run` sukses terakhir ($T_{n-1}$) untuk target yang sama.

* **Aturan Penilaian Risiko (*Severity Rules*):**

  * **CRITICAL:** Subdomain baru terekspos dengan port sensitif terbuka (contoh: `22`, `23`, `445`, `3389`, `6379`, `9200`, `27017`) ATAU memiliki kerentanan `CVE` yang diketahui.

  * **HIGH:** Ditemukan domain *typosquatting* baru yang memiliki catatan `MX` aktif (siap mengirim email *phishing*) atau catatan `A` aktif, ATAU terdeteksi port baru pada aset yang sudah ada.

  * **MEDIUM:** Ditemukan subdomain baru yang aktif dengan port web standar (`80`, `443`) tanpa CVE, atau perubahan alamat IP (*DNS A record change*).

  * **LOW:** Ditemukan subdomain baru di *Certificate Transparency logs* namun belum memiliki resolusi DNS aktif (*NXDOMAIN*).

## 6. Desain Basis Data (SQL Schema)

Skema berikut kompatibel dengan **SQLite** (untuk pengembangan lokal) maupun **PostgreSQL** (untuk deployment produksi):

```
-- 1. Tabel Domain Target
CREATE TABLE targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain VARCHAR(255) NOT NULL UNIQUE,
    is_active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabel Riwayat Eksekusi Pemindaian
CREATE TABLE scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    started_at TIMESTAMP NOT NULL,
    finished_at TIMESTAMP,
    status VARCHAR(20) NOT NULL, -- RUNNING, COMPLETED, FAILED
    total_subdomains INTEGER DEFAULT 0,
    new_findings_count INTEGER DEFAULT 0,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- 3. Tabel Inventaris Subdomain
CREATE TABLE subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    fqdn VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    cname_record VARCHAR(255),
    mx_records TEXT,
    is_resolving BOOLEAN DEFAULT 0,
    first_seen_run_id INTEGER NOT NULL,
    last_seen_run_id INTEGER NOT NULL,
    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(target_id, fqdn),
    FOREIGN KEY (target_id) REFERENCES targets(id),
    FOREIGN KEY (first_seen_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY (last_seen_run_id) REFERENCES scan_runs(id)
);

-- 4. Tabel Pengayaan Pasif Alamat IP
CREATE TABLE ip_enrichments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    open_ports TEXT,       -- JSON array, contoh: [80, 443, 8080]
    cves TEXT,             -- JSON array, contoh: ["CVE-2023-XXXX"]
    cpes TEXT,             -- JSON array
    tags TEXT,             -- JSON array
    enriched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

-- 5. Tabel Pemantauan Domain Typosquatting
CREATE TABLE typosquat_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    spoof_domain VARCHAR(255) NOT NULL,
    permutation_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    has_mx_record BOOLEAN DEFAULT 0,
    registrar VARCHAR(255),
    registration_date VARCHAR(50),
    first_seen_run_id INTEGER NOT NULL,
    last_seen_run_id INTEGER NOT NULL,
    UNIQUE(target_id, spoof_domain),
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- 6. Tabel Catatan Perubahan & Peringatan (Alerts / Diffs)
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    category VARCHAR(50) NOT NULL, -- NEW_SUBDOMAIN, NEW_PORT, NEW_CVE, TYPOSQUAT_ACTIVE
    severity VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    indicator VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    is_notified BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

```

## 7. Kontrak Data & Konfigurasi

### 7.1 Contoh File Konfigurasi (`config/config.yaml`)

```
project:
  name: "Passive EASM & Brand Threat Intelligence Monitor"
  environment: "development"

database:
  url: "sqlite:///data/threat_intel.db"

targets:
  - domain: "example.com"
    enable_easm: true
    enable_typosquat: true
    exclude_subdomains:
      - "dev-sandbox.example.com"

collector_settings:
  dns_concurrency: 20
  request_timeout_sec: 10
  sensitive_ports: [21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017]

alerting:
  enabled: true
  min_severity: "HIGH" # Hanya kirim notifikasi real-time untuk HIGH & CRITICAL
  webhook_provider: "telegram" # telegram | slack | discord

reporting:
  output_dir: "./reports"
  export_formats: ["markdown", "json", "csv"]

```

### 7.2 Skema Output Feed IoC (`ioc_feed.json`)

```
{
  "metadata": {
    "generated_at": "2026-11-26T01:30:00Z",
    "target_domain": "example.com",
    "scan_run_id": 14,
    "total_new_findings": 2
  },
  "indicators": [
    {
      "indicator_type": "domain-name",
      "indicator_value": "examp1e.com",
      "category": "TYPOSQUAT_ACTIVE",
      "severity": "HIGH",
      "attributes": {
        "permutation_type": "homoglyph",
        "resolved_ip": "198.51.100.42",
        "has_mx_record": true
      },
      "recommended_action": "Ajukan takedown domain dan blokir domain pengirim pada Secure Email Gateway."
    },
    {
      "indicator_type": "ipv4-addr",
      "indicator_value": "203.0.113.88",
      "category": "NEW_PORT",
      "severity": "CRITICAL",
      "attributes": {
        "associated_subdomain": "staging-api.example.com",
        "exposed_ports": [443, 6379],
        "cves": []
      },
      "recommended_action": "Verifikasi kepemilikan aset staging-api.example.com dan batasi akses port Redis (6379) dari internet publik."
    }
  ]
}

```

## 8. Kebutuhan Non-Fungsional (NFR)

1. **Manajemen Kredensial:** Token API atau URL *webhook* (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`) dilarang keras ditulis di dalam kode sumber atau `config.yaml`; seluruh rahasia wajib dimuat melalui variabel lingkungan (`.env`).

2. **Observabilitas & Logging:** Menggunakan modul `logging` terstruktur dengan format standar (`[TIMESTAMP] [LEVEL] [MODULE] Message`) serta menyimpan log eksekusi ke file `logs/monitor.log`.

3. **Portabilitas Deployment:** Seluruh aplikasi dan dependensinya harus dikemas dalam `Dockerfile` ringan (`python:3.11-slim`) agar dapat dijalankan secara konsisten di lingkungan lokal maupun penjadwal otomatis (*cronjob* / GitHub Actions).

4. **Idempotensi:** Menjalankan pemindaian berulang kali pada data yang identik tidak boleh menghasilkan baris duplikat pada tabel `subdomains` maupun peringatan palsu berulang pada tabel `alerts`.

## 9. Rencana Pengujian (Testing & QA Strategy)

* **Unit Testing (`pytest`):**

  * Menguji fungsi permutasi `typosquat.py` menghasilkan variasi domain yang akurat tanpa duplikasi.

  * Menguji `sanitizer.py` berhasil menyamarkan alamat email dan nomor telepon pada sampel respons WHOIS/RDAP.

  * Menguji `diff_engine.py` menggunakan data tiruan (*mock data*) untuk memastikan deteksi port baru, subdomain baru, dan klasifikasi *severity* berjalan sesuai aturan.

* **Integration Testing:**

  * Menjalankan alur *end-to-end* penuh pada satu domain uji dengan database SQLite sementara dan memverifikasi pembuatan file `executive_report.md` serta `ioc_feed.json`.

## 10. Rencana Pengembangan 3 Minggu (Development Roadmap)

| Fase | Fokus Pekerjaan | Deliverable Utama | 
| ----- | ----- | ----- | 
| **Minggu 1: Fondasi & Kolektor** | Setup struktur repositori, validasi `config.yaml`, skema database SQLAlchemy, serta modul `crtsh_collector.py` dan `dns_resolver.py`. | Skrip CLI mampu menarik subdomain domain uji, menyelesaikan DNS secara asinkron, dan menyimpannya ke SQLite. | 
| **Minggu 2: Typosquatting, Enrichment & Diff** | Implementasi `typosquat.py`, integrasi pasif Shodan InternetDB (`internetdb.py`), penyaring PII, serta mesin `diff_engine.py` & `risk_scorer.py`. | Sistem mampu mendeteksi domain tiruan aktif, memperkaya IP dengan data CVE/port pasif, dan mencatat perubahan ke tabel `alerts`. | 
| **Minggu 3: Alerting, Reporting & Packaging** | Pembuatan template laporan Jinja2, exporter JSON/CSV, notifikasi Telegram/Slack Webhook, unit test `pytest`, `Dockerfile`, dan dokumentasi `README.md`. | Proyek siap dijalankan dalam kontainer Docker lengkap dengan contoh laporan intelijen dan dokumentasi portofolio di GitHub. | 
