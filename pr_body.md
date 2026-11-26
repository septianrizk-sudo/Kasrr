## Authentication Security Audit & Hardening Specification (REVISI 2)

This PR contains two deliverables:

### 1. Security Audit Report (`AUDIT_AUTHENTICATION.md`)
Critical vulnerabilities found in the authentication system:
- Default credentials: PIN `1234`, Master Code `888888` (line 170)
- Weak 4-6 digit PIN entropy (line 784)
- Non-cryptographic custom hash without salt (line 160)
- Master Code reset reverts PIN to `1234` (line 791)
- No rate limiting, client-side only validation, plaintext localStorage

### 2. Security Hardening Specification (`SECURITY_HARDENING_SPEC.md`) — R2 + R3
Evaluation & refined plan based on Owner Final Decisions (1–6) plus revision notes.

**Recovery Wizard (R2/R3):**
- Master Code lama valid sampai atomic commit sukses (tidak di-hangus prematur)
- Owner membuat & konfirmasi Master Code baru (min 12 char) + PIN baru (4-6 digit)
- Verifikasi kedua credential baru sebelum commit
- **Satu atomic commit**: simpan PIN baru + Master baru, hangus Master lama
- Candidate state/snapshot sebelum `save()`; rollback otomatis jika gagal
- `save()` diperbaiki mengembalikan boolean status; unlock hanya setelah `save() === true`
- **Resume app**: wajib verifikasi ulang Master lama — `masterVerified` tidak permanen
- Master Code pengganti tidak auto-generate one-shot

**Kriptografi final:**
- PBKDF2-HMAC-SHA-256, 600k iterasi, salt 16B, output 256b base64url
- Fallback hash custom DILARANG → fail closed
- Semua async (`await`)

**Migrasi & backup:**
- Legacy migrasi idempoten (field utuh sampai commit atomik)
- Backup envelope credential dikecualikan default; opt-in + peringatan
- Restore tidak menurunkan keamanan diam-diam

**Web Crypto verification on real APK (WebIntoApp):**
- Probe `crypto.getRandomValues`, `crypto.subtle`, PBKDF2 roundtrip, envelope storage
- Fail closed bila gagal

**Risiko tersisa:**
1. PIN 4-6 digit → entropi rendah; offline brute-force mungkin
2. Rate limit lokal manipulable oleh pemilik perangkat
3. Offline WebView ≠ server auth
4. Backup envelope (opt-in) → risiko kebocoran file & pemulihan credential lama
5. XSS via UI (L721-724) → envelope readable
6. WebView lawas tanpa Web Crypto → fitur security tidak aktif

**Test plan T1–T25** (termasuk T24: resume wajib verifikasi ulang Master; T25: simulasi localStorage gagal).

**Branch content:** 2 dokumen baru (`AUDIT_AUTHENTICATION.md`, `SECURITY_HARDENING_SPEC.md`). APK (`KasirKopi.apk`) sudah ada di base branch `kilo/rainy-tide-phw`, tidak ditambahkan oleh PR ini. Tidak ada kode aplikasi yang diubah.

**Note:** PR for review/approval only. No code modified. Awaiting owner approval. Do not merge.