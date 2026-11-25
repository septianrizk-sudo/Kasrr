# KASRR — Security Hardening Specification (Evaluation)

**Status:** Perencanaan saja (planning mode). Tidak ada kode aplikasi yang diedit. Menunggu persetujuan owner sebelum implementasi.
**Basis:** Keputusan Final Owner (1–6) + temuan audit sebelumnya pada `Kasir Kopi (1).html` (877 baris).
**Branch:** `audit/authentication` (berbasis `main`). PR: [#4](https://github.com/septianrizk-sudo/Kasrr/pull/4) — tidak di-merge.

---

## 0. Evaluasi Keputusan Owner vs Implementasi Saat Ini

| Keputusan Owner | Kondisi Saat Ini (Bukti) | Evaluasi |
|---|---|---|
| 1. Setup PIN via menu Pengaturan, bukan prompt wajib pertama buka | Seed selalu membuat `pin:hash('1234')` + `pinDefault:true` (L170); `go()` langsung meminta PIN untuk tab LOCKED (L367-376) | **Belum sesuai.** Area owner selalu "terproteksi" oleh PIN default 1234 sejak awal. Perlu flag `pinEnabled` agar state awal = belum dilindungi. |
| 2. Pemulihan PIN via Master Code buatan owner | Master default `888888` (L170); reset mengembalikan PIN ke 1234 (L791) | **Belum sesuai.** Master Code harus dibuat owner, tanpa default, dan wajib dirotasi setelah dipakai. |
| 3. Area owner terkunci otomatis setelah 5 menit idle | Tidak ada timer idle sama sekali; `view.unlocked` hanya reset saat pindah tab (L369-370) | **Belang belum ada.** Perlu idle timer 5 menit + reset pada aktivitas relevan. |
| 4. Terkunci saat app background / device lock | Tidak ada `visibilitychange` handler | **Belum ada.** Perlu lock on hidden + re-lock on visible. |
| 5. Offline-friendly, penyimpanan lokal | localStorage (L151, L186-189) | **Sesai.** Dipertahankan. |
| 6. Backup/restore manual kompatibel | Backup JSON (L779), restore via file (L855-863) | **Sesai.** Migrasi credential harus menjaga format backup tetap dapat dipulihkan. |

---

## 1. Spesifikasi Arsitektur Keamanan Final

### State (tambahan pada objek state `S`)
```
S.pinEnabled      : boolean   // false = area owner belum dilindungi
S.pinHash         : string    // PBKDF2 output (base64url) atau null
S.pinSalt         : Uint8Array->base64url | null
S.pinIter         : number    // iterasi PBKDF2
S.masterHash      : string | null
S.masterSalt      : base64url | null
S.masterUsed      : boolean   // true bila master pernah dipakai -> wajib rotasi
S.pinFails        : number    // counter percobaan PIN gagal
S.pinLockUntil    : number    // epoch ms lockout PIN
S.masterFails     : number
S.masterLockUntil : number
S.lastActive      : number    // epoch ms untuk idle timer
S.sessionStart    : number    // epoch ms saat unlock (opsional, audit)
```

### Komponen
1. **Security Settings (di menu Atur)** — aktif/nonaktifkan PIN, buat/ubah Master Code, status proteksi.
2. **Credential Store** — envelope `{hash, salt, iter}` untuk PIN & Master Code; disimpan di `S` (localStorage), tanpa plaintext.
3. **Session Guard** — `view.unlocked` + `S.lastActive`; idle 5 menit; visibility lock.
4. **Rate Limiter** — counter + lockout epoch untuk PIN dan Master Code.
5. **Migration Layer** — deteksi format lama (`S.pin` string legacy) → envelope baru tanpa reset data.

### Aturan akses
- `pinEnabled=false`: tab owner (rekap/stok/atur) **dapat dibuka** tetapi menampilkan status "belum terlindungi" + CTA setup PIN; **tidak ada** data owner yang ditampilkan sebagai "terbuka lebar" — konten sensitif (laporan keuangan detail) tetap bisa diakses karena memang belum ada proteksi, namun UI wajib menampilkan peringatan eksplisit.
- `pinEnabled=true`: semua tab LOCKED wajib unlock via PIN (atau Master Code recovery bila PIN lupa).

---

## 2. Alur UI

### A. Setup PIN (pertama kali)
1. Launch app → `S.pinEnabled=false` → tidak ada prompt PIN.
2. Owner buka tab **Atur** → banner: "Area owner belum dilindungi — aktifkan PIN".
3. Klik "Aktifkan PIN" → form masukkan PIN baru (4–6 angka, dikonfirmasi) → `pinEnabled=true`, hash disimpan.
4. Setelah itu, semua tab owner wajib PIN.

### B. Login (unlock)
1. Klik tab LOCKED → modal `askPin()` (L377-383).
2. Verifikasi PBKDF2(PIN, salt) vs `S.pinHash`.
3. Sukses → `unlockTo(tab)` + mulai idle timer. Gagal → increment `pinFails`; lockout bila ≥5.

### C. Ganti PIN
1. Atur → Ganti PIN (3 langkah: lama → baru → konfirmasi), sesuai `pinBoxHtml()` (L712-717).
2. Verifikasi lama, validasi `okPin` (L784), simpan hash baru, reset `pinFails`.

### D. Recovery (Lupa PIN via Master Code)
1. Modal PIN → "Lupa PIN? Pakai Master Code" (L382).
2. Masukkan Master Code → verifikasi.
3. Sukses → PIN direset ke default 1234 **DAN** `masterUsed=true` → UI wajib meminta owner membuat Master Code baru; Master Code lama dianggap **hangus** (rekomendasi paling aman: invalidate + rotasi wajib). Gagal 3× → lockout 60 detik.

---

## 3. Diagram Alur Autentikasi & Penguncian Otomatis

```
[Launch]
   |
   v
pinEnabled=false? --ya--> Atur: banner "belum dilindungi" -> setup PIN -> pinEnabled=true
   | tidak
   v
[Tab LOCKED diklik]
   |
   v
view.unlocked=true? --ya--> akses konten owner
   | tidak
   v
askPin() -----> verifikasi PIN (PBKDF2)
   |               |
   | gagal         | sukses
   v               v
pinFails++     unlockTo(tab); mulai idleTimer(5 menit)
   |               |
   |>=5            | aktivitas user (pointer/key/touch) -> reset idleTimer
   v               |
lockout 30 detik   |
                   |--- idleTimer habis (5 menit) ---> lock()
                   |--- visibilitychange hidden ----> lock()
                   |--- visibilitychange visible ---> jika unlocked: lock() + askPin()

lock(): view.unlocked=false; tutup modal; kembali ke tab kasir; clearInterval/listener

[Recovery] askPin -> "Lupa PIN" -> masukkan Master Code
   | verifikasi -> sukses: PIN=default(1234); masterUsed=true; wajib rotasi Master Code
   | gagal 3x -> lockout 60 detik
```

---

## 4. Daftar File yang Perlu Diubah

Hanya satu file aplikasi: **`Kasir Kopi (1).html`** (dokumen perencanaan ini tidak mengubahnya).

| Area | Baris saat ini | Perubahan yang direncanakan |
|---|---|---|
| `KEY` storage | L151 | Tambahkan versi schema (`kasirkopi.v2`) untuk migrasi |
| `LOCKED` | L152 | Pertahankan; tambahkan guard `pinEnabled` |
| `hash()` custom | L160 | Ganti dengan PBKDF2 (Web Crypto); hapus fallback tidak aman |
| `seed()` | L168-183 | Hapus default PIN/Master; tambahkan `pinEnabled:false`, field envelope |
| `load()`/`migrate()` | L184-189, L495-498 | Tambah deteksi format lama + migrasi credential |
| `go()` / `askPin()` / `unlockTo()` | L366-384 | Integrasi guard `pinEnabled`, idle timer, lock state |
| `pinBoxHtml()` | L712-717 | Validasi kompleksitas PIN sesuai spesifikasi |
| `vAtur()` | L718-729 | Tambah panel Security Settings (status proteksi, setup PIN, Master Code) |
| `F.pin` / `master-reset` / `master` / `pinstep` | L786-832 | PBKDF2 verify, rotasi Master Code, reset counter |
| Listener input/change | L836-864 | Reset idle timer pada aktivitas relevan |
| `init()` | L868-873 | Register visibilitychange + idle timer; bersihkan listener |

Dokumen pendukung (bukan kode aplikasi): `AUDIT_AUTHENTICATION.md`, `SECURITY_HARDENING_SPEC.md`.

---

## 5. Strategi Migrasi Credential Lama

1. **Deteksi:** pada `load()`, bila `S.pin` berupa string legacy (`h…-<len>`) dan `S.pinHash` belum ada → mode migrasi.
2. **Tidak menghapus data lama:** field legacy tetap disimpan sementara; tidak ada reset database.
3. **Transisi:** saat owner pertama kali berhasil masuk (PIN lama terverifikasi via hash legacy), sistem otomatis derive PBKDF2(PIN, salt baru) → tulis `pinHash/pinSalt/pinIter`, lalu hapus field legacy.
4. **Backup/restore:** format JSON backup tetap kompatibel; restore membawa serta envelope credential baru bila ada, atau field legacy bila belum dimigrasi.
5. **Rollback:** bila migrasi gagal, state tetap valid (legacy masih bisa dipakai) — tidak ada data loss.

---

## 6. Kompatibilitas Android WebView & Web Crypto

- **Web Crypto API (`crypto.subtle`)** didukung penuh pada Android WebView berbasis Chrome 69+ (Android 9+ umumnya). Aplikasi Kasrr berbasis WebView offline-friendly → asumsikan modern WebView.
- **PBKDF2** via `crypto.subtle.deriveBits` dengan HMAC-SHA-256, iterasi ≥ 100.000 (OWASP 2023 merekomendasikan 600.000 untuk SHA-256; 100k–600k masih praktis untuk PIN 4–6 digit pada perangkat mobile; pilih 100.000 sebagai keseimbangan UX/offline, dokumentasikan).
- **Async:** semua derive bersifat async → UI modal harus mendukung `await`; tidak boleh fallback sinkron ke hash custom (owner: "Jangan membuat fallback ke hash buatan sendiri yang tidak aman").
- **Bila `crypto.subtle` tidak tersedia:** fail closed — blokir setup PIN/Master Code dengan pesan "Perangkat tidak mendukung penyimpanan credential aman"; jangan turun ke hash tidak aman.
- **Secure context:** `crypto.subtle` butuh HTTPS/localhost; APK WebView memuat file lokal → umumnya `file://` diizinkan di WebView, tetapi perlu verifikasi pada build APK.

---

## 7. Risiko Keamanan yang Masih Tersisa

1. **PIN numerik 4–6 digit** = entropi rendah; offline brute-force pada perangkat yang sudah dikuasai attacker tetap memungkinkan (localStorage dapat dibaca/ditulis). PBKDF2 memperlambat, tidak menghilangkan risiko.
2. **Rate limiting lokal** dapat dimanipulasi oleh pemilik perangkat (clear storage / edit state). Tidak ada enforcement server.
3. **XSS via UI** (mis. input nama toko/operator yang di-render via `esc()` L154, tetapi input di L721-724) — jika XSS berhasil, credential envelope dapat dibaca.
4. **Tidak ada audit log server**; semua log lokal (jika ada) dapat dihapus.
5. **WebView lawas** tanpa Web Crypto → fitur keamanan tidak aktif (fail closed, tapi fungsionalitas hilang).
6. **Master Code rotation wajib** bila owner mengabaikan UI → akun tetap dengan master yang sudah terpakai (mitigasi: UI memaksa rotasi sebelum unlock berikutnya).

---

## 8. Test Plan & Acceptance Criteria

| # | Test | Acceptance Criteria |
|---|---|---|
| T1 | Launch pertama | Tidak ada prompt PIN; Atur terbuka; banner "belum dilindungi" tampil |
| T2 | Setup PIN via Atur | PIN aktif; `pinEnabled=true`; tab owner kini wajib PIN |
| T3 | Login PIN benar | Unlock berhasil; idle timer mulai |
| T4 | Login PIN salah 5× | Lockout 30 detik; UI menampilkan hitungan |
| T5 | Idle 5 menit | Otomatis lock; kembali ke kasir; unlock wajib PIN |
| T6 | App background / device lock | Langsung lock; visible kembali → re-lock + minta PIN |
| T7 | Ganti PIN (3 langkah) | PIN lama salah → gagal; PIN baru valid → sukses; `pinFails` reset |
| T8 | Recovery Master Code | Master benar → PIN reset 1234; `masterUsed=true`; UI memaksa rotasi Master Code |
| T9 | Master Code salah 3× | Lockout 60 detik |
| T10 | Migrasi credential lama | Legacy PIN masih bisa dipakai sekali; setelah itu envelope baru aktif; data transaksi/stok/menu/operator/laporan tidak hilang |
| T11 | Backup/restore JSON | Restore berhasil; credential envelope tetap valid; format lama tetap dapat dipulihkan |
| T12 | Kompatibilitas WebView | PBKDF2 berjalan; bila `crypto.subtle` tidak ada → setup PIN diblokir (fail closed) |

---

## 9. Estimasi Urutan Implementasi per Subtask

1. **A. Setup PIN** (state `pinEnabled`, UI Atur, guard LOCKED) — fondasi; ~0.5–1 hari.
2. **C. Penyimpanan credential** (PBKDF2 + envelope + migrasi legacy) — prasyarat B/D/E; ~1–1.5 hari.
3. **B. Master Code recovery** (buat/ubah/rotasi, validasi, `masterUsed`) — ~0.5–1 hari.
4. **D. Penguncian otomatis** (idle 5 menit, visibility lock, cleanup listener) — ~0.5 hari.
5. **E. Rate limiting** (counter + lockout PIN/Master) — ~0.5 hari.
6. **F. Kompatibilitas & migrasi backup/restore** (format v2, uji restore) — ~0.5–1 hari.
7. **Test plan (T1–T12) + bugfix** — ~1 hari.

**Total estimasi:** 4–6.5 hari kerja, tergantung kompleksitas UI WebView.

---

## Catatan Akhir

- Dokumen ini **evaluatif & perencanaan**; tidak ada kode aplikasi yang diubah.
- Branch `main` tidak diubah; tidak ada merge; tidak ada migrasi data.
- Implementasi menunggu persetujuan owner atas spesifikasi ini.