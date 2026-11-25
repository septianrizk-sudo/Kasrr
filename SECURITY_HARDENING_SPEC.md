# KASRR — Security Hardening Specification (Evaluation) — REVISI 1

**Status:** Perencanaan saja (planning mode). Tidak ada kode aplikasi yang diedit. Menunggu persetujuan owner sebelum implementasi.
**Basis:** Keputusan Final Owner (1–6) + catatan revisi owner (7 butir) + temuan audit sebelumnya pada `Kasir Kopi (1).html` (877 baris).
**Branch:** `audit/authentication` (berbasis `main`). PR: [#4](https://github.com/septianrizk-sudo/Kasrr/pull/4) — tidak di-merge.

## Riwayat Revisi
| Revisi | Perubahan utama | Alasan teknis |
|---|---|---|
| R1 (ini) | Recovery PIN tanpa PIN default; rotasi Master Code wajib & atomic; Master Code min 12 karakter; parameter PBKDF2 final (600k iterasi, salt 16B, async-only); strategi migrasi idempoten + backup envelope policy; verifikasi Web Crypto pada APK WebIntoApp sebenarnya; batas perlindungan & threat model; tambahan uji T13–T20 | Menutup celah lockout & PIN bawaan, menghilangkan ambiguity parameter, memenuhi batasan offline/WebView, memperkuat jaminan tidak ada data bisnis hilang. |
| R2 | Recovery wizard diperbaiki: hapus invalidasi prematur Master Code; alur baru = verifikasi Master lama → buat Master baru → buat PIN baru → verifikasi kedua credential → **atomic commit** → unlock. Invariant anti-lockout diperketat (Master lama tetap valid sampai commit sukses). | Owner menemukan kritik: desain sebelumnya menyimpan Master pengganti yang hanya ditampilkan sekali → kehilangan satu-satunya jalur pemulihan bila ditutup sebelum commit. Desain baru menghapus auto-generate one-shot. |

---

## 0. Evaluasi Keputusan Owner vs Implementasi Saat Ini

| Keputusan Owner | Kondisi Saat Ini (Bukti) | Evaluasi |
|---|---|---|
| 1. Setup PIN via menu Pengaturan, bukan prompt wajib pertama buka | Seed selalu membuat `pin:hash('1234')` + `pinDefault:true` (L170); `go()` langsung meminta PIN untuk tab LOCKED (L367-376) | **Belum sesuai.** Area owner selalu "terproteksi" oleh PIN default 1234 sejak awal. Perlu flag `pinEnabled` agar state awal = belum dilindungi. |
| 2. Pemulihan PIN via Master Code buatan owner | Master default `888888` (L170); reset mengembalikan PIN ke 1234 (L791) | **Belum sesuai.** Master Code harus dibuat owner (min 12 karakter), tanpa default, single-use, rotasi wajib. |
| 3. Area owner terkunci otomatis setelah 5 menit idle | Tidak ada timer idle sama sekali; `view.unlocked` hanya reset saat pindah tab (L369-370) | **Belum ada.** Perlu idle timer 5 menit + reset pada aktivitas relevan. |
| 4. Terkunci saat app background / device lock | Tidak ada `visibilitychange` handler | **Belum ada.** Perlu lock on hidden + re-lock on visible. |
| 5. Offline-friendly, penyimpanan lokal | localStorage (L151, L186-189) | **Sesai.** Dipertahankan. |
| 6. Backup/restore manual kompatibel | Backup JSON (L779), restore via file (L855-863) | **Sesai.** Migrasi credential harus menjaga format backup tetap dapat dipulihkan. |

---

## 1. Spesifikasi Arsitektur Keamanan Final

### 1.1 Parameter kriptografi final (keputusan, bukan rentang)
| Parameter | Nilai final | Alasan |
|---|---|---|
| Algoritma | PBKDF2-HMAC-SHA-256 via `crypto.subtle.deriveBits` | Rekomendasi OWASP 2023 untuk KDF password; didukung Web Crypto. |
| Iterasi | **600.000** | OWASP 2023 untuk PBKDF2-HMAC-SHA-256. **Gate wajib:** benchmark pada perangkat Android target sebelum sign-off; bila derive > 1,0 detik pada target, eskalasi ke owner dengan angka ukur — **tidak ada penurunan otomatis**. |
| Salt | 16 byte acak dari `crypto.getRandomValues` per credential | Mencegah rainbow table antar-pengguna/instalasi. |
| Output | 256 bit, disimpan base64url | Ukuran tetap, aman untuk JSON. |
| Fallback hash custom | **DILARANG** | Bila Web Crypto tidak tersedia → fail closed (owner area diblokir), bukan turun ke hash tidak aman. |
| Sinkron vs async | Semua derive/verify **async** (`await`) | `crypto.subtle` intrinsik async; UI modal wajib menunggu tanpa membekukan event loop. |

### 1.2 Envelope credential (disimpan di `S`, localStorage) — desain R2
```
S.schemaVersion   : 2
S.pinEnabled      : boolean        // false = belum dilindungi (belum ada PIN aktif)
S.pin             : { hash, salt, iter } | null   // PBKDF2 envelope; null bila pinEnabled=false
S.master          : { hash, salt, iter } | null   // null = belum dibuat / sudah hangus
S.recovery        : { step:number, masterPending?:{hash,salt,iter}, pinPending?:{hash,salt,iter}, masterVerified?:boolean, pinVerified?:boolean } | null  // wizard recovery R2: Master LAMA valid sampai atomic commit sukses
S.pinFails, S.pinLockUntil, S.masterFails, S.masterLockUntil : number
S.lastActive, S.sessionStart : number
```
Field legacy (`S.pin` string `h…-<len>`, `S.master` string) **hanya** ada sebelum migrasi; lihat §5.

### 1.3 Komponen
1. **Security Settings (menu Atur)** — status proteksi, aktifkan/ubah PIN, buat/ubah Master Code.
2. **Credential Store** — envelope PBKDF2 saja; tanpa plaintext; tanpa hash custom.
3. **Session Guard** — `view.unlocked` + idle 5 menit + visibility lock (§2, §3).
4. **Rate Limiter** — counter + lockout epoch (§7-E).
5. **Migration Layer** — deteksi legacy, langkah idempoten, commit atomik (§5).
6. **Recovery Wizard** — alur recovery resumable dengan invariant tanpa-jalur-hilang (§2-D).

### 1.4 Aturan akses & batas perlindungan (owner note 6)
- `pinEnabled=false`: data owner **benar-benar belum terlindungi** — UI wajib menampilkan peringatan eksplisit di Atur & saat membuka tab owner ("Area owner belum dilindungi — siapa pun yang membuka perangkat ini dapat mengakses data ini"). Tab owner dapat dibuka untuk setup, tanpa PIN.
- `pinEnabled=true`: **semua** akses owner wajib melewati guard autentikasi (PIN, atau Master Code bila PIN lupa). Tidak ada pengecualian tab.
- **Rate limit lokal bukan perlindungan** terhadap pemilik perangkat yang dapat mengedit localStorage (lihat §7).
- Aplikasi offline berbasis WebView **tidak setara** autentikasi server: tidak ada enforcement jarak jauh, tidak ada audit server, tidak ada pencabutan sesi pusat. Proteksi yang diberikan = **perlindungan kesempatan (opportunistic) terhadap akses kasual**, bukan terhadap penyerang yang menguasai perangkat.

---

## 2. Alur UI

### A. Setup PIN (pertama kali)
1. Launch → `pinEnabled=false` → **tanpa prompt PIN**.
2. Atur → banner "belum dilindungi" → "Aktifkan PIN".
3. Form PIN baru (4–6 angka, dikonfirmasi; anjurkan 6) → derive PBKDF2 async → simpan envelope → `pinEnabled=true`.
4. Setelah aktif, semua tab owner wajib PIN. **Tidak ada** PIN default di langkah mana pun.

### B. Login (unlock)
1. Tab LOCKED → `askPin()` (L377-383) → verifikasi async PBKDF2.
2. Sukses → `unlockTo(tab)` + idle timer mulai. Gagal → `pinFails++`; lockout bila ≥5 (30 detik; 3 siklus → 5 menit + sarankan recovery).

### C. Ganti PIN
1. Atur → Ganti PIN (3 langkah: lama → baru → konfirmasi; `pinBoxHtml()` L712-717).
2. Verifikasi lama async; validasi `okPin` (L784); simpan envelope baru; reset `pinFails`.

### D. Recovery PIN via Master Code (desain R2 — tanpa PIN default, tanpa one-shot Master Code)
Wizard **resumable**. Langkah utama (owner-side, tanpa PIN default, tanpa auto-generate one-shot):
1. **Verifikasi Master Code lama.** Owner memasukkan Master Code → verifikasi async PBKDF2 == `S.master.hash` → **tanpa commit** (Master Code lama tetap valid; `S.recovery.step=1` disimpan). Gagal 3× → lockout 60 detik.
2. **Buat & konfirmasi Master Code pengganti.** Owner memasukkan & mengonfirmasi Master Code baru (min 12 karakter) → derive PBKDF2 async → envelope disimpan di `S.recovery.masterPending` (hanya envelope, tidak ada plaintext). Master Code lama **masih valid** dan belum dikonsumsi.
3. **Buat & konfirmasi PIN baru.** Owner memasukkan & mengonfirmasi PIN baru (4–6 angka, usul 6 angka; tanpa default) → derive PBKDF2 async → envelope disimpan di `S.recovery.pinPending`.
4. **Verifikasi kedua credential baru.** Sistem memverifikasi `masterPending` dan `pinPending` dengan PBKDF2 (cocokkan input owner vs envelope pending).
5. **Satu atomic commit.** `save()` menulis sekaligus: `S.pin = pinPending`, `S.master = masterPending`, `pinEnabled = true`, `S.recovery = null`. Pada **kesuksesan**: Master Code lama **wajib gagal** diverifikasi (pointing ke envelope baru). Pada **kegagalan penyimpanan**: state lama dikembalikan, Master Code lama tetap valid, data bisnis tidak berubah, owner dapat retry.
6. **Setelah commit sukses**, owner boleh unlock area owner (via PIN baru atau Master Code baru).

**Mekanisme & invarian (R2):**
- Master Code lama valid sampai atomic commit sukses — tidak di-hanguskan prematur.
- Tidak ada Master Code/PIN yang disimpan dalam plaintext secara permanen (hanya envelope PBKDF2 di state level maupun wizard pending).
- Jika aplikasi ditutup sebelum langkah commit → recovery dapat dilanjutkan **dengan Master Code lama** (belum dikonsumsi) dari checkpoint terakhir.
- Jika commit gagal → state lama utuh dan valid, data bisnis tidak diubah.
- Jika commit sukses → Master Code lama wajib gagal diverifikasi; Master baru + PIN baru valid.
- Master Code pengganti dibuat & dikonfirmasi owner sendiri; tidak ada sistem yang membuat kode "hanya ditampilkan sekali".

### E. Rotasi Master Code (di Atur) — konsisten dengan R2
Buat Master baru (min 12 karakter) → owner mengonfirmasi → verifikasi Master lama → **atomic commit** (Master baru + envelope terkait) → hangus Master lama. Prinsip yang sama dengan wizard recovery §2-D: Master lama valid sampai commit sukses.

---

## 3. Diagram Alur Autentikasi & Penguncian Otomatis

```
[Launch]
   |
   v
pinEnabled=false? --ya--> Atur: banner "belum dilindungi" -> setup PIN (PBKDF2 async) -> pinEnabled=true
   | tidak
   v
[Tab LOCKED diklik]
   |
   v
view.unlocked=true? --ya--> akses konten owner
   | tidak
   v
askPin() -----> verifikasi PBKDF2 async
   |               |
   | gagal         | sukses
   v               v
pinFails++     unlockTo(tab); mulai idleTimer(5 menit)
   |               |
   |>=5            | aktivitas user (pointer/key/touch) -> reset idleTimer
   v               |
lockout 30 detik   |--- idleTimer habis (5 menit) ---> lock()
   |               |--- visibilitychange hidden ----> lock()
   |(3 siklus)     |--- visible kembali -----------> lock() + askPin()
   v
lockout 5 menit + sarankan recovery

lock(): view.unlocked=false; tutup modal; tab kasir; clearTimeout + hapus listener (anti timer ganda)

[Recovery wizard R2]
askPin -> "Lupa PIN?" -> [1] verifikasi Master LAMA (async, max 3x; tanpa commit; Master LAMA tetap valid)
   | verifikasi gagal -> wizard balik ke [1]; >=3 gagal -> lockout 60 detik
   | verifikasi sukses -> [2] buat+konfirmasi Master BARU (min 12) -> [3] buat+konfirmasi PIN BARU -> [4] verifikasi kedua credential baru (Master BARU, PIN BARU) -> [5] atomic commit (tulis PIN BARU + Master BARU; hangus Master LAMA) -> [6] unlock
   | [5] commit sukses -> Master LAMA wajib gagal; Master BARU & PIN BARU valid; S.recovery=null
   | [5] commit gagal -> state lama valid (Master LAMA, belum dikonsumsi); data bisnis tidak berubah
   | tutup aplikasi sebelum [5] -> S.recovery aktif; Master LAMA masih valid -> resume verifikasi dari checkpoint langkah terakhir
   | gagal verifikasi (Master/PIN) -> wizard kembali ke langkah terkait
```

---

## 4. Daftar File yang Perlu Diubah

Hanya satu file aplikasi: **`Kasir Kopi (1).html`** (dokumen ini tidak mengubahnya).

| Area | Baris saat ini | Perubahan yang direncanakan |
|---|---|---|
| `KEY` storage | L151 | Schema v2 (`kasirkopi.v2`) |
| `LOCKED` | L152 | Pertahankan; tambah guard `pinEnabled` |
| `hash()` custom | L160 | **Hapus**; ganti modul PBKDF2 async (Web Crypto); tanpa fallback custom |
| `seed()` | L168-183 | Tanpa default PIN/Master; `pinEnabled:false`, envelope null, `schemaVersion:2` |
| `load()`/`migrate()` | L184-189, L495-498 | Deteksi legacy + migrasi idempoten (§5) |
| `go()` / `askPin()` / `unlockTo()` | L366-384 | Guard `pinEnabled`, idle/visibility lock, wizard recovery resumable |
| `pinBoxHtml()` | L712-717 | Validasi PIN; async derive |
| `vAtur()` | L718-729 | Panel Security Settings: status proteksi, setup/ubah PIN, buat/ubah Master (min 12), peringatan "belum dilindungi" |
| `F.pin` / `master-reset` / `master` / `pinstep` | L786-832 | PBKDF2 verify async, wizard recovery, rotasi Master atomic, reset counter |
| Listener input/change | L836-864 | Reset idle timer; cleanup listener |
| `init()` | L868-873 | Probe Web Crypto (§6), register visibilitychange, lanjutkan wizard bila `S.recovery.active` |

Dokumen pendukung (bukan kode aplikasi): `AUDIT_AUTHENTICATION.md`, `SECURITY_HARDENING_SPEC.md`.

---

## 5. Strategi Migrasi Credential Lama & Backup (revisi)

### 5.1 Migrasi legacy → PBKDF2 (idempoten, aman saat terputus)
1. **Deteksi:** `load()` menemukan `S.pin` string legacy (`h…-<len>`) tanpa envelope → set `migrationStep=1`, **hanya baca** (tidak menulis).
2. **Trigger:** owner berhasil unlock dengan PIN lama (verify legacy) → derive PBKDF2 async dengan salt baru → **satu kali `save()` atomik** menulis envelope + `migrationStep=done` + hapus field legacy.
3. **Aplikasi ditutup / gagal di tengah jalan:** derive async belum selesai → tidak ada tulisan sama sekali; field legacy masih utuh; unlock berikutnya memakai legacy lagi (idempoten). Bila `save()` berhasil, legacy sudah dihapus — tidak ada state setengah jalan karena penulisan tunggal.
4. **Data bisnis TIDAK disentuh:** migrasi hanya menangani key credential; `tx`, `ingredients`, `menu`, `operators`, `campaigns`, `customers`, `seq`, `shop` tidak pernah dihapus/direset — termasuk bila migrasi gagal total.
5. **Fail closed:** bila Web Crypto tidak tersedia saat migrasi diperlukan → unlock diblokir dengan pesan eksplisit; data bisnis tetap terbaca via backup (§5.3).

### 5.2 Backup JSON & envelope credential — keputusan
- **Default: envelope credential TIDAK disertakan** dalam backup (`pin`, `master`, `recovery`, counter lockout dikecualikan). Restore = data bisnis pulih, credential wajib setup ulang via wizard (tidak ada PIN default untuk masuk).
- **Opt-in:** bila owner memilih menyertakan envelope, UI wajib memperingatkan: file backup berisi hash+salt+iterasi → kebocoran file memungkinkan brute-force offline terhadap PIN 4–6 digit (entropi rendah) meski PBKDF2 600k memperlambat; dan **mengembalikan credential lama** (termasuk Master lama) yang mungkin sudah pernah dikompromikan.
- **Restore tidak boleh menurunkan keamanan diam-diam:** restore envelope lama sementara state aktif lebih baru → konfirmasi eksplisit owner + setelah restore, sistem memaksa perubahan PIN & Master pada unlock berikutnya. Restore field legacy (bukan envelope) → konfirmasi + migrasi ulang otomatis. Restore `pinEnabled=false` sementara aktif `true` → konfirmasi downgrade + banner peringatan.
- **Restore tidak valid** (schema mismatch/corrupt) → abort, state saat ini utuh, toast error; tidak ada reset data.

### 5.3 Jaminan kompatibilitas
Transaksi, stok, menu, operator, laporan, riwayat shift: tidak berubah format; backup/restore JSON tetap berfungsi untuk semua key bisnis pada schema v2.

---

## 6. Verifikasi Web Crypto pada APK WebIntoApp Sebenarnya (owner note 5)

**Jangan mengasumsikan ketersediaan dari versi Android.** Sebelum implementasi credential, jalankan probe pada APK WebIntoApp yang benar digunakan:

| Probe | Langkah | Kriteria lulus |
|---|---|---|
| `crypto.getRandomValues` | Panggil untuk 16 byte | Tidak throw; entropy tampak acak |
| `crypto.subtle` ada | `typeof crypto.subtle !== 'undefined'` pada konteks WebView APK (bukan Chrome desktop) | true |
| PBKDF2 roundtrip | `importKey` → `deriveBits` (SHA-256, 600k, salt 16B) → `exportKey`/verify dua PIN berbeda | Hash konsisten & berbeda antar input; waktu derive terukur |
| Penyimpanan hasil | Simpan envelope ke localStorage APK → reload → verifikasi ulang | Envelope terbaca & verify sukses |
| Benchmark performa | Ukur waktu derive PBKDF2 600k pada perangkat target | ≤ 1,0 detik; bila lebih → eskalasi ke owner (angka ukur), **tanpa downgrade otomatis** |

**Bila gagal satu pun → fail closed:** setup PIN/Master diblokir, area owner tidak dapat dibuka (termasuk recovery), hanya tab kasir yang berfungsi; tampilkan pesan eksplisit ("Perangkat/WebView ini tidak mendukung penyimpanan credential aman") + konsekuensi: fitur owner (rekap/stok/atur, end shift) tidak tersedia sampai perangkat/WebView memenuhi syarat. **Tidak ada fallback hash custom.**

---

## 7. Risiko Keamanan yang Masih Tersisa (laporan ulang)

1. **PIN numerik 4–6 digit** = entropi rendah; serangan brute-force offline tetap mungkin bila penyimpanan perangkat disalin (PBKDF2 600k memperlambat, tidak menghapus risiko). Mitigasi terdekat: anjurkan PIN 6 angka.
2. **Rate limit lokal dapat dimanipulasi** pemilik perangkat (edit `pinFails`/`pinLockUntil`/`pinEnabled`/hash di localStorage) — bukan kontrol keamanan terhadap attacker yang menguasai perangkat.
3. **Offline WebView ≠ autentikasi server:** tidak ada enforcement/audit/revocation pusat; proteksi bersifat kesempatan terhadap akses kasual.
4. **Backup opt-in berisi envelope** → kebocoran file backup memperluas surface brute-force offline & mengembalikan credential lama (§5.2).
5. **Tamper state** (mis. `pinEnabled` diubah true/false manual) → aplikasi wajib fail closed (kunci + wizard setup ulang), tidak crash; uji T20.
6. **XSS via input UI** (nama toko/operator, L721-724) bila terjadi → envelope credential dapat dibaca; `esc()` (L154) membantu namun bukan jaminan.
7. **WebView lawas / WebIntoApp tanpa Web Crypto** → fitur keamanan tidak aktif (fail closed; fungsionalitas owner hilang, §6).
8. **Master Code lupa + PIN lupa** → data tidak dapat dipulihkan (by design, tanpa backdoor); owner wajib menyimpan Master pengganti saat wizard recovery (langkah 3).

---

## 8. Test Plan & Acceptance Criteria (T1–T20)

| # | Test | Acceptance Criteria |
|---|---|---|
| T1 | Launch pertama | Tanpa prompt PIN; Atur terbuka; banner "belum dilindungi" tampil |
| T2 | Setup PIN via Atur | PIN aktif; `pinEnabled=true`; tab owner kini wajib PIN; hash = envelope PBKDF2 (bukan legacy) |
| T3 | Login PIN benar | Unlock berhasil; idle timer mulai |
| T4 | Login PIN salah 5× | Lockout 30 detik; UI hitungan; 3 siklus → 5 menit |
| T5 | Idle 5 menit | Otomatis lock; kembali ke kasir; unlock wajib PIN |
| T6 | App background / device lock | Langsung lock; visible kembali → re-lock + minta PIN |
| T7 | Ganti PIN (3 langkah) | PIN lama salah → gagal; PIN baru valid → sukses; `pinFails` reset |
| T8 | Recovery Master Code (R2) | Tanpa PIN default; verifikasi Master lama → owner buat Master BARU + PIN BARU → verifikasi kedua → **atomic commit** → Master LAMA hangus; wajib buat Master BARU sebelum owner area dibuka; Master LAMA valid sampai commit sukses |
| T9 | Master Code salah 3× | Lockout 60 detik |
| T10 | Migrasi credential lama | Legacy PIN dapat dipakai untuk unlock pertama → envelope baru aktif; legacy terhapus; data bisnis utuh |
| T11 | Backup/restore JSON | Restore berhasil; tanpa envelope → wizard setup credential; dengan envelope (opt-in) → konfirmasi + paksa ubah PIN/Master; tidak ada penurunan keamanan diam-diam |
| T12 | Kompatibilitas WebView | PBKDF2 jalan; `crypto.subtle` tidak ada → setup PIN diblokir (fail closed) |
| T13 | Recovery tanpa PIN default | Tidak ada kode path yang menulis/menerima PIN 1234; recovery selalu membuat PIN baru via wizard (create+confirm) |
| T14 | Master lama tidak dapat dipakai ulang | Setelah recovery sukses, Master lama wajib gagal verifikasi (single-use, envelope diganti) |
| T15 | Recovery terputus (app ditutup sebelum commit) | Tutup di tiap langkah wizard → resume pakai Master LAMA (masih valid); tidak ada state tanpa jalur pemulihan aktif; data bisnis utuh; Master pengganti tidak ditampilkan sekali-saja |
| T16 | Migrasi gagal / aplikasi ditutup saat migrasi | Kill mid-derive → reload: legacy masih valid (idempoten) atau envelope lengkap; tidak ada setengah jalan; data bisnis tidak hilang |
| T17 | Restore backup lama & baru | Backup legacy → konfirmasi + migrasi ulang; backup v2 → envelope valid; konfirmasi eksplisit untuk downgrade/apapun yang menurunkan keamanan |
| T18 | Web Crypto tidak tersedia | Simulasi absence → fail closed: owner area diblokir, kasir tetap jalan, pesan eksplisit; tanpa fallback hash custom |
| T19 | Background / screen lock / foreground | Lock on hidden; re-lock on visible; idle reset pada aktivitas relevan; **tidak ada timer ganda** (satu `idleTimer` aktif) |
| T20 | Tamper localStorage | Edit manual `pinEnabled`/hash/counter lockout → aplikasi fail closed (kunci/wizard setup ulang), tidak crash, data bisnis utuh; dokumen bahwa tamper device-owner di luar cakupan |
| T21 | Tutup aplikasi pada tiap langkah wizard recovery | Setelah tutup sebelum commit: S.recovery aktif & Master LAMA masih valid; resume lanjut dari checkpoint; tidak ada plaintext permanen |
| T22 | Kegagalan penyimpanan saat commit | Commit gagal → state lama dikembalikan; Master LAMA tetap valid; data bisnis tidak berubah; owner dapat retry |
| T23 | Commit recovery sukses | Master LAMA wajib gagal verifikasi; Master BARU & PIN BARU valid; owner area unlockable setelah commit |

---

## 9. Estimasi Urutan Implementasi per Subtask

0. **Verifikasi Web Crypto pada APK WebIntoApp** (probe + benchmark, §6) — gate sebelum semua pekerjaan credential; ~0.5 hari.
1. **A. Setup PIN** (state `pinEnabled`, UI Atur, guard LOCKED) — fondasi; ~0.5–1 hari.
2. **C. Penyimpanan credential** (PBKDF2 async + envelope + migrasi legacy idempoten) — prasyarat B/D/E; ~1–1.5 hari.
3. **B. Master Code recovery** (min 12 karakter, wizard resumable, rotasi atomic, single-use) — ~0.5–1 hari.
4. **D. Penguncian otomatis** (idle 5 menit, visibility lock, cleanup listener) — ~0.5 hari.
5. **E. Rate limiting** (counter + lockout PIN/Master) — ~0.5 hari.
6. **F. Kompatibilitas & migrasi backup/restore** (schema v2, policy envelope, konfirmasi restore) — ~0.5–1 hari.
7. **Test plan (T1–T23) + bugfix** — ~1,5–2 hari.

**Total estimasi:** 5,5–7,5 hari kerja, tergantung hasil benchmark WebView target.

---

## Catatan Akhir
- Dokumen ini **evaluatif & perencanaan**; tidak ada kode aplikasi yang diubah.
- Branch `main` tidak diubah; tidak ada merge; tidak ada migrasi data.
- Revisi R2 difokuskan pada §2-D (recovery wizard), §1.2 (state), §2-E (rotasi), §3 (diagram), dan §8 (test T8/T15/T21–T23) agar konsisten terhadap invariant anti-lockout baru.
- Implementasi menunggu persetujuan owner atas revisi spesifikasi ini.