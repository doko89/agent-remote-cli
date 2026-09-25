# PRD: agent-remote

**Status:** Draft
**Tanggal:** 25 September 2026
**Bahasa implementasi:** Go
**Arsitektur:** Clean Architecture

---

## 1. Ringkasan

`agent-remote` adalah CLI yang membungkus SSH dan WinRM ke dalam satu antarmuka yang seragam. Tool ini punya dua tujuan inti:

1. Menyimpan konfigurasi remote host (SSH maupun WinRM) sehingga tidak perlu mengetik ulang parameter koneksi setiap kali.
2. Membersihkan output koneksi dari banner/MOTD dan noise lain yang tidak relevan, sehingga konsumen utama tool ini — AI agent — hanya menerima informasi yang benar-benar dibutuhkan dari hasil eksekusi command.

Konsumen utama tool ini adalah AI agent yang memanggil `agent-remote` secara non-interaktif, bukan manusia yang mengetik interaktif di terminal. Prinsip ini memengaruhi hampir semua keputusan desain di dokumen ini: output default terstruktur, autentikasi tidak boleh bergantung pada prompt interaktif, dan pesan error harus machine-readable.

---

## 2. Tujuan & Non-Tujuan

### Tujuan

- Satu binary tunggal (Go) yang bisa menjalankan command di remote host lewat SSH atau WinRM dengan antarmuka command yang sama.
- Konfigurasi host tersimpan persisten dan bisa dikelola (tambah, hapus, lihat) tanpa menyimpan password dalam bentuk plaintext.
- Output command remote yang sudah bersih dari banner login/MOTD, dengan opsi untuk melihat output asli bila dibutuhkan.
- Output default berbentuk JSON terstruktur agar mudah diparse oleh AI agent, dengan mode teks polos sebagai opsi.
- Bisa dipakai secara non-interaktif penuh (tidak ada langkah yang wajib menunggu input dari TTY).

### Non-Tujuan (untuk versi ini)

- Bukan pengganti sesi interaktif penuh (`ssh` biasa dengan shell interaktif, `mstsc`/RDP). Fokusnya adalah eksekusi command tunggal, bukan sesi kerja interaktif manusia.
- Bukan secret manager. Tool ini boleh membaca dan (secara opsional) menyimpan secret lewat OS keyring, tapi tidak dirancang untuk menggantikan Vault, AWS Secrets Manager, atau sejenisnya.
- Belum mencakup bastion/multi-hop, port forwarding, atau file transfer (SCP/SFTP) di versi ini.

---

## 3. Pengguna & Skenario Pemakaian

- **AI agent** yang perlu menjalankan diagnostic command, deployment step, atau pengecekan status di server SSH/WinRM sebagai bagian dari tugas otomatis, dan perlu output yang bersih untuk dianalisis lebih lanjut tanpa noise banner login.
- **Operator manusia** yang mengelola daftar host (menambah, memperbarui, menghapus) dan sesekali menjalankan command manual untuk verifikasi, memakai mode `--raw` untuk kenyamanan membaca.
- **Pipeline CI/CD atau skrip otomasi** yang memanggil `agent-remote exec` sebagai salah satu langkah, dan mengandalkan exit code serta struktur JSON untuk menentukan langkah berikutnya.

---

## 4. Terminologi

| Istilah | Arti |
|---|---|
| Host | Satu entri konfigurasi remote (nama, protokol, alamat, kredensial) yang tersimpan di tool ini. |
| Protokol | SSH atau WinRM — cara tool ini berkomunikasi dengan host. |
| Banner/MOTD | Teks informasional yang ditampilkan server saat sesi dibuka (pesan login, pesan compliance, versi sistem, dll), terpisah dari output command yang sesungguhnya. |
| Envelope | Struktur pembungkus standar (`ok`, `data`, `error`) yang dipakai semua command saat mode output JSON aktif. |

---

## 5. Kebutuhan Fungsional

### 5.1 Manajemen Konfigurasi Host

Sistem harus bisa menyimpan, menampilkan, dan menghapus konfigurasi host secara persisten di mesin lokal tempat tool dijalankan.

- Penambahan host dipisah berdasarkan protokol (SSH dan WinRM sebagai jalur command yang berbeda), karena parameter yang relevan untuk masing-masing protokol berbeda (misal path private key hanya relevan untuk SSH; transport NTLM/Kerberos hanya relevan untuk WinRM). Pemisahan ini juga membuat bantuan (`--help`) per protokol hanya menampilkan opsi yang benar-benar berlaku, bukan gabungan semua opsi dari kedua protokol.
- Penambahan host dengan nama yang sudah terdaftar harus ditolak (bukan menimpa diam-diam), untuk mencegah AI agent secara tidak sengaja mengubah konfigurasi yang sudah benar. Perubahan konfigurasi yang sudah ada memerlukan langkah eksplisit yang terpisah dari penambahan baru.
- Setiap host tersimpan minimal punya: nama unik, protokol, alamat/host, port, username, dan referensi metode autentikasi (bukan secret itu sendiri — lihat bagian 5.6).
- Daftar host dan detail satu host harus bisa ditampilkan tanpa pernah menampilkan nilai password/secret dalam bentuk apapun, termasuk saat mode debug.
- Penghapusan host juga harus membersihkan secret terkait yang tersimpan di OS keyring (bila ada), agar tidak ada secret yatim yang tertinggal.

### 5.2 Uji Koneksi

Sistem harus menyediakan cara memverifikasi bahwa suatu host bisa dihubungi dan diautentikasi, tanpa perlu menjalankan command yang berdampak (idle check / handshake saja). Ini berguna sebagai langkah validasi sebelum AI agent bergantung pada host tersebut untuk tugas sesungguhnya.

### 5.3 Eksekusi Command Remote

Sistem harus bisa menjalankan satu command pada host tertentu dan mengembalikan hasilnya (stdout, stderr, exit code, durasi eksekusi).

- Argumen command milik remote harus dipisahkan secara eksplisit dari flag milik `agent-remote` sendiri (memakai separator standar), untuk menghindari ambiguitas ketika command remote juga memakai flag berawalan dash.
- Exit code proses `agent-remote` harus membedakan dua kelas kegagalan yang berbeda: kegagalan pada level tool (host tidak ditemukan, gagal konek, gagal autentikasi, timeout) versus kegagalan pada level command yang dijalankan di remote (command itu sendiri keluar dengan exit code bukan nol). AI agent maupun skrip otomasi perlu bisa membedakan dua kelas ini tanpa mem-parsing pesan teks.

### 5.4 Penyaringan Banner/MOTD

Ini adalah kebutuhan pembeda utama tool ini dibanding wrapper SSH/WinRM generik, dan terdiri dari dua lapis pertahanan:

**Lapis 1 — Cara koneksi dibuat.** Untuk SSH, command dijalankan lewat mekanisme eksekusi non-interaktif (tanpa alokasi pseudo-terminal), karena MOTD/banner login pada kebanyakan sistem hanya dipicu pada sesi interaktif. Ini menghilangkan mayoritas noise banner tanpa perlu penyaringan teks sama sekali. Untuk WinRM, protokolnya sendiri sudah berbasis command-response, sehingga secara alami minim noise semacam ini.

**Lapis 2 — Penyaringan berbasis pola sebagai jaring pengaman.** Karena sebagian sistem tetap bisa menyisipkan pesan informasional ke output meski dijalankan non-interaktif (tergantung konfigurasi server), sistem harus menyediakan mekanisme penyaringan baris berbasis pola (pattern-based line filtering) dengan sekumpulan pola bawaan (contoh kategori: pesan login terakhir, pesan selamat datang distro, ringkasan status paket/update sistem, pesan compliance/legal). Pengguna harus bisa menambah pola kustom per host, dan harus bisa menonaktifkan penyaringan ini sepenuhnya bila menginginkan output asli.

**Pre-auth banner SSH** (pesan yang dikirim server sebelum autentikasi selesai, dikonfigurasi lewat direktif banner di sisi server) harus ditangani terpisah dari stdout command, karena secara protokol memang bukan bagian dari output command — sehingga tidak akan tercampur ke hasil command secara default.

Penyaringan ini adalah heuristik, bukan jaminan sempurna untuk semua konfigurasi server yang mungkin ada. Kebutuhan fungsionalnya adalah: tersedia default yang masuk akal, bisa dikustomisasi per host, dan bisa dimatikan sepenuhnya secara eksplisit.

### 5.5 Format Output

- Mode output default adalah **JSON terstruktur**, berlaku seragam di semua command (bukan hanya perintah eksekusi command), memakai bentuk pembungkus (envelope) yang konsisten agar AI agent bisa memproses hasil dari command manapun dengan satu logika parsing.
- Mode **teks biasa (raw)** tersedia sebagai opsi eksplisit, ditujukan untuk pemakaian manusia langsung di terminal.
- Mode penyaringan banner (5.4) dan mode format output (JSON vs raw) adalah dua pengaturan yang independen satu sama lain — mengaktifkan output teks biasa tidak otomatis mematikan penyaringan banner, begitu pula sebaliknya.

### 5.6 Autentikasi & Penyimpanan Secret

- Password tidak boleh diterima lewat argumen command line dalam bentuk nilai langsung sebagai jalur utama, karena berisiko tercatat di riwayat shell maupun terlihat lewat daftar proses sistem selama command berjalan.
- Jalur penerimaan password yang aman dari kedua risiko di atas harus tersedia (dibaca lewat standard input), untuk dipakai baik saat menyimpan konfigurasi baru maupun saat override sekali pakai tanpa disimpan.
- Sistem harus mendukung referensi ke environment variable sebagai sumber password saat eksekusi, sebagai opsi yang tidak menyimpan secret di tool ini sama sekali — cocok untuk lingkungan yang sudah punya secret manager sendiri.
- Sistem harus mendukung penyimpanan password terenkripsi lewat mekanisme keyring sistem operasi sebagai opsi, dengan catatan ketersediaannya bergantung lingkungan (lihat bagian 9 — Open Questions terkait target lingkungan eksekusi).
- Untuk SSH, autentikasi berbasis private key adalah jalur yang direkomendasikan sebagai metode utama, dengan opsi referensi ke environment variable untuk passphrase key yang terenkripsi.
- Tidak ada skenario di mana secret tersimpan dalam bentuk plaintext yang bisa dibaca langsung dari file konfigurasi.

### 5.7 Transfer File (`cp`)

Sistem harus bisa menyalin file dan direktori antara mesin lokal dan host
remote, serta antar dua host remote, dengan antarmuka seragam ala `scp`:

- Setiap sisi ditulis `[host:]path`: prefix `host:` menunjuk host
  terdaftar, path polos berarti lokal. Colon dengan nama host yang tidak
  dikenal ditolak eksplisit, tidak ditebak diam-diam.
- Tiga kombinasi didukung: lokal→remote, remote→lokal, remote→remote
  (antar host boleh beda protokol). Remote→remote selalu lewat staging
  lokal sementara agar semua kombinasi berperilaku identik.
- Direktori hanya disalin dengan flag rekursif eksplisit (`-r`); tanpa itu
  sumber direktori ditolak dengan pesan yang jelas.
- Semantik `scp` untuk file tunggal: bila dest adalah direktori yang sudah
  ada, file masuk ke dalamnya memakai basename sumber — di semua kombinasi
  sisi (upload, download, relay).
- SSH memakai subsistem SFTP; WinRM memakai transfer base64 per chunk
  lewat PowerShell (dengan sealing pesan yang sama seperti `exec`) karena
  protokolnya tidak punya kanal file. Tiap chunk harus muat dalam satu
  command line Windows (batas 8191 char via `-EncodedCommand`), jadi
  potongan upload dibatasi ~2 KB base64 per exec.
- Hasil (`files`, `bytes`, durasi) dikembalikan dalam envelope yang sama;
  kegagalan transfer adalah kegagalan level tool (exit 2).

### 5.8 Sinkronisasi (`sync`)

`sync` adalah `cp` yang hemat: hanya file baru/berubah yang disalin,
perbandingan memakai ukuran + mtime (toleransi 2 detik untuk skew jam).
Setelah menulis, mtime sumber dicap ke tujuan agar pemindaian berikut
diam.

- Selalu satu arah (src→dest). Mode default half side: tidak pernah
  menghapus. Mode everything (`--delete`) menghapus file/dir tujuan yang
  tidak ada di sumber; `--half` menegaskan default eksplisit.
- `-w/--watch` memindai ulang tiap interval sampai dibatalkan (Ctrl-C),
  menyalin create/update (dan delete bila everything), men-stream satu
  objek JSON per aksi lalu ringkasan akhir.
- Satu file bisa di-sync langsung (tujuan adalah path file); direktori
  selalu penuh (tidak ada pola include/exclude di versi ini).

---

## 6. Cakupan Command

| Command | Fungsi |
|---|---|
| `add ssh <name> [opsi]` | Mendaftarkan host baru dengan protokol SSH. |
| `add winrm <name> [opsi]` | Mendaftarkan host baru dengan protokol WinRM. |
| `rm <name>` | Menghapus host beserta secret terkait yang tersimpan. |
| `list` | Menampilkan seluruh host yang tersimpan (tanpa secret). |
| `show <name>` | Menampilkan detail satu host (tanpa secret). |
| `test <name>` | Memverifikasi konektivitas dan autentikasi tanpa menjalankan command berdampak. |
| `exec <name> -- <command>` | Menjalankan command pada host, mengembalikan stdout/stderr/exit code/durasi dengan banner tersaring. |
| `cp [-r] <src> <dest>` | Menyalin file/direktori; tiap sisi `[host:]path` (lihat 5.7). |
| `sync [--delete\|--half] [-w] <src> <dest>` | Mirror satu arah src→dest; lewati yang segar, `--delete` hapus sisanya, `-w` pantau terus (lihat 5.8). |

Perubahan konfigurasi host yang sudah ada (di luar hapus-lalu-tambah-ulang) dan bentuk final flag per command belum difinalkan — lihat bagian 9.

---

## 7. Arsitektur (Go, Clean Architecture)

Struktur mengikuti prinsip Clean Architecture: dependensi selalu mengarah ke dalam (ke domain), lapisan luar bergantung pada abstraksi yang didefinisikan oleh lapisan dalam, bukan sebaliknya. Tidak ada lapisan dalam yang mengetahui detail implementasi lapisan luar.

### 7.1 Domain (Entities)

Lapisan paling inti, tanpa dependensi eksternal apapun (tidak bergantung pada library SSH, WinRM, YAML, atau framework CLI manapun). Berisi representasi konsep inti bisnis: definisi host beserta atributnya, jenis protokol yang didukung, hasil eksekusi command, dan aturan penyaringan banner sebagai konsep (bukan implementasi regex tertentu).

### 7.2 Use Case (Application Business Rules)

Berisi logika alur kerja aplikasi, dinyatakan lewat interface (port) yang harus dipenuhi oleh lapisan luar. Setiap kemampuan fungsional di bagian 5 dipetakan menjadi satu use case: menambah host, menghapus host, menampilkan daftar/detail host, menguji koneksi, dan mengeksekusi command (termasuk orkestrasi penyaringan banner dan resolusi secret sebelum eksekusi). Lapisan ini mendefinisikan port untuk: penyimpanan konfigurasi, penyedia secret, dan klien koneksi remote (SSH/WinRM) — tanpa tahu implementasi konkretnya.

### 7.3 Interface Adapters

Menjembatani use case dengan dunia luar: parsing argumen CLI menjadi permintaan use case, serta presenter yang mengubah hasil use case menjadi bentuk output (envelope JSON atau teks biasa). Di sinilah pemilihan format output (bagian 5.5) diterapkan, terpisah dari logika bisnis di use case.

### 7.4 Infrastructure (Frameworks & Drivers)

Implementasi konkret dari port yang didefinisikan use case: klien SSH, klien WinRM, penyimpanan konfigurasi berbasis file di mesin lokal, penyedia secret (environment variable, standard input, keyring OS), dan pustaka parsing argumen CLI yang dipakai di lapisan adapter. Perakitan seluruh implementasi konkret ke masing-masing port dilakukan satu kali di titik komposisi aplikasi (composition root), sehingga lapisan use case tidak pernah mengimpor package infrastruktur secara langsung.

### 7.5 Manfaat Struktur Ini untuk Tool Ini Secara Spesifik

- Penambahan protokol baru di masa depan (misal Telnet, atau varian autentikasi WinRM lain) cukup menambah adapter baru tanpa menyentuh use case.
- Strategi penyaringan banner (bagian 5.4) bisa diuji secara terisolasi di lapisan domain/use case tanpa perlu koneksi SSH/WinRM sungguhan.
- Penyimpanan konfigurasi bisa diganti (misal dari file YAML lokal menjadi backend lain) tanpa mengubah use case maupun CLI.

---

## 8. Kebutuhan Non-Fungsional

- **Portabilitas**: didistribusikan sebagai binary tunggal per platform (Linux/macOS/Windows), tanpa runtime tambahan yang perlu diinstal terpisah.
- **Keamanan**: tidak ada secret dalam bentuk plaintext yang tersimpan permanen di file konfigurasi; permukaan command line tidak boleh membocorkan secret lewat riwayat shell atau daftar proses.
- **Dapat diprediksi oleh agent**: struktur output, exit code, dan pesan error harus konsisten antar command sehingga AI agent bisa membangun logika penanganan yang generik, bukan menangani tiap command secara khusus.
- **Non-interaktif penuh**: seluruh command harus bisa dijalankan sampai selesai tanpa menunggu input dari TTY, kecuali pengguna secara eksplisit memilih jalur interaktif (misal prompt password saat dipanggil manusia langsung di terminal).
- **Ekstensibilitas protokol**: penambahan protokol baru di masa depan tidak boleh memerlukan perubahan pada lapisan domain/use case.

---

## 9. Pertanyaan Terbuka / Keputusan yang Belum Difinalkan

Poin-poin berikut sudah didiskusikan tapi belum mendapat keputusan final, dan perlu diselesaikan sebelum implementasi detail dimulai:

1. **Target lingkungan eksekusi utama** — apakah tool ini diasumsikan berjalan di desktop/laptop interaktif (di mana keyring OS asli biasanya tersedia), atau di server/CI/container headless (di mana keyring OS sering tidak tersedia atau tidak reliabel)? Ini menentukan apakah keyring dijadikan opsi utama penyimpanan secret atau hanya opsi sekunder di belakang environment variable/standard input.
2. **Semantik exit code detail** — kelas kegagalan tool sudah disepakati harus terpisah dari kegagalan command remote (bagian 5.3), tapi nilai exit code spesifik untuk tiap kelas kegagalan tool (host tidak ditemukan, gagal autentikasi, timeout, dll — satu kode seragam atau berbeda-beda) belum ditentukan.
3. **Format JSON: ringkas (satu baris) vs rapi (indented) sebagai default** — mengingat JSON kini jadi default yang juga akan sering dilihat manusia di terminal, perlu diputuskan default-nya ringkas dengan opsi `--pretty`, atau sebaliknya.
4. **Field kode error machine-readable** — apakah struktur error pada envelope JSON hanya berisi pesan teks bebas, atau juga menyertakan kode error terstruktur (string pendek yang stabil, tidak berubah antar versi) agar AI agent bisa melakukan percabangan logika tanpa mem-parsing teks pesan.
5. **Command untuk mengubah konfigurasi host yang sudah ada** — apakah diperlukan command tersendiri untuk memperbarui sebagian field suatu host, atau cukup lewat hapus-lalu-tambah-ulang.
6. **Nama final untuk penonaktifan penyaringan banner** — perlu dipastikan tidak bentrok dengan flag pemilihan format output (`--raw` telah dialokasikan untuk mode teks biasa pada bagian 5.5), mengingat kedua pengaturan ini independen satu sama lain.
7. **Parsing otomatis terhadap output command remote yang kebetulan berbentuk JSON** — apakah dibutuhkan di versi ini sebagai flag opt-in pada `exec`, atau ditunda ke versi berikutnya.

---

## 10. Di Luar Cakupan Versi Ini

- Sesi interaktif penuh (shell interaktif SSH, remote desktop WinRM).
- Bastion host / multi-hop connection.
- Manajemen secret tingkat lanjut (rotasi otomatis, integrasi langsung dengan secret manager pihak ketiga di luar environment variable).

---

## 11. Ringkasan Keputusan Kunci dari Diskusi

| Keputusan | Pilihan yang Disepakati |
|---|---|
| Bahasa & arsitektur | Go, Clean Architecture |
| Struktur command untuk protokol | Subcommand per protokol di bawah `add` (`add ssh`, `add winrm`), bukan flag `--protocol` tunggal atau URI gabungan |
| Perilaku `add` pada nama yang sudah ada | Ditolak (bukan overwrite diam-diam) |
| Format output default | JSON terstruktur untuk semua command, dengan `--raw` sebagai opt-out ke teks biasa |
| Penyaringan banner vs format output | Dua pengaturan independen, tidak boleh saling memengaruhi secara implisit |
| Password lewat command line | Tidak lewat nilai langsung sebagai jalur utama; jalur utama lewat standard input, dengan opsi environment variable dan keyring OS |
| Pemisahan argumen command remote | Wajib pakai separator eksplisit terhadap flag milik `agent-remote` |
