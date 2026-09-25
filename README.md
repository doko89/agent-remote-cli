# agent-remote

Satu binary Go yang membungkus SSH dan WinRM dalam antarmuka seragam,
untuk **AI agent** (non-interaktif) sebagai konsumen utama. Implementasi dari
[PRD.md](PRD.md), memakai Clean Architecture.

## Dibangun

```sh
go build -o agent-remote .
go vet ./... && go test ./...
```

## Pemakaian

```sh
# Daftarkan host (SSH dan WinRM jalurnya terpisah)
agent-remote add ssh web1 --host 10.0.0.1 --user deploy --auth env --auth-ref DEPLOY_PW
agent-remote add winrm w1 --host 10.0.0.5 --user admin --password-stdin < pw.txt

# Kelola
agent-remote list
agent-remote show web1
agent-remote rm web1            # juga membersihkan secret keyring

# Validasi tanpa efek samping, lalu eksekusi (separator `--` wajib)
agent-remote test web1
agent-remote exec web1 -- df -h /
```

Config tersimpan di `~/.config/agent-remote/hosts.json`
(atau `$AGENT_REMOTE_CONFIG`), mode `0600`, **tanpa nilai secret**.

## Output & exit code

Default JSON satu baris, envelope seragam semua command:

```json
{"ok":true,"data":{"hosts":[...]}}
{"ok":false,"error":{"code":"auth_failed","message":"..."}}
```

`--pretty` meng-indentasi; `--raw` beralih ke teks manusia.
Filter banner (`--no-filter`) dan format (`--raw`) independen.

| Exit | Arti |
|------|------|
| 0 | sukses (command remote exit 0) |
| 1 | command remote jalan, exit ≠ 0 (ada di `data.exit_code`) |
| 2 | kegagalan tool (`error.code`: `host_not_found`, `auth_failed`, `connection_failed`, `timeout`, `secret_unavailable`, `invalid_input`, `store_error`, ...) |

## Secret (tidak pernah jadi nilai flag)

| Sumber | Add | Exec/Test |
|--------|-----|-----------|
| OS keyring (`auth=keyring`, default) | `--password-stdin` / `--password-env VAR` | tersimpan |
| Env var (`auth=env --auth-ref VAR`) | referensi saja | dibaca per-run |
| Stdin (`auth=stdin`) | tanpa simpan | dibaca per-run (pipe; TTY ditolak) |
| SSH key (`auth=keyfile --auth-ref PATH`) | path saja | passphrase via `--passphrase-env VAR` atau override |
| Override sekali pakai | — | `exec`/`test --password-stdin` / `--password-env VAR` |

## Penyaringan banner (2 lapis)

1. **SSH tanpa PTY** (WinRM memang request/response) — MOTD sesi
   interaktif tidak masuk stream. Pre-auth banner SSH ditangkap terpisah
   (`pre_auth_banner`), tidak pernah tercampur ke stdout.
2. **Filter baris berbasis pola**: bawaan (last-login, welcome distro,
   ringkasan apt, mail, compliance) + `--filter-pattern` per host +
   `--no-filter` untuk output asli.

## Keputusan atas 7 pertanyaan terbuka PRD §9

1. **Keyring utama/sekunder**: keyring = default `add`, tapi env/stdin
   setara dan didokumentasikan untuk headless/CI.
2. **Exit code**: 0 sukses / 1 remote gagal / 2 tool gagal (detail di `error.code`).
3. **JSON default ringkas satu baris**; `--pretty` opt-in.
4. **Ada `error.code` stabil** — agent bercabang di sini, bukan teks pesan.
5. **Tanpa command update** — ubah via `rm` + `add` (eksplisit, anti-clobber).
6. **Nonaktif filter = `--no-filter`** (exec/add); `--raw` murni format output.
7. **Parsing JSON output remote ditunda** (di luar versi ini).

## Arsitektur

```
internal/domain/                 tanpa dependensi luar
internal/usecase/                ports: HostStore, SecretResolver, RemoteClient(+Factory)
internal/adapter/cli, presenter   parsing argv + envelope JSON / raw
internal/infrastructure/          configstore (file), secret (env/stdin/keyring),
                                  sshclient, winrmclient
main.go                          satu-satunya composition root
```

Protokol baru = tambah 1 package infra + 1 case di factory.

## Keterbatasan yang diketahui

- Host key SSH belum di-pinning (`InsecureIgnoreHostKey`); `known_hosts`
  adalah follow-up yang didokumentasikan.
- `test`/keyring mengandalkan retry hanya untuk handshake; `exec` tidak
  pernah retry (anti eksekusi ganda).
- WinRM `exec` berjalan via PowerShell. Transport NTLM mentah
  (`Negotiate` + token NTLMSSP mentah, bukan SPNEGO) + sealing pesan
  (wajib saat `AllowUnencrypted=false`) — teruji live lawan Windows asli.
  `TestLiveWinRM` (env `AGENT_REMOTE_WINRM_LIVE=host,user,pass`) membuktikan
  ulang full-stack; unit offline memakai challenge Type2 rekaman.
- Client SSH teruji lawan server SSH dalam-proses: tanpa PTY, banner
  terpisah, exit code, timeout, keyfile.
- Coverage ≥85% di domain/usecase/cli/presenter/sshclient; configstore,
  secret, dan winrmclient menyisakan jalur I/O defensif / OS-dependent
  (keyring, WinRM live) — lihat `go test -cover ./...`.
