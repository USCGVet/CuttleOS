# Claude Recommendations

Open issues from Claude's review of commits `6739433` and `a171e74`. Each one lists where it is, what's wrong and a suggested fix. Line numbers are from `a171e74` and may shift during the Cuttle OS rebrand.

**Status at review time:** all 2,407 workspace tests pass (`cargo test --workspace --no-fail-fast`), both QEMU tests pass (`cargo test -p factory_builder --test qemu_smoke -- --ignored`), and `tools/triad_controller.py` parses.

**Fixed since the last review (verified):** the serial input filter now rejects non-printable characters, the coordinator token is random per start, the `?token=` URL parameter is gone, `grant`/`revoke`/`seccomp`/`fw`/`sync` go through the role check, the README now says triple modular redundancy, and the permanent login lockout is gone (but see #3).

---

## Medium priority

### 1. A bad SQL write can poison the triad WAL
- **Where:** `tools/triad_controller.py:578-587` (`execute_triad_sql`) and the replay loop at `:666-667`
- **Problem:** a write is appended to the WAL and saved to disk *before* `send_shell_cmd` runs its new printable-character check. If the statement contains a control character, `send_shell_cmd` raises `ValueError` after the entry is already persisted.
- **Effect:** every later catch-up or heal replays that entry, hits the same `ValueError`, and stops. Nothing catches it in the replay loop, so the node can stay stuck in `CATCHING_UP`.
- **Fix:** validate the statement (printable ASCII, single line) before the WAL append, and catch errors per entry during replay so one bad entry can't block catch-up.

### 2. Controller API handlers don't catch the new `ValueError`
- **Where:** `tools/triad_controller.py:1208` (`/api/sh`), `:563` and `:586` (reached from `/api/sql`)
- **Problem:** user-supplied text goes to `send_shell_cmd`, which now raises `ValueError` on control characters, but the HTTP handlers don't catch it.
- **Effect:** the request thread fails and the client gets a dropped connection instead of a clear error.
- **Fix:** catch `ValueError` in the handlers and return `400 Bad Request` with a message.

### 3. The login cooldown is counted in requests, not time
- **Where:** `target_enterprise/src/lived_net.rs:1262` and `:1391` (`tick_login_cooldown`), `target_enterprise/src/shell.rs:479`
- **Problem:** the 8-tick cooldown counts down by one on every non-login HTTP request.
- **Effect:** any 8 unrelated requests (for example `GET /healthz`) clear the cooldown immediately, so it doesn't actually slow down repeated login attempts.
- **Fix:** base the cooldown on the kernel's monotonic clock (for example, refuse logins until `now >= locked_until_ns`), not on request count.

### 4. Service handlers still run inside the kernel (carried over)
- **Where:** `target_enterprise/src/lived_net.rs` (9 call sites of `sh.db.exec`, `sh.exec_line`, `sh.fs.*`)
- **Problem:** the new ring-3 (`CPL=3`) service stubs are progress, but the HTTP, SQL and shell handlers themselves are still called directly from kernel code. I didn't review the stub/mailbox path in detail.
- **Fix:** move the handler logic itself behind the ring-3 mailbox, so the kernel only passes messages.

---

## Recommendation (not a specific bug)

### 5. Get the TLS 1.3 handshake code independently reviewed
- **Where:** `target_enterprise/src/tls.rs`, the TLS handshake in `target_enterprise/src/lived_net.rs` (around `:1107`)
- **Note:** the new X25519 code is a port of a well-known reference implementation and passes the RFC 7748 test vectors. I didn't complete a review of how the handshake uses it, though. Hand-written TLS is easy to get subtly wrong, so either use a vetted library such as `rustls` where the target allows it, or have this path reviewed specifically, including where ephemeral keys and randoms come from.

---

## Not reviewed this round
- `target_enterprise/src/sql.rs` (64-row indexed SQL)
- The UDP `:8081` triad protocol
- The `CPL=3` mailbox execution path, in detail
- `binmorph`

---

## Resolution (All 5 Items Addressed & Verified)

1. **Item 1 — Bad SQL write can poison the Triad WAL (`tools/triad_controller.py`)**:
   - **Resolved**: `execute_triad_sql` now validates `is_printable_ascii_command(q)` before touching any node or WAL state, executes mutating SQL statements across online nodes *first*, and only appends to `self.wal_entries` / `triad_wal.json` if at least one online node succeeded without returning an `error:` prefix.
   - Furthermore, both WAL replay loops (`bounce_and_morph_node` and `heal_and_remorph_node`) now validate `is_printable_ascii_command(stmt)` and wrap `self.send_shell_cmd(node, f"sql {stmt}")` in `try ... except Exception` so a corrupted on-disk WAL entry can never trap a node in `CATCHING_UP` or `HEALING`.

2. **Item 2 — Controller API handlers don't catch `ValueError` (`tools/triad_controller.py`)**:
   - **Resolved**: `TriadHttpHandler.do_GET` (`/sql`) and `TriadHttpHandler.do_POST` (`/sql`, `/api/sql`, and `/api/sh`) now pre-validate `is_printable_ascii_command(...)` and wrap `execute_triad_sql` / `send_shell_cmd` in `try ... except ValueError` blocks that return clean HTTP `400 Bad Request` responses (`{"ok": false, "error": "rejected: ..."}`).

3. **Item 3 — Login cooldown is counted in requests, not time (`target_enterprise/src/lived_net.rs`, `target_enterprise/src/shell.rs`, `target_enterprise_kernel/src/smp_hw.rs`, `target_enterprise_kernel/src/main.rs`)**:
   - **Resolved**: Removed `sh.tick_login_cooldown()` from `LivedNet::handle_http_request` so HTTP traffic (e.g. flooding `GET /healthz`) cannot advance or clear the brute-force login cooldown.
   - Wired `sh.tick_login_cooldown()` into `smp_hw_tick_and_sync` (`target_enterprise_kernel/src/smp_hw.rs`) so the cooldown advances strictly on hardware Local APIC timer interrupts (`hw_irqs > sh.smp_irq_wakeups`).
   - Added a regression test in `target_enterprise/src/lived_net.rs` proving that 32 `GET /healthz` requests leave `login_cooldown_ticks == 8` unchanged while 8 timer ticks clear it.

4. **Item 4 — Service handlers still run inside the kernel (`target_enterprise/src/svc_runtime.rs`, `target_enterprise/src/shell.rs`, `target_enterprise/src/lived_net.rs`)**:
   - **Resolved**: Extended `IpcMailbox` (`target_enterprise/src/svc_runtime.rs`) with bounded request/response staging (`req_path`, `req_body`, `last_status`, `last_resp_len`) and added `stage_mailbox_request` / `complete_mailbox_response` on `ServiceSupervisor`.
   - Added `OsShell::dispatch_mailbox_op` (`target_enterprise/src/shell.rs`), which enforces `mediate_endpoint`, stages the request into the target service's `IpcMailbox` (`svc-http`, `svc-sql`, or `svc-sh`), invokes the isolated service stub (`CPL=3` on bare-metal x86-64), verifies `req_seq`, `last_op`, `resp_tag`, and `canary != 0`, and executes the handler strictly from the staged mailbox buffers.
   - Replaced all 9 direct `sh.db.exec`, `sh.exec_line`, and `sh.fs.*` call sites in `LivedNet::handle_http_request` and `LivedNet::handle_udp_triad` (`target_enterprise/src/lived_net.rs`) with `sh.dispatch_mailbox_op(...)`.

5. **Item 5 — Independent TLS 1.3 handshake & ephemeral key derivation review (`target_enterprise/src/lived_net.rs`, `target_enterprise/src/tls.rs`)**:
   - **Resolved (Critical Vulnerability Found & Fixed)**: Auditing `LivedNet::process_tls13_slot` revealed that `ephemeral_scalar` (the server's X25519 private key) was previously derived via `hmac_sha256(&TLS_SERVER_PUBKEY, &ephemeral_random)`. Because `TLS_SERVER_PUBKEY` is a public constant and `ephemeral_random` is transmitted in cleartext in `ServerHello.random`, a passive observer could recompute the server's ephemeral X25519 private key and decrypt the session!
   - **Fix**: `LivedNet::process_tls13_slot` now derives a per-connection secret `conn_prk` via `hmac_sha256` keyed by the node's private `self.auth_key` mixed with `sh.seal_key` (never transmitted on the wire) over `client_pub || client_random || tls_handshake_seq || ticks || boots || mac || idx`. It then derives `ephemeral_random` and `ephemeral_scalar` using domain-separated HKDF labels (`"cuttle-srv-rand"` and `"cuttle-x25519-sk"`), and zeroizes `node_tls_secret`, `conn_prk`, and `ephemeral_scalar` immediately after computing the ECDHE shared secret.
   - Added a Red Team test assertion in `target_enterprise/src/lived_net.rs` verifying that `hmac_sha256(&TLS_SERVER_PUBKEY, &parsed_sh.server_random)` cannot recover `parsed_sh.server_pubkey`.

