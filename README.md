# Cuttle OS

> **Three hearts. One appliance. A new skin every boot.**

**Cuttle OS** is a Moving Target Defense (MTD) x86-64 unikernel, isolated service appliance, and automated binary diversification factory written in Rust. Like its namesake cuttlefish — which repatterns its skin in milliseconds to evade predators, stabilizes its body around a rigid internal **cuttlebone**, and pumps blood through **three hearts** — Cuttle OS combines:

- **The Cuttlebone (`cuttle-contracts` & `locked_modules.toml`)**: The minimal, formally specified contract surface, hardware Ring-0/Ring-3 isolation boundary, and constant-time cryptographic seal core that holds still while everything around it changes.
- **Skins (`cuttle-diversifier` + `factory_builder` + `cuttle-binmorph`)**: Every build cycle, VM boot (~140ms fast binary morph), and live in-place service rotation (`service rotate`) sheds the previous binary layout and adopts a structurally distinct x86-64 machine-code **skin** while preserving cryptographically sealed state across reboots.
- **Cuttle Triad — *"Three hearts. One appliance. Lose a heart, keep beating."* (`triad.bat` / `tools/triad_controller.py`)**: Packages **3 independent 4-core Cuttle OS VMs** (each with its own binary skin and domain-separated cryptographic keys) into a single Triple Modular Redundancy (TMR) 2-of-3 majority-vote + 4 KiB RAID XOR parity ($D_1 \oplus D_2 = P$) appliance.
- **Ink (Active Tamper Detection & Self-Healing)**: Native UDP `:8081` quorum state-hash verification (`TRIAD_ALERT status=DIVERGENCE`), 2-of-3 majority syndrome checks, and eBPF/canary traps immediately detect single-node tampering, isolate the compromised node, reconstruct its state from the surviving two hearts, and force an emergency skin re-morph.

## Expected Use Case

Cuttle OS is a hardened multi-role network and state appliance OS built for high-assurance edge gateways, zero-trust SQL state appliances, and isolated remote management nodes where static binary homogeneity enables exploit reuse. The Ring-0 kernel keeps the hardware scheduler, memory/KPTI page tables, device drivers, network/storage primitives, IPC bus, capability gate, eBPF seccomp filter, and TPM/HMAC attestation, while gating all application service endpoints — the Web Server & Dashboard (`svc-http`, `/sbin/svc-http`), the Relational SQL Engine (`svc-sql`, `/sbin/svc-sql`), and the Interactive/Exec Shell (`svc-sh`, `/sbin/svc-sh`) — behind [`ServiceSupervisor`](target_enterprise/src/svc_runtime.rs)'s deny-by-default role, KPTI page-table (`x86_pml4`), capability, eBPF seccomp, and IPC mediation boundary. Each service owns an independent ELF64 image and a diversified 32-byte x86-64 Ring-3 (`CPL=3`) machine-code stub verified at hardware `CPL=3` (`iretq` → user-mapped `IpcMailbox` read/sign/write → `int 0x80` on `TSS.RSP0`). Under Option 3 role provisioning (`wfe`, `sql`, `shell`, `full`), each node loads only the service ELFs required for its assigned role into memory (leaving unused services unloaded and unmapped) and can independently morph, restart, and attest individual service binaries in place without rebooting the kernel.

---

## Workspace Architecture

| Crate | Purpose |
| :--- | :--- |
| [`contracts`](contracts) | Immutable `no_std` trait and wire-format contract definitions (`cuttle-contracts`) shared by the kernel and host verifier — the rigid **Cuttlebone** that is never morphed. |
| [`target_enterprise`](target_enterprise) | Pure `no_std` OS subsystem implementations, allocation-free except the HTTPS stack (73 modules: HTTPS via rustls TLS 1.3 + a RustCrypto provider, X.509, TCP/IP, HTTP, DNS, DHCP, ARP, ICMP, VirtIO, NVMe, AHCI, IOMMU, KPTI, VFS, JFS, FAT32, WAL, SQL, TPM 2.0, eBPF, Seccomp, AuditLog, and [`OsShell`](target_enterprise/src/shell.rs)). |
| [`target_enterprise_kernel`](target_enterprise_kernel) | Bare-metal `x86_64-unknown-none` bootable unikernel linking `target_enterprise` to physical hardware drivers (16550 UART, PCI, AHCI, NVMe, VirtIO-net/blk, e1000, APIC/IOAPIC, HPET/PIT/RTC). |
| [`diversifier`](diversifier) | Deterministic, seed-driven Rust AST diversifier (`cuttle-diversifier`) applying item/statement/match-arm reordering, private symbol/local renaming, arithmetic/branch/loop semantic rewrites, and inline-hint perturbation. |
| [`binmorph`](binmorph) | Post-link, size-preserving x86-64 ELF `.text` binary rewriter (`cuttle-binmorph`) performing register permutation, prologue/epilogue stack-slot permutation, basic-block instruction commutation, and opcode-class instruction morphing to generate new binary **skins** in ~140ms. |
| [`mtd_metrics`](mtd_metrics) | Binary gadget analyzer and ROP/JOP chain exploit simulator (`cuttle-mtd-metrics`). |
| [`verifier`](verifier) | Candidate acceptance gate (`verify`) enforcing public-symbol preservation, locked-module integrity, unit/property test suites, and per-function performance bounds (`perf.jsonl`). |
| [`factory_builder`](factory_builder) | Host packager that builds `target_enterprise_kernel` with per-seed codegen flags, provisions the out-of-band device key, and wraps the kernel ELF into BIOS/UEFI disk images. |
| [`morph_engine`](morph_engine) | Factory orchestrator (`morph`) managing scheduled morph cycles (`scheduler.toml`), Ed25519 M-of-N threshold attestation chains (`attest.log.jsonl`), and Merkle root anchors. |

---

## Diversification Pipeline ("Skins")

Every morph cycle applies three orthogonal diversification layers to the 69 enrolled kernel modules in [`scheduler.toml`](scheduler.toml) (while refusing to touch the **Cuttlebone** security-critical files listed in [`locked_modules.toml`](locked_modules.toml)):

1. **Source AST Diversification (`cuttle-diversifier`)**:
   - Reorders top-level items, independent statements, and literal `match` arms.
   - Renames private functions and lexical local bindings.
   - Applies reversible semantic perturbations (power-of-two multiply/shift inversion, branch polarity inversion, `for` ↔ `while` loop rewrites) and per-function `#[inline(never)]` / `#[inline(always)]` codegen hints.
   - Skips any function containing `unsafe` blocks or `#[no_mangle]` / `extern` ABI boundaries.
2. **Compiler & Linker Layout Randomization (`factory_builder`)**:
   - Compiles the kernel with `-Zrandomize-layout -Zlayout-seed=<seed>`, linker section shuffling (`--shuffle-sections=.text=<seed>`), and seed-derived LLVM backend thresholds (`--inline-threshold`, `--unroll-threshold`, `--regalloc-csr-first-time-cost`, `--x86-cmov-converter`).
3. **Post-Link Size-Preserving Binary Rewriting (`cuttle-binmorph`)**:
   - Rewrites `.text` in place without shifting function boundaries or invalidating relocations across 7 passes:
     1. Whole-function `{R12, R13, R14, R15}` callee-saved register permutation.
     2. Leaf-function `{R8, R9, R10, R11}` caller-saved scratch register permutation.
     3. Return-block and external-tail-call scratch register renaming across `{R8..R11, RCX, RSI, RDI}`.
     4. Prologue `push` / reverse epilogue `pop` stack-slot permutation across `{RBX, RBP, R12..R15}`.
     5. Seeded Fisher-Yates instruction-window commutation (up to 6 instructions) with `[rip + disp32]` displacement fixup.
     6. Opcode-class and multi-instruction encoding morphing (`mov` ↔ `or`/`and`/`lea`/`xchg`, `add`/`sub` ↔ `lea`, `cmp`/`sub` ↔ `test`, cross-branch `CF/AF`-dead `add ↔ sub (-imm)`, and 2-instruction small-immediate load decomposition) with 100% scrubbing of unintended `ret` (`0xC3/0xC2/0xCB/0xCA/0xCF`) and indirect `call/jmp` (`0xFF /2..5`) bytes.
     7. Cross-width basic-block multi-instruction rewriting (`(L_i ∓ 1) + mid + (L_j ± 1)`), shifting interior instruction boundaries by `±1` byte while flipping endpoint mnemonics (`xor` ↔ `sub`, `mov` → SIB `lea`, `cmp` ↔ `test`, `add/sub/lea ±1` ↔ `inc/dec`).

---

## OS Runtime, Services & Security Model

### True 4-Core Hardware SMP, Multi-Stack Threads & Event-Driven `HLT` / IPI Architecture
- **Hardware Multi-Core AP Bringup ([`smp_hw.rs`](target_enterprise_kernel/src/smp_hw.rs))**: Installs a position-independent 16-bit Real Mode → 32-bit Protected Mode → 64-bit Long Mode trampoline at physical `0x8000`, copies the kernel's PML4 (`%cr3`) into mailbox `0x8100`, and wakes secondary processors (`CPU 1..=3`) via Local APIC `INIT` + `SIPI` (`0xFEE0_0300`).
- **Preemptive/Cooperative Multi-Stack Kernel Threads (`0x8200`)**: Maintains 4 dedicated 16 KiB kernel thread stacks (`thread_entry_0..3`) and switches hardware `%rsp` + callee-saved registers (`%rbp`, `%rbx`, `%r12..%r15`) via `SWITCH_CONTEXT_CODE` at `pa_to_va(0x8200)`.
- **Event-Driven Hardware `HLT` Sleep + Local APIC Timer (`0x40`) & Doorbell IPI (`0x41`)**:
  - Installs a shared 64-bit Runtime GDT (`0x8240`), 256-entry Runtime IDT (`0x9000`), legacy 8259 PIC remap/mask (`0x20..0x2F`), and machine-code ISR stubs (`ISR_LAPIC_EOI` at `0x8300`, `SLEEP_HLT_CODE` `[0xFB, 0xF4, 0xFA, 0xC3]` = `sti; hlt; cli; ret` at `0x8370`).
  - **Secondary Cores (`CPU 1..3`)**: Sleep in hardware `C1 HLT` (`0%` host CPU) when idle and wake in sub-microsecond time when `CPU 0` or a kernel thread fires a Fixed `All-Excluding-Self` Doorbell IPI (`0x000C_4041`) on `vector 0x41`.
  - **Bootstrap Processor (`CPU 0`)**: Drains all pending VirtIO-Net packets and `COM1`/PS/2 bytes at full speed while I/O is active, and enters `HLT` (`smp_hw_idle_wait()`) whenever idle, waking on Local APIC Periodic Timer interrupts (`vector 0x40`).
- **Hardware Privilege Isolation ([`gdt.rs`](target_enterprise/src/gdt.rs), [`interrupts.rs`](target_enterprise/src/interrupts.rs), [`banners_arch_platform.rs`](target_enterprise_kernel/src/banners_arch_platform.rs))**: Loads a 7-entry x86-64 GDT (`KERNEL_CODE=0x08`, `KERNEL_DATA=0x10`, `USER_DATA=0x1B`, `USER_CODE=0x23`, 16-byte `TSS=0x28`), a 104-byte `Tss64` with dedicated `RSP0` and `IST1` stacks (`ltr`), and drops from Ring-0 (`CPL=0`) to Ring-3 (`CPL=3`) via `iretq`, trapping back via `int 0x80`.

### Cuttle Triad — *"Three Hearts. One Appliance."* (Hypervisor Coordinator + Native In-Guest UDP `:8081` Quorum Protocol)
Because each 4-core Cuttle OS VM requires only **3.5 MB of disk**, **128 MB of RAM**, and **~0% host CPU when idle (`HLT`)**, [`triad.bat`](triad.bat) and [`tools/triad_controller.py`](tools/triad_controller.py) package **3 independent Cuttle OS VMs into ONE logical appliance** (`http://127.0.0.1:18080`) backed by both the host coordinator and a native in-guest peer-to-peer UDP replication protocol on port `:8081` (`TRIAD_PREPARE` / `TRIAD_ACK` / `TRIAD_STATUS`):
- **Spatial & Temporal N-Variant Skin Diversity (~140ms Fast Binary Morph + Per-Node Cryptographic Keys)**:
  - **`OS-1 (SQL-Data-A)`**, **`OS-2 (SQL-Data-B)`**, and **`OS-3 (SQL-Parity / Witness)`** boot 3 distinct x86-64 kernel binary skins generated via `binmorph.exe` (~15,500 instructions rewritten and ~280 functions register-permuted in ~140ms per VM, spliced directly into each VM's BIOS image at byte offset `784896`) and are provisioned with **3 distinct domain-separated 256-bit device keys** (`node1/device_key_node1.bin`..`node3`) via `-fw_cfg`, giving every VM its own `seal_key`, `attest_key`, and per-node + per-boot Ring-3 service ELF skins.
- **Native In-Guest Peer-to-Peer Triad Protocol (`UDP :8081`, [`lived_net.rs`](target_enterprise/src/lived_net.rs))**:
  - Guest kernels natively verify and execute HMAC-SHA256-authenticated, replay-protected `TRIAD_PREPARE <seq> <node_id> <hmac_hex64> <sql>` and `TRIAD_ACK <seq> <node_id> <state_hash_hex16> <hmac_hex64>` datagrams on UDP `:8081`, computing a 64-bit FNV-1a SQL `state_hash()` across all tables and rows, tracking 2-of-3 quorum commits (`TRIAD_QUORUM`), and raising split-brain / state-tamper alerts (`TRIAD_ALERT status=DIVERGENCE`) whenever a peer reports a conflicting state hash for the same sequence number.
- **Triple Modular Redundancy (TMR) 2-of-3 Majority Vote, Persistent WAL & 4 KiB RAID XOR Parity ($D_1 \oplus D_2 = P$)**:
  - All SQL and shell operations on the coordinator require a freshly generated ephemeral 128-bit coordinator session token (`secrets.token_hex(16)`, passed via `X-Cuttle-Session` or `Authorization: Bearer`) and strictly reject any payload containing non-printable or control characters (`0x08` BS, `0x7F` DEL, etc.).
  - Read queries (`SELECT`, `.tables`, `.schema`) are verified by 2-of-3 majority vote across online nodes.
  - Mutating SQL writes (`INSERT`, `UPDATE`, `DELETE`, `CREATE`, `DROP`) increment a monotonic Triad transaction sequence (`triad_tx_seq`), persist to `triad/triad_wal.json`, commit in parallel to online nodes' AHCI disks (`LBA 1058..1065`), and update the 4 KiB bitwise XOR parity block ($P = D_1 \oplus D_2$).
- **Zero-Downtime Rolling Morph (*"Lose a heart, keep beating"*), WAL Delta Catch-Up (`CATCHING_UP`) & Automatic Single-Node Tamper Self-Healing**:
  - When any node drains and reboots to adopt a newly scrambled binary skin (`DRAINING → MORPHING`), the surviving 2 hearts hold a `2/3` majority and continue committing SQL writes with zero downtime; on `SHELL resume OK` (`CATCHING_UP`), the controller replays missed WAL transactions before returning the node to `3/3 ONLINE`.
  - If an unauthorized modification or disk corruption alters state on any single OS, the 2-of-3 majority vote and 4 KiB XOR parity verification ($D_{\text{corrupted}} = D_{\text{peer}} \oplus P$) detect the divergence, isolate the compromised node, reconstruct its canonical SQL state from the healthy 2/3 majority + WAL, and force an immediate emergency binary skin re-morph.

### Service Policy Mediation, Hardware `CPL=3` Mailbox Execution & Role Profiles ([`svc_runtime.rs`](target_enterprise/src/svc_runtime.rs))
[`ServiceSupervisor`](target_enterprise/src/svc_runtime.rs) enforces a deny-by-default service policy, KPTI page-table (`x86_pml4`), capability, eBPF seccomp, and IPC mediation boundary in front of the HTTP (`LivedNet`), SQL (`SqlDb`), and shell/VFS (`OsShell`) subsystem engines. Each enabled service (`svc-http`, `svc-sql`, `svc-sh`) owns an independent 64-bit ELF image and a diversified 32-byte x86-64 Ring-3 (`CPL=3`) machine-code stub seeded from both the node's cryptographic `seal_key` and boot generation (`derive_service_base_seed_for_boot(seal_key, boot_gen)`), a live [`PageTable<8>`](target_enterprise/src/paging.rs) user page table (`user_l4`) serialized and verified via [`kpti::x86_pml4::serialize_into`](target_enterprise/src/kpti.rs), a dedicated canary-guarded [`IpcMailbox`](target_enterprise/src/svc_runtime.rs), a capability bitmask, and a syscall seccomp filter. At boot and rotation, each service's 32-byte machine-code stub executes at hardware `CPL=3` (`iretq` → reads the user-mapped mailbox request word at `[rsp - 0x20]`, XOR-signs it with the per-variant 32-bit salt into `[rsp - 0x18]`, and traps via `int 0x80` on `TSS.RSP0` via [`exec_service_ring3_stub`](target_enterprise_kernel/src/banners_arch_platform.rs), while Red Team canary-corruption tests prove tampered mailbox frames are rejected), and on every runtime request [`ServiceSupervisor::mediate_endpoint`](target_enterprise/src/svc_runtime.rs) verifies the role/capability/seccomp policy, records the IPC mailbox hop, and executes the service's measured eBPF binary inside a canary-guarded stack frame before the subsystem handler runs:
- **Option 3 Role-Specific Service Provisioning (`NodeRole`)**:
  - **`wfe` (Web Front-End Appliance)**: Loads only `/sbin/svc-http` (`0x41_0000`). Neither `svc-sql` nor `svc-sh` is loaded into memory.
  - **`sql` (SQL RAID Storage Appliance)**: Loads only `/sbin/svc-sql` (`0x42_0000`). Neither `svc-http` nor `svc-sh` is loaded into memory.
  - **`shell` (Bastion / Exec Appliance)**: Loads only `/sbin/svc-sh` (`0x43_0000`).
  - **`full` (Unified Standalone Appliance)**: Loads `svc-http`, `svc-sql`, and `svc-sh` in separate live `PageTable<8>` KPTI user page tables where no service maps kernel secrets (`0xFFFF_8000_0000_0000`) or another service's code page.
- **Independent Per-Service Skin Rotation & Attestation**:
  - `service rotate <svc-http|svc-sql|svc-sh> [seed]` re-morphs and restarts an individual service ELF and its 32-byte `CPL=3` stub in place **without rebooting the kernel**, verifies its new IMA SHA-256 digest and `x86_pml4`-serialized `user_l4` KPTI page table, re-runs its hardware `CPL=3` mailbox stub, extends TPM 2.0 `PCR-10` (`svc_pcr10`), and binds the updated measurement into `attest` quotes.
- **Standing Service Policy & Endpoint Credential Matrix**:

| Service / Binary | KPTI User VA | Granted Capabilities (Deny-by-Default) | Allowed Syscalls (eBPF Seccomp) | Endpoints / Operations | Required Credentials |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`svc-http`** (`/sbin/svc-http`) | `0x0041_0000` | `NET_RAW \| SVC_IPC` *(denied direct disk/storage, VFS write, exec)* | `getpid`, `yield`, `time`, `ipc_send`, `net_io` *(denied `open`, `storage_io`, `exec`)* | `GET /status`, `/healthz`, `/app`, `/sql?<SELECT>`, `/fs/<path>`, `/triad`<br>`POST /session/login`<br>`GET /session/whoami`, `POST /session/logout` | Public read-only (`GET`); `POST /session/login` requires keyed `HMAC-SHA256(auth_key, seq \|\| user)` (`401`/`403` otherwise, rate-limited with `429` for an 8-tick decaying cooldown window after 5 failed attempts); `whoami`/`logout` require valid 128-bit `sid` (`401` otherwise; `503` if role-disabled) |
| **`svc-sql`** (`/sbin/svc-sql`) | `0x0042_0000` | `DURABLE_WAL_WRITE \| SVC_IPC` *(denied `NET_RAW`, `FS_BYPASS`, `exec`)* | `getpid`, `yield`, `time`, `ipc_send`, `storage_io` *(denied `open`, `net_io`, `exec`)* | `GET /sql?<SELECT>` / `POST /sql` (`SELECT`, `.tables`, `.schema`)<br>`POST /sql` (`CREATE`, `DROP`, `INSERT`, `UPDATE`, `DELETE`)<br>UDP `:8081` `TRIAD_PREPARE` / `TRIAD_ACK` | Read-only queries: public via `svc-http -> svc-sql` IPC (`503` if role-disabled); Mutating SQL statements: require verified 128-bit session `sid` (`503` if role-disabled, `401 Unauthorized` on `GET` or missing/invalid `sid`); UDP `:8081` Triad replication requires monotonic `seq` + `HMAC-SHA256` |
| **`svc-sh`** (`/sbin/svc-sh`) | `0x0043_0000` | `FS_BYPASS \| SVC_IPC \| SVC_EXEC` *(denied `NET_RAW`)* | `getpid`, `yield`, `time`, `open`, `ipc_send`, `exec` *(denied `net_io`)* | `POST /sh`, `POST /exec`, `PUT /fs/<path>`, `DELETE /fs/<path>`<br>Shell `write`, `rm`, `spawn`, `kill`, `exec`, `grant`, `revoke`, `seccomp`, `fw`, `ima`, `sync`<br>UDP `:8080` `AUTH <seq> <hmac> <cmd>` | HTTP endpoints require verified 128-bit session `sid` (`503` if role-disabled, `401` otherwise); all mutating console commands (`write`/`rm`/`spawn`/`kill`/`exec`/`grant`/`revoke`/`seccomp`/`fw`/`ima`/`sync`) gated by `svc-sh` role policy; UDP mutating commands require replay-protected `HMAC-SHA256` (`EACCES` otherwise) |

### Embedded Relational SQL Database (`SqlDb`)
- **Zero-Allocation Indexed SQLite-Compatible Engine ([`sql.rs`](target_enterprise/src/sql.rs))**: Supports up to 4 tables and 64 rows per table (`256` rows total) with secondary hash/fingerprint indexing (`CREATE INDEX <name> ON <table> (<col>)`, `DROP INDEX <name>`), `CREATE TABLE <name> (<col> <INT|INTEGER|TEXT>, ...)`, `DROP TABLE <name>`, `INSERT INTO <name> VALUES (...)`, `SELECT * | COUNT(*) | SUM(<col>) | MIN(<col>) | MAX(<col>) | AVG(<col>) | <col>, ... FROM <name> [WHERE <col> <op|LIKE> <val>] [ORDER BY <col> [ASC|DESC]] [LIMIT <n>]`, `UPDATE <name> SET <col> = <val> [WHERE ...]`, `DELETE FROM <name> [WHERE ...]`, `.tables` / `SHOW TABLES`, and `.schema` / `DESCRIBE <name>`.
- **Red Team Parser Hardening & Authenticated Block Persistence (`CTTLSQL1`)**: Rejects interior unescaped single quotes (`WHERE k = 'a' OR '1'='1'`), checked `i64` arithmetic overflows, and exponential `LIKE` glob backtracking (using a non-recursive linear-time iterative glob matcher), and serializes all 64-row tables plus secondary index metadata into an 8-sector (`4 KiB`) AHCI disk partition (`LBA 1058..=1065`) protected by a constant-time keyed `HMAC-SHA256` tag over all 8 sectors.

### Dynamic Web Application Server, HTTPS (rustls TLS 1.3) & 16-Slot TCP Stack (`LivedNet`)
[`LivedNet`](target_enterprise/src/lived_net.rs) serves both HTTP/TCP (`:80`) and HTTPS (`:443`) across a 16-slot concurrent TCP connection table (`[Tcb; 16]`) with SYN-flood priority eviction (evicting half-open `SynReceived` slots before any `Established` connection) and per-slot RTO tick tracking (`tick_tcp_rto`):
- **HTTPS on `:443` ([`https.rs`](target_enterprise/src/https.rs), [`tls_provider.rs`](target_enterprise/src/tls_provider.rs))**: The TLS 1.3 protocol is [rustls](https://github.com/rustls/rustls) (`no_std` + `alloc`, driven through its unbuffered API, one session per TCP slot); the cryptography is a RustCrypto provider written for the bare-metal soft-float target: `TLS_AES_128_GCM_SHA256` and `TLS_CHACHA20_POLY1305_SHA256`, X25519 and secp256r1 key exchange, ECDSA P-256 / SHA-256 signatures with RFC 6979 nonces, and a ChaCha20 CSPRNG that requires hardware entropy (`RDRAND` or TPM 2.0 `GetRandom`, enabled by `-cpu max` under QEMU) and fails closed (`TlsEntropyStatus::Unseeded`) when neither hardware entropy source is available. TLS 1.3 only; no session tickets, resumption or 0-RTT. Each node presents a self-signed X.509 v3 certificate for its own P-256 key (SAN `localhost`, `127.0.0.1`, `10.0.2.15`) and prints the entropy source, provisioning state, and certificate SHA-256 fingerprint at boot (`HTTPS UP port=443 tls13=rustls entropy=<rdrand|tpm|rdrand+tpm> provisioned=<0|1> cert_sha256=…`). Every HTTP route answers identically on `:80` and `:443`.
- **HTTPS boot proofs**: Every boot runs the provider's known-answer vectors (AES-128-GCM NIST SP 800-38D Case 3, ChaCha20-Poly1305 RFC 8439 §2.8.2, X25519 RFC 7748 §6.1, ECDSA P-256 RFC 6979 §A.2.5, P-256 ECDH CAVP, SHA-256 FIPS 180-4, HMAC-SHA256 RFC 4231, HKDF-SHA256 RFC 5869, and record tamper rejection), parses and verifies a generated certificate, and replays a recorded TLS 1.3 session through the real `LivedNet` frame path with all 16 TCP slots in use, requiring every server byte to match (`HTTPS compose OK … sha=…`). [`tests/tls_kat.rs`](target_enterprise/tests/tls_kat.rs) and [`tests/https_interop.rs`](target_enterprise/tests/https_interop.rs) check every RFC/NIST vector and test the server against an independent rustls client using *ring* crypto (both cipher suites, both key-exchange groups, certificate pinning, tampered-Finished rejection, `401` on unauthenticated calls), including a dedicated sub-invocation compiled with the kernel's five soft-float `RUSTFLAGS` cfgs; `tools/https_check.py` checks a booted node with OpenSSL, Python `ssl` and curl, and the Triad self-test checks every node over TLS 1.3 against its pinned certificate, before and after a live morph.
- **Dynamic HTML5 Dashboard (`GET /app`, `GET /dashboard`, `GET /index.html`)**: Renders live kernel boot generation, VFS file count, SQL table/row telemetry, active web session count, and authenticated operator identity.
- **Cryptographic Web Sessions (`POST /session/login`, `GET /session/whoami`, `POST /session/logout`)**: Authenticates `<user>:<seq>:<hmac_sha256_hex>` against the device's UDP/web auth key (with a decaying 8-tick cooldown after 5 failed attempts) and issues a 128-bit `HMAC-SHA256` session token (`Set-Cookie: sid=<32hex>; HttpOnly; Path=/`), accepted on subsequent requests via `Cookie: sid=<32hex>` or `X-Session-Token: <32hex>`.
- **Networked SQL Database Server (`GET /sql?<query>`, `POST /sql`, `GET /db`, `POST /db`)**: Executes read-only `SELECT`, `.tables`, and `.schema` queries openly and requires a valid session token (`401 Unauthorized` otherwise) for mutating `CREATE`, `DROP`, `INSERT`, `UPDATE`, and `DELETE` statements.
- **Sandboxed Remote Code Execution (`POST /exec`)**: Requires a valid session token and executes registered user binaries (`exec <path> [arg]`) through the full IMA SHA-256 verification → ELF64 parse → KPTI page-table check → TPM 2.0 `PCR-10` extend → stack canary check → eBPF execution pipeline.
- **VFS File Server (`GET /fs/<path>`, `PUT /fs/<path>`, `DELETE /fs/<path>`)**: Serves files from `MemRamFs` with automatic `text/html`, `application/json`, and `text/plain` content-type detection; `PUT` and `DELETE` require an authenticated session and enforce system-path protection (`/etc/*`, `/proc/*`, `/bin/*`).
- **Telemetry, UDP `:8080` Control Plane & UDP `:8081` Triad Protocol**: Serves read-only telemetry (`GET /status`, `/ps`, `/smp`, `/threads`, `/ls`, `/audit`, `/uname`, `/seal`, `/attest`, `/seccomp`, `/ima`, `/fw`, `/triad`), enforces stateless CIDR firewall rules (`fw`), accepts replay-protected `AUTH <seq> <hmac_sha256_hex> <cmd>` datagrams on UDP `:8080`, and processes peer-to-peer `TRIAD_PREPARE` / `TRIAD_ACK` / `TRIAD_STATUS` quorum datagrams on UDP `:8081`.

### Unified Subsystem Shell & Continuous OS Event Loop (`OsShell`)
[`OsShell`](target_enterprise/src/shell.rs) and [`live_os_console_loop`](target_enterprise_kernel/src/main.rs) multiplex VirtIO-net packet processing, COM1 (`0x3F8`) + PS/2 (`0x60`/`0x64`) interactive console commands, Local APIC timer/IPI wakeups, and AHCI disk persistence in a single continuous event loop:
- **Virtual Filesystem & Block-Backed Partition (`MemRamFs`)**: `ls`, `cat`, `write`, `rm`, `stat`, `df`, `sync` persisted across reboots in a 16-sector (`8 KiB`) AHCI partition (`LBA 1042..=1057`, `CTTLFS01`).
- **Multi-Core SMP & Kernel Thread Commands**: `smp [status | run [n]]` and `threads` (displays per-core APIC IDs, `hlt+irq0x40` / `hlt+ipi0x41` states, hardware IRQ/IPI counters, and per-stack context switches).
- **SQL, Triad Cluster & Session Console Commands**: `sql <statement | .tables | .schema>`, `triad [status | node <0|1|2> | propose <sql>]`, and `session [status | login <user> | verify <sid> | logout <sid>]`.
- **Process Scheduler & Capability-Gated Syscalls**: `ps`, `spawn`, `kill`, `caps`, `grant`, `revoke`, `syscall`.
- **Per-PID eBPF Seccomp Sandboxing**: `seccomp [status | deny <pid> <getpid|yield|time|open|all> | clear <pid>]`.
- **Measured User Execution, TPM 2.0 TIS Driver & Remote Attestation**: `exec <path> [arg]`, `ima [status | enroll <path>]`, `attest [nonce]`, and `audit`.

### Out-of-Band Key Provisioning & State Continuity
- **Master Key Provisioning ([`provisioning.rs`](target_enterprise_kernel/src/provisioning.rs))**: `factory_builder`, `run.bat`, `triad_controller.py`, and `cuttle_fleet.py` generate 32-byte OS-CSPRNG keys and session/client tokens (`device_secret_key.bin`, `target/cuttle_images/triad/operator_token.txt`, `target/cuttle_images/triad/node*/device_key_node*.bin`, `target/cuttle_images/fleet/provider_token.txt`, and `target/cuttle_images/fleet/<client>/{master_key.bin,client_token.txt}`) exclusively with owner-only permissions (`0600` on POSIX / current-user ACL via `icacls` on Windows; all gitignored and never stored in source, the kernel ELF, or the guest disk) and pass each VM's device key to QEMU via `-fw_cfg name=opt/cuttle_device_key,file=...`. Malformed or truncated existing secret files are rejected at startup rather than silently truncated or overwritten. On unprovisioned boots, the kernel harvests hardware entropy from `RDRAND` and physical TPM 2.0 TIS `GetRandom` (`0xFED4_0000`), mixed with `RDTSC`, CMOS RTC, and 8254 PIT jitter.
- **Domain-Separated Runtime Keys**:
  - **UDP & Web Session Auth Key**: `HMAC-SHA256(master_key, "cuttle-net-auth-v1:" || mac_address)`. On unprovisioned boots (no `fw_cfg` key), `LivedNet` starts in unprovisioned mode and rejects all state-mutating `AUTH`, `/session/login`, `/sql`, `/sh`, `/exec`, and `/fs` requests even if a caller computes an HMAC under a zero key.
  - **Durable Disk Seal Key**: `HMAC-SHA256(master_key, "cuttle-durable-seal-v1:" || "ahci0-lba1040")`. Seals and verifies the 2-sector (`LBA 1040..=1041`) AHCI WAL header (`CTTLSHL1`), the 16-sector (`LBA 1042..=1057`) `CTTLFS01` filesystem partition, and the 8-sector (`LBA 1058..=1065`) `CTTLSQL1` SQL database partition in constant time across reboots.
  - **Remote Attestation Key**: `HMAC-SHA256(master_key, "cuttle-remote-attest-v1:" || seed)`.
  - **TLS Identity**: `HMAC-SHA256(master_key, "cuttle-tls-identity-v1:" || mac_address)` seeds the node's P-256 key via rejection sampling in $[1, n-1]$ (`provisioned=1`), so a provisioned node keeps the same HTTPS certificate across reboots and morph cycles (clients can pin it). Unprovisioned boots (`provisioned=0`) derive an ephemeral certificate from hardware entropy each boot.

---

## Attacker Models & Measured MTD Metrics

Evaluated via `cuttle-binmorph` and `cuttle-mtd-metrics` (`churn` and `chainsim`) across seeded builds of `target_enterprise_kernel` (`787` functions, `76,193` instructions, `2,000` 8-gadget ROP chains):

| Metric / Attacker Model | Scope | Measured Result |
| :--- | :--- | :--- |
| **Morphed `.text` instructions (`binmorph`)** | Instructions rewritten in place per build (~140ms) | **`29.5%`** (`73%+` of eligible candidates; `~285` functions register-swapped) |
| **Positional gadget survival (`binmorph` only)** | Gadgets remaining at the same offset with identical disassembly | **`25.8%`** (`0.0%` when combined with source + linker morphing) |
| **Attacker A — Static 8-step ROP chain** | Stockpiled exploit with hardcoded gadget offsets from build $N$ fired at build $N+1$ | **`0.0%`** (`0 / 2,000` chains survive) |
| **Attacker B — Exact-register 8-step chain relocation** | Attacker with a full `.text` dump of build $N+1$ who relocates each step to any offset containing the same address-masked gadget with the same registers | **`1.15%`** (`23 / 2,000` chains rebuildable; **`98.85%` broken**) |
| **Attacker B\_reg — Register-adapting 8-step chain relocation** | Attacker with a full `.text` dump of build $N+1$ who can both relocate gadgets and freely substitute any general-purpose register of matching width (`r64`/`r32`/`r16`/`r8`) | **`8.80%`** (`176 / 2,000` chains rebuildable; **`91.20%` broken**) |

---

## Build, Test & Run

### 1. Launch the Cuttle Triad Appliance (*"Three Hearts. One Appliance."* — 3 VMs + TMR 2-of-3 Majority + RAID-SQL + Rolling MTD)
```powershell
.\triad.bat
# Or pass --gui to also display all 3 native 1280x720 QEMU windows:
.\triad.bat --gui
# Run the automated 3-VM live morph + WAL catch-up + 2-of-3 self-healing test:
python tools/triad_controller.py --self-test
```
Then open **`http://127.0.0.1:18080/app`** in your browser, or **`http://127.0.0.1:18080/console`** for the tabbed live ops console ([`tools/triad_console.html`](tools/triad_console.html)): Overview, Operations (SQL, read-only inspection, vault, guard/cron, morph controls, guided drills), Live Cycle (animated view of rolling morphs, WAL catch-up and self-healing) and Event Log. Operations need the operator session token the controller prints at startup.

### 1b. Run a Multi-Client Fleet (provider + isolated client farms)
[`fleet.bat`](fleet.bat) starts [`tools/cuttle_fleet.py`](tools/cuttle_fleet.py), a provider that manages one isolated **farm** per client. Each farm is a set of Triads chosen by the client's plan in [`tools/fleet.toml`](tools/fleet.toml), and each job runs a real kernel role profile:

| Job | Kernel role | 2-of-3 vote compares |
| :--- | :--- | :--- |
| Web front end | `wfe` (svc-http only) | per-file path, size, and SHA-256 content digests (wiping and resyncing from a healthy peer on divergence) |
| SQL database | `sql` (svc-sql only) | `kv` table + XOR parity |
| Search index | `sql` | `kv` + `idx` tables (schema provisioned through the WAL) |
| Business jobs (cron) | `full` (jobs need svc-sh, listing needs svc-http) | `kv` table; read-only desired cron jobs are re-applied after every boot |

Plans `basic` (web + SQL) and `pro` (web + SQL + index + cron) ship with seven sample clients (60 VMs, up to 5 jobs per plan). Every farm runs in its own process with its own random master key (all node device keys derive from it), state directory, and WALs. The provider token sees every client; a client token sees only its own farm (`403` on any other or unknown client ID). Farms bind `127.0.0.1`, accept only a per-run secret held by the provider (scrubbed from the farm environment before child processes spawn), and launch VMs with `forward_node_ports=False` so guest `:80`/`:443` ports are not forwarded on host loopback (whereas standalone `triad.bat` forwards `:18101–18103` and `:18501–18503` on loopback for direct node inspection).
```powershell
.\fleet.bat                                   # console: http://127.0.0.1:18888/fleet
python tools/cuttle_fleet.py --self-test      # 2-client fleet: auth, scoping, roles, data/key/port isolation
```

### QEMU accelerator: WHPX (Hyper-V) or TCG
`triad.bat` and `fleet.bat` take `--accel auto|whpx|tcg` (default `auto`), while single-VM `run.bat` and `qemu_smoke` default to `tcg` (`run.bat whpx` or `CUTTLE_QEMU_ACCEL=whpx` opts into WHPX). `auto` uses **WHPX**, the Windows Hypervisor Platform's hardware virtualization, when this host can run it, and **TCG** software emulation otherwise. With WHPX, guest code runs natively, so boots and morphs are faster and an idle VM barely costs host CPU. Under TCG, every timer tick is emulated.
- `triad.bat --accel tcg`, `fleet.bat --accel tcg` or `run.bat tcg`; or set `CUTTLE_ACCEL`. The fleet also reads `accelerator` in `tools/fleet.toml`, globally or per plan.
- `auto` probes WHPX once at startup. Because some Windows hosts accept a WHPX guest (and emit QEMU stderr feature warnings) without ever letting its BIOS leave reset, a VM that prints no recognized guest serial marker within 8 s under WHPX is relaunched on TCG, and that Triad stays on TCG.
- The QEMU smoke test and `run.bat` stay on TCG by default (deterministic reference). `CUTTLE_QEMU_ACCEL=whpx` or `run.bat whpx` runs under WHPX.

### 2. Boot a Single 4-Core VM Under QEMU
Run `run.bat` to build the kernel ELF, package a BIOS disk image, and boot a single 4-core VM in QEMU (`http://127.0.0.1:18080/app`), or run the automated multi-boot + tamper-rejection QEMU smoke suite:
```powershell
.\run.bat
cargo test -p factory_builder --test qemu_smoke -- --ignored --nocapture --test-threads=1
```

### 2b. Talk to a Node over HTTPS
Each node serves HTTPS on guest port 443 (`run.bat` forwards it to `127.0.0.1:18443`; standalone Triad nodes use `:18501–18503`). The certificate is self-signed per node, so pin it: fetch it once, compare its SHA-256 with the `HTTPS UP … cert_sha256=` line on the node's serial console, then trust exactly that certificate.
```powershell
python tools/https_check.py --port 18443 --save-cert node.pem   # fetch, then OpenSSL + Python ssl + curl checks
curl --ssl-no-revoke --cacert node.pem https://localhost:18443/healthz   # --ssl-no-revoke: Windows curl (Schannel); no CRL for a self-signed cert
openssl s_client -connect 127.0.0.1:18443 -tls1_3 -CAfile node.pem -verify_hostname localhost -verify_return_error -brief
```

### 3. Run Workspace Unit & Integration Tests
```powershell
cargo check --workspace --all-targets
cargo test --workspace --lib
```

### 4. Run the Gadget Churn & ROP Chain Evaluation
```powershell
cargo run --release -p cuttle-mtd-metrics -- churn <base.elf> <variant.elf>
cargo run --release -p cuttle-mtd-metrics -- chainsim <base.elf> <variant.elf>
```

## License

CuttleOS is licensed under the [Apache License 2.0](LICENSE) (see also [NOTICE](NOTICE)). You may use, modify and redistribute it, including inside commercial and closed-source products; keep the license and notices, and state your changes. The CuttleOS name and logo are not licensed for use as another product's name.

Every dependency is permissively licensed (with the two documented exceptions below), so CuttleOS stays open source while software built on top of it can stay proprietary. [`deny.toml`](deny.toml) holds the policy; the license check fails on any unapproved copyleft dependency. [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) lists every third-party component inside a boot image with its license text, and must ship with any distributed image. Check both with:
```powershell
powershell -File tools\license_check.ps1     # cargo deny on all 3 Cargo workspaces + notices up to date
python tools/third_party_notices.py         # regenerate THIRD_PARTY_NOTICES.md after a dependency change
```
Two components use non-Apache-2.0/MIT/BSD licenses and are documented in [`NOTICE`](NOTICE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md): the embedded Noto Sans Mono bitmap font inside `noto-sans-mono-bitmap` (SIL Open Font License 1.1) and `ucs2` (MPL-2.0, file-level copyleft, used only in the optional UEFI loader `factory_builder --uefi`; under MPL-2.0 §3.2, distributing unmodified `ucs2` inside a larger work does not require relicensing CuttleOS provided recipients are informed where unmodified `ucs2` source can be obtained).
