# Cuttle OS

> **Three hearts. One appliance. Rearranging its own guts every boot.**

## Cuttle OS in Plain English (The 60-Second Version)

Most computers run the exact same compiled binary as every other machine running that software. If an attacker finds one memory bug and builds an exploit on their laptop, that same exploit works on every copy of the system everywhere, forever.

**Cuttle OS fixes that by constantly rearranging its own internal guts.**

Saying it "changes its skin" actually undersells what happens inside. Skin is surface-level; Cuttle OS rewires its **internal organs** on every build, every reboot, and even live while running:

1. **It scrambles its own machine code ("Rearranging the Guts" — `cuttle-diversifier` + `factory_builder` + `cuttle-binmorph`):**
   Every instance of Cuttle OS does the exact same job, but the raw x86-64 instructions inside the kernel and services are completely different from build to build and boot to boot. It shuffles function and statement order in the Rust source code, randomizes compiler memory layouts, swaps which CPU registers (`R8`–`R15`) and stack slots functions use, reorders instructions, and replaces instruction opcodes with equivalent machine code. An exploit written against one copy crashes uselessly on the next copy — or even on the same machine a minute later.
2. **A rigid spine holds the rules and data steady ("The Cuttlebone" — `cuttle-contracts` & `locked_modules.toml`):**
   While the machine-code guts get scrambled, a tiny locked core ([`cuttle-contracts`](contracts) and [`locked_modules.toml`](locked_modules.toml)) never changes. That keeps wire formats, hardware Ring-0/Ring-3 boundary rules, and encrypted disk data compatible across morphs — so the OS can reboot into a freshly scrambled binary and pick up right where it left off without losing a single SQL row or file.
3. **Three brains vote on every answer ("The Triad" — `triad.bat` / `tools/triad_controller.py`):**
   Because Cuttle OS is tiny (~5.5 MB disk image, 128 MB RAM), a single appliance runs **three separate 4-core Cuttle OS virtual machines at once** — each with *different* internal machine-code guts and its own cryptographic keys:
   - Every read and write is checked by a **2-of-3 majority vote** plus **8 KiB RAID-style XOR parity** ($D_1 \oplus D_2 \oplus D_3 = P$) across the three nodes.
   - One node at a time can drain, scramble its guts into a brand-new binary (~1.1–1.8 s on the full HTTPS + SQL kernel), reboot, and catch up from the transaction log with **zero downtime** while the other two keep serving.
   - **Ink (Active Divergence Detection & Self-Healing):** If a fault or unauthorized disk edit corrupts one node, 2-of-3 majority voting over canonical `.dump <table> digest` SHA-256 state probes, native UDP `:8081` quorum state-hash checks (`TRIAD_ALERT status=DIVERGENCE`), and eBPF/canary traps detect the divergence, fence the bad node, rebuild its state from the healthy 2-of-3 majority + WAL + 8 KiB XOR parity, and force it to re-morph into a fresh binary automatically.

**In short:** Cuttle OS is a tiny bare-metal Rust appliance operating system (with a built-in web server, relational SQL engine, encrypted vault, VFS, shell, and TLS 1.3 stack) that runs as three differently-wired clones voting together, constantly scrambling their internal machine code so attackers never have a stationary target.

---

## Expected Use Case & Current Scope

Cuttle OS is a hardened single-purpose / multi-role network and state appliance OS designed for edge gateways, SQL/KV state appliances, and remote management nodes where static binary monoculture enables exploit reuse:

- **Deny-by-default service mediation:** The Ring-0 kernel retains the scheduler, physical/slab/KPTI memory managers, hardware drivers, network/storage stacks, IPC bus, capability gate, eBPF seccomp filter, and TPM/HMAC attestation, while gating all application endpoints — Web Server & Dashboard (`svc-http`, `/sbin/svc-http`), Relational SQL Engine (`svc-sql`, `/sbin/svc-sql`), and Exec/Management Shell (`svc-sh`, `/sbin/svc-sh`) — behind [`ServiceSupervisor`](target_enterprise/src/svc_runtime.rs).
- **Role-scoped footprints (`wfe`, `sql`, `shell`, `full`):** Under role provisioning, each node loads only the service ELFs required for its role (leaving unused services unloaded and unmapped) and can rotate, restart, and attest individual service binaries in place without rebooting the kernel.
- **Verified vs. unverified hardware boundary:** The full stack (BIOS + UEFI `OVMF`, 4-core SMP, KPTI + Ring-3 `CPL=3` ELF64 execution, AHCI, NVMe, VirtIO-blk/net, e1000, TLS 1.3, 12 MiB CoW page store, `blkdebug` sector fault healing, 3-VM Triad rolling morphs, and multi-tenant Fleet orchestration) is continuously verified under QEMU (`tcg` and Windows `whpx`). Physical bare-metal x86-64 silicon burn-in and live Linux `swtpm` / discrete SPI-LPC TPM 2.0 daemon attachment are not yet verified on this host.

---

## Workspace Architecture

| Crate / Tool | Purpose |
| :--- | :--- |
| [`contracts`](contracts) | Immutable `no_std` trait and wire-format contract definitions (`cuttle-contracts`, `9` modules) shared by the kernel and host verifier — the rigid **Cuttlebone** that is never morphed. |
| [`target_enterprise`](target_enterprise) | Pure `no_std` OS subsystem library (`82` modules: multi-region 4 KiB physical frame manager, segregated slab allocator, multi-page Ring-3 ELF64 process VM, MSI/MSI-X I/O completion rings, page-granular encrypted CoW + `CWAL` [`PagedBlockStore`](target_enterprise/src/paged_store.rs), HTTPS via `rustls` TLS 1.3 + RustCrypto, X.509, send-side sliding-window TCP/IP + IPv6 ICMPv6/NDP, HTTP, DNS, DHCP, ARP, TFTP, VirtIO, NVMe, AHCI, VT-d IOMMU, KPTI, VFS, JFS, FAT32, GPT, WAL, B+Tree, indexed SQL, TPM 2.0 PCR-policy NV sealing + monotonic counters, eBPF, Seccomp, AuditLog, and [`OsShell`](target_enterprise/src/shell.rs)). |
| [`target_enterprise_kernel`](target_enterprise_kernel) | Bare-metal `x86_64-unknown-none` bootable OS kernel (`14` modules, BIOS & UEFI `OVMF`/`EDK2`) linking `target_enterprise` to hardware drivers (16550 UART, PCI MSI/MSI-X, AHCI, NVMe, VirtIO-net/blk, Intel e1000, APIC/IOAPIC, HPET/PIT/RTC, TPM 2.0 TIS, and UEFI GOP framebuffer console). |
| [`diversifier`](diversifier) | Deterministic, seed-driven Rust AST diversifier (`cuttle-diversifier`) applying item/statement/match-arm reordering, private symbol/local renaming, arithmetic/branch/loop semantic rewrites, and inline-hint perturbation. |
| [`binmorph`](binmorph) | Post-link, size-preserving x86-64 ELF `.text` binary rewriter (`cuttle-binmorph`) performing 7-pass register permutation, prologue/epilogue stack-slot permutation, basic-block instruction commutation, and opcode/boundary morphing. |
| [`mtd_metrics`](mtd_metrics) | Binary gadget analyzer and ROP/JOP chain exploit simulator (`cuttle-mtd-metrics`). |
| [`verifier`](verifier) | Candidate acceptance gate (`verify`) enforcing public-symbol preservation, signed policy/locked-module integrity, unit/property test suites, and per-function performance bounds (`perf.jsonl`). |
| [`factory_builder`](factory_builder) | Host packager that builds `target_enterprise_kernel` with reproducible `--remap-path-prefix` + per-seed codegen/layout flags, mints device keys and operator TPM re-anchor tokens, and wraps the kernel ELF into BIOS/UEFI disk images. |
| [`morph_engine`](morph_engine) | Factory orchestrator (`morph`) managing scheduled morph cycles ([`scheduler.toml`](scheduler.toml)), Ed25519 `threshold_m`-of-`N` attestation chains (`attest.log.jsonl`), signed [`factory_expected.toml`](factory_expected.toml) / [`locked_modules.toml`](locked_modules.toml) policies, and RFC 6962 domain-separated Merkle proofs. |
| [`tools/triad_controller.py`](tools/triad_controller.py) & [`tools/cuttle_fleet.py`](tools/cuttle_fleet.py) | Host-side 3-VM Triad coordinator (2-of-3 majority voting, authenticated `/triad/rpc`, encrypted WAL mirroring, `CTTLBKUP1` encrypted backup/restore, XOR parity healing, live rolling morphs, and web ops console) and multi-tenant Fleet orchestrator. |

---

## Compiler-Enforced Totality & Durability Hardening

Across all **105 `.rs` files** in [`contracts`](contracts), [`target_enterprise`](target_enterprise), and [`target_enterprise_kernel`](target_enterprise_kernel):

- **Crate-Wide Panic/Unwrap Gates:**
  - [`target_enterprise/src/lib.rs`](target_enterprise/src/lib.rs) enforces `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented, clippy::unreachable, clippy::fallible_impl_from))]` across all 82 OS library modules without crate-wide lint suppressions.
  - [`target_enterprise_kernel/src/main.rs`](target_enterprise_kernel/src/main.rs) enforces `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::todo, clippy::unimplemented, clippy::unreachable, clippy::fallible_impl_from))]` across all 14 bare-metal kernel modules.
- **Release Integer Overflow Traps:** [`target_enterprise_kernel/Cargo.toml`](target_enterprise_kernel/Cargo.toml) sets `overflow-checks = true` in `[profile.release]`, keeping checked arithmetic active in optimized bare-metal kernel images.
- **No Silent Input Truncation:** Wire codecs, HTTP/HTTPS routes, SQL statements, VFS paths, vault secrets, and session usernames validate full lengths upfront and reject oversized inputs with explicit errors (`ENOSPC`, `ENAMETOOLONG`, `413 Payload Too Large`, or typed `Err`) rather than clamping or dropping trailing bytes.
- **All-or-Nothing Atomicity & Frame Reclamation:** Packet/record builders pre-validate output capacity before mutating buffers; mid-growth Ring-3 `BRK` OOM ([`proc_vm.rs`](target_enterprise/src/proc_vm.rs)) and failed NVMe/VirtIO-blk candidate probes ([`phys_mm.rs`](target_enterprise/src/phys_mm.rs), [`hw_storage_drivers.rs`](target_enterprise_kernel/src/hw_storage_drivers.rs)) zero-scrub and reclaim every partially allocated physical 4 KiB frame.
- **Read-Back-Verified, Content-Nonce Encrypted Storage:** Every committed 4 KiB CoW page in [`paged_store.rs`](target_enterprise/src/paged_store.rs) derives its `ChaCha20-Poly1305` nonce from both header metadata and plaintext (`page_nonce`), enforces a monotonic `lsn_floor` across interrupted epochs, and reads back every written page, directory sector, and superblock before marking an epoch committed.

---

## Diversification Pipeline ("Skins")

Every morph cycle applies three orthogonal diversification layers to the 68 enrolled `target_enterprise` modules in [`scheduler.toml`](scheduler.toml) (while refusing to modify any file listed in [`locked_modules.toml`](locked_modules.toml), and rejecting stale `*.candidate.rs` artifacts before touching a checkout):

1. **Source AST Diversification (`cuttle-diversifier`)**:
   - Reorders top-level items, dependency-verified independent statements (tracking referenced locals and field projections), and side-effect-free literal `match` arms.
   - Renames private functions and lexical local bindings while preserving cross-module visibility.
   - Applies reversible semantic perturbations (checked/wrapping power-of-two shift rewrites, De Morgan/relational branch polarity inversion, `for` ↔ `while` loop rewrites with `continue`-safe increment placement) and per-function `#[inline(never)]` / `#[inline(always)]` codegen hints.
   - Skips any function containing `unsafe` blocks or `#[no_mangle]` / `extern` ABI boundaries.
2. **Compiler & Linker Layout Randomization (`factory_builder`)**:
   - Compiles the kernel with deterministic workspace path remapping (`--remap-path-prefix`), `-Zrandomize-layout -Zlayout-seed=<seed>`, linker section shuffling (`--shuffle-sections=.text=<seed>`), and seed-derived LLVM backend thresholds (`--inline-threshold`, `--unroll-threshold`, `--regalloc-csr-first-time-cost`, `--x86-cmov-converter`).
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

### 1. 4-Core Hardware SMP, Guarded Stacks, Per-CPU `Tss64` & Ring-3 (`CPL=3`) Processes
- **ACPI Topology & Multi-Core AP Bring-Up ([`acpi_rsdp.rs`](target_enterprise/src/acpi_rsdp.rs), [`smp.rs`](target_enterprise/src/smp.rs), [`smp_hw.rs`](target_enterprise_kernel/src/smp_hw.rs)):** Parses `RSDP` → `XSDT`/`RSDT` → `MADT` (`xAPIC` + `x2APIC`), `HPET`, and `DMAR` tables, maps a `W^X`-split real-mode trampoline at `0x8000`, and wakes `CPU 1..=3` via Local APIC `INIT` + `SIPI`.
- **16 Hardware-Guarded Stacks & Emergency Heap Headroom:** Maps `4 AP` (16 KiB), `4 KTHREAD` (16 KiB), `4 IST1` `#DF` (4 KiB), and `4` `IST2`/`IST3` (`#NMI` / `#MC`) stacks into `SMP_GUARDED_STACKS_VA` with unmapped (`PTE_P = 0`) top/bottom guard pages, alongside a `512 KiB` Ring-0 heap reserve gating port-443 TLS allocations.
- **Per-CPU `Tss64`, TLB Shootdowns (`0x42`) & Crash Containment (`0x43`):** Installs the 64-bit GDT, per-CPU `Tss64` (`RSP0` + `IST1` `#DF` + `IST2` `#NMI` + `IST3` `#MC`), and 256-entry Runtime IDT immediately after `set_phys_offset`, with HPET-calibrated Local APIC timer (`0x40`), Doorbell IPI (`0x41`), synchronous cross-CPU TLB shootdown IPI (`0x42`) under `PT_MOD_LOCK`, Ring-3 preemption timer (`0x50`), and `SmpLockupWatchdog`. On Ring-0 panic/fault, the kernel halts peer APs (`0x43`), scrubs runtime keys, logs over `COM1`, and writes a `ChaCha20-Poly1305` `CTTLPENC` crash dump (`LBA 1536..1568`) via lock-free AHCI Slot 1 or dedicated emergency NVMe queues.
- **Physical Frame / Slab MM, CPU Protections, VT-d SLPTs & Ring-3 ELF64 ([`phys_mm.rs`](target_enterprise/src/phys_mm.rs), [`slab_alloc.rs`](target_enterprise/src/slab_alloc.rs), [`proc_vm.rs`](target_enterprise/src/proc_vm.rs), [`proc_hw.rs`](target_enterprise_kernel/src/proc_hw.rs), [`iommu.rs`](target_enterprise/src/iommu.rs), [`kpti.rs`](target_enterprise/src/kpti.rs)):**
  - Manages up to `8 GiB` RAM across BIOS `E820` and UEFI `GetMemoryMap` with zero-scrubbed frame/slab reclamation.
  - Enforces `EFER.NXE`, `CR0.WP`, `CR4.SMEP`, `CR4.SMAP`, `CR4.UMIP`, `CR4.FSGSBASE`, `PTE_NX` on MMIO BARs, and 4-level Intel VT-d Root/Context/SLPT DMA confinement (`iommu::vtd_hw`).
  - Executes multi-page Ring-3 (`CPL=3`) ELF64 processes in per-process KPTI `CR3` page tables (`PT_LOAD` `RX`/`RO+NX`/`RW+NX`, guard pages, `PROC_SYS_BRK` heap, `16 KiB` user stack, `4 KiB` IPC mailbox) with per-process `FXSAVE64`/`FXRSTOR64` SIMD state, canonical `FS_BASE`/`GS_BASE` save/restore, `SYSCALL`/`LSTAR` flag masking (`TF|IF|DF|IOPL|NT|AC`), preemptive `0x50` quanta across `CPU 0..3`, and fault containment with automatic morphed service respawn.
- **MSI/MSI-X Block & Network Drivers ([`async_io.rs`](target_enterprise/src/async_io.rs), [`hw_storage_drivers.rs`](target_enterprise_kernel/src/hw_storage_drivers.rs), [`hw_net_drivers.rs`](target_enterprise_kernel/src/hw_net_drivers.rs)):** Routes PCI MSI/MSI-X onto IDT vectors `0x45` (block) and `0x46` (network) with hardware TSC deadlines per command class across AHCI (pinned port + `IDENTIFY` serial check), NVMe (`Admin` + `I/O SQ/CQ` + `NVME_OPC_FLUSH` + 512B namespace verification), and VirtIO-blk (authenticated-store discovery + optional `opt/cuttle_storage_backend` pin), plus 8-slot pipelined `VirtIO-net` TX/RX.

### 2. Cuttle Triad — *"Three Hearts. One Appliance."* (`triad.bat` / `tools/triad_controller.py`)
[`triad.bat`](triad.bat) and [`tools/triad_controller.py`](tools/triad_controller.py) coordinate **3 independent 4-core Cuttle OS VMs as one logical appliance** (`http://127.0.0.1:18080`) paired with an in-guest UDP `:8081` quorum protocol (`TRIAD_PREPARE` / `TRIAD_ACK` / `TRIAD_STATUS`):
- **Spatial & Temporal Binary Diversity + Per-Node Keys:** `OS-1 (SQL-Data-A)`, `OS-2 (SQL-Data-B)`, and `OS-3 (SQL-Parity)` boot 3 distinct `binmorph` kernel variants (~`74,200` instruction encodings rewritten and ~`1,000` functions register-permuted across `2,907` functions per VM) with 3 domain-separated 256-bit device keys (`node1..node3`), giving each VM distinct `seal_key`, `attest_key`, TLS identity, and Ring-3 service stubs.
- **2-of-3 Majority Vote, Encrypted WAL Mirroring, Snapshots & 8 KiB XOR Parity ($D_1 \oplus D_2 \oplus D_3 = P$):**
  - Read queries (`SELECT`, `.tables`, `.schema`) require a 2-of-3 majority match across online nodes; `wfe` roles compare per-file path, size, and SHA-256 content digests.
  - Mutating SQL statements require the ephemeral 128-bit operator bearer token (plus loopback `Origin` CSRF validation), persist to `HMAC-SHA256`-sealed `triad_wal.json` and `coordinator_epoch.json` (`state_schema = 2`, anti-deletion floor, persisted `node_rpc_seq`), commit in parallel to online nodes with durable `sync` quorum verification before advancing `tx_seq`, and update the authenticated 8 KiB XOR parity block.
  - Supports off-box `ChaCha20-Poly1305` WAL mirroring (`--wal-mirror-dir`, `CTTLWMIR1`) and encrypted cluster backup/verify/restore (`GET /api/backup`, `--backup`, `--verify-backup`, `--restore`, `CTTLBKUP1`), plus standby coordinator epoch fencing (`--standby` + `POST /api/failover`).
- **Zero-Downtime Rolling Morph, A/B Fallback & Automatic 2-of-3 Self-Healing:**
  - Draining one node into its inactive A/B image slot (`slot_a` / `slot_b`) leaves 2-of-3 nodes serving writes; failed boots roll back automatically (`AB_ROLLBACK`), and returning nodes verify `commit_seq` via `HMAC-SHA256` `attest` quotes before replaying missed WAL entries (`CATCHING_UP → ONLINE`).
  - Whole-disk rollback (`DISK_ROLLBACK_DETECTED`), storage halts (`STORAGE FAULT`), or single-node data divergence trigger automatic disk archival/replacement, 2-of-3 majority + WAL + XOR parity reconstruction, and an emergency binary re-morph (documented in [`docs/runbooks/README.md`](docs/runbooks/README.md)).

### 3. Service Policy Mediation & Role Profiles ([`svc_runtime.rs`](target_enterprise/src/svc_runtime.rs))
Each service (`svc-http`, `svc-sql`, `svc-sh`) owns an independent ELF64 binary, a diversified 32-byte Ring-3 (`CPL=3`) stub executed via `iretq` → `int 0x80` on `TSS.RSP0`, a live [`PageTable<8>`](target_enterprise/src/kpti.rs) KPTI user view (`x86_pml4`), a canary-guarded `IpcMailbox`, a capability mask, and an eBPF seccomp filter. `service rotate <svc-http|svc-sql|svc-sh> [seed]` rotates and re-attests (`svc_pcr10`) an individual service in place without rebooting.

| Service / Binary | KPTI User VA | Granted Capabilities | Allowed Syscalls (eBPF Seccomp) | Endpoints / Operations | Required Credentials |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`svc-http`** (`/sbin/svc-http`) | `0x0041_0000` | `NET_RAW \| SVC_IPC` | `getpid`, `yield`, `time`, `ipc_send`, `net_io` | `GET /status`, `/healthz`, `/app`, `/sql?<SELECT>`, `/fs/<path>`, `/triad`<br>`POST /session/login`, `GET /session/whoami`, `POST /session/logout`<br>`POST /triad/rpc` | Public read-only `GET`; `POST /session/login` requires `HMAC-SHA256(auth_key, seq \|\| user)` (rate-limited `429` after 5 failures); `whoami`/`logout` require 128-bit `sid`; `POST /triad/rpc` requires `NodeRole::Full`, `HMAC-SHA256("cuttle-triad-rpc-v1:")` + monotonic `seq` + current epoch, and signs replies up to `32 KiB` with `X-Cuttle-Rpc-Mac` |
| **`svc-sql`** (`/sbin/svc-sql`) | `0x0042_0000` | `DURABLE_WAL_WRITE \| SVC_IPC` | `getpid`, `yield`, `time`, `ipc_send`, `storage_io` | `GET /sql?<SELECT>` / `POST /sql` (`SELECT`, `.tables`, `.schema`)<br>`POST /sql` (`CREATE`, `DROP`, `INSERT`, `UPDATE`, `DELETE`)<br>UDP `:8081` `TRIAD_PREPARE` / `TRIAD_ACK` | Read-only queries public via `svc-http -> svc-sql` IPC (`503` if role-disabled); mutating SQL requires verified 128-bit `sid` (`401` otherwise); UDP `:8081` requires monotonic `seq` + `HMAC-SHA256` |
| **`svc-sh`** (`/sbin/svc-sh`) | `0x0043_0000` | `FS_BYPASS \| SVC_IPC \| SVC_EXEC` | `getpid`, `yield`, `time`, `open`, `ipc_send`, `exec` | `GET /mem`, `POST /sh`, `POST /exec`, `PUT/DELETE /fs/<path>`, `/vault/*`<br>Console mutating commands<br>UDP `:8080` `AUTH <seq> <hmac> <cmd>` | HTTP endpoints require verified 128-bit `sid` (`401` otherwise, `503` if role-disabled); UDP `:8080` requires replay-protected `HMAC-SHA256` (`EACCES` otherwise) |

### 4. Relational SQL (`SqlDb`), Page-Granular CoW Storage (`PagedBlockStore`) & Durable State
- **Indexed SQL Engine ([`sql.rs`](target_enterprise/src/sql.rs)):** Supports up to `8` tables × `2,048` row slots in `paged_mode` (`4 × 64` on `< 2 MiB` disks) with B+Tree `INT` range indexes and secondary hash indexes (`CREATE/DROP INDEX`), `COUNT/SUM/MIN/MAX/AVG`, `WHERE` (`=`, `!=`, `<`, `<=`, `>`, `>=`, linear-time non-recursive `LIKE`), `ORDER BY`, `LIMIT`, per-session transaction isolation, and canonical SHA-256 `.dump <table> digest` probes.
- **Page-Granular Encrypted CoW Storage ([`state_store.rs`](target_enterprise/src/state_store.rs), [`paged_store.rs`](target_enterprise/src/paged_store.rs)):**
  - Every durable mutation is committed and flushed to disk **before** acknowledging the console or HTTP caller.
  - Disks `>= 2 MiB` (`>= 4,096` sectors) enable `CTTLPGS1` `PagedBlockStore` (`PAGED_V2_MAX_LOGICAL_PAGES = 1024` 4 KiB pages = `4 MiB` logical payload / `2,048` physical CoW pages on `>= 12 MiB` disks; `256` pages on `4..<8 MiB` disks; `118` pages on `2 MiB` disks, shared between VFS and SQL and enforced upfront with `ENOSPC`), anchored inside an `HMAC-SHA256`-authenticated `AB_FORMAT_V3` commit sector (`LBA 1149`) over dual `ChaCha20-Poly1305` shadow/primary state slots (`LBA 1040..=1148`).
  - Unauthenticated or corrupted paged disks halt fail-closed with `STORAGE FAULT` rather than reinitializing over existing pages; unprovisioned boots enter `EPHEMERAL` mode (`EROFS` / `503`).
  - When a hardware TPM 2.0 (`0xFED4_0000`) is present, `AB_FORMAT_V3` binds `tpm_anchored = 1` and a decoupled monotonic NV counter (`0x0150_0010`), failing closed if the TPM disappears or trails the counter and supporting one-time `CTTLRA01` operator re-anchoring (`factory_builder mint-tpm-reanchor`).
- **HTTPS (TLS 1.3) & Dual-Stack Networking ([`lived_net.rs`](target_enterprise/src/lived_net.rs), [`https.rs`](target_enterprise/src/https.rs), [`tls_provider.rs`](target_enterprise/src/tls_provider.rs)):**
  - Serves HTTP (`:80`) and `rustls` TLS 1.3 (`:443`, `AES-128-GCM` + `ChaCha20-Poly1305`, X25519 + P-256 ECDHE, RFC 6979 ECDSA P-256, hardware `RDRAND`/TPM entropy fail-closed CSPRNG, deterministic provisioned node certificates) across 16 concurrent TCP slots with send-side RFC 5681 congestion control, validated window updates + zero-window persist probes, 3-dup-ACK Fast Retransmit, 8-segment (`<= 32 KiB` gap) OOO reassembly, keyed ISNs, timer-only RTO ticks, stateless IPv4/IPv6 firewalling (including during the early boot window), and IPv6 ICMPv6 Echo + NDP/DAD *(no TCP or UDP services run over IPv6)*.
- **Out-of-Band Key Provisioning ([`provisioning.rs`](target_enterprise_kernel/src/provisioning.rs)):** Keys and operator/client tokens are generated via OS CSPRNG with owner-only ACLs (`0600` / `icacls`), gitignored, and injected via QEMU `-fw_cfg` (or TPM 2.0 NV `0x0150_0011` gated by `TPM2_PolicyPCR(PCR0 + PCR7)` + `CTK1` AEAD + `TPM2_NV_ReadLock`; physical LPC/SPI bus parameter encryption is not implemented).

---

## Attacker Models, Measured MTD Metrics & Verification Suite

Evaluated via `cuttle-binmorph`, `cuttle-mtd-metrics`, [`differential_equiv.rs`](binmorph/tests/differential_equiv.rs), [`qemu_smoke.rs`](factory_builder/tests/qemu_smoke.rs), and [`tools/verify_metrics_independent.py`](tools/verify_metrics_independent.py):

| Metric / Verification Gate | Scope | Measured Result |
| :--- | :--- | :--- |
| **Kernel `.text` functions mutated (`binmorph`)** | In-place binary rewrite per seed on `target_enterprise_kernel` (`2,215` baseline benchmark functions; `2,907` functions on full HTTPS/paged kernel) | **`86.3%` of functions mutated** (`0` functions gaining unintended `ret`-family `0xC3/0xC2/0xCB/0xCA/0xCF` or indirect `call/jmp` `0xFF /2..5` bytes; `~74,200` instructions rewritten per Triad node) |
| **Interior `0xC3`/`0xCF` gadget scrubbing** | Non-terminator `ret` (`0xC3`) and `iretq` (`0xCF`) bytes inside `.text` (`verify_metrics_independent.py`) | **`2,939 → 2,273`** (**`666` unintended gadget bytes scrubbed**) |
| **Positional gadget survival** | Gadgets remaining at the same offset with identical disassembly | **`25.8%`** (`binmorph` alone) / **`0.0%`** (combined source + compiler layout + `binmorph`) |
| **Attacker A — Static 8-step ROP chain** | Hardcoded gadget offsets from build $N$ replayed against build $N+1$ | **`0.0%` survival** (`0 / 2,000` chains) |
| **Attacker B — Exact-register relocation** | Full `.text` disclosure of build $N+1$, relocating exact-register gadgets | **`1.15%` survival** (`98.85%` broken) |
| **Attacker B\_reg — Register-adapting relocation** | Full `.text` disclosure of build $N+1$ + arbitrary same-width GPR substitution | **`8.80%` survival** (`91.20%` broken) |
| **x86-64 Differential Equivalence ([`differential_equiv.rs`](binmorph/tests/differential_equiv.rs))** | Concrete `X86MicroVm` execution comparing post-`ret` GPRs, `RSP`, `.data`/`.bss`, and 16 KiB stack/heap RAM on compiled kernel functions | **`1,114` real kernel functions**, **`570,368` concrete executions across `32`–`64` seeds**, **`979` injected instruction faults caught** |
| **QEMU Multi-Boot, Scale & Fault Smoke ([`qemu_smoke.rs`](factory_builder/tests/qemu_smoke.rs))** | `10` end-to-end QEMU suites (BIOS, UEFI `OVMF`, 3-seed morph continuity, `4 MiB` & `12 MiB` `PagedBlockStore` + TLS 1.3 burn-in, NVMe-only + flood, VirtIO-only + pinned multi-disk, `blkdebug` sector `EIO` healing, tampered-seal refusal) | **`10 / 10` suites passing** with `overflow-checks = true` active in `[profile.release]` |
| **Triad 2-of-3 Quorum, XOR Parity & Fleet Self-Tests** | Live 3-VM rolling `binmorph`, crash/restart `tx_seq` continuity, wiped-disk rollback detection + RAID XOR/WAL reconstruction, 6 chaos scenarios, and multi-client Fleet role/token scoping | **Passing** across `triad_controller.py --unit-test`, `triad_controller.py --self-test`, `cuttle_fleet.py --unit-test`, `cuttle_fleet.py --self-test`, and `tools/chaos.py` |

---

## Build, Test & Run

> **Nightly Toolchain Requirement:** Building [`target_enterprise_kernel`](target_enterprise_kernel/rust-toolchain.toml) (`-Zbuild-std`) and packaging BIOS/UEFI boot images via [`factory_builder_pkg`](factory_builder_pkg/rust-toolchain.toml) (`bootloader 0.11.17`) pin **`nightly-2026-10-22`** (`rustc 1.101.0-nightly (1a2c4797e 2026-10-21)`) with `rust-src` and `llvm-tools-preview`:
> ```powershell
> rustup toolchain install nightly-2026-10-22 --component rust-src --component llvm-tools-preview
> ```

### 1. Launch the Cuttle Triad Appliance (*"Three Hearts. One Appliance."*)
```powershell
.\triad.bat
# Display all 3 native 1280x720 QEMU GOP console windows:
.\triad.bat --gui
# Mirror encrypted WAL off-box and create/verify an encrypted cluster backup:
python tools/triad_controller.py --wal-mirror-dir D:\CuttleMirror
python tools/triad_controller.py --backup cluster.cttlbk --verify-backup cluster.cttlbk
# Run the automated 3-VM live morph + WAL catch-up + 2-of-3 self-healing suite:
python tools/triad_controller.py --self-test
```
Open **`http://127.0.0.1:18080/app`** or **`http://127.0.0.1:18080/console`** ([`tools/triad_console.html`](tools/triad_console.html)) and paste the ephemeral operator session token printed at startup.

### 1b. Run a Multi-Client Fleet (Provider + Per-Client Triad Farms)
[`fleet.bat`](fleet.bat) launches [`tools/cuttle_fleet.py`](tools/cuttle_fleet.py), managing isolated Triad farms per client plan in [`tools/fleet.toml`](tools/fleet.toml):

| Job | Kernel Role | 2-of-3 Vote Compares |
| :--- | :--- | :--- |
| Web front end | `wfe` (`svc-http` only) | Per-file path, size, and SHA-256 content digests (wiping and resyncing on divergence) |
| SQL database | `sql` (`svc-sql` only) | `kv` table + 8 KiB XOR parity |
| Search index | `sql` | `kv` + `idx` tables (schema provisioned through the WAL) |
| Business jobs (`cron`) | `full` | `kv` table; desired read-only cron jobs re-applied after each boot |

```powershell
.\fleet.bat                                   # console: http://127.0.0.1:18888/fleet
python tools/cuttle_fleet.py --unit-test      # fast host unit & integrity checks
python tools/cuttle_fleet.py --self-test      # live 18-VM 2-client fleet verification
```

### QEMU Accelerator: WHPX (Hyper-V) or TCG
`triad.bat` and `fleet.bat` accept `--accel auto|whpx|tcg` (default `auto`: uses **WHPX** hardware virtualization when responsive within 8 s, automatically falling back to **TCG** software emulation otherwise). Single-VM `run.bat` and `qemu_smoke` default to deterministic `tcg` (`run.bat whpx` or `CUTTLE_QEMU_ACCEL=whpx` opts into WHPX).

### 2. Boot a Single 4-Core VM & Talk to HTTPS (`:443`)
```powershell
.\run.bat
python tools/https_check.py --port 18443 --save-cert node.pem
curl --ssl-no-revoke --cacert node.pem https://localhost:18443/healthz
openssl s_client -connect 127.0.0.1:18443 -tls1_3 -CAfile node.pem -verify_hostname localhost -verify_return_error -brief
```

### 3. Run the Full Verification Gate & Totality Checks
```powershell
cargo clippy -p target_enterprise --lib --no-deps
cargo test --workspace --no-fail-fast
cargo test -p factory_builder --test qemu_smoke -- --ignored
Push-Location target_enterprise_kernel; cargo clippy --release --no-deps; cargo build --release; Pop-Location
python -c "import ast; ast.parse(open('tools/triad_controller.py', encoding='utf-8').read())"
```

### 4. Run Gadget Churn & ROP Chain Evaluation
```powershell
cargo run --release -p cuttle-mtd-metrics -- churn <base.elf> <variant.elf>
cargo run --release -p cuttle-mtd-metrics -- chainsim <base.elf> <variant.elf>
```

---

## License

CuttleOS is licensed under the [Apache License 2.0](LICENSE) (see also [NOTICE](NOTICE)). You may use, modify and redistribute it, including inside commercial and closed-source products; keep the license and notices, and state your changes. The CuttleOS name and logo are not licensed for use as another product's name.

Every dependency is permissively licensed (with the two documented exceptions below), so CuttleOS stays open source while software built on top of it can stay proprietary. [`deny.toml`](deny.toml) holds the policy; the license check fails on any unapproved copyleft dependency. [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) lists every third-party component inside a boot image with its license text, and must ship with any distributed image. Check both with:
```powershell
powershell -File tools\license_check.ps1     # cargo deny on all 3 Cargo workspaces + notices up to date
python tools/third_party_notices.py         # regenerate THIRD_PARTY_NOTICES.md after a dependency change
```
Two components use non-Apache-2.0/MIT/BSD licenses and are documented in [`NOTICE`](NOTICE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md): the embedded Noto Sans Mono bitmap font inside `noto-sans-mono-bitmap` (SIL Open Font License 1.1) and `ucs2` (MPL-2.0, file-level copyleft, used only in the optional UEFI loader `factory_builder --uefi`; under MPL-2.0 §3.2, distributing unmodified `ucs2` inside a larger work does not require relicensing CuttleOS provided recipients are informed where unmodified `ucs2` source can be obtained).
