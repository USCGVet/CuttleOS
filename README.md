# Proteus

Proteus is a Moving Target Defense (MTD) x86-64 unikernel and automated diversification factory written in Rust. Each build cycle produces a structurally distinct bare-metal kernel binary while preserving a formally specified contract surface (`proteus-contracts`) and cryptographically sealed runtime state across reboots.

## Expected Use Case

Proteus is designed for high-assurance appliances, isolated network gateways, and unikernel workloads where static binary homogeneity enables exploit reuse. By continuously randomizing source-level AST structure, compiler codegen/layout decisions, and post-link x86-64 instruction encodings on every build cycle, Proteus invalidates gadget addresses (`Attacker A`), exact-register gadget sequences (`Attacker B`), and register-agnostic opcode-class gadget templates (`Attacker B_reg`) between builds without changing observable protocol or syscall behavior.

---

## Workspace Architecture

| Crate | Purpose |
| :--- | :--- |
| [`contracts`](file:///d:/RustProjects/Proteus/contracts) | Immutable `no_std` trait and wire-format contract definitions (`proteus-contracts`) shared by the kernel and host verifier. Never morphed. |
| [`target_enterprise`](file:///d:/RustProjects/Proteus/target_enterprise) | Pure `no_std`, zero-allocation OS subsystem implementations (73 modules: TLS 1.3, X.509, TCP/IP, HTTP, DNS, DHCP, ARP, ICMP, VirtIO, NVMe, AHCI, IOMMU, KPTI, VFS, JFS, FAT32, WAL, SQL, TPM 2.0, eBPF, Seccomp, AuditLog, and [`OsShell`](file:///d:/RustProjects/Proteus/target_enterprise/src/shell.rs)). |
| [`target_enterprise_kernel`](file:///d:/RustProjects/Proteus/target_enterprise_kernel) | Bare-metal `x86_64-unknown-none` bootable unikernel linking `target_enterprise` to physical hardware drivers (16550 UART, PCI, AHCI, NVMe, VirtIO-net/blk, e1000, APIC/IOAPIC, HPET/PIT/RTC). |
| [`diversifier`](file:///d:/RustProjects/Proteus/diversifier) | Deterministic, seed-driven Rust AST diversifier (`proteus-diversifier`) applying item/statement/match-arm reordering, private symbol/local renaming, arithmetic/branch/loop semantic rewrites, and inline-hint perturbation. |
| [`binmorph`](file:///d:/RustProjects/Proteus/binmorph) | Post-link, size-preserving x86-64 ELF `.text` binary rewriter (`proteus-binmorph`) performing register permutation, prologue/epilogue stack-slot permutation, basic-block instruction commutation, and opcode-class instruction morphing. |
| [`mtd_metrics`](file:///d:/RustProjects/Proteus/mtd_metrics) | Binary gadget analyzer and ROP/JOP chain exploit simulator (`proteus-mtd-metrics`). |
| [`verifier`](file:///d:/RustProjects/Proteus/verifier) | Candidate acceptance gate (`verify`) enforcing public-symbol preservation, locked-module integrity, unit/property test suites, and per-function performance bounds (`perf.jsonl`). |
| [`factory_builder`](file:///d:/RustProjects/Proteus/factory_builder) | Host packager that builds `target_enterprise_kernel` with per-seed codegen flags, provisions the out-of-band device key, and wraps the kernel ELF into BIOS/UEFI disk images. |
| [`morph_engine`](file:///d:/RustProjects/Proteus/morph_engine) | Factory orchestrator (`morph`) managing scheduled morph cycles (`scheduler.toml`), Ed25519 M-of-N threshold attestation chains (`attest.log.jsonl`), and Merkle root anchors. |

---

## Diversification Pipeline

Every morph cycle applies three orthogonal diversification layers to the 69 enrolled kernel modules in [`scheduler.toml`](file:///d:/RustProjects/Proteus/scheduler.toml) (while refusing to touch the security-critical files listed in [`locked_modules.toml`](file:///d:/RustProjects/Proteus/locked_modules.toml)):

1. **Source AST Diversification (`proteus-diversifier`)**:
   - Reorders top-level items, independent statements, and literal `match` arms.
   - Renames private functions and lexical local bindings.
   - Applies reversible semantic perturbations (power-of-two multiply/shift inversion, branch polarity inversion, `for` ↔ `while` loop rewrites) and per-function `#[inline(never)]` / `#[inline(always)]` codegen hints.
   - Skips any function containing `unsafe` blocks or `#[no_mangle]` / `extern` ABI boundaries.
2. **Compiler & Linker Layout Randomization (`factory_builder`)**:
   - Compiles the kernel with `-Zrandomize-layout -Zlayout-seed=<seed>`, linker section shuffling (`--shuffle-sections=.text=<seed>`), and seed-derived LLVM backend thresholds (`--inline-threshold`, `--unroll-threshold`, `--regalloc-csr-first-time-cost`, `--x86-cmov-converter`).
3. **Post-Link Size-Preserving Binary Rewriting (`proteus-binmorph`)**:
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

### Hardware Privilege Isolation & Interrupt Architecture
- **Live GDT, 64-bit TSS, and 256-Entry IDT ([`gdt.rs`](file:///d:/RustProjects/Proteus/target_enterprise/src/gdt.rs), [`interrupts.rs`](file:///d:/RustProjects/Proteus/target_enterprise/src/interrupts.rs), [`banners_arch_platform.rs`](file:///d:/RustProjects/Proteus/target_enterprise_kernel/src/banners_arch_platform.rs))**: Loads a 7-entry x86-64 GDT (`KERNEL_CODE=0x08`, `KERNEL_DATA=0x10`, `USER_DATA=0x1B`, `USER_CODE=0x23`, 16-byte `TSS=0x28`), a 104-byte `Tss64` with dedicated `RSP0` and `IST1` stacks (`ltr`), and a 256-entry IDT (`lidt`).
- **Ring-3 User Execution & Syscall Trap (`int 0x80`)**: Drops from Ring-0 (`CPL=0`) to Ring-3 (`CPL=3`) over a user-mapped page table (`PTE_USER`) via `iretq`, executes user-mode code, and traps back to Ring-0 on `TSS.RSP0` via vector `0x80` (`TYPE_TRAP_GATE_DPL3 = 0xEF`), dispatching through `SyscallDispatchImpl::dispatch_with_cap`.

### Embedded Relational SQL Database (`SqlDb`)
- **Zero-Allocation SQLite-Compatible Subset ([`sql.rs`](file:///d:/RustProjects/Proteus/target_enterprise/src/sql.rs))**: Supports `CREATE TABLE <name> (<col> <INT|INTEGER|TEXT>, ...)`, `DROP TABLE <name>`, `INSERT INTO <name> VALUES (...)`, `SELECT * | COUNT(*) | <col>, ... FROM <name> [WHERE <col> <op> <val>] [ORDER BY <col> [ASC|DESC]] [LIMIT <n>]`, `UPDATE <name> SET <col> = <val> [WHERE ...]`, `DELETE FROM <name> [WHERE ...]`, `.tables` / `SHOW TABLES`, and `.schema` / `DESCRIBE <name>`.
- **Authenticated Block Persistence (`PRTSSQL1`)**: Serializes tables and rows into an 8-sector (`4 KiB`) AHCI disk partition (`LBA 1058..=1065`) protected by a constant-time keyed `HMAC-SHA256` tag over all 8 sectors.

### Dynamic Web Application Server, Sessions & Remote Execution (`LivedNet`)
[`LivedNet`](file:///d:/RustProjects/Proteus/target_enterprise/src/lived_net.rs) serves both HTTP/TCP (`:80`) and TLS 1.3 / HTTPS (`:443`) across a 4-slot concurrent TCP connection table (`[Tcb; 4]`):
- **Dynamic HTML5 Dashboard (`GET /app`, `GET /dashboard`, `GET /index.html`)**: Renders live kernel boot generation, VFS file count, SQL table/row telemetry, active web session count, and authenticated operator identity.
- **Cryptographic Web Sessions (`POST /session/login`, `GET /session/whoami`, `POST /session/logout`)**: Authenticates `<user>:<seq>:<hmac_sha256_hex>` against the device's UDP/web auth key and issues a 128-bit `HMAC-SHA256` session token (`Set-Cookie: sid=<32hex>; HttpOnly; Path=/`), accepted on subsequent requests via `Cookie: sid=<32hex>` or `X-Session-Token: <32hex>`.
- **Networked SQL Database Server (`GET /sql?<query>`, `POST /sql`, `GET /db`, `POST /db`)**: Executes read-only `SELECT`, `.tables`, and `.schema` queries openly and requires a valid session token (`401 Unauthorized` otherwise) for mutating `CREATE`, `DROP`, `INSERT`, `UPDATE`, and `DELETE` statements.
- **Sandboxed Remote Code Execution (`POST /exec`)**: Requires a valid session token and executes registered user binaries (`exec <path> [arg]`) through the full IMA SHA-256 verification → ELF64 parse → KPTI page-table check → TPM 2.0 `PCR-10` extend → stack canary check → eBPF execution pipeline.
- **VFS File Server (`GET /fs/<path>`, `PUT /fs/<path>`, `DELETE /fs/<path>`)**: Serves files from `MemRamFs` with automatic `text/html`, `application/json`, and `text/plain` content-type detection; `PUT` and `DELETE` require an authenticated session and enforce system-path protection (`/etc/*`, `/proc/*`, `/bin/*`).
- **Telemetry & UDP Control Plane**: Serves read-only telemetry (`GET /status`, `/ps`, `/ls`, `/audit`, `/uname`, `/seal`, `/attest`, `/seccomp`, `/ima`, `/fw`), enforces stateless CIDR firewall rules (`fw`), and accepts replay-protected `AUTH <seq> <hmac_sha256_hex> <cmd>` datagrams on UDP `:8080`.

### Unified Subsystem Shell & Continuous OS Event Loop (`OsShell`)
[`OsShell`](file:///d:/RustProjects/Proteus/target_enterprise/src/shell.rs) and [`live_os_console_loop`](file:///d:/RustProjects/Proteus/target_enterprise_kernel/src/main.rs#L779-L895) multiplex VirtIO-net packet processing, COM1 (`0x3F8`) + PS/2 (`0x60`/`0x64`) interactive console commands, and AHCI disk persistence in a single continuous event loop:
- **Virtual Filesystem & Block-Backed Partition (`MemRamFs`)**: `ls`, `cat`, `write`, `rm`, `stat`, `df`, `sync` persisted across reboots in a 16-sector (`8 KiB`) AHCI partition (`LBA 1042..=1057`, `PRTSFS01`).
- **SQL & Session Console Commands**: `sql <statement | .tables | .schema>` and `session [status | login <user> | verify <sid> | logout <sid>]`.
- **Process Scheduler & Capability-Gated Syscalls**: `ps`, `spawn`, `kill`, `caps`, `grant`, `revoke`, `syscall`.
- **Per-PID eBPF Seccomp Sandboxing**: `seccomp [status | deny <pid> <getpid|yield|time|open|all> | clear <pid>]`.
- **Measured User Execution, TPM 2.0 TIS Driver & Remote Attestation**: `exec <path> [arg]`, `ima [status | enroll <path>]`, `attest [nonce]`, and `audit`.

### Out-of-Band Key Provisioning & State Continuity
- **Master Key Provisioning ([`provisioning.rs`](file:///d:/RustProjects/Proteus/target_enterprise_kernel/src/provisioning.rs))**: `factory_builder` generates a 32-byte OS-CSPRNG key in `device_secret_key.bin` (gitignored, never stored in source, the kernel ELF, or the guest disk) and passes it to QEMU via `-fw_cfg name=opt/proteus_device_key,file=device_secret_key.bin`. On unprovisioned boots, the kernel harvests hardware entropy from `RDRAND`, `RDTSC`, CMOS RTC, 8254 PIT, and physical TPM 2.0 TIS `GetRandom` (`0xFED4_0000`).
- **Domain-Separated Runtime Keys**:
  - **UDP & Web Session Auth Key**: `HMAC-SHA256(master_key, "proteus-net-auth-v1:" || mac_address)`. On unprovisioned boots (no `fw_cfg` key), `LivedNet` starts in unprovisioned mode and rejects all state-mutating `AUTH` and `/session/login` requests.
  - **Durable Disk Seal Key**: `HMAC-SHA256(master_key, "proteus-durable-seal-v1:" || "ahci0-lba1040")`. Seals and verifies the 2-sector (`LBA 1040..=1041`) AHCI WAL header (`PRTSSHL1`), the 16-sector (`LBA 1042..=1057`) `PRTSFS01` filesystem partition, and the 8-sector (`LBA 1058..=1065`) `PRTSSQL1` SQL database partition in constant time across reboots.
  - **Remote Attestation Key**: `HMAC-SHA256(master_key, "proteus-remote-attest-v1:" || seed)`.

---

## Attacker Models & Measured MTD Metrics

Evaluated via `proteus-binmorph` and `proteus-mtd-metrics` (`churn` and `chainsim`) across seeded builds of `target_enterprise_kernel` (`729` functions, `66,254` instructions, `2,000` 8-gadget ROP chains):

| Metric / Attacker Model | Scope | Measured Result |
| :--- | :--- | :--- |
| **Morphed `.text` instructions (`binmorph`)** | Instructions rewritten in place per build | **`29.5%`** (`19,508 / 66,254`) |
| **Positional gadget survival (`binmorph` only)** | Gadgets remaining at the same offset with identical disassembly | **`25.8%`** (`0.0%` when combined with source + linker morphing) |
| **Attacker A — Static 8-step ROP chain** | Stockpiled exploit with hardcoded gadget offsets from build $N$ fired at build $N+1$ | **`0.0%`** (`0 / 2,000` chains survive) |
| **Attacker B — Exact-register 8-step chain relocation** | Attacker with a full `.text` dump of build $N+1$ who relocates each step to any offset containing the same address-masked gadget with the same registers | **`1.15%`** (`23 / 2,000` chains rebuildable; **`98.85%` broken**) |
| **Attacker B\_reg — Register-adapting 8-step chain relocation** | Attacker with a full `.text` dump of build $N+1$ who can both relocate gadgets and freely substitute any general-purpose register of matching width (`r64`/`r32`/`r16`/`r8`) | **`8.80%`** (`176 / 2,000` chains rebuildable; **`91.20%` broken**) |

---

## Build, Test & Run

### 1. Run Workspace Unit & Integration Tests
```powershell
cargo check --workspace --all-targets
cargo test --workspace --lib
```

### 2. Build the Bare-Metal Kernel (`x86_64-unknown-none`)
```powershell
cargo run -p factory_builder -- build-kernel --kernel-crate d:\RustProjects\Proteus\target_enterprise_kernel
```

### 3. Boot Under QEMU
Run `run.bat` to build the kernel ELF, package a BIOS disk image, and boot it in QEMU with COM1 serial output, or run the automated multi-boot + tamper-rejection QEMU smoke suite:
```powershell
cargo test -p factory_builder --test qemu_smoke -- --ignored --nocapture --test-threads=1
```

### 4. Run the Gadget Churn & ROP Chain Evaluation
```powershell
cargo run --release -p proteus-mtd-metrics -- churn <base.elf> <variant.elf>
cargo run --release -p proteus-mtd-metrics -- chainsim <base.elf> <variant.elf>
```

