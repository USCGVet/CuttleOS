# Proteus

Proteus is a Moving Target Defense (MTD) x86-64 unikernel and automated diversification factory written in Rust. Each build cycle produces a structurally distinct bare-metal kernel binary while preserving a formally specified contract surface (`proteus-contracts`) and cryptographically sealed runtime state across reboots.

## Expected Use Case

Proteus is designed for high-assurance appliances, isolated network gateways, and unikernel workloads where static binary homogeneity enables exploit reuse. By continuously randomizing source-level AST structure, compiler codegen/layout decisions, and post-link x86-64 instruction encodings on every build cycle, Proteus invalidates gadget addresses (`Attacker A`), exact-register gadget sequences (`Attacker B`), and register-agnostic opcode-class gadget templates (`Attacker B_reg`) between builds without changing observable protocol or syscall behavior.

---

## Workspace Architecture

| Crate | Purpose |
| :--- | :--- |
| [`contracts`](file:///d:/RustProjects/Proteus/contracts) | Immutable `no_std` trait and wire-format contract definitions (`proteus-contracts`) shared by the kernel and host verifier. Never morphed. |
| [`target_enterprise`](file:///d:/RustProjects/Proteus/target_enterprise) | Pure `no_std`, zero-allocation OS subsystem implementations (72 modules: TLS 1.3, X.509, TCP/IP, HTTP, DNS, DHCP, ARP, ICMP, VirtIO, NVMe, AHCI, IOMMU, KPTI, VFS, JFS, FAT32, WAL, TPM 2.0, eBPF, Seccomp, AuditLog, and [`OsShell`](file:///d:/RustProjects/Proteus/target_enterprise/src/shell.rs)). |
| [`target_enterprise_kernel`](file:///d:/RustProjects/Proteus/target_enterprise_kernel) | Bare-metal `x86_64-unknown-none` bootable unikernel linking `target_enterprise` to physical hardware drivers (16550 UART, PCI, AHCI, NVMe, VirtIO-net/blk, e1000, APIC/IOAPIC, HPET/PIT/RTC). |
| [`diversifier`](file:///d:/RustProjects/Proteus/diversifier) | Deterministic, seed-driven Rust AST diversifier (`proteus-diversifier`) applying item/statement/match-arm reordering, private symbol/local renaming, arithmetic/branch/loop semantic rewrites, and inline-hint perturbation. |
| [`binmorph`](file:///d:/RustProjects/Proteus/binmorph) | Post-link, size-preserving x86-64 ELF `.text` binary rewriter (`proteus-binmorph`) performing register permutation, prologue/epilogue stack-slot permutation, basic-block instruction commutation, and opcode-class instruction morphing. |
| [`mtd_metrics`](file:///d:/RustProjects/Proteus/mtd_metrics) | Binary gadget analyzer and ROP/JOP chain exploit simulator (`proteus-mtd-metrics`). |
| [`verifier`](file:///d:/RustProjects/Proteus/verifier) | Candidate acceptance gate (`verify`) enforcing public-symbol preservation, locked-module integrity, unit/property test suites, and per-function performance bounds (`perf.jsonl`). |
| [`factory_builder`](file:///d:/RustProjects/Proteus/factory_builder) | Host packager that builds `target_enterprise_kernel` with per-seed codegen flags, provisions the out-of-band device key, and wraps the kernel ELF into BIOS/UEFI disk images. |
| [`morph_engine`](file:///d:/RustProjects/Proteus/morph_engine) | Factory orchestrator (`morph`) managing scheduled morph cycles (`scheduler.toml`), Ed25519 M-of-N threshold attestation chains (`attest.log.jsonl`), and Merkle root anchors. |

---

## Diversification Pipeline

Every morph cycle applies three orthogonal diversification layers to the 68 enrolled kernel modules in [`scheduler.toml`](file:///d:/RustProjects/Proteus/scheduler.toml) (while refusing to touch the security-critical files listed in [`locked_modules.toml`](file:///d:/RustProjects/Proteus/locked_modules.toml)):

1. **Source AST Diversification (`proteus-diversifier`)**:
   - Reorders top-level items, independent statements, and literal `match` arms.
   - Renames private functions and lexical local bindings.
   - Applies reversible semantic perturbations (power-of-two multiply/shift inversion, branch polarity inversion, `for` ↔ `while` loop rewrites) and per-function `#[inline(never)]` / `#[inline(always)]` codegen hints.
   - Skips any function containing `unsafe` blocks or `#[no_mangle]` / `extern` ABI boundaries.
2. **Compiler & Linker Layout Randomization (`factory_builder`)**:
   - Compiles the kernel with `-Zrandomize-layout -Zlayout-seed=<seed>`, linker section shuffling (`--shuffle-sections=.text=<seed>`), and seed-derived LLVM backend thresholds (`--inline-threshold`, `--unroll-threshold`, `--regalloc-csr-first-time-cost`, `--x86-cmov-converter`).
3. **Post-Link Size-Preserving Binary Rewriting (`proteus-binmorph`)**:
   - Rewrites `.text` in place without shifting instruction offsets or invalidating relocations across 6 passes:
     1. Whole-function `{R12, R13, R14, R15}` callee-saved register permutation.
     2. Leaf-function `{R8, R9, R10, R11}` caller-saved scratch register permutation.
     3. Return-block and external-tail-call scratch register renaming across `{R8..R11, RCX, RSI, RDI}`.
     4. Prologue `push` / reverse epilogue `pop` stack-slot permutation across `{RBX, RBP, R12..R15}`.
     5. Seeded Fisher-Yates instruction-window commutation (up to 6 instructions) with `[rip + disp32]` displacement fixup.
     6. Opcode-class and multi-instruction encoding morphing (`mov` ↔ `or`/`and`/`lea`/`xchg`, `add`/`sub` ↔ `lea`, `cmp`/`sub` ↔ `test`, cross-branch `CF/AF`-dead `add ↔ sub (-imm)`, and 2-instruction small-immediate load decomposition) with 100% scrubbing of unintended `ret` (`0xC3/0xC2/0xCB/0xCA/0xCF`) and indirect `call/jmp` (`0xFF /2..5`) bytes.

---

## OS Runtime & Security Model

### Unified Subsystem Shell (`OsShell`)
[`OsShell`](file:///d:/RustProjects/Proteus/target_enterprise/src/shell.rs) provides the interactive serial console and remote control plane:
- **Virtual Filesystem (`MemRamFs`)**: `ls`, `cat`, `write`, `rm`, `stat` (with write/unlink protection on system paths `/etc/*`, `/proc/*`, `/bin/*`).
- **Process Scheduler (`RoundRobin`)**: `ps`, `spawn`, `kill` (with system daemon protection on `PID 1..4`).
- **Capability-Gated Syscalls (`SyscallTable` + `CapProof`)**: `caps <pid>`, `grant <pid> <fs|net|wal|all>`, `revoke <pid> <fs|net|wal|all>`, `syscall <pid> <getpid|yield|time|open> [path]`.
- **Per-PID eBPF Seccomp Sandboxing**: `seccomp [status | deny <pid> <getpid|yield|time|open|all> | clear <pid>]` compiles and executes a Seccomp-eBPF filter program inside [`EBpfImpl`](file:///d:/RustProjects/Proteus/target_enterprise/src/ebpf.rs) at syscall entry prior to capability checks.
- **Measured User Execution (`exec <path> [arg]`, `ima [status | enroll <path>]`)**: Verifies the binary's SHA-256 digest against the IMA trust table, parses ELF64 headers (`Elf64Impl`), verifies an isolated user page table (`KptiImpl`), extends TPM 2.0 `PCR-10` (`TpmImpl`), checks a stack canary (`StackCanaryImpl`), and executes the program in `EBpfImpl`.
- **Remote Attestation Quotes (`attest [nonce]`)**: Emits `attest: v=1 boots=<N> pcr10=<hex64> ima=<count> seal=<hex64> nonce=<nonce> hmac=<hex64>` signed with a domain-separated 256-bit `HMAC-SHA256` attestation key over the live boot counter, TPM `PCR-10`, IMA table count, live state seal, and caller nonce.
- **Audit Log (`AuditLogImpl`)**: Records `Allowed`, `Denied`, and `Error` events across all shell, syscall, Seccomp, capability, firewall, attestation, and disk-seal operations (`audit`).

### Out-of-Band Key Provisioning & State Continuity
- **Master Key Provisioning ([`provisioning.rs`](file:///d:/RustProjects/Proteus/target_enterprise_kernel/src/provisioning.rs))**: `factory_builder` generates a 32-byte OS-CSPRNG key in `device_secret_key.bin` (gitignored, never stored in source, the kernel ELF, or the guest disk) and passes it to QEMU via `-fw_cfg name=opt/proteus_device_key,file=device_secret_key.bin`.
- **Domain-Separated Runtime Keys**:
  - **UDP Control-Plane Auth Key**: `HMAC-SHA256(master_key, "proteus-net-auth-v1:" || mac_address)`. On unprovisioned boots (no `fw_cfg` key), `LivedNet` starts in unprovisioned mode and rejects all state-mutating `AUTH` commands.
  - **Durable Disk Seal Key**: `HMAC-SHA256(master_key, "proteus-durable-seal-v1:" || "ahci0-lba1040")`. Seals and verifies the 2-sector (`LBA 1040..=1041`) AHCI persistence image (`SHELL_DISK_MAGIC = b"PRTSSHL1"`) in constant time across reboots. Tampered disk sectors emit `SHELL resume REJECTED` on COM1 and log an `AuditVerdict::Denied` event.
  - **Remote Attestation Key**: `HMAC-SHA256(master_key, "proteus-remote-attest-v1:" || seed)`.
- **Network Control Plane ([`lived_net.rs`](file:///d:/RustProjects/Proteus/target_enterprise/src/lived_net.rs))**:
  - Enforces stateless CIDR firewall rules (`fw [status | block <cidr> | allow <cidr> | clear]`) at the IPv4 wire boundary.
  - Serves read-only telemetry over HTTP/TCP port 80 (`GET /status`, `/ps`, `/ls`, `/audit`, `/uname`, `/seal`, `/attest`, `/seccomp`, `/ima`, `/fw`) and unauthenticated UDP port 8080 `CMD <read-only-cmd>`.
  - Requires `AUTH <seq> <hmac_sha256_hex> <cmd>` with strictly monotonic anti-replay sequence numbers (`seq`) for any state-mutating command over UDP port 8080.

---

## Attacker Models & Measured MTD Metrics

Evaluated via `cargo run --release -p proteus-mtd-metrics --example redteam_attack` across seeded builds of `target_enterprise_kernel` (`690` functions, `61,164` instructions, `2,000` 8-gadget ROP chains):

| Metric / Attacker Model | Scope | Measured Result |
| :--- | :--- | :--- |
| **Morphed `.text` instructions (`binmorph`)** | Instructions rewritten in place per build | **`29.7%`** (`18,154 / 61,164`) |
| **Positional gadget survival (`binmorph` only)** | Gadgets remaining at the same offset with identical disassembly | **`29.0%`** (`0.0%` when combined with source + linker morphing) |
| **Attacker A — Static 8-step ROP chain** | Stockpiled exploit with hardcoded gadget offsets from build $N$ fired at build $N+1$ | **`0.0%`** (`0 / 2,000` chains survive) |
| **Attacker B — Exact-register 8-step chain relocation** | Attacker with a full `.text` dump of build $N+1$ who relocates each step to any offset containing the same address-masked gadget with the same registers | **`1.35%`** (`27 / 2,000` chains rebuildable; **`98.65%` broken**) |
| **Attacker B\_reg — Register-adapting 8-step chain relocation** | Attacker with a full `.text` dump of build $N+1$ who can both relocate gadgets and freely substitute any general-purpose register of matching width (`r64`/`r32`/`r16`/`r8`) | **`9.75%`** (`195 / 2,000` chains rebuildable; **`90.25%` broken**) |

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
cargo test -p factory_builder --test qemu_smoke -- --ignored --nocapture
```

### 4. Run the Red-Team Gadget & ROP Chain Evaluation
```powershell
cargo run --release -p proteus-mtd-metrics --example redteam_attack
```
