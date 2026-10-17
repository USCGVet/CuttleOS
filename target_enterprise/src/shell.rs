//! Interactive OS console shell and unified subsystem runtime (`OsShell`).
//!
//! Pure `no_std`, zero-allocation command processor and control-plane runtime:
//!
//! - **Virtual Filesystem ([`MemRamFs`])**: `ls`, `cat`, `write`, `rm`, `stat`
//! - **Task Scheduler ([`RoundRobin`])**: `ps`, `spawn`, `kill`
//! - **Capability-Gated Syscalls ([`check_cap`], [`dispatch_with_cap`])**:
//!   `caps`, `grant`, `revoke`, `syscall <pid> <getpid|yield|time|open> [arg]`
//! - **Per-PID eBPF Seccomp Sandboxing**: `seccomp [status | deny <pid> <op> | clear <pid>]`
//! - **Measured User Execution**: `exec <path> [arg]` and `ima [status | enroll <path>]`
//!   (IMA SHA-256 verification, ELF64 load, KPTI page-table check, TPM 2.0 `PCR-10`
//!   extend, stack canary check, and eBPF execution)
//! - **Wire-Boundary CIDR Firewall**: `fw [status | block <cidr> | allow <cidr> | clear]`
//! - **Keyed HMAC-SHA256 WAL & Disk Continuity**: `seal`, [`OsShell::checkpoint_sealed`],
//!   [`OsShell::restore_sealed`], [`OsShell::pack_disk_image`], [`OsShell::unpack_disk_image`]
//! - **Remote Attestation Quotes**: `attest [nonce]`
//! - **Tamper-Evident Audit Ring ([`AuditLogImpl`])**: `audit`
//! - **System Telemetry & Power Control**: `status`, `uname`, `net`, `halt`, `poweroff`, `reboot`

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    bpf_op, caps, AuditEvent, AuditLog, AuditVerdict, BpfContext, BpfInstr, CanaryToken, EBpf,
    Elf64, ElfPhdr, Filesystem, FilterAction, FilterRule, Kpti, StackCanary, Tpm, WriteAheadLog,
    AUDIT_MESSAGE_LEN, BPF_MAX_INSTRUCTIONS, BPF_STACK_SIZE, ELF_CLASS64, ELF_DATA_LE,
    ELF_EHDR_LEN, ELF_EM_X86_64, ELF_ET_EXEC, ELF_MAGIC, ELF_MAX_PHDRS, ELF_PHDR_LEN, ELF_PT_LOAD,
    FS_O_CREATE, FS_O_RDONLY, FS_O_RDWR, FS_O_TRUNC, FW_PORT_ANY, FW_PROTO_ANY, STACK_CANARY_LEN,
    TPM_ALG_SHA256,
};

use crate::audit::AuditLogImpl;
use crate::durable_seal::{
    seal_bytes, seal_bytes_keyed, seal_matches, seal_matches_keyed, DEFAULT_ATTEST_KEY,
    DEFAULT_DURABLE_SEAL_KEY, DURABLE_DIGEST_LEN,
};
use crate::ebpf::EBpfImpl;
use crate::elf64::Elf64Impl;
use crate::firewall::FirewallTable;
use crate::kpti::{
    KptiImpl, PageTable, KPTI_TRAMPOLINE_VIRT, PAGE_MASK, PTE_PRESENT, PTE_USER, PTE_WRITABLE,
};
use crate::scheduler::{RoundRobin, TaskId, TaskState};
use crate::stack_canary::StackCanaryImpl;
use crate::syscall::{
    check_cap, dispatch_with_cap, Errno, SYS_EXIT, SYS_GETPID, SYS_GETTIME_NS, SYS_OPEN, SYS_YIELD,
};
use crate::tpm::{TpmImpl, TPM_MAX_CMD_LEN};
use crate::vfs::MemRamFs;
use crate::wal::{durable_wal_proof, WalError, WalImpl};

/// Maximum length of an interactive command line in bytes.
pub const SHELL_LINE_MAX: usize = 256;
/// Maximum number of inodes in the live OS shell RamFs.
pub const SHELL_FS_INODES: usize = 16;
/// Byte capacity of the live OS shell RamFs pool.
pub const SHELL_FS_POOL: usize = 4096;
/// Number of 512-byte disk sectors in the block-backed filesystem partition (`8 KiB`).
pub const SHELL_FS_PART_SECTORS: usize = 16;
/// Total byte size of the 16-sector block-backed filesystem partition (`8192` bytes).
pub const SHELL_FS_PART_BYTES: usize = SHELL_FS_PART_SECTORS * 512;
/// 8-byte superblock magic for the block-backed filesystem partition (`PRTSFS01`).
pub const SHELL_FS_MAGIC: &[u8; 8] = b"PRTSFS01";
/// Maximum number of tasks in the live OS shell scheduler table.
pub const SHELL_MAX_TASKS: usize = 16;
/// Number of audit events retained in the live OS shell audit ring.
pub const SHELL_AUDIT_CAP: usize = 32;
/// Maximum number of IMA trusted binary digests.
pub const SHELL_IMA_CAP: usize = 8;
/// Maximum number of concurrent authenticated web/control-plane sessions.
pub const SHELL_MAX_SESSIONS: usize = 4;
/// Interactive console prompt string.
pub const SHELL_PROMPT: &[u8] = b"proteus> ";

/// Authenticated dynamic web/control-plane session entry.
#[derive(Copy, Clone, Debug)]
pub struct WebSession {
    /// Whether this session slot is active.
    pub active: bool,
    /// 32-character lowercase hex session ID (`sid`) derived via keyed `HMAC-SHA256`.
    pub token_hex: [u8; 32],
    /// Principal / username bytes.
    pub user: [u8; 16],
    /// Valid length of `user`.
    pub user_len: u8,
    /// Monotonic sequence when this session was created.
    pub created_seq: u64,
    /// Number of authenticated requests served in this session.
    pub requests: u32,
}

impl WebSession {
    /// Construct an empty inactive session slot.
    pub const fn empty() -> Self {
        Self {
            active: false,
            token_hex: [0u8; 32],
            user: [0u8; 16],
            user_len: 0,
            created_seq: 0,
            requests: 0,
        }
    }

    /// Principal username slice.
    pub fn user_bytes(&self) -> &[u8] {
        &self.user[..self.user_len as usize]
    }
}

/// Seccomp deny bit for `SYS_GETPID` (`getpid`).
pub const SECCOMP_DENY_GETPID: u8 = 1 << 0;
/// Seccomp deny bit for `SYS_YIELD` (`yield`).
pub const SECCOMP_DENY_YIELD: u8 = 1 << 1;
/// Seccomp deny bit for `SYS_GETTIME_NS` (`time`).
pub const SECCOMP_DENY_TIME: u8 = 1 << 2;
/// Seccomp deny bit for `SYS_OPEN` (`open`).
pub const SECCOMP_DENY_OPEN: u8 = 1 << 3;
/// Seccomp deny mask for all user-facing shell syscalls (`getpid|yield|time|open`).
pub const SECCOMP_DENY_ALL: u8 =
    SECCOMP_DENY_GETPID | SECCOMP_DENY_YIELD | SECCOMP_DENY_TIME | SECCOMP_DENY_OPEN;

/// System-level action requested by a shell command.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShellAction {
    /// Continue normal operation; `0` or more reply bytes were written.
    Continue(usize),
    /// Operator requested clean system halt / ACPI S5 poweroff.
    Halt(usize),
    /// Operator requested system reboot.
    Reboot(usize),
}

impl ShellAction {
    /// Number of output bytes written into the caller's reply buffer.
    pub const fn bytes_written(self) -> usize {
        match self {
            ShellAction::Continue(n) | ShellAction::Halt(n) | ShellAction::Reboot(n) => n,
        }
    }
}

/// Live, stateful OS console environment integrating VFS, Scheduler,
/// Capability Gate, Syscall Dispatcher, Per-PID eBPF Seccomp Sandboxing,
/// IMA Binary Verification, TPM PCR-10 Measurement, Stateless CIDR Firewall,
/// Embedded Relational SQL Engine (`SqlDb`), Dynamic Web Session Engine,
/// Keyed HMAC-SHA256 WAL Continuity, Signed Remote Attestation Quotes, and AuditLog.
pub struct OsShell {
    /// Mounted root in-memory filesystem.
    pub fs: MemRamFs<SHELL_FS_INODES, SHELL_FS_POOL>,
    /// Embedded relational SQL database engine (`SqlDb`).
    pub db: crate::sql::SqlDb,
    /// Active authenticated dynamic web/control-plane sessions.
    pub sessions: [WebSession; SHELL_MAX_SESSIONS],
    /// Live round-robin task scheduler.
    pub sched: RoundRobin<SHELL_MAX_TASKS>,
    /// Security audit ring recording all administrative commands.
    pub audit: AuditLogImpl<SHELL_AUDIT_CAP>,
    /// Per-PID capability bitmask indexed by `pid as usize` (for `pid < SHELL_MAX_TASKS`).
    pub task_caps: [u64; SHELL_MAX_TASKS],
    /// Per-PID eBPF Seccomp syscall deny bitmask indexed by `pid as usize`
    /// (`SECCOMP_DENY_GETPID | SECCOMP_DENY_YIELD | SECCOMP_DENY_TIME | SECCOMP_DENY_OPEN`).
    pub seccomp_mask: [u8; SHELL_MAX_TASKS],
    /// Live stateless IPv4 CIDR packet filter table.
    pub fw: FirewallTable<8>,
    /// IMA trusted binary paths.
    ima_paths: [[u8; 32]; SHELL_IMA_CAP],
    /// Byte lengths of `ima_paths` entries.
    ima_path_lens: [u8; SHELL_IMA_CAP],
    /// IMA trusted SHA-256 binary digests.
    ima_digests: [[u8; DURABLE_DIGEST_LEN]; SHELL_IMA_CAP],
    /// Number of enrolled IMA binary digests.
    ima_count: usize,
    /// Rolling TPM PCR-10 SHA-256 aggregate (`SHA256(pcr10 || binary_sha256)`).
    pub ima_pcr10: [u8; DURABLE_DIGEST_LEN],
    /// Count of IMA/TPM PCR-10 measurements extended during `exec`.
    pub ima_measurements: u64,
    /// Monotonic anti-replay sequence watermark for authenticated UDP control-plane commands,
    /// persisted across morph reboots via WAL (`Q` record).
    pub auth_seq: u64,
    /// 256-bit HMAC-SHA256 device key used to cryptographically seal and verify
    /// WAL/disk persistence checkpoints (`checkpoint_sealed` / `restore_sealed`).
    pub seal_key: [u8; DURABLE_DIGEST_LEN],
    /// 256-bit HMAC-SHA256 device key used to sign live remote attestation quotes
    /// (`attest [nonce]` / `GET /attest`).
    pub attest_key: [u8; DURABLE_DIGEST_LEN],
    /// Number of online hardware SMP logical processors (`1..=4`).
    pub smp_cpus_online: u8,
    /// Per-CPU hardware execution tick counters (`CPU 0..3`).
    pub smp_cpu_ticks: [u64; 4],
    /// Per-CPU parallel job completion counters (`CPU 0..3`).
    pub smp_cpu_jobs: [u64; 4],
    /// Total hardware interrupt wakeups across Local APIC timer (`0x40`) and Doorbell IPIs (`0x41`).
    pub smp_irq_wakeups: u64,
    /// Total Inter-Processor Interrupt (IPI `0x41`) doorbells sent to wake sleeping AP cores from `HLT`.
    pub smp_ipi_doorbells: u64,
    /// Per-task hardware stack context-switch counters indexed by `pid as usize`.
    pub kthread_switches: [u64; SHELL_MAX_TASKS],
    /// Ring-3 user-space service supervisor (`svc-http`, `svc-sql`, `svc-sh`),
    /// role-specific ELF64 loader, KPTI isolator, and IPC/Seccomp policy enforcer.
    pub svc: crate::svc_runtime::ServiceSupervisor,
    /// Consecutive failed authentication attempts for brute-force rate limiting.
    pub failed_login_streak: u32,
    /// Next PID to assign on `spawn`.
    next_pid: TaskId,
    /// Monotonic command counter (used as synthetic timestamp/sequence).
    cmd_seq: u64,
    /// Interactive line buffer for serial/keyboard input.
    line_buf: [u8; SHELL_LINE_MAX],
    /// Current byte count in `line_buf`.
    line_len: usize,
}

impl OsShell {
    /// Construct an unseeded empty shell suitable for `static mut` BSS allocation.
    /// Call [`OsShell::seed_defaults`] before executing commands.
    pub const fn empty() -> Self {
        Self {
            fs: MemRamFs::new(),
            db: crate::sql::SqlDb::empty(),
            sessions: [WebSession::empty(); SHELL_MAX_SESSIONS],
            sched: RoundRobin::new(),
            audit: AuditLogImpl::new(),
            task_caps: [0u64; SHELL_MAX_TASKS],
            seccomp_mask: [0u8; SHELL_MAX_TASKS],
            fw: FirewallTable::new(),
            ima_paths: [[0u8; 32]; SHELL_IMA_CAP],
            ima_path_lens: [0u8; SHELL_IMA_CAP],
            ima_digests: [[0u8; DURABLE_DIGEST_LEN]; SHELL_IMA_CAP],
            ima_count: 0,
            ima_pcr10: [0u8; DURABLE_DIGEST_LEN],
            ima_measurements: 0,
            auth_seq: 0,
            seal_key: DEFAULT_DURABLE_SEAL_KEY,
            attest_key: DEFAULT_ATTEST_KEY,
            smp_cpus_online: 4,
            smp_cpu_ticks: [0u64; 4],
            smp_cpu_jobs: [0u64; 4],
            smp_irq_wakeups: 0,
            smp_ipi_doorbells: 0,
            kthread_switches: [0u64; SHELL_MAX_TASKS],
            svc: crate::svc_runtime::ServiceSupervisor::empty(),
            failed_login_streak: 0,
            next_pid: 5,
            cmd_seq: 1,
            line_buf: [0u8; SHELL_LINE_MAX],
            line_len: 0,
        }
    }

    /// Construct and seed a fresh live OS shell environment.
    ///
    /// Pre-populates:
    /// - `/etc/hostname` (`"proteus-te\n"`)
    /// - `/etc/os-release` (`"NAME=\"Proteus MTD OS\"\nVERSION=\"1.0-enterprise\"\nARCH=\"x86_64\"\n"`)
    /// - `/etc/motd` (`"Proteus Enterprise Moving-Target-Defense OS\nType 'help' for commands.\n"`)
    /// - `/proc/net` (`"iface=virtio-net0 ip=10.0.2.15 udp=8080 tcp=80 icmp=echo\n"`)
    /// - System tasks: PID 1 (`init`), PID 2 (`kthreadd-net`), PID 3 (`kthreadd-wal`), PID 4 (`proteus-sh`)
    pub fn new() -> Self {
        let mut s = Self::empty();
        s.seed_defaults();
        s
    }

    /// Construct a fresh seeded shell bound to an explicit per-device 256-bit `seal_key`.
    pub fn with_seal_key(seal_key: [u8; DURABLE_DIGEST_LEN]) -> Self {
        let mut s = Self::empty();
        s.seal_key = seal_key;
        s.seed_defaults();
        s
    }

    /// Populate default system files (`/etc/hostname`, `/etc/os-release`,
    /// `/etc/motd`, `/proc/net`), kernel tasks (`PID 1..4`), pre-enrolled
    /// IMA SHA-256 digests for `/bin/fib` and `/bin/sum`, and default relational
    /// SQL tables (`services`, `kv`) in place.
    pub fn seed_defaults(&mut self) {
        let _ = self.fs.seed_file(b"/etc/hostname", b"proteus-te\n", 64, 1);
        let _ = self.fs.seed_file(
            b"/etc/os-release",
            b"NAME=\"Proteus MTD OS\"\nVERSION=\"1.0-enterprise\"\nARCH=\"x86_64\"\n",
            128,
            1,
        );
        let _ = self.fs.seed_file(
            b"/etc/motd",
            b"Proteus Enterprise Moving-Target-Defense OS\nType 'help' for commands.\n",
            128,
            1,
        );
        let _ = self.fs.seed_file(
            b"/proc/net",
            b"iface=virtio-net0 ip=10.0.2.15 udp=8080 tcp=80 icmp=echo\n",
            128,
            1,
        );
        self.db.seed_defaults();

        let _ = self.sched.enqueue_with_priority(1, 10);
        let _ = self.sched.enqueue_with_priority(2, 5);
        let _ = self.sched.enqueue_with_priority(3, 5);
        let _ = self.sched.enqueue_with_priority(4, 5);
        // System tasks PID 1..4 hold all valid kernel capabilities; spawned workers start at 0.
        let sys_caps = caps::FS_BYPASS | caps::NET_RAW | caps::DURABLE_WAL_WRITE;
        self.task_caps[1] = sys_caps;
        self.task_caps[2] = sys_caps;
        self.task_caps[3] = sys_caps;
        self.task_caps[4] = sys_caps;
        self.seccomp_mask = [0u8; SHELL_MAX_TASKS];
        self.smp_cpus_online = 4;
        self.smp_cpu_ticks = [1, 1, 1, 1];
        self.smp_cpu_jobs = [1, 1, 1, 1];
        self.smp_irq_wakeups = 4;
        self.smp_ipi_doorbells = 1;
        self.kthread_switches = [0u64; SHELL_MAX_TASKS];
        self.kthread_switches[1] = 1;
        self.kthread_switches[2] = 1;
        self.kthread_switches[3] = 1;
        self.kthread_switches[4] = 1;
        // Advance scheduler so PID 4 (proteus-sh) is active after boot init/daemons.
        let _ = self.sched.pick_next();
        let _ = self.sched.pick_next();
        let _ = self.sched.pick_next();
        let _ = self.sched.pick_next();

        // Pre-enroll trusted IMA SHA-256 digests for built-in ELF64 binaries `/bin/fib` and `/bin/sum`.
        self.ima_count = 0;
        let mut bin_buf = [0u8; 256];
        let fib_n = build_fib_elf(&mut bin_buf);
        let mut fib_dig = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes(&bin_buf[..fib_n], &mut fib_dig);
        let _ = self.enroll_ima_digest(b"/bin/fib", &fib_dig);

        let sum_n = build_sum_elf(&mut bin_buf);
        let mut sum_dig = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes(&bin_buf[..sum_n], &mut sum_dig);
        let _ = self.enroll_ima_digest(b"/bin/sum", &sum_dig);

        // Initialize Ring-3 isolated service runtime (`svc-http`, `svc-sql`, `svc-sh`)
        // with a per-node base seed derived from `self.seal_key`.
        self.failed_login_streak = 0;
        self.svc = crate::svc_runtime::ServiceSupervisor::empty();
        let base_seed = crate::svc_runtime::derive_service_base_seed(&self.seal_key);
        self.svc
            .init_role(crate::svc_runtime::NodeRole::Full, base_seed);
    }

    /// Seed standard user-space ELF64 executables (`/bin/fib` and `/bin/sum`)
    /// into the in-memory filesystem if not already present.
    pub fn install_user_bins(&mut self) {
        if self.fs.stat(b"/bin/fib").is_err() {
            let mut buf = [0u8; 256];
            let n = build_fib_elf(&mut buf);
            let _ = self.fs.seed_file(b"/bin/fib", &buf[..n], 256, 1);
        }
        if self.fs.stat(b"/bin/sum").is_err() {
            let mut buf = [0u8; 256];
            let n = build_sum_elf(&mut buf);
            let _ = self.fs.seed_file(b"/bin/sum", &buf[..n], 256, 1);
        }
    }

    /// Register or update a trusted SHA-256 digest for `path` in the IMA table.
    pub fn enroll_ima_digest(&mut self, path: &[u8], digest: &[u8; DURABLE_DIGEST_LEN]) -> bool {
        if path.is_empty() || path.len() > 32 {
            return false;
        }
        let mut i = 0usize;
        while i < self.ima_count {
            let plen = self.ima_path_lens[i] as usize;
            if bytes_eq(&self.ima_paths[i][..plen], path) {
                self.ima_digests[i] = *digest;
                return true;
            }
            i += 1;
        }
        if self.ima_count >= SHELL_IMA_CAP {
            return false;
        }
        let idx = self.ima_count;
        self.ima_paths[idx] = [0u8; 32];
        let mut k = 0usize;
        while k < path.len() {
            self.ima_paths[idx][k] = path[k];
            k += 1;
        }
        self.ima_path_lens[idx] = path.len() as u8;
        self.ima_digests[idx] = *digest;
        self.ima_count += 1;
        true
    }

    /// Verify in constant time that `data` matches the enrolled IMA SHA-256
    /// digest for `path`. If verified, writes the 32-byte digest to `out_dig`.
    pub fn verify_ima_digest(
        &self,
        path: &[u8],
        data: &[u8],
        out_dig: &mut [u8; DURABLE_DIGEST_LEN],
    ) -> bool {
        let mut i = 0usize;
        while i < self.ima_count {
            let plen = self.ima_path_lens[i] as usize;
            if bytes_eq(&self.ima_paths[i][..plen], path) {
                if seal_matches(data, &self.ima_digests[i]) {
                    *out_dig = self.ima_digests[i];
                    return true;
                }
                return false;
            }
            i += 1;
        }
        false
    }

    /// Record a network/firewall/auth event into the shell's security audit ring.
    pub fn record_net_audit(&mut self, verdict: AuditVerdict, msg: &[u8]) {
        self.record_audit(30, verdict, msg);
    }

    /// Count of currently active authenticated web/control-plane sessions.
    pub fn active_session_count(&self) -> usize {
        let mut count = 0usize;
        let mut i = 0usize;
        while i < SHELL_MAX_SESSIONS {
            if self.sessions[i].active {
                count += 1;
            }
            i += 1;
        }
        count
    }

    /// Returns `true` if login attempts are currently rate-limited due to repeated failures (`>= 5`).
    #[inline]
    pub const fn is_login_rate_limited(&self) -> bool {
        self.failed_login_streak >= 5
    }

    /// Record a failed login attempt, incrementing `failed_login_streak` and logging to the audit ring.
    pub fn record_login_failure(&mut self) {
        self.failed_login_streak = self.failed_login_streak.saturating_add(1);
        if self.failed_login_streak >= 5 {
            self.record_audit(32, AuditVerdict::Denied, b"shell:session:rate-limit");
        } else {
            self.record_audit(32, AuditVerdict::Denied, b"shell:session:bad-auth");
        }
    }

    /// Mint a new 128-bit (`32` hex character) authenticated session token for `user`
    /// derived via `HMAC-SHA256(self.attest_key, "proteus-session-v1:" || user || seq || challenge)`.
    pub fn create_session(&mut self, user: &[u8], challenge: &[u8]) -> [u8; 32] {
        self.failed_login_streak = 0;
        let uname = if user.is_empty() { b"admin" } else { user };
        let ulen = uname.len().min(16);

        let mut free_slot = None;
        let mut oldest_slot = 0usize;
        let mut oldest_seq = u64::MAX;
        let mut i = 0usize;
        while i < SHELL_MAX_SESSIONS {
            if !self.sessions[i].active {
                free_slot = Some(i);
                break;
            }
            if self.sessions[i].created_seq < oldest_seq {
                oldest_seq = self.sessions[i].created_seq;
                oldest_slot = i;
            }
            i += 1;
        }
        let slot = free_slot.unwrap_or(oldest_slot);

        let mut msg = [0u8; 128];
        let mut pos = 0usize;
        pos += copy_into(b"proteus-session-v1:", &mut msg[pos..]);
        pos += copy_into(&uname[..ulen], &mut msg[pos..]);
        pos += copy_into(b":", &mut msg[pos..]);
        pos += dec_u64(self.cmd_seq, &mut msg[pos..]);
        pos += copy_into(b":", &mut msg[pos..]);
        let clen = challenge.len().min(32);
        pos += copy_into(&challenge[..clen], &mut msg[pos..]);

        let mut digest = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes_keyed(&self.attest_key, &msg[..pos], &mut digest);
        let mut token_hex = [0u8; 32];
        let _ = hex_bytes(&digest[..16], &mut token_hex);

        let mut sess = WebSession::empty();
        sess.active = true;
        sess.token_hex = token_hex;
        sess.user[..ulen].copy_from_slice(&uname[..ulen]);
        sess.user_len = ulen as u8;
        sess.created_seq = self.cmd_seq;
        sess.requests = 0;
        self.sessions[slot] = sess;
        self.record_audit(32, AuditVerdict::Allowed, b"shell:session:login");
        token_hex
    }

    /// Validate a 32-character hex session token in constant time and increment its request counter.
    /// Returns `Some(slot_index)` if valid.
    pub fn validate_session(&mut self, token_hex: &[u8]) -> Option<usize> {
        let tok = trim_ascii(token_hex);
        if tok.len() != 32 {
            return None;
        }
        let mut matched: Option<usize> = None;
        let mut i = 0usize;
        while i < SHELL_MAX_SESSIONS {
            if self.sessions[i].active {
                let mut diff = 0u8;
                let mut k = 0usize;
                while k < 32 {
                    diff |= self.sessions[i].token_hex[k] ^ tok[k];
                    k += 1;
                }
                if diff == 0 {
                    matched = Some(i);
                }
            }
            i += 1;
        }
        if let Some(idx) = matched {
            self.sessions[idx].requests = self.sessions[idx].requests.wrapping_add(1);
            Some(idx)
        } else {
            None
        }
    }

    /// Revoke an active session matching `token_hex` in constant time.
    pub fn revoke_session(&mut self, token_hex: &[u8]) -> bool {
        let tok = trim_ascii(token_hex);
        if tok.len() != 32 {
            return false;
        }
        let mut i = 0usize;
        while i < SHELL_MAX_SESSIONS {
            if self.sessions[i].active {
                let mut diff = 0u8;
                let mut k = 0usize;
                while k < 32 {
                    diff |= self.sessions[i].token_hex[k] ^ tok[k];
                    k += 1;
                }
                if diff == 0 {
                    self.sessions[i] = WebSession::empty();
                    self.record_audit(32, AuditVerdict::Allowed, b"shell:session:logout");
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    /// Serialize `self.db` into an 8-sector (`4 KiB`) partition image sealed with `self.seal_key`.
    pub fn pack_sql_partition(&self, sectors: &mut [[u8; 512]; crate::sql::SQL_PART_SECTORS]) {
        self.db.save_partition(&self.seal_key, sectors);
    }

    /// Verify and restore `self.db` from an 8-sector (`4 KiB`) partition image sealed with `self.seal_key`.
    pub fn unpack_sql_partition(
        &mut self,
        sectors: &[[u8; 512]; crate::sql::SQL_PART_SECTORS],
    ) -> bool {
        self.db.load_partition(&self.seal_key, sectors)
    }

    /// Returns `true` if `line` is a strictly read-only inspection command
    /// safe for unauthenticated UDP telemetry queries (`CMD <line>`).
    pub fn is_readonly_command(line: &[u8]) -> bool {
        let trimmed = trim_ascii(line);
        if trimmed.is_empty() {
            return true;
        }
        let (cmd, rest) = split_first_word(trimmed);
        if bytes_eq(cmd, b"help")
            || bytes_eq(cmd, b"?")
            || bytes_eq(cmd, b"uname")
            || bytes_eq(cmd, b"status")
            || bytes_eq(cmd, b"uptime")
            || bytes_eq(cmd, b"ps")
            || bytes_eq(cmd, b"threads")
            || bytes_eq(cmd, b"caps")
            || bytes_eq(cmd, b"ls")
            || bytes_eq(cmd, b"cat")
            || bytes_eq(cmd, b"stat")
            || bytes_eq(cmd, b"df")
            || bytes_eq(cmd, b"net")
            || bytes_eq(cmd, b"audit")
            || bytes_eq(cmd, b"seal")
            || bytes_eq(cmd, b"attest")
        {
            return true;
        }
        if (bytes_eq(cmd, b"ima")
            || bytes_eq(cmd, b"fw")
            || bytes_eq(cmd, b"seccomp")
            || bytes_eq(cmd, b"session")
            || bytes_eq(cmd, b"smp")
            || bytes_eq(cmd, b"service"))
            && (rest.is_empty() || bytes_eq(rest, b"status") || bytes_eq(rest, b"threads"))
        {
            return true;
        }
        if bytes_eq(cmd, b"sql") && !rest.is_empty() {
            return crate::sql::SqlDb::is_readonly_query(rest);
        }
        false
    }

    /// Checkpoint all user/mutable files, active worker tasks (`pid >= 5`)
    /// plus their capability and eBPF Seccomp masks, stateless firewall CIDR
    /// rules (`W`), custom enrolled IMA binary digests (`I`), and the monotonic
    /// UDP anti-replay sequence watermark (`Q`) into `wal`, flushing with a
    /// `DURABLE_WAL_WRITE` [`proteus_contracts::CapProof`].
    ///
    /// Returns the number of WAL records written.
    pub fn checkpoint_wal<const C: usize>(&mut self, wal: &mut WalImpl<C>) -> Result<usize, WalError> {
        let proof = match durable_wal_proof(self.task_caps[4]) {
            Ok(p) => p,
            Err(_) => {
                self.record_audit(19, AuditVerdict::Denied, b"shell:wal:no-cap");
                return Ok(0);
            }
        };

        let mut count = 0usize;
        let mut i = 0usize;
        while i < SHELL_FS_INODES {
            if let Some((path, data)) = self.fs.inode_data(i) {
                if !is_default_system_file(path) && path.len() <= 128 && data.len() <= 256 {
                    let mut rec = [0u8; 390];
                    rec[0] = b'F';
                    rec[1] = path.len() as u8;
                    let mut k = 0usize;
                    while k < path.len() {
                        rec[2 + k] = path[k];
                        k += 1;
                    }
                    let d_off = 2 + path.len();
                    let mut m = 0usize;
                    while m < data.len() {
                        rec[d_off + m] = data[m];
                        m += 1;
                    }
                    wal.append(&rec[..d_off + data.len()])?;
                    count += 1;
                }
            }
            i += 1;
        }

        let mut s = 0usize;
        while s < SHELL_MAX_TASKS {
            if let Some(t) = self.sched.slot(s) {
                if t.state != TaskState::Empty && t.state != TaskState::Exited && t.id >= 5 {
                    let mut rec = [0u8; 13];
                    rec[0] = b'T';
                    let pid_b = t.id.to_le_bytes();
                    rec[1] = pid_b[0];
                    rec[2] = pid_b[1];
                    rec[3] = pid_b[2];
                    rec[4] = pid_b[3];
                    let cap_mask = if (t.id as usize) < SHELL_MAX_TASKS {
                        (self.task_caps[t.id as usize] & 0x00FF_FFFF_FFFF_FFFF)
                            | ((self.seccomp_mask[t.id as usize] as u64) << 56)
                    } else {
                        0
                    };
                    let cap_b = cap_mask.to_le_bytes();
                    let mut c = 0usize;
                    while c < 8 {
                        rec[5 + c] = cap_b[c];
                        c += 1;
                    }
                    wal.append(&rec)?;
                    count += 1;
                }
            }
            s += 1;
        }

        // Persist stateless CIDR firewall rules (`W` records, 7 bytes each).
        let rules = self.fw.as_slice();
        let mut r_idx = 0usize;
        while r_idx < rules.len() {
            let r = &rules[r_idx];
            let act_byte = match r.action {
                FilterAction::Accept => 0u8,
                FilterAction::Drop => 1u8,
                FilterAction::Reject => 2u8,
            };
            let rec = [
                b'W',
                r.src_ip[0],
                r.src_ip[1],
                r.src_ip[2],
                r.src_ip[3],
                r.src_mask,
                act_byte,
            ];
            wal.append(&rec)?;
            count += 1;
            r_idx += 1;
        }

        // Persist custom enrolled IMA binary digests (`I` records, 2 + plen + 32 bytes).
        let mut ima_i = 0usize;
        while ima_i < self.ima_count {
            let plen = self.ima_path_lens[ima_i] as usize;
            let path = &self.ima_paths[ima_i][..plen];
            if !bytes_eq(path, b"/bin/fib") && !bytes_eq(path, b"/bin/sum") && plen <= 32 {
                let mut rec = [0u8; 2 + 32 + DURABLE_DIGEST_LEN];
                rec[0] = b'I';
                rec[1] = plen as u8;
                let mut k = 0usize;
                while k < plen {
                    rec[2 + k] = path[k];
                    k += 1;
                }
                let d_off = 2 + plen;
                let mut d = 0usize;
                while d < DURABLE_DIGEST_LEN {
                    rec[d_off + d] = self.ima_digests[ima_i][d];
                    d += 1;
                }
                wal.append(&rec[..d_off + DURABLE_DIGEST_LEN])?;
                count += 1;
            }
            ima_i += 1;
        }

        // Persist monotonic UDP control-plane anti-replay sequence watermark (`Q` record, 9 bytes).
        if self.auth_seq > 0 {
            let sb = self.auth_seq.to_le_bytes();
            let rec = [
                b'Q', sb[0], sb[1], sb[2], sb[3], sb[4], sb[5], sb[6], sb[7],
            ];
            wal.append(&rec)?;
            count += 1;
        }

        wal.flush(proof)?;
        self.record_audit(19, AuditVerdict::Allowed, b"shell:wal:checkpoint");
        Ok(count)
    }

    /// Replay a committed [`WalImpl`] into this shell, restoring all
    /// persisted files, active worker tasks, per-task capability and Seccomp
    /// masks, stateless firewall CIDR rules, custom IMA digests, and the
    /// anti-replay sequence watermark.
    ///
    /// Returns the number of WAL records applied.
    pub fn restore_wal<const C: usize>(&mut self, wal: &WalImpl<C>) -> usize {
        let mut applied = 0usize;
        wal.replay(&mut |_lsn: u64, payload: &[u8]| {
            if payload.len() >= 2 && payload[0] == b'F' {
                let plen = payload[1] as usize;
                if 2 + plen <= payload.len() {
                    let path = &payload[2..2 + plen];
                    let data = &payload[2 + plen..];
                    if let Ok(h) = self.fs.open(path, FS_O_RDWR | FS_O_CREATE | FS_O_TRUNC) {
                        let _ = self.fs.write(h, 0, data);
                        let _ = self.fs.close(h);
                        applied += 1;
                    }
                }
            } else if payload.len() == 13 && payload[0] == b'T' {
                let pid = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                let packed = u64::from_le_bytes([
                    payload[5],
                    payload[6],
                    payload[7],
                    payload[8],
                    payload[9],
                    payload[10],
                    payload[11],
                    payload[12],
                ]);
                let cap_mask = packed & 0x00FF_FFFF_FFFF_FFFF;
                let seccomp = (packed >> 56) as u8;
                if pid >= 5 {
                    let _ = self.sched.enqueue_with_priority(pid, 5);
                    if (pid as usize) < SHELL_MAX_TASKS {
                        self.task_caps[pid as usize] = cap_mask;
                        self.seccomp_mask[pid as usize] = seccomp & SECCOMP_DENY_ALL;
                    }
                    if pid >= self.next_pid {
                        self.next_pid = pid.wrapping_add(1);
                    }
                    applied += 1;
                }
            } else if payload.len() == 7 && payload[0] == b'W' {
                let prefix = payload[5];
                if prefix <= 32 {
                    let action = match payload[6] {
                        0 => FilterAction::Accept,
                        2 => FilterAction::Reject,
                        _ => FilterAction::Drop,
                    };
                    let rule = FilterRule {
                        src_ip: [payload[1], payload[2], payload[3], payload[4]],
                        src_mask: prefix,
                        dst_ip: [0, 0, 0, 0],
                        dst_mask: 0,
                        proto: FW_PROTO_ANY,
                        src_port_start: FW_PORT_ANY,
                        src_port_end: FW_PORT_ANY,
                        dst_port_start: FW_PORT_ANY,
                        dst_port_end: FW_PORT_ANY,
                        action,
                    };
                    if self.fw.insert(rule).is_ok() {
                        applied += 1;
                    }
                }
            } else if payload.len() >= 2 + DURABLE_DIGEST_LEN && payload[0] == b'I' {
                let plen = payload[1] as usize;
                if plen <= 32 && 2 + plen + DURABLE_DIGEST_LEN == payload.len() {
                    let path = &payload[2..2 + plen];
                    let mut dig = [0u8; DURABLE_DIGEST_LEN];
                    let mut d = 0usize;
                    while d < DURABLE_DIGEST_LEN {
                        dig[d] = payload[2 + plen + d];
                        d += 1;
                    }
                    if self.enroll_ima_digest(path, &dig) {
                        applied += 1;
                    }
                }
            } else if payload.len() == 9 && payload[0] == b'Q' {
                let seq = u64::from_le_bytes([
                    payload[1],
                    payload[2],
                    payload[3],
                    payload[4],
                    payload[5],
                    payload[6],
                    payload[7],
                    payload[8],
                ]);
                if seq > self.auth_seq {
                    self.auth_seq = seq;
                }
                applied += 1;
            }
        });
        self.record_audit(20, AuditVerdict::Allowed, b"shell:wal:restore");
        applied
    }

    /// Checkpoint live OS state to `wal` and compute a 32-byte keyed `HMAC-SHA256`
    /// cryptographic seal (`seal_out`) over the committed WAL stream using `self.seal_key`.
    pub fn checkpoint_sealed<const C: usize>(
        &mut self,
        wal: &mut WalImpl<C>,
        seal_out: &mut [u8; DURABLE_DIGEST_LEN],
    ) -> Result<usize, WalError> {
        let count = self.checkpoint_wal(wal)?;
        compute_wal_seal(&self.seal_key, wal, seal_out);
        Ok(count)
    }

    /// Verify `expected_seal` against `wal` in constant time using keyed `HMAC-SHA256`
    /// ([`seal_matches_keyed`]) before replaying state into this shell.
    ///
    /// Rejects tampered or unkeyed-forged WAL streams with [`WalError::PayloadTooLarge`]
    /// and logs an [`AuditVerdict::Denied`] event.
    pub fn restore_sealed<const C: usize>(
        &mut self,
        wal: &WalImpl<C>,
        expected_seal: &[u8; DURABLE_DIGEST_LEN],
    ) -> Result<usize, WalError> {
        let mut scratch = [0u8; 1024];
        let len = serialize_wal_for_seal(wal, &mut scratch);
        if !seal_matches_keyed(&self.seal_key, &scratch[..len], expected_seal) {
            self.record_audit(21, AuditVerdict::Denied, b"shell:wal:seal-mismatch");
            return Err(WalError::PayloadTooLarge);
        }
        Ok(self.restore_wal(wal))
    }

    /// Pack the live shell state into two 512-byte disk sectors (`hdr_sector`
    /// and `wal_sector`) protected by a 32-byte SHA-256 seal (`PRTSSHL1` magic).
    ///
    /// Designed for crash-atomic persistence on AHCI / VirtIO-Blk: write
    /// `wal_sector` to `LBA + 1` first, then `hdr_sector` to `LBA` last.
    pub fn pack_disk_image(
        &mut self,
        boots: u64,
        hdr_sector: &mut [u8; 512],
        wal_sector: &mut [u8; 512],
    ) -> Result<usize, WalError> {
        let mut wal: WalImpl<512> = WalImpl::new();
        let mut seal = [0u8; DURABLE_DIGEST_LEN];
        let count = self.checkpoint_sealed(&mut wal, &mut seal)?;

        let backing = wal.backing();
        let mut i = 0usize;
        while i < 512 {
            wal_sector[i] = backing[i];
            hdr_sector[i] = 0;
            i += 1;
        }
        let magic = b"PRTSSHL1";
        let mut m = 0usize;
        while m < 8 {
            hdr_sector[m] = magic[m];
            m += 1;
        }
        let bb = boots.to_le_bytes();
        let mut b = 0usize;
        while b < 8 {
            hdr_sector[8 + b] = bb[b];
            b += 1;
        }
        let cb = (wal.durable_cursor() as u32).to_le_bytes();
        hdr_sector[16] = cb[0];
        hdr_sector[17] = cb[1];
        hdr_sector[18] = cb[2];
        hdr_sector[19] = cb[3];
        let mut s = 0usize;
        while s < DURABLE_DIGEST_LEN {
            hdr_sector[20 + s] = seal[s];
            s += 1;
        }
        Ok(count)
    }

    /// Unpack and verify a two-sector (`hdr_sector`, `wal_sector`) disk image
    /// written by [`OsShell::pack_disk_image`], restoring files, worker tasks,
    /// and capabilities only if the `PRTSSHL1` magic and 32-byte SHA-256 seal
    /// match in constant time.
    ///
    /// Returns `Ok((saved_boots, applied_records))`.
    pub fn unpack_disk_image(
        &mut self,
        hdr_sector: &[u8; 512],
        wal_sector: &[u8; 512],
    ) -> Result<(u64, usize), WalError> {
        if !bytes_eq(&hdr_sector[0..8], b"PRTSSHL1") {
            self.record_audit(21, AuditVerdict::Denied, b"shell:wal:header-corrupt");
            return Err(WalError::PayloadTooLarge);
        }
        let saved_boots = u64::from_le_bytes([
            hdr_sector[8],
            hdr_sector[9],
            hdr_sector[10],
            hdr_sector[11],
            hdr_sector[12],
            hdr_sector[13],
            hdr_sector[14],
            hdr_sector[15],
        ]);
        let cursor = u32::from_le_bytes([
            hdr_sector[16],
            hdr_sector[17],
            hdr_sector[18],
            hdr_sector[19],
        ]) as usize;
        if cursor > 512 {
            self.record_audit(21, AuditVerdict::Denied, b"shell:wal:cursor-overflow");
            return Err(WalError::OutOfCapacity);
        }
        let mut expected_seal = [0u8; DURABLE_DIGEST_LEN];
        let mut s = 0usize;
        while s < DURABLE_DIGEST_LEN {
            expected_seal[s] = hdr_sector[20 + s];
            s += 1;
        }
        let wal = WalImpl::<512>::from_backing(*wal_sector, cursor);
        let applied = self.restore_sealed(&wal, &expected_seal)?;
        Ok((saved_boots, applied))
    }

    /// Pack all mutable/user files (`!is_default_system_file`) from `self.fs`
    /// into a 16-sector (`8 KiB`) block-backed filesystem partition image
    /// (`PRTSFS01` magic + 2-sector inode directory + 8-sector `4 KiB` data pool +
    /// 5 reserved sectors) sealed with a chained keyed `HMAC-SHA256` (`self.seal_key`).
    ///
    /// Returns `Ok((file_count, data_bytes))`.
    pub fn pack_fs_partition(
        &mut self,
        generation: u64,
        sectors: &mut [[u8; 512]; SHELL_FS_PART_SECTORS],
    ) -> Result<(usize, usize), WalError> {
        let proof = match durable_wal_proof(self.task_caps[4]) {
            Ok(p) => p,
            Err(_) => {
                self.record_audit(21, AuditVerdict::Denied, b"shell:fs:no-cap");
                return Err(WalError::PayloadTooLarge);
            }
        };
        proof.consume();

        let mut s = 0usize;
        while s < SHELL_FS_PART_SECTORS {
            sectors[s] = [0u8; 512];
            s += 1;
        }

        let mut file_count = 0usize;
        let mut data_cursor = 0usize;
        let mut i = 0usize;
        while i < SHELL_FS_INODES {
            if let Some((path, data)) = self.fs.inode_data(i) {
                if !is_default_system_file(path) {
                    if path.is_empty() || path.len() > 46 {
                        return Err(WalError::PayloadTooLarge);
                    }
                    if data_cursor.saturating_add(data.len()) > SHELL_FS_POOL {
                        return Err(WalError::OutOfCapacity);
                    }
                    let dir_sec = 1 + (file_count / 8);
                    let dir_off = (file_count % 8) * 64;
                    let plen_b = (path.len() as u16).to_le_bytes();
                    let doff_b = (data_cursor as u16).to_le_bytes();
                    let dlen_b = (data.len() as u32).to_le_bytes();
                    let mtime_b = 1u64.to_le_bytes();
                    sectors[dir_sec][dir_off] = plen_b[0];
                    sectors[dir_sec][dir_off + 1] = plen_b[1];
                    sectors[dir_sec][dir_off + 2] = doff_b[0];
                    sectors[dir_sec][dir_off + 3] = doff_b[1];
                    sectors[dir_sec][dir_off + 4] = dlen_b[0];
                    sectors[dir_sec][dir_off + 5] = dlen_b[1];
                    sectors[dir_sec][dir_off + 6] = dlen_b[2];
                    sectors[dir_sec][dir_off + 7] = dlen_b[3];
                    let mut p = 0usize;
                    while p < path.len() {
                        sectors[dir_sec][dir_off + 8 + p] = path[p];
                        p += 1;
                    }
                    let mut m = 0usize;
                    while m < 8 {
                        sectors[dir_sec][dir_off + 56 + m] = mtime_b[m];
                        m += 1;
                    }

                    let mut b = 0usize;
                    while b < data.len() {
                        let abs = data_cursor + b;
                        sectors[3 + (abs / 512)][abs % 512] = data[b];
                        b += 1;
                    }
                    data_cursor += data.len();
                    file_count += 1;
                }
            }
            i += 1;
        }

        let mut k = 0usize;
        while k < 8 {
            sectors[0][k] = SHELL_FS_MAGIC[k];
            k += 1;
        }
        let gen_b = generation.to_le_bytes();
        let mut g = 0usize;
        while g < 8 {
            sectors[0][8 + g] = gen_b[g];
            g += 1;
        }
        let fc_b = (file_count as u32).to_le_bytes();
        sectors[0][16] = fc_b[0];
        sectors[0][17] = fc_b[1];
        sectors[0][18] = fc_b[2];
        sectors[0][19] = fc_b[3];
        let db_b = (data_cursor as u32).to_le_bytes();
        sectors[0][20] = db_b[0];
        sectors[0][21] = db_b[1];
        sectors[0][22] = db_b[2];
        sectors[0][23] = db_b[3];

        let mut seal = [0u8; DURABLE_DIGEST_LEN];
        compute_fs_partition_seal(&self.seal_key, sectors, &mut seal);
        let mut h = 0usize;
        while h < DURABLE_DIGEST_LEN {
            sectors[0][24 + h] = seal[h];
            h += 1;
        }
        Ok((file_count, data_cursor))
    }

    /// Verify and unpack a 16-sector (`8 KiB`) block-backed filesystem partition
    /// written by [`OsShell::pack_fs_partition`].
    ///
    /// Verifies the `PRTSFS01` superblock magic and the chained keyed `HMAC-SHA256`
    /// seal over all 16 sectors in constant time before mounting/restoring files
    /// (including multi-sector files up to `SHELL_FS_POOL = 4096` bytes).
    /// Returns `Ok((generation, file_count, data_bytes))`.
    pub fn unpack_fs_partition(
        &mut self,
        sectors: &[[u8; 512]; SHELL_FS_PART_SECTORS],
    ) -> Result<(u64, usize, usize), WalError> {
        if !bytes_eq(&sectors[0][0..8], SHELL_FS_MAGIC) {
            self.record_audit(21, AuditVerdict::Denied, b"shell:fs:magic-corrupt");
            return Err(WalError::PayloadTooLarge);
        }
        let generation = u64::from_le_bytes([
            sectors[0][8],
            sectors[0][9],
            sectors[0][10],
            sectors[0][11],
            sectors[0][12],
            sectors[0][13],
            sectors[0][14],
            sectors[0][15],
        ]);
        let file_count = u32::from_le_bytes([
            sectors[0][16],
            sectors[0][17],
            sectors[0][18],
            sectors[0][19],
        ]) as usize;
        let data_bytes = u32::from_le_bytes([
            sectors[0][20],
            sectors[0][21],
            sectors[0][22],
            sectors[0][23],
        ]) as usize;
        if file_count > SHELL_FS_INODES || data_bytes > SHELL_FS_POOL {
            self.record_audit(21, AuditVerdict::Denied, b"shell:fs:bounds-overflow");
            return Err(WalError::OutOfCapacity);
        }

        let mut expected_seal = [0u8; DURABLE_DIGEST_LEN];
        let mut h = 0usize;
        while h < DURABLE_DIGEST_LEN {
            expected_seal[h] = sectors[0][24 + h];
            h += 1;
        }
        if !verify_fs_partition_seal(&self.seal_key, sectors, &expected_seal) {
            self.record_audit(21, AuditVerdict::Denied, b"shell:fs:seal-mismatch");
            return Err(WalError::PayloadTooLarge);
        }

        let mut idx = 0usize;
        while idx < file_count {
            let dir_sec = 1 + (idx / 8);
            let dir_off = (idx % 8) * 64;
            let plen = u16::from_le_bytes([
                sectors[dir_sec][dir_off],
                sectors[dir_sec][dir_off + 1],
            ]) as usize;
            let doff = u16::from_le_bytes([
                sectors[dir_sec][dir_off + 2],
                sectors[dir_sec][dir_off + 3],
            ]) as usize;
            let dlen = u32::from_le_bytes([
                sectors[dir_sec][dir_off + 4],
                sectors[dir_sec][dir_off + 5],
                sectors[dir_sec][dir_off + 6],
                sectors[dir_sec][dir_off + 7],
            ]) as usize;
            let mtime = u64::from_le_bytes([
                sectors[dir_sec][dir_off + 56],
                sectors[dir_sec][dir_off + 57],
                sectors[dir_sec][dir_off + 58],
                sectors[dir_sec][dir_off + 59],
                sectors[dir_sec][dir_off + 60],
                sectors[dir_sec][dir_off + 61],
                sectors[dir_sec][dir_off + 62],
                sectors[dir_sec][dir_off + 63],
            ]);
            if plen == 0 || plen > 46 || doff.saturating_add(dlen) > data_bytes {
                self.record_audit(21, AuditVerdict::Denied, b"shell:fs:dirent-corrupt");
                return Err(WalError::PayloadTooLarge);
            }
            let path = &sectors[dir_sec][dir_off + 8..dir_off + 8 + plen];
            let mut chunk = [0u8; 256];
            if dlen <= 256 {
                let mut b = 0usize;
                while b < dlen {
                    let abs = doff + b;
                    chunk[b] = sectors[3 + (abs / 512)][abs % 512];
                    b += 1;
                }
                if let Ok(fh) = self.fs.open(path, FS_O_RDWR | FS_O_CREATE | FS_O_TRUNC) {
                    let _ = self.fs.write(fh, 0, &chunk[..dlen]);
                    let _ = self.fs.close(fh);
                }
            } else {
                let _ = self.fs.unlink(path);
                if self.fs.seed_file(path, &[], dlen, mtime).is_ok() {
                    if let Ok(fh) = self.fs.open(path, FS_O_RDWR) {
                        let mut rel = 0usize;
                        while rel < dlen {
                            let rem = dlen - rel;
                            let step = if rem < 256 { rem } else { 256 };
                            let mut b = 0usize;
                            while b < step {
                                let abs = doff + rel + b;
                                chunk[b] = sectors[3 + (abs / 512)][abs % 512];
                                b += 1;
                            }
                            let _ = self.fs.write(fh, rel as u64, &chunk[..step]);
                            rel += step;
                        }
                        let _ = self.fs.close(fh);
                    }
                }
            }
            idx += 1;
        }
        Ok((generation, file_count, data_bytes))
    }

    /// Compute a 32-byte SHA-256 cryptographic seal over the live OS state
    /// (mutable files, active tasks, capability masks, firewall rules,
    /// IMA table, anti-replay watermark, and audit watermark).
    #[inline(never)]
    pub fn compute_state_seal(&self, out: &mut [u8; DURABLE_DIGEST_LEN]) {
        let mut buf = [0u8; 1024];
        let mut pos = 0usize;
        let mut i = 0usize;
        while i < SHELL_FS_INODES {
            if let Some((path, data)) = self.fs.inode_data(i) {
                pos += copy_into(path, &mut buf[pos..]);
                pos += copy_into(b":", &mut buf[pos..]);
                pos += copy_into(data, &mut buf[pos..]);
                pos += copy_into(b";", &mut buf[pos..]);
            }
            i += 1;
        }
        let mut s = 0usize;
        while s < SHELL_MAX_TASKS {
            if let Some(t) = self.sched.slot(s) {
                if t.state != TaskState::Empty && t.state != TaskState::Exited {
                    pos += dec_u64(t.id as u64, &mut buf[pos..]);
                    pos += copy_into(b"=", &mut buf[pos..]);
                    let cap = if (t.id as usize) < SHELL_MAX_TASKS {
                        self.task_caps[t.id as usize]
                    } else {
                        0
                    };
                    let sc = if (t.id as usize) < SHELL_MAX_TASKS {
                        self.seccomp_mask[t.id as usize]
                    } else {
                        0
                    };
                    pos += dec_u64(cap, &mut buf[pos..]);
                    if sc != 0 {
                        pos += copy_into(b"/", &mut buf[pos..]);
                        pos += dec_u64(sc as u64, &mut buf[pos..]);
                    }
                    pos += copy_into(b";", &mut buf[pos..]);
                }
            }
            s += 1;
        }
        pos += dec_u64(self.fw.as_slice().len() as u64, &mut buf[pos..]);
        pos += copy_into(b":", &mut buf[pos..]);
        pos += dec_u64(self.ima_count as u64, &mut buf[pos..]);
        pos += copy_into(b":", &mut buf[pos..]);
        pos += dec_u64(self.auth_seq, &mut buf[pos..]);
        pos += copy_into(b":", &mut buf[pos..]);
        pos += dec_u64(self.audit.high_watermark(), &mut buf[pos..]);
        pos += copy_into(b":", &mut buf[pos..]);
        pos += copy_into(self.svc.role.as_bytes(), &mut buf[pos..]);
        pos += copy_into(b":", &mut buf[pos..]);
        pos += copy_into(&self.svc.svc_pcr10, &mut buf[pos..]);
        seal_bytes(&buf[..pos], out);
    }

    /// Feed a single raw console byte (from COM1 16550 or PS/2 keyboard).
    ///
    /// - `echo_out` receives any terminal echo bytes (e.g., character echo,
    ///   backspace erase sequence, or trailing `proteus> ` prompt).
    /// - When `\r` or `\n` completes a command line, the command is executed
    ///   and its output + next prompt are written to `reply_out`.
    /// - Returns `(echo_len, ShellAction)`.
    pub fn feed_byte(
        &mut self,
        b: u8,
        boots: u64,
        net_rx: u64,
        net_tx: u64,
        echo_out: &mut [u8],
        reply_out: &mut [u8],
    ) -> (usize, ShellAction) {
        if b == b'\r' || b == b'\n' {
            let mut elen = 0usize;
            elen += copy_into(b"\r\n", &mut echo_out[elen..]);
            let mut cmd = [0u8; SHELL_LINE_MAX];
            let clen = self.line_len;
            let mut i = 0usize;
            while i < clen {
                cmd[i] = self.line_buf[i];
                i += 1;
            }
            self.line_len = 0;

            let action = self.exec_line(&cmd[..clen], boots, net_rx, net_tx, reply_out);
            let mut rlen = action.bytes_written();
            if let ShellAction::Continue(_) = action {
                rlen += copy_into(SHELL_PROMPT, &mut reply_out[rlen..]);
                return (elen, ShellAction::Continue(rlen));
            }
            return (elen, action);
        }

        // Backspace (0x08) or DEL (0x7F).
        if b == 0x08 || b == 0x7F {
            if self.line_len > 0 {
                self.line_len -= 1;
                let n = copy_into(b"\x08 \x08", echo_out);
                return (n, ShellAction::Continue(0));
            }
            return (0, ShellAction::Continue(0));
        }

        // Printable ASCII + tab.
        if (0x20..=0x7E).contains(&b) && self.line_len < SHELL_LINE_MAX {
            self.line_buf[self.line_len] = b;
            self.line_len += 1;
            if !echo_out.is_empty() {
                echo_out[0] = b;
                return (1, ShellAction::Continue(0));
            }
        }
        (0, ShellAction::Continue(0))
    }

    /// Execute one complete command line and write the formatted output into `out`.
    #[inline(never)]
    pub fn exec_line(
        &mut self,
        raw_line: &[u8],
        boots: u64,
        net_rx: u64,
        net_tx: u64,
        out: &mut [u8],
    ) -> ShellAction {
        let line = trim_ascii(raw_line);
        if line.is_empty() {
            return ShellAction::Continue(0);
        }

        // Tick the round-robin scheduler once per command to advance task execution.
        if let Some(pid) = self.sched.pick_next() {
            let p_idx = pid as usize;
            if p_idx < SHELL_MAX_TASKS {
                self.kthread_switches[p_idx] = self.kthread_switches[p_idx].wrapping_add(1);
            }
            let n_cpus = (self.smp_cpus_online as usize).clamp(1, 4);
            let cpu_idx = p_idx % n_cpus;
            self.smp_cpu_ticks[cpu_idx] = self.smp_cpu_ticks[cpu_idx].wrapping_add(1);
            self.smp_cpu_jobs[cpu_idx] = self.smp_cpu_jobs[cpu_idx].wrapping_add(1);
        }

        let (cmd, rest) = split_first_word(line);
        if bytes_eq(cmd, b"help") || bytes_eq(cmd, b"?") {
            self.record_audit(1, AuditVerdict::Allowed, b"shell:help");
            let n = copy_into(
                b"commands: help uname status ps smp threads service spawn kill caps grant revoke syscall seccomp exec ima fw seal attest ls cat write rm stat df sync sql session net audit halt reboot\n",
                out,
            );
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"uname") {
            self.record_audit(2, AuditVerdict::Allowed, b"shell:uname");
            let n = copy_into(
                b"Proteus-TE x86_64 1.0-mtd (Moving Target Defense Kernel)\n",
                out,
            );
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"status") || bytes_eq(cmd, b"uptime") {
            self.record_audit(3, AuditVerdict::Allowed, b"shell:status");
            let n = self.cmd_status(boots, net_rx, net_tx, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"ps") {
            self.record_audit(4, AuditVerdict::Allowed, b"shell:ps");
            let n = self.cmd_ps(out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"smp") || bytes_eq(cmd, b"threads") {
            let n = self.cmd_smp(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"spawn") {
            if self
                .svc
                .mediate_endpoint(
                    crate::svc_runtime::IpcOp::ShellExec,
                    false,
                    true,
                    &mut self.audit,
                )
                .is_err()
            {
                let n = copy_into(
                    b"error: EACCES (svc-sh disabled by node role or policy)\n",
                    out,
                );
                return ShellAction::Continue(n);
            }
            let pid = self.next_pid;
            if self.sched.enqueue_with_priority(pid, 5) {
                if (pid as usize) < SHELL_MAX_TASKS {
                    self.task_caps[pid as usize] = 0;
                    self.seccomp_mask[pid as usize] = 0;
                }
                self.next_pid = self.next_pid.wrapping_add(1);
                self.record_audit(5, AuditVerdict::Allowed, b"shell:spawn");
                let mut pos = 0usize;
                pos += copy_into(b"spawned pid=", &mut out[pos..]);
                pos += dec_u64(pid as u64, &mut out[pos..]);
                pos += copy_into(b"\n", &mut out[pos..]);
                return ShellAction::Continue(pos);
            }
            self.record_audit(5, AuditVerdict::Error, b"shell:spawn:full");
            let n = copy_into(b"error: task table full\n", out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"kill") {
            let n = self.cmd_kill(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"caps") {
            let n = self.cmd_caps(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"grant") {
            let n = self.cmd_grant_revoke(rest, true, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"revoke") {
            let n = self.cmd_grant_revoke(rest, false, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"syscall") {
            let n = self.cmd_syscall(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"seccomp") {
            let n = self.cmd_seccomp(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"exec") {
            let n = self.cmd_exec(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"ima") {
            let n = self.cmd_ima(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"fw") {
            let n = self.cmd_fw(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"seal") {
            let n = self.cmd_seal(out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"attest") {
            let n = self.cmd_attest(boots, rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"ls") {
            self.record_audit(7, AuditVerdict::Allowed, b"shell:ls");
            let n = self.cmd_ls(out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"cat") {
            let n = self.cmd_cat(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"write") {
            let n = self.cmd_write(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"rm") {
            let n = self.cmd_rm(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"stat") {
            let n = self.cmd_stat(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"df") {
            let n = self.cmd_df(out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"sync") {
            let n = self.cmd_sync(out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"sql") {
            let n = self.cmd_sql(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"session") {
            let n = self.cmd_session(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"service") || bytes_eq(cmd, b"svc") {
            let n = self.cmd_service(rest, out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"net") {
            self.record_audit(12, AuditVerdict::Allowed, b"shell:net");
            let mut pos = 0usize;
            pos += copy_into(
                b"iface=virtio-net0 ip=10.0.2.15 udp=8080 tcp=80 icmp=echo rx=",
                &mut out[pos..],
            );
            pos += dec_u64(net_rx, &mut out[pos..]);
            pos += copy_into(b" tx=", &mut out[pos..]);
            pos += dec_u64(net_tx, &mut out[pos..]);
            pos += copy_into(b"\n", &mut out[pos..]);
            return ShellAction::Continue(pos);
        }

        if bytes_eq(cmd, b"audit") {
            self.record_audit(13, AuditVerdict::Allowed, b"shell:audit");
            let n = self.cmd_audit(out);
            return ShellAction::Continue(n);
        }

        if bytes_eq(cmd, b"halt") || bytes_eq(cmd, b"poweroff") {
            self.record_audit(14, AuditVerdict::Allowed, b"shell:halt");
            let n = copy_into(b"system halting...\n", out);
            return ShellAction::Halt(n);
        }

        if bytes_eq(cmd, b"reboot") {
            self.record_audit(15, AuditVerdict::Allowed, b"shell:reboot");
            let n = copy_into(b"system rebooting...\n", out);
            return ShellAction::Reboot(n);
        }

        self.record_audit(0xFF, AuditVerdict::Error, b"shell:unknown");
        let mut pos = 0usize;
        pos += copy_into(b"unknown command: ", &mut out[pos..]);
        pos += copy_into(cmd, &mut out[pos..]);
        pos += copy_into(b" (type 'help')\n", &mut out[pos..]);
        ShellAction::Continue(pos)
    }

    fn record_audit(&mut self, op_nr: u32, verdict: AuditVerdict, msg: &[u8]) {
        let mut message = [0u8; AUDIT_MESSAGE_LEN];
        let n = if msg.len() < AUDIT_MESSAGE_LEN {
            msg.len()
        } else {
            AUDIT_MESSAGE_LEN
        };
        let mut i = 0usize;
        while i < n {
            message[i] = msg[i];
            i += 1;
        }
        let ev = AuditEvent {
            event_id: 0,
            wall_unix: self.cmd_seq,
            task_id: 4, // proteus-sh
            syscall_nr: op_nr,
            verdict,
            message,
        };
        self.cmd_seq = self.cmd_seq.wrapping_add(1);
        let _ = self.audit.append(ev);
    }

    fn active_task_count(&self) -> usize {
        let mut count = 0usize;
        let mut i = 0usize;
        while i < SHELL_MAX_TASKS {
            if let Some(t) = self.sched.slot(i) {
                if t.state != TaskState::Empty && t.state != TaskState::Exited {
                    count += 1;
                }
            }
            i += 1;
        }
        count
    }

    fn cmd_status(&self, boots: u64, net_rx: u64, net_tx: u64, out: &mut [u8]) -> usize {
        let mut pos = 0usize;
        pos += copy_into(b"status: ok boots=", &mut out[pos..]);
        pos += dec_u64(boots, &mut out[pos..]);
        pos += copy_into(b" tasks=", &mut out[pos..]);
        pos += dec_u64(self.active_task_count() as u64, &mut out[pos..]);
        pos += copy_into(b" files=", &mut out[pos..]);
        pos += dec_u64(self.fs.inode_count() as u64, &mut out[pos..]);
        pos += copy_into(b" audit_events=", &mut out[pos..]);
        pos += dec_u64(self.audit.high_watermark(), &mut out[pos..]);
        pos += copy_into(b" net_rx=", &mut out[pos..]);
        pos += dec_u64(net_rx, &mut out[pos..]);
        pos += copy_into(b" net_tx=", &mut out[pos..]);
        pos += dec_u64(net_tx, &mut out[pos..]);
        pos += copy_into(b"\n", &mut out[pos..]);
        pos
    }

    fn cmd_ps(&self, out: &mut [u8]) -> usize {
        let mut pos = 0usize;
        pos += copy_into(b"PID STATE DISPATCHES NAME\n", &mut out[pos..]);
        let mut i = 0usize;
        while i < SHELL_MAX_TASKS {
            if let Some(t) = self.sched.slot(i) {
                if t.state != TaskState::Empty && t.state != TaskState::Exited {
                    pos += dec_u64(t.id as u64, &mut out[pos..]);
                    pos += copy_into(b" ", &mut out[pos..]);
                    let st: &[u8] = match t.state {
                        TaskState::Running => b"Running ",
                        TaskState::Ready => b"Ready ",
                        TaskState::Blocked => b"Blocked ",
                        TaskState::Exited => b"Exited ",
                        TaskState::Empty => b"Empty ",
                    };
                    pos += copy_into(st, &mut out[pos..]);
                    pos += dec_u64(t.picked as u64, &mut out[pos..]);
                    pos += copy_into(b" ", &mut out[pos..]);
                    let name: &[u8] = match t.id {
                        1 => b"init\n",
                        2 => b"kthreadd-net\n",
                        3 => b"kthreadd-wal\n",
                        4 => b"proteus-sh\n",
                        _ => b"worker\n",
                    };
                    pos += copy_into(name, &mut out[pos..]);
                }
            }
            i += 1;
        }
        pos
    }

    fn cmd_smp(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        let (sub, rest) = split_first_word(trim_ascii(arg));
        let n_cpus = (self.smp_cpus_online as usize).clamp(1, 4);
        if bytes_eq(sub, b"run") || bytes_eq(sub, b"dispatch") {
            let count = parse_u32_ascii(trim_ascii(rest)).unwrap_or(4).clamp(1, 64) as usize;
            let mut k = 0usize;
            while k < count {
                let cpu_idx = k % n_cpus;
                self.smp_cpu_ticks[cpu_idx] = self.smp_cpu_ticks[cpu_idx].wrapping_add(16);
                self.smp_cpu_jobs[cpu_idx] = self.smp_cpu_jobs[cpu_idx].wrapping_add(1);
                if let Some(pid) = self.sched.pick_next() {
                    let p_idx = pid as usize;
                    if p_idx < SHELL_MAX_TASKS {
                        self.kthread_switches[p_idx] =
                            self.kthread_switches[p_idx].wrapping_add(1);
                    }
                }
                k += 1;
            }
            self.smp_ipi_doorbells = self.smp_ipi_doorbells.wrapping_add(1);
            self.smp_irq_wakeups = self.smp_irq_wakeups.wrapping_add(n_cpus.saturating_sub(1) as u64);
            self.record_audit(30, AuditVerdict::Allowed, b"shell:smp:dispatch");
            let mut total_sw = 0u64;
            let mut s = 0usize;
            while s < SHELL_MAX_TASKS {
                total_sw = total_sw.wrapping_add(self.kthread_switches[s]);
                s += 1;
            }
            let mut pos = 0usize;
            pos += copy_into(b"smp: dispatched ", &mut out[pos..]);
            pos += dec_u64(count as u64, &mut out[pos..]);
            pos += copy_into(b" parallel jobs across ", &mut out[pos..]);
            pos += dec_u64(n_cpus as u64, &mut out[pos..]);
            pos += copy_into(b" cores (ctx_switches=", &mut out[pos..]);
            pos += dec_u64(total_sw, &mut out[pos..]);
            pos += copy_into(b" ipis=", &mut out[pos..]);
            pos += dec_u64(self.smp_ipi_doorbells, &mut out[pos..]);
            pos += copy_into(b")\n", &mut out[pos..]);
            return pos;
        }

        self.record_audit(30, AuditVerdict::Allowed, b"shell:smp:status");
        let mut total_sw = 0u64;
        let mut s = 0usize;
        while s < SHELL_MAX_TASKS {
            total_sw = total_sw.wrapping_add(self.kthread_switches[s]);
            s += 1;
        }
        let mut pos = 0usize;
        pos += copy_into(b"smp: cpus=", &mut out[pos..]);
        pos += dec_u64(n_cpus as u64, &mut out[pos..]);
        pos += copy_into(b"/4 arch=x86_64-lapic-ipi threads=", &mut out[pos..]);
        pos += dec_u64(self.active_task_count() as u64, &mut out[pos..]);
        pos += copy_into(b" ctx_switches=", &mut out[pos..]);
        pos += dec_u64(total_sw, &mut out[pos..]);
        pos += copy_into(b" idle=hlt-ipi irqs=", &mut out[pos..]);
        pos += dec_u64(self.smp_irq_wakeups, &mut out[pos..]);
        pos += copy_into(b" ipis=", &mut out[pos..]);
        pos += dec_u64(self.smp_ipi_doorbells, &mut out[pos..]);
        pos += copy_into(b"\n", &mut out[pos..]);

        let mut c = 0usize;
        while c < 4 {
            pos += copy_into(b"  cpu", &mut out[pos..]);
            pos += dec_u64(c as u64, &mut out[pos..]);
            pos += copy_into(
                if c == 0 {
                    b" [BSP apic=0]: "
                } else {
                    b" [AP  apic="
                },
                &mut out[pos..],
            );
            if c > 0 {
                pos += dec_u64(c as u64, &mut out[pos..]);
                pos += copy_into(b"]: ", &mut out[pos..]);
            }
            if c < n_cpus {
                pos += copy_into(
                    if c == 0 {
                        b"online (hlt+irq0x40) ticks="
                    } else {
                        b"online (hlt+ipi0x41) ticks="
                    },
                    &mut out[pos..],
                );
                pos += dec_u64(self.smp_cpu_ticks[c], &mut out[pos..]);
                pos += copy_into(b" jobs=", &mut out[pos..]);
                pos += dec_u64(self.smp_cpu_jobs[c], &mut out[pos..]);
                pos += copy_into(b"\n", &mut out[pos..]);
            } else {
                pos += copy_into(b"offline\n", &mut out[pos..]);
            }
            c += 1;
        }

        let mut i = 0usize;
        while i < SHELL_MAX_TASKS {
            if let Some(t) = self.sched.slot(i) {
                if t.state != TaskState::Empty && t.state != TaskState::Exited {
                    let p_idx = t.id as usize;
                    let cpu_aff = (p_idx.wrapping_sub(1)) % n_cpus;
                    let sw = if p_idx < SHELL_MAX_TASKS {
                        self.kthread_switches[p_idx].max(t.picked as u64)
                    } else {
                        t.picked as u64
                    };
                    pos += copy_into(b"  tid=", &mut out[pos..]);
                    pos += dec_u64(t.id as u64, &mut out[pos..]);
                    pos += copy_into(b" cpu=", &mut out[pos..]);
                    pos += dec_u64(cpu_aff as u64, &mut out[pos..]);
                    pos += copy_into(b" ctx_sw=", &mut out[pos..]);
                    pos += dec_u64(sw, &mut out[pos..]);
                    pos += copy_into(b" ", &mut out[pos..]);
                    let name: &[u8] = match t.id {
                        1 => b"init\n",
                        2 => b"kthreadd-net\n",
                        3 => b"kthreadd-wal\n",
                        4 => b"proteus-sh\n",
                        _ => b"worker\n",
                    };
                    pos += copy_into(name, &mut out[pos..]);
                }
            }
            i += 1;
        }
        pos
    }

    fn cmd_kill(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        if self
            .svc
            .mediate_endpoint(
                crate::svc_runtime::IpcOp::ShellExec,
                false,
                true,
                &mut self.audit,
            )
            .is_err()
        {
            return copy_into(
                b"error: EACCES (svc-sh disabled by node role or policy)\n",
                out,
            );
        }
        let target = trim_ascii(arg);
        let Some(pid) = parse_u32_ascii(target) else {
            self.record_audit(6, AuditVerdict::Error, b"shell:kill:bad-pid");
            return copy_into(b"usage: kill <pid>\n", out);
        };
        if pid <= 4 {
            self.record_audit(6, AuditVerdict::Denied, b"shell:kill:protected-task");
            return copy_into(b"error: permission denied (protected system task)\n", out);
        }
        if self.sched.exit(pid, 0) {
            let _ = self.sched.reap(pid);
            if (pid as usize) < SHELL_MAX_TASKS {
                self.task_caps[pid as usize] = 0;
                self.seccomp_mask[pid as usize] = 0;
            }
            self.record_audit(6, AuditVerdict::Allowed, b"shell:kill");
            let mut pos = 0usize;
            pos += copy_into(b"killed pid=", &mut out[pos..]);
            pos += dec_u64(pid as u64, &mut out[pos..]);
            pos += copy_into(b"\n", &mut out[pos..]);
            pos
        } else {
            self.record_audit(6, AuditVerdict::Error, b"shell:kill:not-found");
            copy_into(b"error: no such pid\n", out)
        }
    }

    fn cmd_caps(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        let Some(pid) = parse_u32_ascii(trim_ascii(arg)) else {
            self.record_audit(16, AuditVerdict::Error, b"shell:caps:bad-pid");
            return copy_into(b"usage: caps <pid>\n", out);
        };
        if (pid as usize) >= SHELL_MAX_TASKS || self.sched.task(pid).is_none() {
            self.record_audit(16, AuditVerdict::Error, b"shell:caps:no-pid");
            return copy_into(b"error: no such pid\n", out);
        }
        let mask = self.task_caps[pid as usize];
        self.record_audit(16, AuditVerdict::Allowed, b"shell:caps");
        let mut pos = 0usize;
        pos += copy_into(b"pid=", &mut out[pos..]);
        pos += dec_u64(pid as u64, &mut out[pos..]);
        pos += copy_into(b" caps=", &mut out[pos..]);
        pos += dec_u64(mask, &mut out[pos..]);
        pos += copy_into(b"\n", &mut out[pos..]);
        pos
    }

    fn cmd_grant_revoke(&mut self, arg: &[u8], is_grant: bool, out: &mut [u8]) -> usize {
        let (pid_str, cap_name) = split_first_word(trim_ascii(arg));
        let Some(pid) = parse_u32_ascii(pid_str) else {
            self.record_audit(17, AuditVerdict::Error, b"shell:cap:bad-args");
            return copy_into(b"usage: grant|revoke <pid> <fs|net|wal|all>\n", out);
        };
        if pid <= 4 && !is_grant {
            self.record_audit(17, AuditVerdict::Denied, b"shell:revoke:protected-task");
            return copy_into(b"error: permission denied (protected system task)\n", out);
        };
        if (pid as usize) >= SHELL_MAX_TASKS || self.sched.task(pid).is_none() {
            self.record_audit(17, AuditVerdict::Error, b"shell:cap:no-pid");
            return copy_into(b"error: no such pid\n", out);
        }
        let bit = if bytes_eq(cap_name, b"fs") {
            caps::FS_BYPASS
        } else if bytes_eq(cap_name, b"net") {
            caps::NET_RAW
        } else if bytes_eq(cap_name, b"wal") {
            caps::DURABLE_WAL_WRITE
        } else if bytes_eq(cap_name, b"all") {
            caps::FS_BYPASS | caps::NET_RAW | caps::DURABLE_WAL_WRITE
        } else {
            self.record_audit(17, AuditVerdict::Error, b"shell:cap:unknown");
            return copy_into(b"error: unknown cap (use fs, net, wal, all)\n", out);
        };
        if is_grant {
            self.task_caps[pid as usize] |= bit;
            self.record_audit(17, AuditVerdict::Allowed, b"shell:grant");
        } else {
            self.task_caps[pid as usize] &= !bit;
            self.record_audit(17, AuditVerdict::Allowed, b"shell:revoke");
        }
        let mut pos = 0usize;
        pos += copy_into(if is_grant { b"granted " } else { b"revoked " }, &mut out[pos..]);
        pos += copy_into(cap_name, &mut out[pos..]);
        pos += copy_into(b" on pid=", &mut out[pos..]);
        pos += dec_u64(pid as u64, &mut out[pos..]);
        pos += copy_into(b"\n", &mut out[pos..]);
        pos
    }

    fn cmd_syscall(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        let (pid_str, rest) = split_first_word(trim_ascii(arg));
        let (sys_name, sys_arg) = split_first_word(rest);
        let Some(pid) = parse_u32_ascii(pid_str) else {
            self.record_audit(18, AuditVerdict::Error, b"shell:syscall:bad-args");
            return copy_into(b"usage: syscall <pid> <getpid|yield|time|open> [path]\n", out);
        };
        if (pid as usize) >= SHELL_MAX_TASKS || self.sched.task(pid).is_none() {
            self.record_audit(18, AuditVerdict::Error, b"shell:syscall:no-pid");
            return copy_into(b"error: no such pid\n", out);
        }
        let nr = if bytes_eq(sys_name, b"open") {
            SYS_OPEN
        } else if bytes_eq(sys_name, b"getpid") {
            SYS_GETPID
        } else if bytes_eq(sys_name, b"yield") {
            SYS_YIELD
        } else if bytes_eq(sys_name, b"time") {
            SYS_GETTIME_NS
        } else {
            self.record_audit(18, AuditVerdict::Error, b"shell:syscall:unknown");
            return copy_into(b"error: unknown syscall (use getpid, yield, time, open)\n", out);
        };

        // Pre-dispatch eBPF Seccomp-BPF syscall sandboxing gate:
        // Evaluates the per-PID eBPF filter program in `EBpfImpl` before kernel capability checks.
        let seccomp = self.seccomp_mask[pid as usize];
        if seccomp != 0 && !evaluate_seccomp_ebpf(seccomp, nr) {
            self.record_audit(18, AuditVerdict::Denied, b"shell:syscall:seccomp");
            return copy_into(
                b"syscall denied: EACCES (blocked by eBPF seccomp filter)\n",
                out,
            );
        }

        let mask = self.task_caps[pid as usize];
        if nr == SYS_OPEN {
            let path = if sys_arg.is_empty() { b"/etc/hostname" } else { sys_arg };
            // Check FS_BYPASS capability via the locked CapProof mint path.
            let proof = match check_cap(SYS_OPEN, mask) {
                Ok(p) => p,
                Err(Errno::EPERM) => {
                    self.record_audit(18, AuditVerdict::Denied, b"shell:syscall:open:eperm");
                    return copy_into(b"syscall denied: EPERM (missing fs capability)\n", out);
                }
                Err(_) => {
                    self.record_audit(18, AuditVerdict::Error, b"shell:syscall:open:err");
                    return copy_into(b"syscall error\n", out);
                }
            };
            proof.consume();
            match self.fs.open(path, FS_O_RDONLY) {
                Ok(h) => {
                    let _ = self.fs.close(h);
                    self.record_audit(18, AuditVerdict::Allowed, b"shell:syscall:open");
                    return copy_into(b"syscall ok: ret=0\n", out);
                }
                Err(_) => {
                    self.record_audit(18, AuditVerdict::Error, b"shell:syscall:open:enoent");
                    return copy_into(b"syscall error: ENOENT\n", out);
                }
            }
        }

        match dispatch_with_cap(nr, mask, 0, 0, 0, 0, 0, 0) {
            Ok(ret) => {
                self.record_audit(18, AuditVerdict::Allowed, b"shell:syscall:ok");
                let mut pos = 0usize;
                pos += copy_into(b"syscall ok: ret=", &mut out[pos..]);
                pos += dec_u64(ret, &mut out[pos..]);
                pos += copy_into(b"\n", &mut out[pos..]);
                pos
            }
            Err(Errno::EPERM) => {
                self.record_audit(18, AuditVerdict::Denied, b"shell:syscall:eperm");
                copy_into(b"syscall denied: EPERM\n", out)
            }
            Err(_) => {
                self.record_audit(18, AuditVerdict::Error, b"shell:syscall:err");
                copy_into(b"syscall error\n", out)
            }
        }
    }

    fn cmd_seccomp(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        let (sub, rest) = split_first_word(trim_ascii(arg));
        if sub.is_empty() || bytes_eq(sub, b"status") {
            self.record_audit(27, AuditVerdict::Allowed, b"shell:seccomp:status");
            let mut active_filters = 0usize;
            let mut p = 0usize;
            while p < SHELL_MAX_TASKS {
                if self.seccomp_mask[p] != 0 && self.sched.task(p as u32).is_some() {
                    active_filters += 1;
                }
                p += 1;
            }
            let mut pos = 0usize;
            pos += copy_into(b"seccomp: filters=", &mut out[pos..]);
            pos += dec_u64(active_filters as u64, &mut out[pos..]);
            pos += copy_into(b" engine=ebpf\n", &mut out[pos..]);
            let mut pid = 0usize;
            while pid < SHELL_MAX_TASKS {
                let m = self.seccomp_mask[pid];
                if m != 0 && self.sched.task(pid as u32).is_some() {
                    pos += copy_into(b"  pid=", &mut out[pos..]);
                    pos += dec_u64(pid as u64, &mut out[pos..]);
                    pos += copy_into(b" deny_mask=", &mut out[pos..]);
                    pos += dec_u64(m as u64, &mut out[pos..]);
                    pos += copy_into(b" (", &mut out[pos..]);
                    pos += fmt_seccomp_mask(m, &mut out[pos..]);
                    pos += copy_into(b")\n", &mut out[pos..]);
                }
                pid += 1;
            }
            return pos;
        }
        if bytes_eq(sub, b"clear") {
            let Some(pid) = parse_u32_ascii(trim_ascii(rest)) else {
                self.record_audit(27, AuditVerdict::Error, b"shell:seccomp:bad-pid");
                return copy_into(b"usage: seccomp clear <pid>\n", out);
            };
            if (pid as usize) >= SHELL_MAX_TASKS || self.sched.task(pid).is_none() {
                self.record_audit(27, AuditVerdict::Error, b"shell:seccomp:no-pid");
                return copy_into(b"error: no such pid\n", out);
            }
            self.seccomp_mask[pid as usize] = 0;
            self.record_audit(27, AuditVerdict::Allowed, b"shell:seccomp:clear");
            let mut pos = 0usize;
            pos += copy_into(b"seccomp: cleared filter on pid=", &mut out[pos..]);
            pos += dec_u64(pid as u64, &mut out[pos..]);
            pos += copy_into(b"\n", &mut out[pos..]);
            return pos;
        }
        if bytes_eq(sub, b"deny") {
            let (pid_str, sys_name) = split_first_word(trim_ascii(rest));
            let Some(pid) = parse_u32_ascii(pid_str) else {
                self.record_audit(27, AuditVerdict::Error, b"shell:seccomp:bad-args");
                return copy_into(
                    b"usage: seccomp deny <pid> <getpid|yield|time|open|all>\n",
                    out,
                );
            };
            if pid <= 4 {
                self.record_audit(27, AuditVerdict::Denied, b"shell:seccomp:protected-task");
                return copy_into(b"error: permission denied (protected system task)\n", out);
            }
            if (pid as usize) >= SHELL_MAX_TASKS || self.sched.task(pid).is_none() {
                self.record_audit(27, AuditVerdict::Error, b"shell:seccomp:no-pid");
                return copy_into(b"error: no such pid\n", out);
            }
            let bit = if bytes_eq(sys_name, b"getpid") {
                SECCOMP_DENY_GETPID
            } else if bytes_eq(sys_name, b"yield") {
                SECCOMP_DENY_YIELD
            } else if bytes_eq(sys_name, b"time") {
                SECCOMP_DENY_TIME
            } else if bytes_eq(sys_name, b"open") {
                SECCOMP_DENY_OPEN
            } else if bytes_eq(sys_name, b"all") {
                SECCOMP_DENY_ALL
            } else {
                self.record_audit(27, AuditVerdict::Error, b"shell:seccomp:unknown");
                return copy_into(
                    b"error: unknown syscall (use getpid, yield, time, open, all)\n",
                    out,
                );
            };
            self.seccomp_mask[pid as usize] |= bit;
            let new_mask = self.seccomp_mask[pid as usize];
            self.record_audit(27, AuditVerdict::Allowed, b"shell:seccomp:deny");
            let mut pos = 0usize;
            pos += copy_into(b"seccomp: denied ", &mut out[pos..]);
            pos += copy_into(sys_name, &mut out[pos..]);
            pos += copy_into(b" on pid=", &mut out[pos..]);
            pos += dec_u64(pid as u64, &mut out[pos..]);
            pos += copy_into(b" (mask=", &mut out[pos..]);
            pos += dec_u64(new_mask as u64, &mut out[pos..]);
            pos += copy_into(b")\n", &mut out[pos..]);
            return pos;
        }
        self.record_audit(27, AuditVerdict::Error, b"shell:seccomp:bad-arg");
        copy_into(
            b"usage: seccomp [status | deny <pid> <getpid|yield|time|open|all> | clear <pid>]\n",
            out,
        )
    }

    fn cmd_ls(&self, out: &mut [u8]) -> usize {
        let mut pos = 0usize;
        let mut i = 0usize;
        while i < SHELL_FS_INODES {
            if let Some((path, len)) = self.fs.inode_entry(i) {
                pos += copy_into(path, &mut out[pos..]);
                pos += copy_into(b" (", &mut out[pos..]);
                pos += dec_u64(len as u64, &mut out[pos..]);
                pos += copy_into(b" B)\n", &mut out[pos..]);
            }
            i += 1;
        }
        pos
    }

    fn cmd_cat(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        let path = trim_ascii(arg);
        if path.is_empty() {
            self.record_audit(8, AuditVerdict::Error, b"shell:cat:no-arg");
            return copy_into(b"usage: cat <path>\n", out);
        }
        let h = match self.fs.open(path, FS_O_RDONLY) {
            Ok(h) => h,
            Err(_) => {
                self.record_audit(8, AuditVerdict::Error, b"shell:cat:not-found");
                return copy_into(b"error: file not found\n", out);
            }
        };
        let n = self.fs.read(h, 0, out).unwrap_or(0);
        let _ = self.fs.close(h);
        self.record_audit(8, AuditVerdict::Allowed, b"shell:cat");
        let mut pos = n;
        if n > 0 && out[n - 1] != b'\n' && pos < out.len() {
            out[pos] = b'\n';
            pos += 1;
        }
        pos
    }

    fn cmd_write(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        if self
            .svc
            .mediate_endpoint(
                crate::svc_runtime::IpcOp::VfsWrite,
                false,
                true,
                &mut self.audit,
            )
            .is_err()
        {
            return copy_into(
                b"error: EACCES (svc-sh disabled by node role or policy)\n",
                out,
            );
        }
        let (path, content) = split_first_word(trim_ascii(arg));
        if path.is_empty() || content.is_empty() {
            self.record_audit(9, AuditVerdict::Error, b"shell:write:bad-args");
            return copy_into(b"usage: write <path> <text>\n", out);
        }
        if bytes_eq(path, b"/etc/os-release") {
            self.record_audit(9, AuditVerdict::Denied, b"shell:write:protected");
            return copy_into(b"error: permission denied (immutable system file)\n", out);
        }
        let h = match self.fs.open(path, FS_O_RDWR | FS_O_CREATE | FS_O_TRUNC) {
            Ok(h) => h,
            Err(_) => {
                self.record_audit(9, AuditVerdict::Error, b"shell:write:open-failed");
                return copy_into(b"error: cannot open path for write\n", out);
            }
        };
        let mut payload = [0u8; SHELL_LINE_MAX];
        let mut plen = copy_into(content, &mut payload);
        if plen < payload.len() {
            payload[plen] = b'\n';
            plen += 1;
        }
        let written = match self.fs.write(h, 0, &payload[..plen]) {
            Ok(w) => w,
            Err(_) => {
                let _ = self.fs.close(h);
                self.record_audit(9, AuditVerdict::Error, b"shell:write:io-err");
                return copy_into(b"error: write failed\n", out);
            }
        };
        let _ = self.fs.close(h);
        self.record_audit(9, AuditVerdict::Allowed, b"shell:write");
        let mut pos = 0usize;
        pos += copy_into(b"wrote ", &mut out[pos..]);
        pos += dec_u64(written as u64, &mut out[pos..]);
        pos += copy_into(b" bytes to ", &mut out[pos..]);
        pos += copy_into(path, &mut out[pos..]);
        pos += copy_into(b"\n", &mut out[pos..]);
        pos
    }

    fn cmd_rm(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        if self
            .svc
            .mediate_endpoint(
                crate::svc_runtime::IpcOp::VfsDelete,
                false,
                true,
                &mut self.audit,
            )
            .is_err()
        {
            return copy_into(
                b"error: EACCES (svc-sh disabled by node role or policy)\n",
                out,
            );
        }
        let path = trim_ascii(arg);
        if path.is_empty() {
            self.record_audit(10, AuditVerdict::Error, b"shell:rm:no-arg");
            return copy_into(b"usage: rm <path>\n", out);
        }
        if bytes_eq(path, b"/etc/os-release") {
            self.record_audit(10, AuditVerdict::Denied, b"shell:rm:protected");
            return copy_into(b"error: permission denied (immutable system file)\n", out);
        }
        match self.fs.unlink(path) {
            Ok(()) => {
                self.record_audit(10, AuditVerdict::Allowed, b"shell:rm");
                let mut pos = 0usize;
                pos += copy_into(b"removed ", &mut out[pos..]);
                pos += copy_into(path, &mut out[pos..]);
                pos += copy_into(b"\n", &mut out[pos..]);
                pos
            }
            Err(_) => {
                self.record_audit(10, AuditVerdict::Error, b"shell:rm:not-found");
                copy_into(b"error: cannot remove path\n", out)
            }
        }
    }

    fn cmd_stat(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        let path = trim_ascii(arg);
        if path.is_empty() {
            self.record_audit(11, AuditVerdict::Error, b"shell:stat:no-arg");
            return copy_into(b"usage: stat <path>\n", out);
        }
        match self.fs.stat(path) {
            Ok(st) => {
                self.record_audit(11, AuditVerdict::Allowed, b"shell:stat");
                let mut pos = 0usize;
                pos += copy_into(b"path=", &mut out[pos..]);
                pos += copy_into(path, &mut out[pos..]);
                pos += copy_into(b" size=", &mut out[pos..]);
                pos += dec_u64(st.size, &mut out[pos..]);
                pos += copy_into(b" mode=0x", &mut out[pos..]);
                pos += dec_u64(st.mode as u64, &mut out[pos..]);
                pos += copy_into(b"\n", &mut out[pos..]);
                pos
            }
            Err(_) => {
                self.record_audit(11, AuditVerdict::Error, b"shell:stat:not-found");
                copy_into(b"error: path not found\n", out)
            }
        }
    }

    fn cmd_df(&mut self, out: &mut [u8]) -> usize {
        self.record_audit(28, AuditVerdict::Allowed, b"shell:df");
        let mut pos = 0usize;
        pos += copy_into(b"fs: magic=PRTSFS01 inodes=", &mut out[pos..]);
        pos += dec_u64(self.fs.inode_count() as u64, &mut out[pos..]);
        pos += copy_into(b"/", &mut out[pos..]);
        pos += dec_u64(SHELL_FS_INODES as u64, &mut out[pos..]);
        pos += copy_into(b" pool_bytes=", &mut out[pos..]);
        pos += dec_u64(self.fs.pool_used() as u64, &mut out[pos..]);
        pos += copy_into(b"/", &mut out[pos..]);
        pos += dec_u64(SHELL_FS_POOL as u64, &mut out[pos..]);
        pos += copy_into(b" part_sectors=", &mut out[pos..]);
        pos += dec_u64(SHELL_FS_PART_SECTORS as u64, &mut out[pos..]);
        pos += copy_into(b"\n", &mut out[pos..]);
        pos
    }

    fn cmd_sync(&mut self, out: &mut [u8]) -> usize {
        let proof = match durable_wal_proof(self.task_caps[4]) {
            Ok(p) => p,
            Err(_) => {
                self.record_audit(29, AuditVerdict::Denied, b"shell:sync:no-cap");
                return copy_into(b"error: permission denied (missing wal capability)\n", out);
            }
        };
        proof.consume();
        self.record_audit(29, AuditVerdict::Allowed, b"shell:sync");
        let mut user_files = 0usize;
        let mut user_bytes = 0usize;
        let mut i = 0usize;
        while i < SHELL_FS_INODES {
            if let Some((path, data)) = self.fs.inode_data(i) {
                if !is_default_system_file(path) {
                    user_files += 1;
                    user_bytes += data.len();
                }
            }
            i += 1;
        }
        let mut state_seal = [0u8; DURABLE_DIGEST_LEN];
        self.compute_state_seal(&mut state_seal);
        let mut hmac = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes_keyed(&self.seal_key, &state_seal, &mut hmac);
        let mut pos = 0usize;
        pos += copy_into(b"sync: ok files=", &mut out[pos..]);
        pos += dec_u64(user_files as u64, &mut out[pos..]);
        pos += copy_into(b" bytes=", &mut out[pos..]);
        pos += dec_u64(user_bytes as u64, &mut out[pos..]);
        pos += copy_into(b" seal=", &mut out[pos..]);
        pos += hex_bytes(&hmac[..8], &mut out[pos..]);
        pos += copy_into(b"\n", &mut out[pos..]);
        pos
    }

    fn cmd_sql(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        let q = trim_ascii(arg);
        if q.is_empty() {
            self.record_audit(31, AuditVerdict::Error, b"shell:sql:no-arg");
            return copy_into(
                b"usage: sql <SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|.tables|.schema>\n",
                out,
            );
        }
        let is_ro = crate::sql::SqlDb::is_readonly_query(q);
        let op = if is_ro {
            crate::svc_runtime::IpcOp::SqlQuery
        } else {
            crate::svc_runtime::IpcOp::SqlMutate
        };
        if self
            .svc
            .mediate_endpoint(op, false, true, &mut self.audit)
            .is_err()
        {
            return copy_into(
                b"error: EACCES (svc-sql disabled by node role or policy)\n",
                out,
            );
        }
        self.record_audit(31, AuditVerdict::Allowed, b"shell:sql");
        self.db.exec(q, out)
    }

    #[inline(never)]
    fn cmd_service(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        use crate::svc_runtime::{NodeRole, ServiceId, SERVICE_COUNT};

        let (sub, rest) = split_first_word(trim_ascii(arg));
        if sub.is_empty() || bytes_eq(sub, b"status") {
            self.record_audit(33, AuditVerdict::Allowed, b"shell:service:status");
            let mut pos = 0usize;
            pos += copy_into(b"service: role=", &mut out[pos..]);
            pos += copy_into(self.svc.role.as_bytes(), &mut out[pos..]);
            pos += copy_into(b" running=", &mut out[pos..]);
            pos += dec_u64(self.svc.running_count() as u64, &mut out[pos..]);
            pos += copy_into(b"/3 ipc_msgs=", &mut out[pos..]);
            pos += dec_u64(self.svc.ipc_total, &mut out[pos..]);
            pos += copy_into(b" svc_pcr10=", &mut out[pos..]);
            pos += hex_bytes(&self.svc.svc_pcr10[..8], &mut out[pos..]);
            pos += copy_into(b"...\n", &mut out[pos..]);
            let mut i = 0usize;
            while i < SERVICE_COUNT {
                let s = &self.svc.services[i];
                pos += copy_into(b"  ", &mut out[pos..]);
                pos += copy_into(s.id.name(), &mut out[pos..]);
                pos += copy_into(b" path=", &mut out[pos..]);
                pos += copy_into(s.id.elf_path(), &mut out[pos..]);
                pos += copy_into(b" state=", &mut out[pos..]);
                pos += copy_into(s.state.as_bytes(), &mut out[pos..]);
                pos += copy_into(b" va=", &mut out[pos..]);
                pos += dec_u64(s.policy.user_va_base, &mut out[pos..]);
                pos += copy_into(
                    if s.kpti_isolated {
                        b" kpti=isolated caps="
                    } else {
                        b" kpti=unmapped caps="
                    },
                    &mut out[pos..],
                );
                pos += dec_u64(s.policy.cap_mask, &mut out[pos..]);
                pos += copy_into(b" seccomp=", &mut out[pos..]);
                pos += dec_u64(s.policy.seccomp_allow_mask as u64, &mut out[pos..]);
                pos += copy_into(b" rot=", &mut out[pos..]);
                pos += dec_u64(s.rotations, &mut out[pos..]);
                pos += copy_into(b" restarts=", &mut out[pos..]);
                pos += dec_u64(s.restarts, &mut out[pos..]);
                pos += copy_into(b" reqs=", &mut out[pos..]);
                pos += dec_u64(s.requests_served, &mut out[pos..]);
                pos += copy_into(b" denials=", &mut out[pos..]);
                pos += dec_u64(s.policy_denials, &mut out[pos..]);
                pos += copy_into(b" sha256=", &mut out[pos..]);
                pos += hex_bytes(&s.elf_sha256[..8], &mut out[pos..]);
                pos += copy_into(b"...\n", &mut out[pos..]);
                i += 1;
            }
            return pos;
        }

        if bytes_eq(sub, b"role") {
            let role_tok = trim_ascii(rest);
            let Some(role) = NodeRole::from_bytes(role_tok) else {
                self.record_audit(33, AuditVerdict::Error, b"shell:service:bad-role");
                return copy_into(b"usage: service role <wfe|sql|shell|full>\n", out);
            };
            self.svc.set_role(role, &mut self.audit);
            // Unlink any disabled service ELF binaries from the VFS so they do not reside in RAM.
            let mut i = 0usize;
            while i < SERVICE_COUNT {
                let svc = ServiceId::ALL[i];
                if !role.allows(svc) {
                    let _ = self.fs.unlink(svc.elf_path());
                }
                i += 1;
            }
            let mut pos = 0usize;
            pos += copy_into(b"service: role=", &mut out[pos..]);
            pos += copy_into(role.as_bytes(), &mut out[pos..]);
            pos += copy_into(b" running=", &mut out[pos..]);
            pos += dec_u64(self.svc.running_count() as u64, &mut out[pos..]);
            pos += copy_into(b"/3 svc_pcr10=", &mut out[pos..]);
            pos += hex_bytes(&self.svc.svc_pcr10[..8], &mut out[pos..]);
            pos += copy_into(b"...\n", &mut out[pos..]);
            return pos;
        }

        if bytes_eq(sub, b"rotate") || bytes_eq(sub, b"morph") {
            let (svc_tok, seed_tok) = split_first_word(trim_ascii(rest));
            let Some(svc) = ServiceId::from_bytes(svc_tok) else {
                self.record_audit(33, AuditVerdict::Error, b"shell:service:bad-name");
                return copy_into(
                    b"usage: service rotate <svc-http|svc-sql|svc-sh> [seed]\n",
                    out,
                );
            };
            let seed = parse_u64_ascii(trim_ascii(seed_tok)).unwrap_or_else(|| {
                let mut entropy_buf = [0u8; 48];
                entropy_buf[..32].copy_from_slice(&self.svc.svc_pcr10);
                entropy_buf[32..40].copy_from_slice(&self.cmd_seq.to_le_bytes());
                entropy_buf[40..48].copy_from_slice(&self.svc.base_seed.to_le_bytes());
                let mut dig = [0u8; DURABLE_DIGEST_LEN];
                seal_bytes_keyed(&self.seal_key, &entropy_buf, &mut dig);
                u64::from_le_bytes([
                    dig[0], dig[1], dig[2], dig[3], dig[4], dig[5], dig[6], dig[7],
                ])
            });
            let Ok(new_dig) = self.svc.rotate_service(svc, seed, &mut self.audit) else {
                return copy_into(
                    b"error: EACCES (service disabled by current node role)\n",
                    out,
                );
            };
            // If materialized in VFS, refresh the on-VFS ELF binary and IMA digest in place.
            if self.fs.stat(svc.elf_path()).is_ok() {
                let _ = self.fs.unlink(svc.elf_path());
                let slot = &self.svc.services[svc.index()];
                let _ = self.fs.seed_file(
                    svc.elf_path(),
                    &slot.elf_image[..slot.elf_len],
                    256,
                    1,
                );
                let _ = self.enroll_ima_digest(svc.elf_path(), &new_dig);
            }
            let slot = &self.svc.services[svc.index()];
            let mut pos = 0usize;
            pos += copy_into(b"service: rotated ", &mut out[pos..]);
            pos += copy_into(svc.name(), &mut out[pos..]);
            pos += copy_into(b" rot=", &mut out[pos..]);
            pos += dec_u64(slot.rotations, &mut out[pos..]);
            pos += copy_into(b" seed=", &mut out[pos..]);
            pos += dec_u64(slot.variant_seed, &mut out[pos..]);
            pos += copy_into(b" sha256=", &mut out[pos..]);
            pos += hex_bytes(&new_dig[..8], &mut out[pos..]);
            pos += copy_into(b"... svc_pcr10=", &mut out[pos..]);
            pos += hex_bytes(&self.svc.svc_pcr10[..8], &mut out[pos..]);
            pos += copy_into(b"...\n", &mut out[pos..]);
            return pos;
        }

        if bytes_eq(sub, b"crash") || bytes_eq(sub, b"fault") {
            let Some(svc) = ServiceId::from_bytes(trim_ascii(rest)) else {
                return copy_into(b"usage: service crash <svc-http|svc-sql|svc-sh>\n", out);
            };
            if self.svc.simulate_crash(svc, &mut self.audit).is_err() {
                return copy_into(b"error: service unloaded for current role\n", out);
            }
            let mut pos = 0usize;
            pos += copy_into(b"service: faulted ", &mut out[pos..]);
            pos += copy_into(svc.name(), &mut out[pos..]);
            pos += copy_into(b" (supervisor will auto-restart)\n", &mut out[pos..]);
            return pos;
        }

        if bytes_eq(sub, b"restart") {
            let Some(svc) = ServiceId::from_bytes(trim_ascii(rest)) else {
                return copy_into(b"usage: service restart <svc-http|svc-sql|svc-sh>\n", out);
            };
            if self.svc.ensure_running(svc, &mut self.audit).is_err() {
                return copy_into(b"error: service unloaded for current role\n", out);
            }
            let mut pos = 0usize;
            pos += copy_into(b"service: restarted ", &mut out[pos..]);
            pos += copy_into(svc.name(), &mut out[pos..]);
            pos += copy_into(b" state=running restarts=", &mut out[pos..]);
            pos += dec_u64(self.svc.services[svc.index()].restarts, &mut out[pos..]);
            pos += copy_into(b"\n", &mut out[pos..]);
            return pos;
        }

        copy_into(
            b"usage: service [status | role <wfe|sql|shell|full> | rotate <name> [seed] | crash <name> | restart <name>]\n",
            out,
        )
    }

    fn cmd_session(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        let (sub, rest) = split_first_word(trim_ascii(arg));
        if sub.is_empty() || bytes_eq(sub, b"status") {
            self.record_audit(32, AuditVerdict::Allowed, b"shell:session:status");
            let mut pos = 0usize;
            pos += copy_into(b"sessions: active=", &mut out[pos..]);
            pos += dec_u64(self.active_session_count() as u64, &mut out[pos..]);
            pos += copy_into(b"/", &mut out[pos..]);
            pos += dec_u64(SHELL_MAX_SESSIONS as u64, &mut out[pos..]);
            pos += copy_into(b"\n", &mut out[pos..]);
            let mut i = 0usize;
            while i < SHELL_MAX_SESSIONS {
                if self.sessions[i].active {
                    pos += copy_into(b"  slot=", &mut out[pos..]);
                    pos += dec_u64(i as u64, &mut out[pos..]);
                    pos += copy_into(b" user=", &mut out[pos..]);
                    pos += copy_into(self.sessions[i].user_bytes(), &mut out[pos..]);
                    pos += copy_into(b" reqs=", &mut out[pos..]);
                    pos += dec_u64(self.sessions[i].requests as u64, &mut out[pos..]);
                    pos += copy_into(b" sid=", &mut out[pos..]);
                    pos += copy_into(&self.sessions[i].token_hex[..8], &mut out[pos..]);
                    pos += copy_into(b"...\n", &mut out[pos..]);
                }
                i += 1;
            }
            return pos;
        }
        if bytes_eq(sub, b"create") || bytes_eq(sub, b"login") {
            let (user, nonce) = split_first_word(rest);
            if user.is_empty() {
                self.record_audit(32, AuditVerdict::Error, b"shell:session:no-user");
                return copy_into(b"usage: session create <user> [nonce]\n", out);
            }
            let sid = self.create_session(user, nonce);
            let mut pos = 0usize;
            pos += copy_into(b"session: created user=", &mut out[pos..]);
            pos += copy_into(&user[..user.len().min(16)], &mut out[pos..]);
            pos += copy_into(b" sid=", &mut out[pos..]);
            pos += copy_into(&sid, &mut out[pos..]);
            pos += copy_into(b"\n", &mut out[pos..]);
            return pos;
        }
        if bytes_eq(sub, b"revoke") || bytes_eq(sub, b"logout") {
            if self.revoke_session(rest) {
                return copy_into(b"session: revoked\n", out);
            }
            self.record_audit(32, AuditVerdict::Error, b"shell:session:not-found");
            return copy_into(b"error: session not found\n", out);
        }
        copy_into(b"usage: session [status | create <user> [nonce] | revoke <sid>]\n", out)
    }

    fn cmd_audit(&self, out: &mut [u8]) -> usize {
        let mut pos = 0usize;
        pos += copy_into(b"audit_events=", &mut out[pos..]);
        pos += dec_u64(self.audit.len() as u64, &mut out[pos..]);
        pos += copy_into(b" watermark=", &mut out[pos..]);
        pos += dec_u64(self.audit.high_watermark(), &mut out[pos..]);
        pos += copy_into(b"\n", &mut out[pos..]);
        for ev in self.audit.iter() {
            pos += copy_into(b"  id=", &mut out[pos..]);
            pos += dec_u64(ev.event_id, &mut out[pos..]);
            pos += copy_into(b" pid=", &mut out[pos..]);
            pos += dec_u64(ev.task_id as u64, &mut out[pos..]);
            pos += copy_into(b" verdict=", &mut out[pos..]);
            let vstr: &[u8] = match ev.verdict {
                AuditVerdict::Allowed => b"Allowed",
                AuditVerdict::Denied => b"Denied",
                AuditVerdict::Error => b"Error",
            };
            pos += copy_into(vstr, &mut out[pos..]);
            pos += copy_into(b" msg=", &mut out[pos..]);
            let mut mlen = 0usize;
            while mlen < ev.message.len() && ev.message[mlen] != 0 {
                mlen += 1;
            }
            pos += copy_into(&ev.message[..mlen], &mut out[pos..]);
            pos += copy_into(b"\n", &mut out[pos..]);
        }
        pos
    }

    #[inline(never)]
    fn cmd_exec(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        let (path, arg_str) = split_first_word(trim_ascii(arg));
        if path.is_empty() {
            self.record_audit(22, AuditVerdict::Error, b"shell:exec:no-arg");
            return copy_into(b"usage: exec <path> [arg]\n", out);
        }

        // Gate user ELF execution through `svc-sh` (`IpcOp::UserElfExec`).
        if self
            .svc
            .mediate_endpoint(
                crate::svc_runtime::IpcOp::UserElfExec,
                false,
                true,
                &mut self.audit,
            )
            .is_err()
        {
            return copy_into(
                b"error: EACCES (svc-sh disabled by node role or policy)\n",
                out,
            );
        }

        // Materialize built-in user-space ELF64 programs (/bin/fib, /bin/sum) on demand.
        if (bytes_eq(path, b"/bin/fib") || bytes_eq(path, b"/bin/sum"))
            && self.fs.stat(path).is_err()
        {
            self.install_user_bins();
        }
        // Materialize role-enabled Ring-3 service ELF64 binaries (/sbin/svc-*) on demand.
        if let Some(svc) = crate::svc_runtime::ServiceId::from_bytes(path) {
            if self.svc.role.allows(svc) && self.fs.stat(svc.elf_path()).is_err() {
                let slot = &self.svc.services[svc.index()];
                if slot.elf_len > 0 {
                    let dig = slot.elf_sha256;
                    let _ = self.fs.seed_file(
                        svc.elf_path(),
                        &slot.elf_image[..slot.elf_len],
                        256,
                        1,
                    );
                    let _ = self.enroll_ima_digest(svc.elf_path(), &dig);
                }
            }
        }

        let h = match self.fs.open(path, FS_O_RDONLY) {
            Ok(h) => h,
            Err(_) => {
                self.record_audit(22, AuditVerdict::Error, b"shell:exec:not-found");
                return copy_into(b"error: executable not found\n", out);
            }
        };
        let mut img = [0u8; 512];
        let n = self.fs.read(h, 0, &mut img).unwrap_or(0);
        let _ = self.fs.close(h);

        // 0. Blue-Team Pre-Parse Gate: Verify IMA SHA-256 binary integrity in constant time
        // BEFORE exposing the ELF64 parser to untrusted file bytes.
        let mut bin_dig = [0u8; DURABLE_DIGEST_LEN];
        if !self.verify_ima_digest(path, &img[..n], &mut bin_dig) {
            self.record_audit(22, AuditVerdict::Denied, b"shell:exec:ima-denied");
            return copy_into(b"error: EPERM (IMA signature verification failed)\n", out);
        }

        // 1. Parse and verify ELF64 header and PT_LOAD program header.
        let hdr = match Elf64Impl::parse_header(&img[..n]) {
            Ok(hdr) => hdr,
            Err(_) => {
                self.record_audit(22, AuditVerdict::Denied, b"shell:exec:bad-elf");
                return copy_into(b"error: invalid elf64 executable\n", out);
            }
        };
        let mut phdrs = [ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }; ELF_MAX_PHDRS];
        let ph_count = match Elf64Impl::load_phdrs(&img[..n], &hdr, &mut phdrs) {
            Ok(c) if c >= 1 && phdrs[0].ptype == ELF_PT_LOAD => c,
            _ => {
                self.record_audit(22, AuditVerdict::Denied, b"shell:exec:bad-phdr");
                return copy_into(b"error: invalid elf64 phdrs\n", out);
            }
        };
        let _ = ph_count;
        let code_off = phdrs[0].offset as usize;
        let code_len = phdrs[0].filesz as usize;
        if code_len == 0
            || (code_len % 8) != 0
            || code_off.saturating_add(code_len) > n
            || (code_len / 8) > BPF_MAX_INSTRUCTIONS
        {
            self.record_audit(22, AuditVerdict::Denied, b"shell:exec:bad-code");
            return copy_into(b"error: invalid code segment\n", out);
        }

        // 2. Construct and validate KPTI isolated user page table view.
        const KERNEL_SECRET_VA: u64 = 0xFFFF_8000_0000_0000;
        let user_code_va = hdr.entry & PAGE_MASK;
        let mut kernel_l4: PageTable<8> = PageTable::new();
        let _ = kernel_l4.map(KERNEL_SECRET_VA, PTE_PRESENT | PTE_WRITABLE);
        let _ = kernel_l4.map(KPTI_TRAMPOLINE_VIRT, PTE_PRESENT | PTE_USER);
        let _ = kernel_l4.map(user_code_va, PTE_PRESENT | PTE_USER);
        let secrets = [KERNEL_SECRET_VA];
        let user_l4 = KptiImpl::<8>::build_user_view(&kernel_l4, &secrets);
        if KptiImpl::<8>::validate_user_view(&user_l4, &kernel_l4, &secrets).is_err()
            || !user_l4.is_mapped(user_code_va)
            || user_l4.is_mapped(KERNEL_SECRET_VA)
        {
            self.record_audit(22, AuditVerdict::Denied, b"shell:exec:kpti-violation");
            return copy_into(b"error: kpti user page table validation failed\n", out);
        }

        // 3. Extend TCG TPM 2.0 PCR-10 (IMA runtime binary measurement register).
        let mut tpm_cmd = [0u8; TPM_MAX_CMD_LEN];
        let tpm_len = match TpmImpl::build_pcr_extend(&mut tpm_cmd, 10, TPM_ALG_SHA256, &bin_dig) {
            Ok(l) => l,
            Err(_) => {
                self.record_audit(22, AuditVerdict::Denied, b"shell:exec:tpm-error");
                return copy_into(b"error: tpm pcr10 extend failed\n", out);
            }
        };
        if tpm_len != TPM_MAX_CMD_LEN || tpm_cmd[0] != 0x80 || tpm_cmd[1] != 0x02 {
            self.record_audit(22, AuditVerdict::Denied, b"shell:exec:tpm-hdr");
            return copy_into(b"error: tpm header validation failed\n", out);
        }
        let mut pcr_concat = [0u8; DURABLE_DIGEST_LEN * 2];
        pcr_concat[..DURABLE_DIGEST_LEN].copy_from_slice(&self.ima_pcr10);
        pcr_concat[DURABLE_DIGEST_LEN..].copy_from_slice(&bin_dig);
        let mut next_pcr10 = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes(&pcr_concat, &mut next_pcr10);
        self.ima_pcr10 = next_pcr10;
        self.ima_measurements = self.ima_measurements.wrapping_add(1);

        // 4. Decode eBPF instruction stream from PT_LOAD segment.
        let insn_count = code_len / 8;
        let mut prog = [BpfInstr::new(0, 0, 0, 0, 0); 64];
        if insn_count > prog.len() {
            self.record_audit(22, AuditVerdict::Error, b"shell:exec:too-large");
            return copy_into(b"error: program exceeds shell exec slot limit\n", out);
        }
        let mut idx = 0usize;
        while idx < insn_count {
            let base = code_off + idx * 8;
            let op = img[base];
            let regs = img[base + 1];
            let off = i16::from_le_bytes([img[base + 2], img[base + 3]]);
            let imm = i32::from_le_bytes([
                img[base + 4],
                img[base + 5],
                img[base + 6],
                img[base + 7],
            ]);
            prog[idx] = BpfInstr {
                opcode: op,
                regs,
                offset: off,
                imm,
            };
            idx += 1;
        }
        if !arg_str.is_empty() {
            if let Some(arg_val) = parse_u32_ascii(arg_str) {
                // Only patch prog[0].imm when prog[0] is `mov64 r_dst, imm` (argument loader).
                if prog[0].opcode == (bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_MOV) {
                    prog[0].imm = arg_val as i32;
                }
            }
        }

        // 5. Spawn ephemeral user process in RoundRobin, plant StackCanary SSP at top of
        //    sandbox stack frame, execute in eBPF VM, verify canary, and reap via SYS_EXIT.
        let exec_pid = self.next_pid;
        let spawned = self.sched.enqueue_with_priority(exec_pid, 5);
        if spawned {
            self.next_pid = self.next_pid.wrapping_add(1);
        }
        let canary_entropy = (self.cmd_seq
            ^ ((exec_pid as u64) << 32)
            ^ u64::from_le_bytes([
                bin_dig[0], bin_dig[1], bin_dig[2], bin_dig[3], bin_dig[4], bin_dig[5], bin_dig[6],
                bin_dig[7],
            ]))
            | 1;
        let canary_seed = canary_entropy.to_le_bytes();
        let canary: CanaryToken = match StackCanaryImpl::mint(&canary_seed) {
            Ok(c) => c,
            Err(_) => {
                self.record_audit(22, AuditVerdict::Denied, b"shell:exec:canary-seed");
                return copy_into(b"error: stack canary mint failed\n", out);
            }
        };
        let mut bpf_ctx = BpfContext::new();
        let frame_canary = CanaryToken {
            bytes: core::hint::black_box(canary.bytes),
        };
        let redzone_off = BPF_STACK_SIZE - STACK_CANARY_LEN;

        let ret_val = match EBpfImpl::run(&prog[..insn_count], &mut bpf_ctx) {
            Ok(v) => v,
            Err(_) => {
                if spawned {
                    let _ = self.sched.exit(exec_pid, 1);
                    let _ = self.sched.reap(exec_pid);
                }
                self.record_audit(22, AuditVerdict::Denied, b"shell:exec:ebpf-trap");
                return copy_into(b"error: user program trapped in sandbox\n", out);
            }
        };
        let mut redzone_dirty = 0u8;
        let mut r = redzone_off;
        while r < BPF_STACK_SIZE {
            redzone_dirty |= bpf_ctx.stack[r];
            r += 1;
        }
        if StackCanaryImpl::verify(&canary, &frame_canary).is_err() || redzone_dirty != 0 {
            if spawned {
                let _ = self.sched.exit(exec_pid, 134);
                let _ = self.sched.reap(exec_pid);
            }
            self.record_audit(22, AuditVerdict::Denied, b"shell:exec:stack-smashed");
            return copy_into(b"error: stack smashing detected in sandbox\n", out);
        }

        let _ = dispatch_with_cap(SYS_EXIT, 0, ret_val, 0, 0, 0, 0, 0);
        if spawned {
            let _ = self.sched.exit(exec_pid, ret_val as i32);
            let _ = self.sched.reap(exec_pid);
        }

        self.record_audit(22, AuditVerdict::Allowed, b"shell:exec");
        let mut pos = 0usize;
        pos += copy_into(b"exec: path=", &mut out[pos..]);
        pos += copy_into(path, &mut out[pos..]);
        pos += copy_into(b" entry=", &mut out[pos..]);
        pos += dec_u64(hdr.entry, &mut out[pos..]);
        pos += copy_into(b" kpti=isolated insns=", &mut out[pos..]);
        pos += dec_u64(insn_count as u64, &mut out[pos..]);
        pos += copy_into(b" ret=", &mut out[pos..]);
        pos += dec_u64(ret_val, &mut out[pos..]);
        pos += copy_into(b"\n", &mut out[pos..]);
        pos
    }

    fn cmd_ima(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        let (sub, rest) = split_first_word(trim_ascii(arg));
        if sub.is_empty() || bytes_eq(sub, b"status") {
            self.record_audit(24, AuditVerdict::Allowed, b"shell:ima:status");
            let mut pos = 0usize;
            pos += copy_into(b"ima: trusted=", &mut out[pos..]);
            pos += dec_u64(self.ima_count as u64, &mut out[pos..]);
            pos += copy_into(b" measurements=", &mut out[pos..]);
            pos += dec_u64(self.ima_measurements, &mut out[pos..]);
            pos += copy_into(b" pcr10=", &mut out[pos..]);
            pos += hex_bytes(&self.ima_pcr10, &mut out[pos..]);
            pos += copy_into(b"\n", &mut out[pos..]);
            return pos;
        }
        if bytes_eq(sub, b"enroll") {
            let path = trim_ascii(rest);
            if path.is_empty() {
                self.record_audit(24, AuditVerdict::Error, b"shell:ima:no-path");
                return copy_into(b"usage: ima enroll <path>\n", out);
            }
            let h = match self.fs.open(path, FS_O_RDONLY) {
                Ok(h) => h,
                Err(_) => {
                    self.record_audit(24, AuditVerdict::Error, b"shell:ima:not-found");
                    return copy_into(b"error: file not found\n", out);
                }
            };
            let mut img = [0u8; 512];
            let n = self.fs.read(h, 0, &mut img).unwrap_or(0);
            let _ = self.fs.close(h);
            let mut dig = [0u8; DURABLE_DIGEST_LEN];
            seal_bytes(&img[..n], &mut dig);
            if !self.enroll_ima_digest(path, &dig) {
                self.record_audit(24, AuditVerdict::Error, b"shell:ima:full");
                return copy_into(b"error: ima table full or path too long\n", out);
            }
            self.record_audit(24, AuditVerdict::Allowed, b"shell:ima:enroll");
            let mut pos = 0usize;
            pos += copy_into(b"ima enrolled path=", &mut out[pos..]);
            pos += copy_into(path, &mut out[pos..]);
            pos += copy_into(b" sha256=", &mut out[pos..]);
            pos += hex_bytes(&dig, &mut out[pos..]);
            pos += copy_into(b"\n", &mut out[pos..]);
            return pos;
        }
        self.record_audit(24, AuditVerdict::Error, b"shell:ima:bad-arg");
        copy_into(b"usage: ima [status | enroll <path>]\n", out)
    }

    fn cmd_fw(&mut self, arg: &[u8], out: &mut [u8]) -> usize {
        let (sub, rest) = split_first_word(trim_ascii(arg));
        if sub.is_empty() || bytes_eq(sub, b"status") {
            self.record_audit(25, AuditVerdict::Allowed, b"shell:fw:status");
            let rules = self.fw.as_slice();
            let mut pos = 0usize;
            pos += copy_into(b"fw: rules=", &mut out[pos..]);
            pos += dec_u64(rules.len() as u64, &mut out[pos..]);
            pos += copy_into(b" default=allow\n", &mut out[pos..]);
            let mut i = 0usize;
            while i < rules.len() {
                let r = &rules[i];
                pos += copy_into(b"  rule[", &mut out[pos..]);
                pos += dec_u64(i as u64, &mut out[pos..]);
                pos += copy_into(b"] src=", &mut out[pos..]);
                pos += fmt_ipv4(r.src_ip, &mut out[pos..]);
                pos += copy_into(b"/", &mut out[pos..]);
                pos += dec_u64(r.src_mask as u64, &mut out[pos..]);
                pos += copy_into(
                    match r.action {
                        FilterAction::Accept => b" action=allow\n",
                        FilterAction::Drop => b" action=drop\n",
                        FilterAction::Reject => b" action=reject\n",
                    },
                    &mut out[pos..],
                );
                i += 1;
            }
            return pos;
        }
        if bytes_eq(sub, b"clear") {
            self.fw.clear();
            self.record_audit(25, AuditVerdict::Allowed, b"shell:fw:clear");
            return copy_into(b"fw: cleared all rules\n", out);
        }
        let action = if bytes_eq(sub, b"block") || bytes_eq(sub, b"drop") {
            Some(FilterAction::Drop)
        } else if bytes_eq(sub, b"allow") {
            Some(FilterAction::Accept)
        } else {
            None
        };
        if let Some(act) = action {
            let cidr_str = trim_ascii(rest);
            let (ip, prefix) = match parse_ipv4_cidr_ascii(cidr_str) {
                Some(v) => v,
                None => {
                    self.record_audit(25, AuditVerdict::Error, b"shell:fw:bad-cidr");
                    return copy_into(b"error: invalid IPv4 CIDR (expected A.B.C.D[/prefix])\n", out);
                }
            };
            let rule = FilterRule {
                src_ip: ip,
                src_mask: prefix,
                dst_ip: [0, 0, 0, 0],
                dst_mask: 0,
                proto: FW_PROTO_ANY,
                src_port_start: FW_PORT_ANY,
                src_port_end: FW_PORT_ANY,
                dst_port_start: FW_PORT_ANY,
                dst_port_end: FW_PORT_ANY,
                action: act,
            };
            if self.fw.insert(rule).is_err() {
                self.record_audit(25, AuditVerdict::Error, b"shell:fw:full");
                return copy_into(b"error: firewall rule table full\n", out);
            }
            self.record_audit(25, AuditVerdict::Allowed, b"shell:fw:add");
            let mut pos = 0usize;
            pos += copy_into(
                match act {
                    FilterAction::Drop => b"fw: blocked src=",
                    _ => b"fw: allowed src=",
                },
                &mut out[pos..],
            );
            pos += fmt_ipv4(ip, &mut out[pos..]);
            pos += copy_into(b"/", &mut out[pos..]);
            pos += dec_u64(prefix as u64, &mut out[pos..]);
            pos += copy_into(b"\n", &mut out[pos..]);
            return pos;
        }
        self.record_audit(25, AuditVerdict::Error, b"shell:fw:bad-arg");
        copy_into(b"usage: fw [status | block <ip/prefix> | allow <ip/prefix> | clear]\n", out)
    }

    #[inline(never)]
    fn cmd_seal(&mut self, out: &mut [u8]) -> usize {
        self.record_audit(23, AuditVerdict::Allowed, b"shell:seal");
        let mut dig = [0u8; DURABLE_DIGEST_LEN];
        self.compute_state_seal(&mut dig);
        let mut pos = 0usize;
        pos += copy_into(b"seal: sha256=", &mut out[pos..]);
        pos += hex_bytes(&dig, &mut out[pos..]);
        pos += copy_into(b" files=", &mut out[pos..]);
        pos += dec_u64(self.fs.inode_count() as u64, &mut out[pos..]);
        pos += copy_into(b" tasks=", &mut out[pos..]);
        pos += dec_u64(self.active_task_count() as u64, &mut out[pos..]);
        pos += copy_into(b" audit=", &mut out[pos..]);
        pos += dec_u64(self.audit.high_watermark(), &mut out[pos..]);
        pos += copy_into(b"\n", &mut out[pos..]);
        pos
    }

    /// Format the canonical remote attestation payload (`v=1 boots=<boots> pcr10=<hex64> svc_pcr10=<hex16> role=<role> ima=<count> seal=<hex64> nonce=<nonce>`)
    /// into `out` and return the byte length.
    fn format_attestation_body(&self, boots: u64, nonce: &[u8], out: &mut [u8]) -> usize {
        let mut state_seal = [0u8; DURABLE_DIGEST_LEN];
        self.compute_state_seal(&mut state_seal);
        let clean_nonce = sanitize_nonce(nonce);
        let mut pos = 0usize;
        pos += copy_into(b"v=1 boots=", &mut out[pos..]);
        pos += dec_u64(boots, &mut out[pos..]);
        pos += copy_into(b" pcr10=", &mut out[pos..]);
        pos += hex_bytes(&self.ima_pcr10, &mut out[pos..]);
        pos += copy_into(b" svc_pcr10=", &mut out[pos..]);
        pos += hex_bytes(&self.svc.svc_pcr10[..8], &mut out[pos..]);
        pos += copy_into(b" role=", &mut out[pos..]);
        pos += copy_into(self.svc.role.as_bytes(), &mut out[pos..]);
        pos += copy_into(b" ima=", &mut out[pos..]);
        pos += dec_u64(self.ima_measurements, &mut out[pos..]);
        pos += copy_into(b" seal=", &mut out[pos..]);
        pos += hex_bytes(&state_seal, &mut out[pos..]);
        pos += copy_into(b" nonce=", &mut out[pos..]);
        pos += copy_into(clean_nonce, &mut out[pos..]);
        pos
    }

    /// Compute the 32-byte `HMAC-SHA256` remote attestation signature over the
    /// live kernel state (`boots`, `ima_pcr10`, `ima_measurements`, `state_seal`,
    /// and caller-supplied challenge `nonce`) using `self.attest_key`.
    pub fn compute_attestation_mac(
        &self,
        boots: u64,
        nonce: &[u8],
        mac_out: &mut [u8; DURABLE_DIGEST_LEN],
    ) {
        let mut body = [0u8; 320];
        let blen = self.format_attestation_body(boots, nonce, &mut body);
        seal_bytes_keyed(&self.attest_key, &body[..blen], mac_out);
    }

    /// Verify in constant time that `expected_mac` is a valid `HMAC-SHA256`
    /// remote attestation quote signature for the current live kernel state
    /// (`boots`, `ima_pcr10`, `ima_measurements`, `state_seal`, and `nonce`).
    pub fn verify_attestation_mac(
        &self,
        boots: u64,
        nonce: &[u8],
        expected_mac: &[u8; DURABLE_DIGEST_LEN],
    ) -> bool {
        let mut body = [0u8; 320];
        let blen = self.format_attestation_body(boots, nonce, &mut body);
        seal_matches_keyed(&self.attest_key, &body[..blen], expected_mac)
    }

    /// Emit an `HMAC-SHA256` remote attestation quote line (`attest: ... hmac=<hex64>\n`)
    /// into `out` and return the byte length.
    #[inline(never)]
    pub fn cmd_attest(&mut self, boots: u64, arg: &[u8], out: &mut [u8]) -> usize {
        self.record_audit(26, AuditVerdict::Allowed, b"shell:attest");
        let nonce = trim_ascii(arg);
        let mut body = [0u8; 320];
        let blen = self.format_attestation_body(boots, nonce, &mut body);
        let mut mac = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes_keyed(&self.attest_key, &body[..blen], &mut mac);
        let mut pos = 0usize;
        pos += copy_into(b"attest: ", &mut out[pos..]);
        pos += copy_into(&body[..blen], &mut out[pos..]);
        pos += copy_into(b" hmac=", &mut out[pos..]);
        pos += hex_bytes(&mac, &mut out[pos..]);
        pos += copy_into(b"\n", &mut out[pos..]);
        pos
    }
}

impl Default for OsShell {
    fn default() -> Self {
        Self::new()
    }
}

fn is_default_system_file(path: &[u8]) -> bool {
    bytes_eq(path, b"/etc/hostname")
        || bytes_eq(path, b"/etc/os-release")
        || bytes_eq(path, b"/etc/motd")
        || bytes_eq(path, b"/proc/net")
        || bytes_eq(path, b"/bin/fib")
        || bytes_eq(path, b"/bin/sum")
        || bytes_eq(path, b"/sbin/svc-http")
        || bytes_eq(path, b"/sbin/svc-sql")
        || bytes_eq(path, b"/sbin/svc-sh")
}

fn serialize_wal_for_seal<const C: usize>(wal: &WalImpl<C>, out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    wal.replay(&mut |lsn: u64, payload: &[u8]| {
        pos += dec_u64(lsn, &mut out[pos..]);
        pos += copy_into(b":", &mut out[pos..]);
        pos += copy_into(payload, &mut out[pos..]);
        pos += copy_into(b";", &mut out[pos..]);
    });
    pos
}

fn compute_wal_seal<const C: usize>(
    key: &[u8; DURABLE_DIGEST_LEN],
    wal: &WalImpl<C>,
    seal_out: &mut [u8; DURABLE_DIGEST_LEN],
) {
    let mut scratch = [0u8; 1024];
    let len = serialize_wal_for_seal(wal, &mut scratch);
    seal_bytes_keyed(key, &scratch[..len], seal_out);
}

fn compute_fs_partition_seal(
    key: &[u8; DURABLE_DIGEST_LEN],
    sectors: &[[u8; 512]; SHELL_FS_PART_SECTORS],
    seal_out: &mut [u8; DURABLE_DIGEST_LEN],
) {
    let mut chain = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(key, &sectors[0][0..24], &mut chain);
    let mut buf = [0u8; DURABLE_DIGEST_LEN + 512];
    let mut sec = 1usize;
    while sec < SHELL_FS_PART_SECTORS {
        let mut i = 0usize;
        while i < DURABLE_DIGEST_LEN {
            buf[i] = chain[i];
            i += 1;
        }
        let mut j = 0usize;
        while j < 512 {
            buf[DURABLE_DIGEST_LEN + j] = sectors[sec][j];
            j += 1;
        }
        seal_bytes_keyed(key, &buf, &mut chain);
        sec += 1;
    }
    *seal_out = chain;
}

fn verify_fs_partition_seal(
    key: &[u8; DURABLE_DIGEST_LEN],
    sectors: &[[u8; 512]; SHELL_FS_PART_SECTORS],
    expected_seal: &[u8; DURABLE_DIGEST_LEN],
) -> bool {
    let mut chain = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(key, &sectors[0][0..24], &mut chain);
    let mut buf = [0u8; DURABLE_DIGEST_LEN + 512];
    let mut sec = 1usize;
    while sec + 1 < SHELL_FS_PART_SECTORS {
        let mut i = 0usize;
        while i < DURABLE_DIGEST_LEN {
            buf[i] = chain[i];
            i += 1;
        }
        let mut j = 0usize;
        while j < 512 {
            buf[DURABLE_DIGEST_LEN + j] = sectors[sec][j];
            j += 1;
        }
        seal_bytes_keyed(key, &buf, &mut chain);
        sec += 1;
    }
    let mut i = 0usize;
    while i < DURABLE_DIGEST_LEN {
        buf[i] = chain[i];
        i += 1;
    }
    let mut j = 0usize;
    while j < 512 {
        buf[DURABLE_DIGEST_LEN + j] = sectors[SHELL_FS_PART_SECTORS - 1][j];
        j += 1;
    }
    seal_matches_keyed(key, &buf, expected_seal)
}

fn build_elf_ebpf_binary(insns: &[BpfInstr], out: &mut [u8]) -> usize {
    let header_len = ELF_EHDR_LEN + ELF_PHDR_LEN;
    let code_len = insns.len() * 8;
    let total = header_len + code_len;
    if out.len() < total {
        return 0;
    }
    let mut i = 0usize;
    while i < total {
        out[i] = 0;
        i += 1;
    }
    let entry: u64 = 0x401000;
    out[0] = ELF_MAGIC[0];
    out[1] = ELF_MAGIC[1];
    out[2] = ELF_MAGIC[2];
    out[3] = ELF_MAGIC[3];
    out[4] = ELF_CLASS64;
    out[5] = ELF_DATA_LE;
    out[6] = 1; // EV_CURRENT
    out[16..18].copy_from_slice(&ELF_ET_EXEC.to_le_bytes());
    out[18..20].copy_from_slice(&ELF_EM_X86_64.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[24..32].copy_from_slice(&entry.to_le_bytes());
    out[32..40].copy_from_slice(&(ELF_EHDR_LEN as u64).to_le_bytes());
    out[52..54].copy_from_slice(&(ELF_EHDR_LEN as u16).to_le_bytes());
    out[54..56].copy_from_slice(&(ELF_PHDR_LEN as u16).to_le_bytes());
    out[56..58].copy_from_slice(&1u16.to_le_bytes());

    let p = &mut out[ELF_EHDR_LEN..header_len];
    p[0..4].copy_from_slice(&ELF_PT_LOAD.to_le_bytes());
    p[4..8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    p[8..16].copy_from_slice(&(header_len as u64).to_le_bytes());
    p[16..24].copy_from_slice(&entry.to_le_bytes());
    p[24..32].copy_from_slice(&entry.to_le_bytes());
    p[32..40].copy_from_slice(&(code_len as u64).to_le_bytes());
    p[40..48].copy_from_slice(&(code_len as u64).to_le_bytes());
    p[48..56].copy_from_slice(&0x1000u64.to_le_bytes());

    let mut k = 0usize;
    while k < insns.len() {
        let off = header_len + k * 8;
        let insn = insns[k];
        out[off] = insn.opcode;
        out[off + 1] = insn.regs;
        let ob = insn.offset.to_le_bytes();
        out[off + 2] = ob[0];
        out[off + 3] = ob[1];
        let ib = insn.imm.to_le_bytes();
        out[off + 4] = ib[0];
        out[off + 5] = ib[1];
        out[off + 6] = ib[2];
        out[off + 7] = ib[3];
        k += 1;
    }
    total
}

fn build_fib_elf(out: &mut [u8]) -> usize {
    let mov64_imm = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_MOV;
    let mov64_reg = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_MOV | bpf_op::BPF_SRC_X;
    let add64_reg = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_ADD | bpf_op::BPF_SRC_X;
    let sub64_imm = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_SUB;
    let jeq_imm = bpf_op::BPF_CLASS_JMP | bpf_op::BPF_JMP_JEQ;
    let jgt_imm = bpf_op::BPF_CLASS_JMP | bpf_op::BPF_JMP_JGT;
    let prog = [
        BpfInstr::new(mov64_imm, 1, 0, 0, 10), // r1 = n (default 10)
        BpfInstr::new(mov64_imm, 0, 0, 0, 0),  // r0 = a = 0
        BpfInstr::new(mov64_imm, 2, 0, 0, 1),  // r2 = b = 1
        BpfInstr::new(jeq_imm, 1, 0, 6, 0),    // if r1 == 0 goto EXIT
        BpfInstr::new(mov64_reg, 3, 0, 0, 0),  // r3 = r0
        BpfInstr::new(add64_reg, 3, 2, 0, 0),  // r3 += r2
        BpfInstr::new(mov64_reg, 0, 2, 0, 0),  // r0 = r2
        BpfInstr::new(mov64_reg, 2, 3, 0, 0),  // r2 = r3
        BpfInstr::new(sub64_imm, 1, 0, 0, 1),  // r1 -= 1
        BpfInstr::new(jgt_imm, 1, 0, -6, 0),   // if r1 > 0 goto loop
        BpfInstr::new(bpf_op::BPF_OP_EXIT, 0, 0, 0, 0),
    ];
    build_elf_ebpf_binary(&prog, out)
}

fn build_sum_elf(out: &mut [u8]) -> usize {
    let mov64_imm = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_MOV;
    let mov64_reg = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_MOV | bpf_op::BPF_SRC_X;
    let add64_imm = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_ADD;
    let mul64_reg = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_MUL | bpf_op::BPF_SRC_X;
    let rsh64_imm = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_RSH;
    let prog = [
        BpfInstr::new(mov64_imm, 1, 0, 0, 100), // r1 = n (default 100)
        BpfInstr::new(mov64_reg, 0, 1, 0, 0),   // r0 = n
        BpfInstr::new(add64_imm, 1, 0, 0, 1),   // r1 = n + 1
        BpfInstr::new(mul64_reg, 0, 1, 0, 0),   // r0 = n * (n + 1)
        BpfInstr::new(rsh64_imm, 0, 0, 0, 1),   // r0 = n * (n + 1) / 2
        BpfInstr::new(bpf_op::BPF_OP_EXIT, 0, 0, 0, 0),
    ];
    build_elf_ebpf_binary(&prog, out)
}

fn hex_bytes(src: &[u8], out: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut pos = 0usize;
    let mut i = 0usize;
    while i < src.len() && pos + 2 <= out.len() {
        out[pos] = HEX[(src[i] >> 4) as usize];
        out[pos + 1] = HEX[(src[i] & 0x0F) as usize];
        pos += 2;
        i += 1;
    }
    pos
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut start = 0usize;
    while start < s.len() && (s[start] == b' ' || s[start] == b'\t' || s[start] == b'\r' || s[start] == b'\n') {
        start += 1;
    }
    let mut end = s.len();
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t' || s[end - 1] == b'\r' || s[end - 1] == b'\n') {
        end -= 1;
    }
    &s[start..end]
}

fn split_first_word(s: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0usize;
    while i < s.len() && s[i] != b' ' && s[i] != b'\t' {
        i += 1;
    }
    let first = &s[..i];
    let rest = if i < s.len() { trim_ascii(&s[i + 1..]) } else { &[] };
    (first, rest)
}

fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0usize;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn copy_into(src: &[u8], dst: &mut [u8]) -> usize {
    let n = if src.len() < dst.len() {
        src.len()
    } else {
        dst.len()
    };
    let mut i = 0usize;
    while i < n {
        dst[i] = src[i];
        i += 1;
    }
    n
}

fn parse_u32_ascii(s: &[u8]) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut acc: u32 = 0;
    let mut i = 0usize;
    while i < s.len() {
        let c = s[i];
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as u32)?;
        i += 1;
    }
    Some(acc)
}

fn parse_u64_ascii(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    let mut i = 0usize;
    while i < s.len() {
        let c = s[i];
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as u64)?;
        i += 1;
    }
    Some(acc)
}

fn dec_u64(mut v: u64, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    while v > 0 && n < tmp.len() {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut i = 0usize;
    while i < n && i < out.len() {
        out[i] = tmp[n - 1 - i];
        i += 1;
    }
    i
}

fn parse_ipv4_cidr_ascii(s: &[u8]) -> Option<([u8; 4], u8)> {
    let trimmed = trim_ascii(s);
    if trimmed.is_empty() {
        return None;
    }
    let mut slash = trimmed.len();
    let mut i = 0usize;
    while i < trimmed.len() {
        if trimmed[i] == b'/' {
            slash = i;
            break;
        }
        i += 1;
    }
    let ip_part = &trimmed[..slash];
    let prefix = if slash < trimmed.len() {
        let p = parse_u32_ascii(&trimmed[slash + 1..])?;
        if p > 32 {
            return None;
        }
        p as u8
    } else {
        32u8
    };
    let mut octets = [0u8; 4];
    let mut oct_idx = 0usize;
    let mut start = 0usize;
    let mut k = 0usize;
    while k <= ip_part.len() {
        if k == ip_part.len() || ip_part[k] == b'.' {
            if oct_idx >= 4 || k == start {
                return None;
            }
            let val = parse_u32_ascii(&ip_part[start..k])?;
            if val > 255 {
                return None;
            }
            octets[oct_idx] = val as u8;
            oct_idx += 1;
            start = k + 1;
        }
        k += 1;
    }
    if oct_idx != 4 {
        return None;
    }
    Some((octets, prefix))
}

fn fmt_ipv4(b: [u8; 4], out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    pos += dec_u64(b[0] as u64, &mut out[pos..]);
    pos += copy_into(b".", &mut out[pos..]);
    pos += dec_u64(b[1] as u64, &mut out[pos..]);
    pos += copy_into(b".", &mut out[pos..]);
    pos += dec_u64(b[2] as u64, &mut out[pos..]);
    pos += copy_into(b".", &mut out[pos..]);
    pos += dec_u64(b[3] as u64, &mut out[pos..]);
    pos
}

fn sanitize_nonce(raw: &[u8]) -> &[u8] {
    let (tok, _) = split_first_word(trim_ascii(raw));
    if tok.is_empty() {
        return b"0";
    }
    let max_len = if tok.len() > 32 { 32 } else { tok.len() };
    let mut i = 0usize;
    while i < max_len {
        let c = tok[i];
        let valid = c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.';
        if !valid {
            break;
        }
        i += 1;
    }
    if i == 0 {
        b"0"
    } else {
        &tok[..i]
    }
}

/// Dynamically compile and evaluate a per-PID Seccomp-BPF filter program
/// inside the verified [`EBpfImpl`] interpreter (`proteus_contracts::EBpf`).
///
/// Filter program layout:
/// 1. `ST_MEM_DW [r1 + 0], syscall_nr` — writes `seccomp_data.nr` (`u64`) to stack `[0..8]`
/// 2. `LDX_MEM_DW r2, [r1 + 0]` — loads `seccomp_data.nr` into `r2`
/// 3. `MOV64_IMM r0, 0` — sets default return value `SECCOMP_RET_DENY` (`0`)
/// 4. `JMP_JEQ_IMM r2, denied_nr, +jump_to_exit` — for each denied syscall in `seccomp_mask`
/// 5. `MOV64_IMM r0, 1` — sets `SECCOMP_RET_ALLOW` (`1`) if no rule matched
/// 6. `BPF_OP_EXIT`
fn evaluate_seccomp_ebpf(seccomp_mask: u8, syscall_nr: u64) -> bool {
    if seccomp_mask == 0 {
        return true;
    }
    let mut denied_nrs = [0u64; 4];
    let mut denied_count = 0usize;
    if (seccomp_mask & SECCOMP_DENY_GETPID) != 0 {
        denied_nrs[denied_count] = SYS_GETPID;
        denied_count += 1;
    }
    if (seccomp_mask & SECCOMP_DENY_YIELD) != 0 {
        denied_nrs[denied_count] = SYS_YIELD;
        denied_count += 1;
    }
    if (seccomp_mask & SECCOMP_DENY_TIME) != 0 {
        denied_nrs[denied_count] = SYS_GETTIME_NS;
        denied_count += 1;
    }
    if (seccomp_mask & SECCOMP_DENY_OPEN) != 0 {
        denied_nrs[denied_count] = SYS_OPEN;
        denied_count += 1;
    }
    if denied_count == 0 {
        return true;
    }

    let st_dw = bpf_op::BPF_CLASS_ST | bpf_op::BPF_SIZE_DW;
    let ldx_dw = bpf_op::BPF_CLASS_LDX | bpf_op::BPF_SIZE_DW;
    let mov64_imm = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_MOV;
    let jeq_imm = bpf_op::BPF_CLASS_JMP | bpf_op::BPF_JMP_JEQ;

    let mut prog = [BpfInstr::new(0, 0, 0, 0, 0); 12];
    prog[0] = BpfInstr::new(st_dw, 1, 0, 0, syscall_nr as i32);
    prog[1] = BpfInstr::new(ldx_dw, 2, 1, 0, 0);
    prog[2] = BpfInstr::new(mov64_imm, 0, 0, 0, 0);
    let mut j = 0usize;
    while j < denied_count {
        let jump_to_exit = (denied_count - j) as i16;
        prog[3 + j] = BpfInstr::new(jeq_imm, 2, 0, jump_to_exit, denied_nrs[j] as i32);
        j += 1;
    }
    prog[3 + denied_count] = BpfInstr::new(mov64_imm, 0, 0, 0, 1);
    prog[3 + denied_count + 1] = BpfInstr::new(bpf_op::BPF_OP_EXIT, 0, 0, 0, 0);
    let total_insns = 3 + denied_count + 2;

    let mut ctx = BpfContext::new();
    matches!(EBpfImpl::run(&prog[..total_insns], &mut ctx), Ok(1))
}

fn fmt_seccomp_mask(mask: u8, out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    let mut first = true;
    let entries: &[(u8, &[u8])] = &[
        (SECCOMP_DENY_GETPID, b"getpid"),
        (SECCOMP_DENY_YIELD, b"yield"),
        (SECCOMP_DENY_TIME, b"time"),
        (SECCOMP_DENY_OPEN, b"open"),
    ];
    let mut i = 0usize;
    while i < entries.len() {
        let (bit, name) = entries[i];
        if (mask & bit) != 0 {
            if !first {
                pos += copy_into(b",", &mut out[pos..]);
            }
            pos += copy_into(name, &mut out[pos..]);
            first = false;
        }
        i += 1;
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_and_uname_and_status_work() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];

        let act = sh.exec_line(b"help", 7, 10, 20, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.contains("commands: help uname status ps"));

        let act = sh.exec_line(b"uname", 7, 10, 20, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.starts_with("Proteus-TE x86_64"));

        let act = sh.exec_line(b"status", 7, 10, 20, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert_eq!(
            s,
            "status: ok boots=7 tasks=4 files=4 audit_events=3 net_rx=10 net_tx=20\n"
        );
    }

    #[test]
    fn vfs_ls_cat_write_rm_and_protection_work() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];

        let act = sh.exec_line(b"cat /etc/hostname", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"proteus-te\n");

        let act = sh.exec_line(b"write /var/note hello-proteus", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert_eq!(s, "wrote 14 bytes to /var/note\n");

        let act = sh.exec_line(b"cat /var/note", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"hello-proteus\n");

        // Protected file cannot be overwritten or removed.
        let act = sh.exec_line(b"rm /etc/os-release", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.contains("permission denied"));

        // User file can be removed.
        let act = sh.exec_line(b"rm /var/note", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert_eq!(s, "removed /var/note\n");
    }

    #[test]
    fn scheduler_ps_spawn_kill_and_audit_work() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 1024];

        let act = sh.exec_line(b"spawn", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"spawned pid=5\n");

        // Protected PID 1 cannot be killed.
        let act = sh.exec_line(b"kill 1", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.contains("permission denied"));

        // Spawned worker PID 5 can be killed.
        let act = sh.exec_line(b"kill 5", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"killed pid=5\n");

        // Audit log records both Allowed and Denied events.
        let act = sh.exec_line(b"audit", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.contains("verdict=Denied msg=shell:kill:protected-task"));
        assert!(s.contains("verdict=Allowed msg=shell:kill"));
    }

    #[test]
    fn capability_gated_syscalls_and_wal_continuity_roundtrip() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];

        // 1. Spawn worker PID 5 (starts with 0 capabilities).
        let _ = sh.exec_line(b"spawn", 1, 0, 0, &mut out);
        // Unprivileged getpid succeeds:
        let act = sh.exec_line(b"syscall 5 getpid", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"syscall ok: ret=1\n");
        // Privileged SYS_OPEN is denied with EPERM:
        let act = sh.exec_line(b"syscall 5 open /etc/hostname", 1, 0, 0, &mut out);
        assert_eq!(
            &out[..act.bytes_written()],
            b"syscall denied: EPERM (missing fs capability)\n"
        );
        // Grant fs capability to PID 5:
        let act = sh.exec_line(b"grant 5 fs", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"granted fs on pid=5\n");
        // Now SYS_OPEN succeeds!
        let act = sh.exec_line(b"syscall 5 open /etc/hostname", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"syscall ok: ret=0\n");

        // 2. Write a stateful file `/var/state` and checkpoint into WalImpl.
        let _ = sh.exec_line(b"write /var/state morph-survivor", 1, 0, 0, &mut out);
        let mut wal: WalImpl<2048> = WalImpl::new();
        let recs = sh.checkpoint_wal(&mut wal).unwrap();
        assert_eq!(recs, 2); // 1 file (/var/state) + 1 worker task (PID 5)

        // 3. Simulate a morph reboot: construct a brand-new OsShell and restore from WAL.
        let mut next_sh = OsShell::new();
        let applied = next_sh.restore_wal(&wal);
        assert_eq!(applied, 2);

        // Verify `/var/state` survived the reboot:
        let act = next_sh.exec_line(b"cat /var/state", 2, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"morph-survivor\n");

        // Verify PID 5 AND its granted FS_BYPASS capability survived the reboot:
        let act = next_sh.exec_line(b"syscall 5 open /var/state", 2, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"syscall ok: ret=0\n");
    }

    #[test]
    fn interactive_feed_byte_with_backspace_and_halt() {
        let mut sh = OsShell::new();
        let mut echo = [0u8; 64];
        let mut reply = [0u8; 512];

        // Type "unamX\x08e\n"
        for &b in b"unamX" {
            let (elen, act) = sh.feed_byte(b, 1, 0, 0, &mut echo, &mut reply);
            assert_eq!(elen, 1);
            assert_eq!(act, ShellAction::Continue(0));
        }
        let (elen, _) = sh.feed_byte(0x08, 1, 0, 0, &mut echo, &mut reply);
        assert_eq!(&echo[..elen], b"\x08 \x08");
        let _ = sh.feed_byte(b'e', 1, 0, 0, &mut echo, &mut reply);
        let (_, act) = sh.feed_byte(b'\n', 1, 0, 0, &mut echo, &mut reply);
        let out_str = core::str::from_utf8(&reply[..act.bytes_written()]).unwrap();
        assert!(out_str.starts_with("Proteus-TE x86_64"));
        assert!(out_str.ends_with("proteus> "));

        // Type "halt\r"
        for &b in b"halt" {
            let _ = sh.feed_byte(b, 1, 0, 0, &mut echo, &mut reply);
        }
        let (_, act) = sh.feed_byte(b'\r', 1, 0, 0, &mut echo, &mut reply);
        assert!(matches!(act, ShellAction::Halt(_)));
    }

    #[test]
    fn elf64_kpti_ebpf_user_exec_and_rejection_work() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];

        // 1. Execute /bin/fib with default argument (n=10 -> 55).
        let act = sh.exec_line(b"exec /bin/fib", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert_eq!(
            s,
            "exec: path=/bin/fib entry=4198400 kpti=isolated insns=11 ret=55\n"
        );

        // 2. Execute /bin/fib with explicit argument n=12 -> 144.
        let act = sh.exec_line(b"exec /bin/fib 12", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert_eq!(
            s,
            "exec: path=/bin/fib entry=4198400 kpti=isolated insns=11 ret=144\n"
        );

        // 3. Execute /bin/sum with argument n=100 -> 5050.
        let act = sh.exec_line(b"exec /bin/sum 100", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert_eq!(
            s,
            "exec: path=/bin/sum entry=4198400 kpti=isolated insns=6 ret=5050\n"
        );

        // 4. Attempting to execute an unenrolled file (/etc/hostname) is blocked by IMA BEFORE ELF parsing.
        let act = sh.exec_line(b"exec /etc/hostname", 1, 0, 0, &mut out);
        assert_eq!(
            &out[..act.bytes_written()],
            b"error: EPERM (IMA signature verification failed)\n"
        );

        // 5. Even if /etc/hostname is enrolled in IMA, the ELF64 header validator rejects it.
        let _ = sh.exec_line(b"ima enroll /etc/hostname", 1, 0, 0, &mut out);
        let act = sh.exec_line(b"exec /etc/hostname", 1, 0, 0, &mut out);
        assert_eq!(
            &out[..act.bytes_written()],
            b"error: invalid elf64 executable\n"
        );
    }

    #[test]
    fn ima_tpm_pcr10_and_cidr_firewall_commands_work() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];

        // Initial IMA state has 2 trusted binaries (/bin/fib, /bin/sum), 0 measurements, all-zero PCR-10.
        let act = sh.exec_line(b"ima", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert_eq!(
            s,
            "ima: trusted=2 measurements=0 pcr10=0000000000000000000000000000000000000000000000000000000000000000\n"
        );
        assert!(OsShell::is_readonly_command(b"ima"));
        assert!(!OsShell::is_readonly_command(b"ima enroll /var/x"));

        // Running `exec /bin/fib 10` extends TPM PCR-10 (`measurements=1`, non-zero PCR-10).
        let _ = sh.exec_line(b"exec /bin/fib 10", 1, 0, 0, &mut out);
        let act = sh.exec_line(b"ima", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.starts_with("ima: trusted=2 measurements=1 pcr10="));
        assert!(!s.ends_with("0000000000000000000000000000000000000000000000000000000000000000\n"));

        // Firewall rules: block 10.99.0.0/16, inspect status, clear.
        let act = sh.exec_line(b"fw block 10.99.0.0/16", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"fw: blocked src=10.99.0.0/16\n");
        let act = sh.exec_line(b"fw", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.contains("fw: rules=1 default=allow"));
        assert!(s.contains("rule[0] src=10.99.0.0/16 action=drop"));
        let act = sh.exec_line(b"fw clear", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"fw: cleared all rules\n");
    }

    #[test]
    fn sealed_wal_continuity_and_tamper_rejection() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];

        let _ = sh.exec_line(b"write /var/config mode=enforcing", 1, 0, 0, &mut out);
        let _ = sh.exec_line(b"spawn", 1, 0, 0, &mut out);
        let _ = sh.exec_line(b"grant 5 net", 1, 0, 0, &mut out);

        // Interactive `seal` command prints 64-character SHA-256 hex digest.
        let act = sh.exec_line(b"seal", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.starts_with("seal: sha256="));
        assert!(s.contains(" files=5 tasks=5 "));

        // Checkpoint with SHA-256 seal.
        let mut wal: WalImpl<2048> = WalImpl::new();
        let mut seal = [0u8; 32];
        let recs = sh.checkpoint_sealed(&mut wal, &mut seal).unwrap();
        assert_eq!(recs, 2);

        // Tampered seal must be rejected in constant time by restore_sealed.
        let mut tampered_seal = seal;
        tampered_seal[0] ^= 0x01;
        let mut bad_sh = OsShell::new();
        assert_eq!(
            bad_sh.restore_sealed(&wal, &tampered_seal),
            Err(WalError::PayloadTooLarge)
        );

        // Authentic seal succeeds and restores full state.
        let mut next_sh = OsShell::new();
        let applied = next_sh.restore_sealed(&wal, &seal).unwrap();
        assert_eq!(applied, 2);
        let act = next_sh.exec_line(b"cat /var/config", 2, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"mode=enforcing\n");
    }

    #[test]
    fn disk_image_pack_unpack_and_sector_tamper_rejection() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];

        let _ = sh.exec_line(b"write /var/mission active", 7, 0, 0, &mut out);
        let _ = sh.exec_line(b"spawn", 7, 0, 0, &mut out);
        let _ = sh.exec_line(b"grant 5 fs", 7, 0, 0, &mut out);

        let mut hdr_sec = [0u8; 512];
        let mut wal_sec = [0u8; 512];
        let count = sh.pack_disk_image(7, &mut hdr_sec, &mut wal_sec).unwrap();
        assert_eq!(count, 2);

        // Bit-flip in WAL payload sector is caught by SHA-256 seal check!
        let mut bad_wal = wal_sec;
        bad_wal[12] ^= 0x80;
        let mut bad_sh = OsShell::new();
        assert_eq!(
            bad_sh.unpack_disk_image(&hdr_sec, &bad_wal),
            Err(WalError::PayloadTooLarge)
        );

        // Authentic sectors restore cleanly on next boot.
        let mut boot2_sh = OsShell::new();
        let (saved_boots, applied) = boot2_sh.unpack_disk_image(&hdr_sec, &wal_sec).unwrap();
        assert_eq!(saved_boots, 7);
        assert_eq!(applied, 2);

        let act = boot2_sh.exec_line(b"cat /var/mission", 8, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"active\n");
        let act = boot2_sh.exec_line(b"syscall 5 open /var/mission", 8, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"syscall ok: ret=0\n");
    }

    #[test]
    fn cross_morph_security_policy_and_antireplay_continuity() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];

        // 1. Configure CIDR firewall rule, enroll custom IMA digest, and advance auth_seq.
        let _ = sh.exec_line(b"fw block 10.99.0.0/16", 1, 0, 0, &mut out);
        let _ = sh.exec_line(b"write /var/custom_script ok", 1, 0, 0, &mut out);
        let _ = sh.exec_line(b"ima enroll /var/custom_script", 1, 0, 0, &mut out);
        sh.auth_seq = 42;

        // 2. Pack into sealed 2-sector disk image.
        let mut hdr_sec = [0u8; 512];
        let mut wal_sec = [0u8; 512];
        let count = sh.pack_disk_image(1, &mut hdr_sec, &mut wal_sec).unwrap();
        // 1 file (/var/custom_script) + 1 fw rule (W) + 1 IMA entry (I) + 1 auth_seq (Q) = 4 records
        assert_eq!(count, 4);

        // 3. Reboot into fresh OsShell and unpack disk image.
        let mut boot2_sh = OsShell::new();
        assert_eq!(boot2_sh.fw.as_slice().len(), 0);
        assert_eq!(boot2_sh.ima_count, 2);
        assert_eq!(boot2_sh.auth_seq, 0);

        let (saved_boots, applied) = boot2_sh.unpack_disk_image(&hdr_sec, &wal_sec).unwrap();
        assert_eq!(saved_boots, 1);
        assert_eq!(applied, 4);

        // Verify firewall rule survived morph reboot:
        assert_eq!(boot2_sh.fw.as_slice().len(), 1);
        assert_eq!(boot2_sh.fw.as_slice()[0].src_ip, [10, 99, 0, 0]);
        assert_eq!(boot2_sh.fw.as_slice()[0].src_mask, 16);
        assert_eq!(boot2_sh.fw.as_slice()[0].action, FilterAction::Drop);

        // Verify custom IMA digest survived morph reboot (`trusted=3`):
        let act = boot2_sh.exec_line(b"ima", 2, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.starts_with("ima: trusted=3 "));
        let mut dig = [0u8; 32];
        assert!(boot2_sh.verify_ima_digest(b"/var/custom_script", b"ok\n", &mut dig));

        // Verify anti-replay sequence watermark survived morph reboot:
        assert_eq!(boot2_sh.auth_seq, 42);
    }

    #[test]
    fn remote_attestation_quote_and_mac_verification_work() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];
        assert!(OsShell::is_readonly_command(b"attest"));
        assert!(OsShell::is_readonly_command(b"attest challenge-99"));

        let _ = sh.exec_line(b"exec /bin/fib 10", 3, 0, 0, &mut out);
        let act = sh.exec_line(b"attest challenge-99", 3, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.starts_with("attest: v=1 boots=3 pcr10="));
        assert!(s.contains(" ima=1 seal="));
        assert!(s.contains(" nonce=challenge-99 hmac="));

        // Note that `attest` itself records an audit event, advancing the state seal!
        // Compute and verify the MAC on the post-command state:
        let mut mac = [0u8; 32];
        sh.compute_attestation_mac(3, b"challenge-99", &mut mac);
        assert!(sh.verify_attestation_mac(3, b"challenge-99", &mac));
        assert!(!sh.verify_attestation_mac(3, b"wrong-nonce", &mac));
        assert!(!sh.verify_attestation_mac(4, b"challenge-99", &mac));
        let mut bad_mac = mac;
        bad_mac[0] ^= 1;
        assert!(!sh.verify_attestation_mac(3, b"challenge-99", &bad_mac));
    }

    #[test]
    fn ebpf_seccomp_syscall_sandboxing_and_wal_persistence_work() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];

        assert!(OsShell::is_readonly_command(b"seccomp"));
        assert!(OsShell::is_readonly_command(b"seccomp status"));
        assert!(!OsShell::is_readonly_command(b"seccomp deny 5 open"));

        // System tasks (PID 1..4) are protected from Seccomp deny:
        let act = sh.exec_line(b"seccomp deny 1 open", 1, 0, 0, &mut out);
        assert_eq!(
            &out[..act.bytes_written()],
            b"error: permission denied (protected system task)\n"
        );

        // Spawn worker PID 5 and grant FS_BYPASS:
        let _ = sh.exec_line(b"spawn", 1, 0, 0, &mut out);
        let _ = sh.exec_line(b"grant 5 fs", 1, 0, 0, &mut out);
        let act = sh.exec_line(b"syscall 5 open /etc/hostname", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"syscall ok: ret=0\n");

        // Attach eBPF Seccomp filter denying `open` on PID 5:
        let act = sh.exec_line(b"seccomp deny 5 open", 1, 0, 0, &mut out);
        assert_eq!(
            &out[..act.bytes_written()],
            b"seccomp: denied open on pid=5 (mask=8)\n"
        );

        // Even though PID 5 holds FS_BYPASS, the eBPF Seccomp filter blocks `open` with EACCES:
        let act = sh.exec_line(b"syscall 5 open /etc/hostname", 1, 0, 0, &mut out);
        assert_eq!(
            &out[..act.bytes_written()],
            b"syscall denied: EACCES (blocked by eBPF seccomp filter)\n"
        );
        // Unfiltered syscalls (`getpid`) continue to succeed:
        let act = sh.exec_line(b"syscall 5 getpid", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"syscall ok: ret=1\n");

        // Inspect `seccomp status`:
        let act = sh.exec_line(b"seccomp", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert_eq!(
            s,
            "seccomp: filters=1 engine=ebpf\n  pid=5 deny_mask=8 (open)\n"
        );

        // Persist across WAL / disk image and verify Seccomp filter survives morph reboot:
        let mut hdr_sec = [0u8; 512];
        let mut wal_sec = [0u8; 512];
        let count = sh.pack_disk_image(1, &mut hdr_sec, &mut wal_sec).unwrap();
        assert_eq!(count, 1); // 1 worker task (PID 5) with packed caps + seccomp

        let mut boot2_sh = OsShell::new();
        let (_, applied) = boot2_sh.unpack_disk_image(&hdr_sec, &wal_sec).unwrap();
        assert_eq!(applied, 1);
        let act = boot2_sh.exec_line(b"syscall 5 open /etc/hostname", 2, 0, 0, &mut out);
        assert_eq!(
            &out[..act.bytes_written()],
            b"syscall denied: EACCES (blocked by eBPF seccomp filter)\n"
        );

        // Clearing the filter restores `open` access:
        let act = boot2_sh.exec_line(b"seccomp clear 5", 2, 0, 0, &mut out);
        assert_eq!(
            &out[..act.bytes_written()],
            b"seccomp: cleared filter on pid=5\n"
        );
        let act = boot2_sh.exec_line(b"syscall 5 open /etc/hostname", 2, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"syscall ok: ret=0\n");
    }

    #[test]
    fn fs_partition_packs_multi_sector_files_and_rejects_tampering() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 1024];

        // Write a small file via shell command (`6` bytes) and a multi-sector 768-byte file via VFS.
        let _ = sh.exec_line(b"write /var/boot.ok ready", 1, 0, 0, &mut out);
        let mut big = [0u8; 768];
        for (i, b) in big.iter_mut().enumerate() {
            *b = b'A' + ((i % 26) as u8);
        }
        sh.fs.seed_file(b"/var/blob.bin", &big, 768, 42).unwrap();

        let mut sectors = [[0u8; 512]; SHELL_FS_PART_SECTORS];
        let (files, bytes) = sh.pack_fs_partition(9, &mut sectors).unwrap();
        assert_eq!(files, 2);
        assert_eq!(bytes, 6 + 768);
        assert_eq!(&sectors[0][0..8], SHELL_FS_MAGIC);

        // Restore into a fresh shell with the same seal_key:
        let mut sh2 = OsShell::new();
        let (generation, r_files, r_bytes) = sh2.unpack_fs_partition(&sectors).unwrap();
        assert_eq!(generation, 9);
        assert_eq!(r_files, 2);
        assert_eq!(r_bytes, 774);

        let a1 = sh2.exec_line(b"cat /var/boot.ok", 9, 0, 0, &mut out);
        assert_eq!(&out[..a1.bytes_written()], b"ready\n");

        let (_, restored_blob) = (0..SHELL_FS_INODES)
            .filter_map(|i| sh2.fs.inode_data(i))
            .find(|(p, _)| *p == b"/var/blob.bin")
            .expect("restored /var/blob.bin");
        assert_eq!(restored_blob, &big[..]);

        // Tampering with any data sector must fail keyed HMAC-SHA256 verification and log Denied:
        let mut tampered = sectors;
        tampered[4][123] ^= 0x80;
        let mut sh3 = OsShell::new();
        assert!(sh3.unpack_fs_partition(&tampered).is_err());
        assert_eq!(sh3.audit.len(), 1);
    }

    #[test]
    fn df_and_sync_commands_report_partition_state() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];

        assert!(OsShell::is_readonly_command(b"df"));
        assert!(!OsShell::is_readonly_command(b"sync"));

        let _ = sh.exec_line(b"write /var/boot.ok ready", 1, 0, 0, &mut out);
        let act_df = sh.exec_line(b"df", 1, 0, 0, &mut out);
        assert_eq!(
            &out[..act_df.bytes_written()],
            b"fs: magic=PRTSFS01 inodes=5/16 pool_bytes=704/4096 part_sectors=16\n"
        );

        let act_sync = sh.exec_line(b"sync", 1, 0, 0, &mut out);
        let sync_str = core::str::from_utf8(&out[..act_sync.bytes_written()]).unwrap();
        assert!(sync_str.starts_with("sync: ok files=1 bytes=6 seal="));
        assert!(sync_str.ends_with('\n'));
    }

    #[test]
    fn smp_and_threads_commands_report_multi_core_and_dispatch_jobs() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 1024];

        assert!(OsShell::is_readonly_command(b"smp"));
        assert!(OsShell::is_readonly_command(b"smp status"));
        assert!(OsShell::is_readonly_command(b"threads"));
        assert!(!OsShell::is_readonly_command(b"smp run 16"));

        let act_smp = sh.exec_line(b"smp", 1, 0, 0, &mut out);
        let smp_str = core::str::from_utf8(&out[..act_smp.bytes_written()]).unwrap();
        assert!(smp_str.contains("smp: cpus=4/4 arch=x86_64-lapic-ipi threads=4"));
        assert!(smp_str.contains("cpu0 [BSP apic=0]: online"));
        assert!(smp_str.contains("cpu3 [AP  apic=3]: online"));
        assert!(smp_str.contains("tid=1 cpu=0 ctx_sw="));

        let act_run = sh.exec_line(b"smp run 16", 1, 0, 0, &mut out);
        let run_str = core::str::from_utf8(&out[..act_run.bytes_written()]).unwrap();
        assert!(run_str.contains("smp: dispatched 16 parallel jobs across 4 cores (ctx_switches="));
    }

    #[test]
    fn session_status_redacts_full_bearer_tokens() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 512];
        let sid = sh.create_session(b"alice", b"nonce1");
        let full_sid_str = core::str::from_utf8(&sid).unwrap();
        let prefix_str = core::str::from_utf8(&sid[..8]).unwrap();

        let act = sh.exec_line(b"session status", 1, 0, 0, &mut out);
        let status_str = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(status_str.contains(prefix_str));
        assert!(status_str.contains("..."));
        assert!(
            !status_str.contains(full_sid_str),
            "session status must never leak the full 32-hex bearer token"
        );
    }

    #[test]
    fn service_supervisor_role_isolation_rotation_and_attestation_work() {
        let mut sh = OsShell::new();
        let mut out = [0u8; 768];

        assert!(OsShell::is_readonly_command(b"service"));
        assert!(OsShell::is_readonly_command(b"service status"));
        assert!(!OsShell::is_readonly_command(b"service rotate svc-http 42"));
        assert!(!OsShell::is_readonly_command(b"service role wfe"));

        // 1. Default role is `full` with all 3 Ring-3 services KPTI-isolated.
        let act = sh.exec_line(b"service status", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.contains("service: role=full running=3/3"));
        assert!(s.contains("svc-http path=/sbin/svc-http state=running va=4259840 kpti=isolated"));
        assert!(s.contains("svc-sql path=/sbin/svc-sql state=running va=4325376 kpti=isolated"));
        assert!(s.contains("svc-sh path=/sbin/svc-sh state=running va=4390912 kpti=isolated"));

        // 2. Materialize and execute `/sbin/svc-http` in its KPTI-isolated sandbox (`va=4259840`).
        let act = sh.exec_line(b"exec /sbin/svc-http 1", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.starts_with("exec: path=/sbin/svc-http entry=4259840 kpti=isolated insns=10 ret="));

        // 3. Rotate `svc-http` independently (with a full 64-bit seed > u32::MAX) without rebooting
        //    and verify PCR-10 + attestation quote update.
        let mut mac_before = [0u8; 32];
        sh.compute_attestation_mac(1, b"svc-nonce", &mut mac_before);
        let act = sh.exec_line(b"service rotate svc-http 1099511627777", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.starts_with("service: rotated svc-http rot=1 seed=1099511627777 sha256="));
        let mut mac_after = [0u8; 32];
        sh.compute_attestation_mac(1, b"svc-nonce", &mut mac_after);
        assert_ne!(mac_before, mac_after, "rotating a service must update the attestation quote");

        // 4. Simulate a crash in `svc-sql` and verify the supervisor automatically restarts it on the next SQL query.
        let act = sh.exec_line(b"service crash svc-sql", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.contains("service: faulted svc-sql"));
        let act = sh.exec_line(b"sql SELECT COUNT(*) FROM kv", 1, 0, 0, &mut out);
        assert_eq!(&out[..act.bytes_written()], b"count\n2\n");
        assert_eq!(sh.svc.services[1].restarts, 1);

        // 5. Switch node role to `wfe`: `svc-sql` and `svc-sh` are unloaded from memory and refused
        //    across ALL shell commands (`sql`, `exec`, `write`, `rm`, `spawn`, `kill`).
        let act = sh.exec_line(b"service role wfe", 1, 0, 0, &mut out);
        let s = core::str::from_utf8(&out[..act.bytes_written()]).unwrap();
        assert!(s.starts_with("service: role=wfe running=1/3"));
        let act_sql = sh.exec_line(b"sql SELECT * FROM kv", 1, 0, 0, &mut out);
        assert_eq!(
            &out[..act_sql.bytes_written()],
            b"error: EACCES (svc-sql disabled by node role or policy)\n"
        );
        for cmd in [
            b"exec /bin/fib 10".as_slice(),
            b"write /var/test.txt hi".as_slice(),
            b"rm /var/test.txt".as_slice(),
            b"spawn".as_slice(),
            b"kill 5".as_slice(),
        ] {
            let act_sh = sh.exec_line(cmd, 1, 0, 0, &mut out);
            assert_eq!(
                &out[..act_sh.bytes_written()],
                b"error: EACCES (svc-sh disabled by node role or policy)\n"
            );
        }
    }
}
