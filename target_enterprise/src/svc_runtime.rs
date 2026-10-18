//! Ring-3 User-Space Service Runtime, Role-Specific ELF64 Loader, KPTI Address-Space
//! Isolation, Deny-by-Default Capability/Seccomp Policy, IPC Bus & Supervisor (`svc_runtime`).
//!
//! Implements **Option 3 (Minimal Shared Ring-0 Microkernel + Role-Specific Ring-3 Service ELFs)**:
//!
//! 1. **Role-Specific Service Provisioning ([`NodeRole`])**:
//!    - [`NodeRole::Wfe`]: Web Front-End / Gateway node — loads only `svc-http` (`/sbin/svc-http`).
//!      Neither `svc-sql` nor `svc-sh` ELF binaries are loaded into memory.
//!    - [`NodeRole::Sql`]: SQL RAID Storage node — loads only `svc-sql` (`/sbin/svc-sql`).
//!      Neither `svc-http` nor `svc-sh` ELF binaries are loaded into memory.
//!    - [`NodeRole::Shell`]: Bastion / Remote Execution node — loads only `svc-sh` (`/sbin/svc-sh`).
//!    - [`NodeRole::Full`]: Unified standalone appliance — loads `svc-http`, `svc-sql`, and `svc-sh`
//!      into three mutually isolated KPTI user virtual address spaces (`0x41_0000`, `0x42_0000`, `0x43_0000`).
//! 2. **Deny-by-Default Per-Service Policy ([`ServicePolicy`])**:
//!    - Every service declares the exact capability mask (`cap_mask`) and allowed syscall bitmask
//!      (`seccomp_allow_mask`) it requires. The kernel refuses any undeclared capability or syscall
//!      with [`ServiceError::CapabilityDenied`] (`EPERM`) or [`ServiceError::SeccompDenied`] (`EACCES`).
//! 3. **Independent Per-Service Binary Rotation & Attestation ([`ServiceSupervisor::rotate_service`])**:
//!    - Individual Ring-3 service ELFs can be re-morphed with a new `variant_seed` and restarted in
//!      place **without rebooting the kernel**, re-verifying IMA SHA-256 + KPTI isolation and extending
//!      TPM 2.0 `PCR-10` (`svc_pcr10`).

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    bpf_op, caps, AuditEvent, AuditLog, AuditVerdict, BpfContext, BpfInstr, CanaryToken, EBpf,
    Elf64, ElfPhdr, Kpti, StackCanary, Tpm, AUDIT_MESSAGE_LEN, BPF_STACK_SIZE, ELF_CLASS64,
    ELF_DATA_LE, ELF_EHDR_LEN, ELF_EM_X86_64, ELF_ET_EXEC, ELF_MAGIC, ELF_MAX_PHDRS, ELF_PHDR_LEN,
    ELF_PT_LOAD, STACK_CANARY_LEN, TPM_ALG_SHA256,
};

use crate::audit::AuditLogImpl;
use crate::durable_seal::{seal_bytes, seal_bytes_keyed, seal_matches, DURABLE_DIGEST_LEN};
use crate::ebpf::EBpfImpl;
use crate::elf64::Elf64Impl;
use crate::kpti::{
    KptiImpl, PageTable, KPTI_TRAMPOLINE_VIRT, PAGE_MASK, PTE_PRESENT, PTE_USER, PTE_WRITABLE,
};
use crate::stack_canary::StackCanaryImpl;
use crate::tpm::{TpmImpl, TPM_MAX_CMD_LEN};

/// Number of Ring-3 appliance services managed by [`ServiceSupervisor`].
pub const SERVICE_COUNT: usize = 3;
/// Maximum byte size of a synthesized Ring-3 service ELF64 binary.
pub const SVC_ELF_CAP: usize = 256;
/// Maximum number of in-flight messages retained in the [`IpcBus`] ring.
pub const IPC_RING_CAP: usize = 8;

/// Service capability bit: permission to send/receive messages on the kernel [`IpcBus`].
pub const SVC_CAP_IPC: u64 = 1 << 8;
/// Service capability bit: permission to spawn/execute sandboxed user ELF64 binaries.
pub const SVC_CAP_EXEC: u64 = 1 << 9;

/// Dedicated KPTI user virtual address base for `svc-http` (`/sbin/svc-http`).
pub const SVC_HTTP_USER_VA: u64 = 0x0000_0000_0041_0000;
/// Dedicated KPTI user virtual address base for `svc-sql` (`/sbin/svc-sql`).
pub const SVC_SQL_USER_VA: u64 = 0x0000_0000_0042_0000;
/// Dedicated KPTI user virtual address base for `svc-sh` (`/sbin/svc-sh`).
pub const SVC_SH_USER_VA: u64 = 0x0000_0000_0043_0000;
/// Kernel secret virtual address that must never be mapped into any Ring-3 service page table.
pub const KERNEL_SECRET_VA: u64 = 0xFFFF_8000_0000_0000;

/// Syscall bitmask mediated by the per-service eBPF Seccomp filter.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SvcSyscall {
    /// Query service PID (`SYS_GETPID`).
    GetPid = 1 << 0,
    /// Yield processor slice (`SYS_YIELD`).
    Yield = 1 << 1,
    /// Read monotonic clock (`SYS_GETTIME_NS`).
    GetTime = 1 << 2,
    /// Open or mutate VFS files (`SYS_OPEN`).
    Open = 1 << 3,
    /// Send/receive bounded inter-service RPC on [`IpcBus`].
    IpcSend = 1 << 4,
    /// Bind/accept/transmit HTTP/HTTPS network sockets (`CAP_NET`).
    NetIo = 1 << 5,
    /// Read/write sealed SQL block storage sectors (`CAP_STORAGE`).
    StorageIo = 1 << 6,
    /// Execute interactive shell or user ELF64 sandbox (`CAP_EXEC`).
    Exec = 1 << 7,
}

impl SvcSyscall {
    /// Raw bitmask representation of this syscall.
    pub const fn bit(self) -> u8 {
        self as u8
    }

    /// Required capability bitmask for this syscall (deny-by-default).
    pub const fn required_cap(self) -> u64 {
        match self {
            SvcSyscall::GetPid | SvcSyscall::Yield | SvcSyscall::GetTime => 0,
            SvcSyscall::Open => caps::FS_BYPASS,
            SvcSyscall::IpcSend => SVC_CAP_IPC,
            SvcSyscall::NetIo => caps::NET_RAW,
            SvcSyscall::StorageIo => caps::DURABLE_WAL_WRITE,
            SvcSyscall::Exec => SVC_CAP_EXEC,
        }
    }
}

/// Appliance node role profile determining which Ring-3 service ELFs are loaded into memory.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeRole {
    /// Web Front-End / Gateway Appliance: loads only `svc-http` (`/sbin/svc-http`).
    Wfe,
    /// SQL RAID Storage Appliance: loads only `svc-sql` (`/sbin/svc-sql`).
    Sql,
    /// Bastion / Remote Exec Appliance: loads only `svc-sh` (`/sbin/svc-sh`).
    Shell,
    /// Unified Standalone Appliance: loads `svc-http`, `svc-sql`, and `svc-sh`.
    Full,
}

impl NodeRole {
    /// Canonical ASCII name for this role profile.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            NodeRole::Wfe => b"wfe",
            NodeRole::Sql => b"sql",
            NodeRole::Shell => b"shell",
            NodeRole::Full => b"full",
        }
    }

    /// Parse a role profile name (`"wfe"`, `"sql"`, `"shell"`, `"full"`).
    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if bytes_eq(raw, b"wfe") || bytes_eq(raw, b"http") {
            Some(NodeRole::Wfe)
        } else if bytes_eq(raw, b"sql") || bytes_eq(raw, b"db") {
            Some(NodeRole::Sql)
        } else if bytes_eq(raw, b"shell") || bytes_eq(raw, b"sh") {
            Some(NodeRole::Shell)
        } else if bytes_eq(raw, b"full") || bytes_eq(raw, b"all") {
            Some(NodeRole::Full)
        } else {
            None
        }
    }

    /// Returns `true` if `svc` is provisioned and permitted to load under this node role.
    pub const fn allows(self, svc: ServiceId) -> bool {
        match (self, svc) {
            (NodeRole::Full, _) => true,
            (NodeRole::Wfe, ServiceId::Http) => true,
            (NodeRole::Sql, ServiceId::Sql) => true,
            (NodeRole::Shell, ServiceId::Shell) => true,
            _ => false,
        }
    }
}

/// Identifier for an isolated Ring-3 user-space service.
#[repr(usize)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ServiceId {
    /// Web server, TLS/HTTP router, and dashboard renderer (`/sbin/svc-http`).
    Http = 0,
    /// Embedded relational SQL engine and `PRTSSQL1` storage service (`/sbin/svc-sql`).
    Sql = 1,
    /// Authenticated remote shell and measured user ELF sandbox (`/sbin/svc-sh`).
    Shell = 2,
}

impl ServiceId {
    /// All three appliance services in canonical order.
    pub const ALL: [ServiceId; SERVICE_COUNT] =
        [ServiceId::Http, ServiceId::Sql, ServiceId::Shell];

    /// Index into fixed `[_; SERVICE_COUNT]` arrays.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Canonical service name (`"svc-http"`, `"svc-sql"`, `"svc-sh"`).
    pub const fn name(self) -> &'static [u8] {
        match self {
            ServiceId::Http => b"svc-http",
            ServiceId::Sql => b"svc-sql",
            ServiceId::Shell => b"svc-sh",
        }
    }

    /// VFS binary path (`/sbin/svc-http`, `/sbin/svc-sql`, `/sbin/svc-sh`).
    pub const fn elf_path(self) -> &'static [u8] {
        match self {
            ServiceId::Http => b"/sbin/svc-http",
            ServiceId::Sql => b"/sbin/svc-sql",
            ServiceId::Shell => b"/sbin/svc-sh",
        }
    }

    /// Dedicated KPTI user-space virtual address base (`0x41_0000`, `0x42_0000`, `0x43_0000`).
    pub const fn user_va_base(self) -> u64 {
        match self {
            ServiceId::Http => SVC_HTTP_USER_VA,
            ServiceId::Sql => SVC_SQL_USER_VA,
            ServiceId::Shell => SVC_SH_USER_VA,
        }
    }

    /// Dedicated Ring-3 task PID assigned by the supervisor.
    pub const fn pid(self) -> u16 {
        match self {
            ServiceId::Http => 8,
            ServiceId::Sql => 9,
            ServiceId::Shell => 10,
        }
    }

    /// Deny-by-default capability and syscall policy for this service.
    pub const fn policy(self) -> ServicePolicy {
        match self {
            ServiceId::Http => ServicePolicy {
                cap_mask: caps::NET_RAW | SVC_CAP_IPC,
                seccomp_allow_mask: SvcSyscall::GetPid.bit()
                    | SvcSyscall::Yield.bit()
                    | SvcSyscall::GetTime.bit()
                    | SvcSyscall::IpcSend.bit()
                    | SvcSyscall::NetIo.bit(),
                user_va_base: SVC_HTTP_USER_VA,
            },
            ServiceId::Sql => ServicePolicy {
                cap_mask: caps::DURABLE_WAL_WRITE | SVC_CAP_IPC,
                seccomp_allow_mask: SvcSyscall::GetPid.bit()
                    | SvcSyscall::Yield.bit()
                    | SvcSyscall::GetTime.bit()
                    | SvcSyscall::IpcSend.bit()
                    | SvcSyscall::StorageIo.bit(),
                user_va_base: SVC_SQL_USER_VA,
            },
            ServiceId::Shell => ServicePolicy {
                cap_mask: caps::FS_BYPASS | SVC_CAP_IPC | SVC_CAP_EXEC,
                seccomp_allow_mask: SvcSyscall::GetPid.bit()
                    | SvcSyscall::Yield.bit()
                    | SvcSyscall::GetTime.bit()
                    | SvcSyscall::Open.bit()
                    | SvcSyscall::IpcSend.bit()
                    | SvcSyscall::Exec.bit(),
                user_va_base: SVC_SH_USER_VA,
            },
        }
    }

    /// Parse a service identifier from ASCII (`"svc-http"`/`"http"`, `"svc-sql"`/`"sql"`, `"svc-sh"`/`"sh"`).
    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if bytes_eq(raw, b"svc-http") || bytes_eq(raw, b"http") || bytes_eq(raw, b"/sbin/svc-http")
        {
            Some(ServiceId::Http)
        } else if bytes_eq(raw, b"svc-sql")
            || bytes_eq(raw, b"sql")
            || bytes_eq(raw, b"/sbin/svc-sql")
        {
            Some(ServiceId::Sql)
        } else if bytes_eq(raw, b"svc-sh")
            || bytes_eq(raw, b"sh")
            || bytes_eq(raw, b"shell")
            || bytes_eq(raw, b"/sbin/svc-sh")
        {
            Some(ServiceId::Shell)
        } else {
            None
        }
    }
}

/// Deny-by-default security policy declared by a Ring-3 service manifest.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ServicePolicy {
    /// Granted kernel capabilities; any capability bit not set here is refused (`EPERM`).
    pub cap_mask: u64,
    /// Allowed syscall bitmask; any syscall bit not set here is blocked by Seccomp (`EACCES`).
    pub seccomp_allow_mask: u8,
    /// Isolated user-space virtual address base mapped in the service's KPTI page table.
    pub user_va_base: u64,
}

impl ServicePolicy {
    /// Returns `true` if `cap` is granted by this service's policy.
    pub const fn allows_cap(&self, cap: u64) -> bool {
        (self.cap_mask & cap) == cap
    }

    /// Returns `true` if `sys` is permitted by this service's eBPF Seccomp allowlist.
    pub const fn allows_syscall(&self, sys: SvcSyscall) -> bool {
        (self.seccomp_allow_mask & sys.bit()) != 0
    }
}

/// Lifecycle state of a Ring-3 service under [`ServiceSupervisor`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ServiceState {
    /// Not provisioned for the current [`NodeRole`]; binary is unloaded and unmapped from RAM.
    Unloaded,
    /// Verified ELF64 loaded, KPTI page table isolated, and actively serving IPC/syscalls.
    Running,
    /// Faulted or crashed; eligible for automatic supervisor restart on next mediation or tick.
    Faulted,
}

impl ServiceState {
    /// Canonical ASCII state label.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            ServiceState::Unloaded => b"unloaded",
            ServiceState::Running => b"running",
            ServiceState::Faulted => b"faulted",
        }
    }
}

/// High-level IPC / endpoint operation mediated by [`ServiceSupervisor`].
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IpcOp {
    /// `GET /`, `GET /status`, `GET /healthz` (`svc-http`, public).
    HttpGetStatus = 1,
    /// `GET /ps`, `/smp`, `/ls`, `/audit`, `/attest`, etc. (`svc-http`, public read-only).
    HttpGetTelemetry = 2,
    /// `GET /app`, `GET /dashboard` (`svc-http`, public HTML render; no token leak).
    HttpGetDashboard = 3,
    /// `POST /session/login` (`svc-http`, requires valid HMAC-SHA256 proof).
    SessionLogin = 4,
    /// `GET /session/whoami` (`svc-http`, requires valid session `sid`).
    SessionWhoami = 5,
    /// `POST /session/logout` (`svc-http`, requires valid session `sid`).
    SessionLogout = 6,
    /// `GET /sql?<SELECT>` or `POST /sql` read-only query (`svc-http -> svc-sql` IPC, public).
    SqlQuery = 7,
    /// `POST /sql` mutating statement (`svc-http -> svc-sql` IPC, requires valid session `sid`).
    SqlMutate = 8,
    /// `POST /sh` interactive command (`svc-http -> svc-sh` IPC, requires valid session `sid`).
    ShellExec = 9,
    /// `POST /exec` user ELF64 sandbox execution (`svc-http -> svc-sh` IPC, requires valid session `sid`).
    UserElfExec = 10,
    /// `GET /fs/<path>` read-only VFS fetch (`svc-http`, public).
    VfsRead = 11,
    /// `PUT /fs/<path>` VFS write (`svc-http -> svc-sh` IPC, requires valid session `sid`).
    VfsWrite = 12,
    /// `DELETE /fs/<path>` VFS unlink (`svc-http -> svc-sh` IPC, requires valid session `sid`).
    VfsDelete = 13,
}

impl IpcOp {
    /// Returns `true` if this operation requires an authenticated session token (`sid`).
    pub const fn requires_session(self) -> bool {
        matches!(
            self,
            IpcOp::SessionWhoami
                | IpcOp::SessionLogout
                | IpcOp::SqlMutate
                | IpcOp::ShellExec
                | IpcOp::UserElfExec
                | IpcOp::VfsWrite
                | IpcOp::VfsDelete
        )
    }

    /// Target service that executes the operation (`svc-http`, `svc-sql`, or `svc-sh`).
    pub const fn target_service(self) -> ServiceId {
        match self {
            IpcOp::HttpGetStatus
            | IpcOp::HttpGetTelemetry
            | IpcOp::HttpGetDashboard
            | IpcOp::SessionLogin
            | IpcOp::SessionWhoami
            | IpcOp::SessionLogout
            | IpcOp::VfsRead => ServiceId::Http,
            IpcOp::SqlQuery | IpcOp::SqlMutate => ServiceId::Sql,
            IpcOp::ShellExec | IpcOp::UserElfExec | IpcOp::VfsWrite | IpcOp::VfsDelete => {
                ServiceId::Shell
            }
        }
    }

    /// Primary syscall exercised by the target service when handling this operation.
    pub const fn target_syscall(self) -> SvcSyscall {
        match self {
            IpcOp::HttpGetStatus
            | IpcOp::HttpGetTelemetry
            | IpcOp::HttpGetDashboard
            | IpcOp::SessionLogin
            | IpcOp::SessionWhoami
            | IpcOp::SessionLogout
            | IpcOp::VfsRead => SvcSyscall::NetIo,
            IpcOp::SqlQuery | IpcOp::SqlMutate => SvcSyscall::StorageIo,
            IpcOp::ShellExec | IpcOp::UserElfExec => SvcSyscall::Exec,
            IpcOp::VfsWrite | IpcOp::VfsDelete => SvcSyscall::Open,
        }
    }
}

/// Fault / refusal codes returned by [`ServiceSupervisor`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// Target service is not loaded because the active [`NodeRole`] disables it (`503` / `ENOSYS`).
    RoleDisabled,
    /// Endpoint requires an authenticated session token (`sid`) (`401 Unauthorized`).
    Unauthenticated,
    /// Service attempted an operation outside its declared `cap_mask` (`403` / `EPERM`).
    CapabilityDenied,
    /// Service attempted a syscall blocked by its eBPF Seccomp allowlist (`403` / `EACCES`).
    SeccompDenied,
    /// Service ELF64 image failed IMA SHA-256 verification (`EPERM`).
    ImaVerificationFailed,
    /// Service KPTI user page table failed kernel/cross-service isolation validation (`EFAULT`).
    KptiIsolationFailed,
    /// Service eBPF handler trapped or corrupted its stack canary (`EFAULT`).
    SandboxTrap,
}

/// Bounded zero-allocation IPC message recorded on the kernel [`IpcBus`].
#[derive(Copy, Clone, Debug)]
pub struct IpcMessage {
    /// Monotonic IPC sequence number.
    pub seq: u64,
    /// Sender service.
    pub src: ServiceId,
    /// Destination service.
    pub dst: ServiceId,
    /// Mediated operation code.
    pub op: IpcOp,
    /// Whether the caller presented a verified session proof.
    pub session_verified: bool,
}

impl IpcMessage {
    /// Empty IPC message slot.
    pub const fn empty() -> Self {
        Self {
            seq: 0,
            src: ServiceId::Http,
            dst: ServiceId::Http,
            op: IpcOp::HttpGetStatus,
            session_verified: false,
        }
    }
}

/// Byte length of each service's diversified x86-64 `CPL=3` machine-code stub
/// (`mov eax, cs; mov rsi, rax; mov rax, [rsp-0x20]; mov rdx, rax; xor rdx, salt32; mov [rsp-0x18], rdx; mov edi, 2; int 0x80`).
pub const SVC_RING3_STUB_LEN: usize = 32;

/// Per-service IPC & hardware execution mailbox.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IpcMailbox {
    /// Monotonic count of IPC/endpoint requests delivered to this service's mailbox.
    pub req_seq: u64,
    /// Last [`IpcOp`] discriminant delivered to this service (`0` when idle).
    pub last_op: u8,
    /// Per-service 32-bit mailbox canary verified across hardware `CPL=3` mailbox transitions.
    pub canary: u32,
    /// Last 64-bit response tag returned by this service's ELF64 handler.
    pub resp_tag: u64,
    /// Number of populated user-mode entries verified in the serialized x86-64 PML4 (`x86_pml4::serialize_into`).
    pub pml4_entries: usize,
    /// Count of hardware Ring-3 (`CPL=3`, `CS=0x23`) executions completed via `iretq` -> `int 0x80`.
    pub cpl3_runs: u64,
}

impl IpcMailbox {
    /// Construct a zeroed service mailbox.
    pub const fn empty() -> Self {
        Self {
            req_seq: 0,
            last_op: 0,
            canary: 0,
            resp_tag: 0,
            pml4_entries: 0,
            cpl3_runs: 0,
        }
    }
}

/// Per-service runtime descriptor managed by [`ServiceSupervisor`].
#[derive(Copy, Clone, Debug)]
pub struct ServiceSlot {
    /// Service identifier (`Http`, `Sql`, `Shell`).
    pub id: ServiceId,
    /// Current lifecycle state (`Unloaded`, `Running`, `Faulted`).
    pub state: ServiceState,
    /// Deny-by-default security policy enforced by the kernel.
    pub policy: ServicePolicy,
    /// Active binary diversification seed used to synthesize `elf_image` and `ring3_code`.
    pub variant_seed: u64,
    /// Number of times this service's ELF binary has been rotated in place without rebooting.
    pub rotations: u64,
    /// Number of automatic supervisor restarts after faults/crashes.
    pub restarts: u64,
    /// Total mediated requests served by this service.
    pub requests_served: u64,
    /// Total policy violations (capability/seccomp/auth refusals) recorded against this service.
    pub policy_denials: u64,
    /// Whether KPTI user page table isolation is currently verified for this service.
    pub kpti_isolated: bool,
    /// Live per-service KPTI user page table (`UserL4`) isolating this service's address space.
    pub user_l4: PageTable<8>,
    /// Per-service IPC & hardware execution mailbox.
    pub mailbox: IpcMailbox,
    /// Diversified x86-64 Ring-3 (`CPL=3`) machine-code stub executed via `iretq` -> `int 0x80`.
    pub ring3_code: [u8; SVC_RING3_STUB_LEN],
    /// Expected `RDX` (`arg0`) syscall argument produced when `ring3_code` executes at `CPL=3`.
    pub ring3_expected_arg0: u64,
    /// SHA-256 digest of the currently loaded ELF64 binary (`[0; 32]` when `Unloaded`).
    pub elf_sha256: [u8; DURABLE_DIGEST_LEN],
    /// Valid byte length of `elf_image` (`0` when `Unloaded`).
    pub elf_len: usize,
    /// In-memory ELF64 service binary (`[0; 256]` when `Unloaded` to minimize memory footprint).
    pub elf_image: [u8; SVC_ELF_CAP],
}

impl ServiceSlot {
    /// Construct an unloaded service slot for `id`.
    pub const fn empty(id: ServiceId) -> Self {
        Self {
            id,
            state: ServiceState::Unloaded,
            policy: id.policy(),
            variant_seed: 0,
            rotations: 0,
            restarts: 0,
            requests_served: 0,
            policy_denials: 0,
            kpti_isolated: false,
            user_l4: PageTable::new(),
            mailbox: IpcMailbox::empty(),
            ring3_code: [0u8; SVC_RING3_STUB_LEN],
            ring3_expected_arg0: 0,
            elf_sha256: [0u8; DURABLE_DIGEST_LEN],
            elf_len: 0,
            elf_image: [0u8; SVC_ELF_CAP],
        }
    }
}

/// Derive a deterministic per-node AND per-boot 64-bit base seed from a 256-bit `seal_key`
/// and monotonic `boot_gen` counter so both distinct nodes and reboots of the same node
/// start with fresh service ELF variants (`svc-http`, `svc-sql`, `svc-sh`).
pub fn derive_service_base_seed_for_boot(
    seal_key: &[u8; DURABLE_DIGEST_LEN],
    boot_gen: u64,
) -> u64 {
    let mut label = [0u8; 36];
    let prefix = b"proteus-svc-variant-seed-v1:";
    label[..28].copy_from_slice(prefix);
    label[28..36].copy_from_slice(&boot_gen.to_le_bytes());
    let mut dig = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(seal_key, &label, &mut dig);
    let raw = u64::from_le_bytes([
        dig[0], dig[1], dig[2], dig[3], dig[4], dig[5], dig[6], dig[7],
    ]);
    if raw == 0 {
        1
    } else {
        raw
    }
}

/// Derive a deterministic per-node 64-bit base seed from a 256-bit `seal_key` (boot generation 1).
pub fn derive_service_base_seed(seal_key: &[u8; DURABLE_DIGEST_LEN]) -> u64 {
    derive_service_base_seed_for_boot(seal_key, 1)
}

/// Ring-3 Service Init / Supervisor, KPTI Loader, IPC Bus, and Policy Enforcer.
#[derive(Copy, Clone, Debug)]
pub struct ServiceSupervisor {
    /// Active appliance role profile (`Wfe`, `Sql`, `Shell`, or `Full`).
    pub role: NodeRole,
    /// Per-node base seed used to derive per-service variant seeds when booting or enabling services.
    pub base_seed: u64,
    /// Per-service runtime slots (`svc-http`, `svc-sql`, `svc-sh`).
    pub services: [ServiceSlot; SERVICE_COUNT],
    /// Rolling TPM 2.0 `PCR-10` service measurement register (`SHA256(svc_pcr10 || elf_sha256)`).
    pub svc_pcr10: [u8; DURABLE_DIGEST_LEN],
    /// Total service binary measurements extended into `svc_pcr10`.
    pub svc_measurements: u64,
    /// Bounded circular IPC message ring.
    pub ipc_ring: [IpcMessage; IPC_RING_CAP],
    /// Write cursor into `ipc_ring`.
    pub ipc_head: usize,
    /// Monotonic count of inter-service IPC messages mediated by the kernel.
    pub ipc_total: u64,
}

impl ServiceSupervisor {
    /// Construct an unseeded supervisor suitable for `const` static initialization.
    pub const fn empty() -> Self {
        Self {
            role: NodeRole::Full,
            base_seed: 1,
            services: [
                ServiceSlot::empty(ServiceId::Http),
                ServiceSlot::empty(ServiceId::Sql),
                ServiceSlot::empty(ServiceId::Shell),
            ],
            svc_pcr10: [0u8; DURABLE_DIGEST_LEN],
            svc_measurements: 0,
            ipc_ring: [IpcMessage::empty(); IPC_RING_CAP],
            ipc_head: 0,
            ipc_total: 0,
        }
    }

    /// Derive a per-service variant seed from the node's `base_seed` and `svc`.
    #[inline]
    pub const fn derive_slot_seed(&self, svc: ServiceId) -> u64 {
        let idx = (svc.index() as u64) + 1;
        let mixed = self
            .base_seed
            .wrapping_add(idx.wrapping_mul(0x9E37_79B9_7F4A_7C15))
            ^ idx.wrapping_mul(0x517C_C1B7_2722_0A95);
        if mixed == 0 {
            idx
        } else {
            mixed
        }
    }

    /// Initialize and start all services permitted by `role` with initial `base_seed`.
    pub fn init_role(&mut self, role: NodeRole, base_seed: u64) {
        self.role = role;
        self.base_seed = if base_seed == 0 { 1 } else { base_seed };
        let mut i = 0usize;
        while i < SERVICE_COUNT {
            let svc = ServiceId::ALL[i];
            if role.allows(svc) {
                let seed = self.derive_slot_seed(svc);
                let _ = self.load_and_verify_service(svc, seed, false);
            } else {
                self.unload_service(svc);
            }
            i += 1;
        }
    }

    /// Switch the node's role profile at runtime, immediately unloading any disallowed
    /// service ELFs (zeroing their memory pages and KPTI mappings) and loading any newly
    /// enabled service ELFs using the node's per-service seed.
    pub fn set_role<const N: usize>(&mut self, role: NodeRole, audit: &mut AuditLogImpl<N>) {
        self.role = role;
        let mut i = 0usize;
        while i < SERVICE_COUNT {
            let svc = ServiceId::ALL[i];
            if role.allows(svc) {
                if self.services[i].state != ServiceState::Running {
                    let seed = if self.services[i].variant_seed == 0 {
                        self.derive_slot_seed(svc)
                    } else {
                        self.services[i].variant_seed
                    };
                    let _ = self.load_and_verify_service(svc, seed, false);
                }
            } else {
                self.unload_service(svc);
            }
            i += 1;
        }
        record_svc_audit(audit, 40, AuditVerdict::Allowed, b"svc:role:updated");
    }

    /// Unload a service from memory and clear its ELF image, Ring-3 stub, and live KPTI page table.
    fn unload_service(&mut self, svc: ServiceId) {
        let idx = svc.index();
        self.services[idx].state = ServiceState::Unloaded;
        self.services[idx].kpti_isolated = false;
        self.services[idx].user_l4 = PageTable::new();
        self.services[idx].mailbox = IpcMailbox::empty();
        self.services[idx].ring3_code = [0u8; SVC_RING3_STUB_LEN];
        self.services[idx].ring3_expected_arg0 = 0;
        self.services[idx].elf_sha256 = [0u8; DURABLE_DIGEST_LEN];
        self.services[idx].elf_len = 0;
        self.services[idx].elf_image = [0u8; SVC_ELF_CAP];
    }

    /// Synthesize, IMA-hash, ELF64-parse, KPTI-isolate, and TPM `PCR-10`-extend a service binary.
    fn load_and_verify_service(
        &mut self,
        svc: ServiceId,
        variant_seed: u64,
        is_rotation: bool,
    ) -> Result<(), ServiceError> {
        if !self.role.allows(svc) {
            self.unload_service(svc);
            return Err(ServiceError::RoleDisabled);
        }
        let idx = svc.index();
        let mut img = [0u8; SVC_ELF_CAP];
        let elf_len = build_service_elf(svc, variant_seed, &mut img);
        if elf_len == 0 {
            return Err(ServiceError::ImaVerificationFailed);
        }

        // 1. Compute IMA SHA-256 binary measurement digest.
        let mut bin_dig = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes(&img[..elf_len], &mut bin_dig);

        // 2. Parse and validate ELF64 header and PT_LOAD segment.
        let hdr = Elf64Impl::parse_header(&img[..elf_len])
            .map_err(|_| ServiceError::ImaVerificationFailed)?;
        if hdr.entry != svc.user_va_base() {
            return Err(ServiceError::KptiIsolationFailed);
        }
        let mut phdrs = [ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }; ELF_MAX_PHDRS];
        let ph_count = Elf64Impl::load_phdrs(&img[..elf_len], &hdr, &mut phdrs)
            .map_err(|_| ServiceError::ImaVerificationFailed)?;
        if ph_count < 1 || phdrs[0].ptype != ELF_PT_LOAD || phdrs[0].vaddr != svc.user_va_base() {
            return Err(ServiceError::KptiIsolationFailed);
        }

        // 3. Build and validate the service's live KPTI user page table (`user_l4`) and
        //    serialize it via `kpti::x86_pml4::serialize_into` to verify hardware x86-64 PML4 layout:
        //    - Maps KPTI_TRAMPOLINE_VIRT and ONLY this service's user_va_base.
        //    - Excludes KERNEL_SECRET_VA AND excludes all peer services' virtual addresses!
        let user_l4 = build_service_user_l4(svc);
        if !verify_service_kpti_isolation(&user_l4, svc) {
            return Err(ServiceError::KptiIsolationFailed);
        }

        // 4. Synthesize the service's diversified x86-64 Ring-3 (`CPL=3`) machine-code stub.
        let (ring3_code, ring3_expected_arg0) = build_service_ring3_stub(svc, variant_seed);

        // 5. Build and verify TCG TPM 2.0 PCR-10 Extend command and update svc_pcr10.
        let mut tpm_cmd = [0u8; TPM_MAX_CMD_LEN];
        let tpm_len = TpmImpl::build_pcr_extend(&mut tpm_cmd, 10, TPM_ALG_SHA256, &bin_dig)
            .map_err(|_| ServiceError::ImaVerificationFailed)?;
        if tpm_len != TPM_MAX_CMD_LEN || tpm_cmd[0] != 0x80 || tpm_cmd[1] != 0x02 {
            return Err(ServiceError::ImaVerificationFailed);
        }
        let mut pcr_concat = [0u8; DURABLE_DIGEST_LEN * 2];
        pcr_concat[..DURABLE_DIGEST_LEN].copy_from_slice(&self.svc_pcr10);
        pcr_concat[DURABLE_DIGEST_LEN..].copy_from_slice(&bin_dig);
        let mut next_pcr = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes(&pcr_concat, &mut next_pcr);
        self.svc_pcr10 = next_pcr;
        self.svc_measurements = self.svc_measurements.wrapping_add(1);

        // 6. Commit verified service binary, Ring-3 stub, and live user_l4 page table into the supervisor slot.
        let slot = &mut self.services[idx];
        slot.state = ServiceState::Running;
        slot.policy = svc.policy();
        slot.variant_seed = variant_seed;
        if is_rotation {
            slot.rotations = slot.rotations.wrapping_add(1);
        }
        slot.user_l4 = user_l4;
        slot.kpti_isolated = true;
        slot.mailbox.pml4_entries = slot.user_l4.len();
        slot.mailbox.canary = ((variant_seed as u32).wrapping_mul(0x9E37_79B9)) ^ 0xA55A_3C3C;
        slot.ring3_code = ring3_code;
        slot.ring3_expected_arg0 = ring3_expected_arg0;
        slot.elf_sha256 = bin_dig;
        slot.elf_len = elf_len;
        slot.elf_image = img;
        Ok(())
    }

    /// Independently re-morph, reload, and re-attest a single Ring-3 service ELF binary in place
    /// without rebooting the kernel or disrupting peer services.
    pub fn rotate_service<const N: usize>(
        &mut self,
        svc: ServiceId,
        new_seed: u64,
        audit: &mut AuditLogImpl<N>,
    ) -> Result<[u8; DURABLE_DIGEST_LEN], ServiceError> {
        if !self.role.allows(svc) {
            self.services[svc.index()].policy_denials =
                self.services[svc.index()].policy_denials.wrapping_add(1);
            record_svc_audit(audit, 41, AuditVerdict::Denied, b"svc:rotate:role-disabled");
            return Err(ServiceError::RoleDisabled);
        }
        let effective_seed = if new_seed == self.services[svc.index()].variant_seed {
            new_seed.wrapping_add(0xA5A5_5A5A)
        } else {
            new_seed
        };
        self.load_and_verify_service(svc, effective_seed, true)?;
        let msg: &[u8] = match svc {
            ServiceId::Http => b"svc:rotate:svc-http",
            ServiceId::Sql => b"svc:rotate:svc-sql",
            ServiceId::Shell => b"svc:rotate:svc-sh",
        };
        record_svc_audit(audit, 41, AuditVerdict::Allowed, msg);
        Ok(self.services[svc.index()].elf_sha256)
    }

    /// Inject a simulated service crash/fault into `svc` so supervisor auto-restart can be verified.
    pub fn simulate_crash<const N: usize>(
        &mut self,
        svc: ServiceId,
        audit: &mut AuditLogImpl<N>,
    ) -> Result<(), ServiceError> {
        let idx = svc.index();
        if !self.role.allows(svc) || self.services[idx].state == ServiceState::Unloaded {
            return Err(ServiceError::RoleDisabled);
        }
        self.services[idx].state = ServiceState::Faulted;
        record_svc_audit(audit, 42, AuditVerdict::Error, b"svc:supervisor:fault");
        Ok(())
    }

    /// Ensure `svc` is running; if it is in [`ServiceState::Faulted`], automatically restart it
    /// from its verified ELF64 image and log the recovery to `audit`.
    pub fn ensure_running<const N: usize>(
        &mut self,
        svc: ServiceId,
        audit: &mut AuditLogImpl<N>,
    ) -> Result<(), ServiceError> {
        let idx = svc.index();
        if !self.role.allows(svc) || self.services[idx].state == ServiceState::Unloaded {
            self.services[idx].policy_denials =
                self.services[idx].policy_denials.wrapping_add(1);
            record_svc_audit(audit, 43, AuditVerdict::Denied, b"svc:error:role-unloaded");
            return Err(ServiceError::RoleDisabled);
        }
        if self.services[idx].state == ServiceState::Faulted {
            let seed = self.services[idx].variant_seed;
            self.load_and_verify_service(svc, seed, false)?;
            self.services[idx].restarts = self.services[idx].restarts.wrapping_add(1);
            record_svc_audit(audit, 43, AuditVerdict::Allowed, b"svc:supervisor:restart");
        }
        Ok(())
    }

    /// Mediate a direct syscall from `svc`, enforcing its deny-by-default capability mask,
    /// eBPF Seccomp syscall allowlist, IMA binary integrity, and live KPTI `user_l4` isolation.
    pub fn mediate_syscall<const N: usize>(
        &mut self,
        svc: ServiceId,
        sys: SvcSyscall,
        audit: &mut AuditLogImpl<N>,
    ) -> Result<(), ServiceError> {
        self.ensure_running(svc, audit)?;
        let idx = svc.index();
        let policy = self.services[idx].policy;

        // 1. Enforce eBPF Seccomp per-service syscall allowlist (deny-by-default).
        if !policy.allows_syscall(sys) {
            self.services[idx].policy_denials =
                self.services[idx].policy_denials.wrapping_add(1);
            record_svc_audit(audit, 44, AuditVerdict::Denied, b"svc:seccomp:denied");
            return Err(ServiceError::SeccompDenied);
        }

        // 2. Enforce per-service capability mask (deny-by-default).
        let req_cap = sys.required_cap();
        if req_cap != 0 && !policy.allows_cap(req_cap) {
            self.services[idx].policy_denials =
                self.services[idx].policy_denials.wrapping_add(1);
            record_svc_audit(audit, 44, AuditVerdict::Denied, b"svc:cap:denied");
            return Err(ServiceError::CapabilityDenied);
        }

        // 3. Verify live ELF64 IMA digest in constant time before running handler code.
        let elf_len = self.services[idx].elf_len;
        if elf_len == 0
            || !seal_matches(
                &self.services[idx].elf_image[..elf_len],
                &self.services[idx].elf_sha256,
            )
        {
            self.services[idx].policy_denials =
                self.services[idx].policy_denials.wrapping_add(1);
            record_svc_audit(audit, 44, AuditVerdict::Denied, b"svc:ima:tampered");
            return Err(ServiceError::ImaVerificationFailed);
        }

        // 4. Validate the service's actual live `user_l4` page table against KPTI invariants.
        if !self.services[idx].kpti_isolated
            || !verify_service_kpti_isolation(&self.services[idx].user_l4, svc)
        {
            self.services[idx].kpti_isolated = false;
            self.services[idx].policy_denials =
                self.services[idx].policy_denials.wrapping_add(1);
            record_svc_audit(audit, 44, AuditVerdict::Denied, b"svc:kpti:violation");
            return Err(ServiceError::KptiIsolationFailed);
        }
        Ok(())
    }

    /// Gate and dispatch a high-level service endpoint / IPC operation (`op`) across the
    /// service policy & isolation boundary:
    ///
    /// 1. Verifies that the entry service (`svc-http` for network requests) and target service
    ///    (`svc-http`, `svc-sql`, or `svc-sh`) are provisioned under the current [`NodeRole`]
    ///    (returning [`ServiceError::RoleDisabled`] -> `503` if disabled by role).
    /// 2. Enforces the standing endpoint credential gate (`op.requires_session() => session_verified`,
    ///    returning [`ServiceError::Unauthenticated`] -> `401` if missing).
    /// 3. If `target != ServiceId::Http`, mediates an authenticated inter-service [`IpcMessage`]
    ///    from `svc-http` to `target` over [`IpcBus`] (checking `SvcSyscall::IpcSend` + `SVC_CAP_IPC`).
    /// 4. Mediates the target service's required syscall and capability (`NetIo`, `StorageIo`,
    ///    `Exec`, or `Open`) and executes the target service's ELF64 eBPF policy program with
    ///    an in-stack [`StackCanaryImpl`] guard.
    pub fn mediate_endpoint<const N: usize>(
        &mut self,
        op: IpcOp,
        via_http_gateway: bool,
        session_verified: bool,
        audit: &mut AuditLogImpl<N>,
    ) -> Result<u64, ServiceError> {
        let target = op.target_service();

        // 1. Check role availability first so requests to services disabled by the node's role
        //    always return `RoleDisabled` (503) rather than misleading `Unauthenticated` (401).
        if via_http_gateway {
            let http_idx = ServiceId::Http.index();
            if !self.role.allows(ServiceId::Http)
                || self.services[http_idx].state == ServiceState::Unloaded
            {
                self.services[http_idx].policy_denials =
                    self.services[http_idx].policy_denials.wrapping_add(1);
                record_svc_audit(audit, 43, AuditVerdict::Denied, b"svc:error:role-unloaded");
                return Err(ServiceError::RoleDisabled);
            }
        }
        let target_idx = target.index();
        if !self.role.allows(target) || self.services[target_idx].state == ServiceState::Unloaded {
            self.services[target_idx].policy_denials =
                self.services[target_idx].policy_denials.wrapping_add(1);
            record_svc_audit(audit, 43, AuditVerdict::Denied, b"svc:error:role-unloaded");
            return Err(ServiceError::RoleDisabled);
        }

        // 2. Standing Rule (Step 6): Refuse unauthenticated calls to credentialed endpoints BEFORE touching service state.
        if op.requires_session() && !session_verified {
            self.services[target_idx].policy_denials =
                self.services[target_idx].policy_denials.wrapping_add(1);
            record_svc_audit(audit, 45, AuditVerdict::Denied, b"svc:auth:unauthenticated");
            return Err(ServiceError::Unauthenticated);
        }

        // 3. When arriving over HTTP/HTTPS, `svc-http` must be loaded and allowed `NetIo`.
        if via_http_gateway {
            self.mediate_syscall(ServiceId::Http, SvcSyscall::NetIo, audit)?;
            if target != ServiceId::Http {
                // `svc-http` must use IPC (`SvcSyscall::IpcSend` + `SVC_CAP_IPC`) to talk to `svc-sql` or `svc-sh`.
                self.mediate_syscall(ServiceId::Http, SvcSyscall::IpcSend, audit)?;
                self.mediate_syscall(target, SvcSyscall::IpcSend, audit)?;
                self.ipc_total = self.ipc_total.wrapping_add(1);
                let msg = IpcMessage {
                    seq: self.ipc_total,
                    src: ServiceId::Http,
                    dst: target,
                    op,
                    session_verified,
                };
                self.ipc_ring[self.ipc_head % IPC_RING_CAP] = msg;
                self.ipc_head = (self.ipc_head + 1) % IPC_RING_CAP;
                self.services[ServiceId::Http.index()].requests_served =
                    self.services[ServiceId::Http.index()]
                        .requests_served
                        .wrapping_add(1);
            }
        }

        // 4. Mediate the target service's syscall & capability policy.
        let sys = op.target_syscall();
        self.mediate_syscall(target, sys, audit)?;

        // 5. Execute the target service's loaded ELF64 eBPF handler inside an in-stack canary frame
        //    and record the IPC request/response in the service's mailbox.
        let ret = self.execute_service_elf(target, op as u64)?;
        let slot = &mut self.services[target_idx];
        slot.requests_served = slot.requests_served.wrapping_add(1);
        slot.mailbox.req_seq = slot.mailbox.req_seq.wrapping_add(1);
        slot.mailbox.last_op = op as u8;
        slot.mailbox.resp_tag = ret;
        Ok(ret)
    }

    /// Execute the eBPF instruction stream inside `svc`'s loaded ELF64 `PT_LOAD` segment,
    /// planting the [`StackCanaryImpl`] token directly at `[r10 - 8 .. r10]` inside `ctx.stack`
    /// via a 2-instruction prologue and verifying post-run that the executed program did not
    /// corrupt the canary slot.
    fn execute_service_elf(&self, svc: ServiceId, arg_op: u64) -> Result<u64, ServiceError> {
        let slot = &self.services[svc.index()];
        let header_len = ELF_EHDR_LEN + ELF_PHDR_LEN;
        if slot.elf_len <= header_len || ((slot.elf_len - header_len) % 8) != 0 {
            return Err(ServiceError::ImaVerificationFailed);
        }
        let code_len = slot.elf_len - header_len;
        let insn_count = code_len / 8;
        if insn_count == 0 || insn_count > 16 {
            return Err(ServiceError::ImaVerificationFailed);
        }

        let seed_bytes = (slot.variant_seed ^ 0x55AA_55AA_55AA_55AA).to_le_bytes();
        let canary: CanaryToken =
            StackCanaryImpl::mint(&seed_bytes).map_err(|_| ServiceError::SandboxTrap)?;
        let canary_lo = i32::from_le_bytes([
            canary.bytes[0],
            canary.bytes[1],
            canary.bytes[2],
            canary.bytes[3],
        ]);
        let canary_hi = i32::from_le_bytes([
            canary.bytes[4],
            canary.bytes[5],
            canary.bytes[6],
            canary.bytes[7],
        ]);

        let st_mem_w = bpf_op::BPF_CLASS_ST | bpf_op::BPF_SIZE_W;
        let mut prog = [BpfInstr::new(0, 0, 0, 0, 0); 18];
        // Prologue: plant 8-byte stack canary at [r10 - 8 .. r10] inside ctx.stack.
        prog[0] = BpfInstr::new(st_mem_w, 10, 0, -8, canary_lo);
        prog[1] = BpfInstr::new(st_mem_w, 10, 0, -4, canary_hi);

        let mut i = 0usize;
        while i < insn_count {
            let base = header_len + i * 8;
            let op = slot.elf_image[base];
            let regs = slot.elf_image[base + 1];
            let off = i16::from_le_bytes([slot.elf_image[base + 2], slot.elf_image[base + 3]]);
            let imm = i32::from_le_bytes([
                slot.elf_image[base + 4],
                slot.elf_image[base + 5],
                slot.elf_image[base + 6],
                slot.elf_image[base + 7],
            ]);
            prog[2 + i] = BpfInstr {
                opcode: op,
                regs,
                offset: off,
                imm,
            };
            i += 1;
        }
        if prog[2].opcode == (bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_MOV) {
            prog[2].imm = arg_op as i32;
        }

        let mut ctx = BpfContext::new();
        let ret = EBpfImpl::run(&prog[..2 + insn_count], &mut ctx)
            .map_err(|_| ServiceError::SandboxTrap)?;

        let canary_off = BPF_STACK_SIZE - STACK_CANARY_LEN;
        let mut observed_bytes = [0u8; STACK_CANARY_LEN];
        observed_bytes.copy_from_slice(&ctx.stack[canary_off..BPF_STACK_SIZE]);
        let observed = CanaryToken {
            bytes: observed_bytes,
        };
        if StackCanaryImpl::verify(&canary, &observed).is_err() {
            return Err(ServiceError::SandboxTrap);
        }
        Ok(ret)
    }

    /// Count of currently loaded (`ServiceState::Running`) Ring-3 services.
    pub fn running_count(&self) -> usize {
        let mut c = 0usize;
        let mut i = 0usize;
        while i < SERVICE_COUNT {
            if self.services[i].state == ServiceState::Running {
                c += 1;
            }
            i += 1;
        }
        c
    }

    /// Verify live KPTI page table isolation across all currently running services.
    pub fn verify_all_kpti_isolated(&self) -> bool {
        let mut i = 0usize;
        while i < SERVICE_COUNT {
            let svc = ServiceId::ALL[i];
            if self.services[i].state == ServiceState::Running {
                if !verify_service_kpti_isolation(&self.services[i].user_l4, svc) {
                    return false;
                }
            } else if self.services[i].user_l4.len() != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

/// Build the reference kernel page table and peer secret list for `svc`.
fn build_service_kernel_reference(svc: ServiceId) -> (PageTable<8>, [u64; 3]) {
    let own_va = svc.user_va_base() & PAGE_MASK;
    let mut kernel_l4: PageTable<8> = PageTable::new();
    let _ = kernel_l4.map(KERNEL_SECRET_VA, PTE_PRESENT | PTE_WRITABLE);
    let _ = kernel_l4.map(KPTI_TRAMPOLINE_VIRT, PTE_PRESENT | PTE_USER);
    let _ = kernel_l4.map(own_va, PTE_PRESENT | PTE_USER);

    let mut peer_secrets = [KERNEL_SECRET_VA; 3];
    let mut s_idx = 1usize;
    let mut i = 0usize;
    while i < SERVICE_COUNT {
        let other = ServiceId::ALL[i];
        if other != svc {
            let other_va = other.user_va_base() & PAGE_MASK;
            let _ = kernel_l4.map(other_va, PTE_PRESENT | PTE_WRITABLE);
            if s_idx < 3 {
                peer_secrets[s_idx] = other_va;
                s_idx += 1;
            }
        }
        i += 1;
    }
    (kernel_l4, peer_secrets)
}

/// Construct the isolated KPTI user page table (`UserL4`) for `svc`.
pub fn build_service_user_l4(svc: ServiceId) -> PageTable<8> {
    let (kernel_l4, peer_secrets) = build_service_kernel_reference(svc);
    KptiImpl::<8>::build_user_view(&kernel_l4, &peer_secrets)
}

/// Verify that a service's live `user_l4` KPTI page table maps `svc.user_va_base()` and
/// `KPTI_TRAMPOLINE_VIRT`, leaves `KERNEL_SECRET_VA` and every peer service's `user_va_base()`
/// unmapped, and serializes cleanly into a hardware x86-64 PML4 via [`crate::kpti::x86_pml4::serialize_into`].
pub fn verify_service_kpti_isolation(user_l4: &PageTable<8>, svc: ServiceId) -> bool {
    let own_va = svc.user_va_base() & PAGE_MASK;
    let (kernel_l4, peer_secrets) = build_service_kernel_reference(svc);
    if KptiImpl::<8>::validate_user_view(user_l4, &kernel_l4, &peer_secrets).is_err() {
        return false;
    }
    if user_l4.len() != 2
        || !user_l4.is_mapped(own_va)
        || !user_l4.is_mapped(KPTI_TRAMPOLINE_VIRT)
        || user_l4.is_mapped(KERNEL_SECRET_VA)
    {
        return false;
    }
    let mut k = 0usize;
    while k < SERVICE_COUNT {
        let other = ServiceId::ALL[k];
        if other != svc && user_l4.is_mapped(other.user_va_base() & PAGE_MASK) {
            return false;
        }
        k += 1;
    }
    let mut pml4_bytes = [0u8; crate::kpti::x86_pml4::PML4_BYTES];
    let serialized = crate::kpti::x86_pml4::serialize_into(user_l4, &mut pml4_bytes);
    if serialized != 2 {
        return false;
    }
    let mut idx = 0usize;
    while idx < serialized {
        let off = idx * 8;
        let pte = u64::from_le_bytes([
            pml4_bytes[off],
            pml4_bytes[off + 1],
            pml4_bytes[off + 2],
            pml4_bytes[off + 3],
            pml4_bytes[off + 4],
            pml4_bytes[off + 5],
            pml4_bytes[off + 6],
            pml4_bytes[off + 7],
        ]);
        if (pte & (PTE_PRESENT | PTE_USER)) != (PTE_PRESENT | PTE_USER) {
            return false;
        }
        idx += 1;
    }
    true
}

/// Synthesize a diversified 32-byte x86-64 Ring-3 (`CPL=3`) machine-code stub for `svc`
/// parameterized by `variant_seed` that reads the user-mapped IPC mailbox request + canary word
/// from `[rsp - 0x20]`, signs it with `salt32`, writes the response to `[rsp - 0x18]`, and
/// traps to Ring-0 via `int 0x80`:
///
/// ```text
///   8C C8                         mov eax, cs
///   48 89 C6                      mov rsi, rax
///   48 8B 44 24 E0                mov rax, qword ptr [rsp - 0x20]
///   48 89 C2                      mov rdx, rax
///   48 81 F2 <imm32 LE>           xor rdx, <salt32>
///   48 89 54 24 E8                mov qword ptr [rsp - 0x18], rdx
///   BF 02 00 00 00                mov edi, 2        (SYS_GETPID)
///   CD 80                         int 0x80
/// ```
///
/// Returns `(ring3_code, expected_arg0)`.
pub fn build_service_ring3_stub(
    svc: ServiceId,
    variant_seed: u64,
) -> ([u8; SVC_RING3_STUB_LEN], u64) {
    let salt32 = (((variant_seed as u32) ^ ((variant_seed >> 32) as u32)) & 0x7FFF_FF00)
        | (svc.pid() as u32);
    let b = salt32.to_le_bytes();
    let code: [u8; SVC_RING3_STUB_LEN] = [
        0x8C, 0xC8, // mov eax, cs
        0x48, 0x89, 0xC6, // mov rsi, rax
        0x48, 0x8B, 0x44, 0x24, 0xE0, // mov rax, [rsp - 0x20]
        0x48, 0x89, 0xC2, // mov rdx, rax
        0x48, 0x81, 0xF2, b[0], b[1], b[2], b[3], // xor rdx, salt32
        0x48, 0x89, 0x54, 0x24, 0xE8, // mov [rsp - 0x18], rdx
        0xBF, 0x02, 0x00, 0x00, 0x00, // mov edi, 2 (SYS_GETPID)
        0xCD, 0x80, // int 0x80
    ];
    (code, salt32 as u64)
}

/// Synthesize a morphed 64-bit ELF (`ELF64` + `PT_LOAD`) for `svc` parameterized by `variant_seed`.
///
/// The generated eBPF `.text` segment permutes its scratch registers (`r2..r5`), commutes setup
/// instructions, and folds `variant_seed` into cancelable immediate masks so every rotation
/// produces a genuinely distinct ELF binary and SHA-256 digest while preserving functional behavior.
pub fn build_service_elf(svc: ServiceId, variant_seed: u64, out: &mut [u8; SVC_ELF_CAP]) -> usize {
    let mov64_imm = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_MOV;
    let mov64_reg = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_MOV | bpf_op::BPF_SRC_X;
    let add64_imm = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_ADD;
    let sub64_imm = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_SUB;
    let xor64_reg = bpf_op::BPF_CLASS_ALU64 | bpf_op::BPF_OP_XOR | bpf_op::BPF_SRC_X;
    let exit_op = bpf_op::BPF_CLASS_JMP | bpf_op::BPF_OP_EXIT;

    let base_tag: i32 = match svc {
        ServiceId::Http => 0x4854_5450, // "HTTP"
        ServiceId::Sql => 0x5351_4C31,  // "SQL1"
        ServiceId::Shell => 0x5348_454C, // "SHEL"
    };
    let salt = ((variant_seed as i32) ^ ((variant_seed >> 32) as i32)) & 0x00FF_FFFF;
    // Rotate scratch register choice across {r2, r3, r4, r5} based on variant_seed.
    let scratch_a = 2u8 + ((variant_seed as u8) & 1);
    let scratch_b = 4u8 + (((variant_seed >> 1) as u8) & 1);

    // Commute setup order of r0 and scratch_a when bit 2 of variant_seed is set.
    let (i1, i2) = if (variant_seed & 4) == 0 {
        (
            BpfInstr::new(mov64_imm, 0, 0, 0, base_tag),
            BpfInstr::new(mov64_imm, scratch_a, 0, 0, salt),
        )
    } else {
        (
            BpfInstr::new(mov64_imm, scratch_a, 0, 0, salt),
            BpfInstr::new(mov64_imm, 0, 0, 0, base_tag),
        )
    };

    let insns = [
        BpfInstr::new(mov64_imm, 1, 0, 0, 1), // r1 = op_arg
        i1,
        i2,
        BpfInstr::new(mov64_reg, scratch_b, scratch_a, 0, 0),
        BpfInstr::new(add64_imm, 0, 0, 0, salt),
        BpfInstr::new(sub64_imm, 0, 0, 0, salt),
        BpfInstr::new(xor64_reg, scratch_a, scratch_b, 0, 0), // scratch_a = 0
        BpfInstr::new(xor64_reg, 0, scratch_a, 0, 0),         // r0 ^= 0
        BpfInstr::new(xor64_reg, 0, 1, 0, 0),                 // r0 = base_tag ^ op_arg
        BpfInstr::new(exit_op, 0, 0, 0, 0),
    ];

    let header_len = ELF_EHDR_LEN + ELF_PHDR_LEN;
    let code_len = insns.len() * 8;
    let total = header_len + code_len;
    if total > SVC_ELF_CAP {
        return 0;
    }
    let mut z = 0usize;
    while z < SVC_ELF_CAP {
        out[z] = 0;
        z += 1;
    }

    let entry = svc.user_va_base();
    out[0] = ELF_MAGIC[0];
    out[1] = ELF_MAGIC[1];
    out[2] = ELF_MAGIC[2];
    out[3] = ELF_MAGIC[3];
    out[4] = ELF_CLASS64;
    out[5] = ELF_DATA_LE;
    out[6] = 1;
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

fn record_svc_audit<const N: usize>(
    audit: &mut AuditLogImpl<N>,
    syscall_nr: u32,
    verdict: AuditVerdict,
    msg: &[u8],
) {
    let mut message = [0u8; AUDIT_MESSAGE_LEN];
    let n = msg.len().min(AUDIT_MESSAGE_LEN);
    let mut i = 0usize;
    while i < n {
        message[i] = msg[i];
        i += 1;
    }
    let _ = audit.append(AuditEvent {
        event_id: 0,
        wall_unix: audit.high_watermark().wrapping_add(1),
        task_id: 1, // init / service supervisor
        syscall_nr,
        verdict,
        message,
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_profiles_load_only_provisioned_services_and_zero_unused_memory() {
        let mut sup = ServiceSupervisor::empty();
        let mut audit: AuditLogImpl<16> = AuditLogImpl::new();

        // 1. WFE role loads ONLY svc-http; svc-sql and svc-sh are unloaded and zeroed in RAM.
        sup.init_role(NodeRole::Wfe, 100);
        assert_eq!(sup.running_count(), 1);
        assert_eq!(
            sup.services[ServiceId::Http.index()].state,
            ServiceState::Running
        );
        assert!(sup.services[ServiceId::Http.index()].elf_len > 0);
        assert_eq!(
            sup.services[ServiceId::Sql.index()].state,
            ServiceState::Unloaded
        );
        assert_eq!(sup.services[ServiceId::Sql.index()].elf_len, 0);
        assert_eq!(
            sup.services[ServiceId::Shell.index()].state,
            ServiceState::Unloaded
        );
        assert_eq!(sup.services[ServiceId::Shell.index()].elf_len, 0);

        // Calling SQL or Shell endpoints on a WFE-only node is refused with RoleDisabled!
        assert_eq!(
            sup.mediate_endpoint(IpcOp::SqlQuery, true, false, &mut audit),
            Err(ServiceError::RoleDisabled)
        );
        assert_eq!(
            sup.mediate_endpoint(IpcOp::ShellExec, true, true, &mut audit),
            Err(ServiceError::RoleDisabled)
        );
        // Calling HTTP dashboard / status on WFE node succeeds!
        assert!(sup
            .mediate_endpoint(IpcOp::HttpGetDashboard, true, false, &mut audit)
            .is_ok());

        // 2. SQL role loads ONLY svc-sql; svc-http and svc-sh are unloaded.
        sup.set_role(NodeRole::Sql, &mut audit);
        assert_eq!(sup.running_count(), 1);
        assert_eq!(
            sup.services[ServiceId::Http.index()].state,
            ServiceState::Unloaded
        );
        assert_eq!(
            sup.services[ServiceId::Sql.index()].state,
            ServiceState::Running
        );
        assert!(sup
            .mediate_endpoint(IpcOp::SqlQuery, false, false, &mut audit)
            .is_ok());
        assert_eq!(
            sup.mediate_endpoint(IpcOp::HttpGetDashboard, true, false, &mut audit),
            Err(ServiceError::RoleDisabled)
        );
    }

    #[test]
    fn deny_by_default_capability_and_seccomp_policy_blocks_cross_service_actions() {
        let mut sup = ServiceSupervisor::empty();
        let mut audit: AuditLogImpl<16> = AuditLogImpl::new();
        sup.init_role(NodeRole::Full, 42);

        // svc-http is denied direct block storage IO, file open, and exec:
        assert_eq!(
            sup.mediate_syscall(ServiceId::Http, SvcSyscall::StorageIo, &mut audit),
            Err(ServiceError::SeccompDenied)
        );
        assert_eq!(
            sup.mediate_syscall(ServiceId::Http, SvcSyscall::Open, &mut audit),
            Err(ServiceError::SeccompDenied)
        );
        assert_eq!(
            sup.mediate_syscall(ServiceId::Http, SvcSyscall::Exec, &mut audit),
            Err(ServiceError::SeccompDenied)
        );

        // svc-sql is denied raw network socket IO, file open, and exec:
        assert_eq!(
            sup.mediate_syscall(ServiceId::Sql, SvcSyscall::NetIo, &mut audit),
            Err(ServiceError::SeccompDenied)
        );
        assert_eq!(
            sup.mediate_syscall(ServiceId::Sql, SvcSyscall::Open, &mut audit),
            Err(ServiceError::SeccompDenied)
        );
        assert_eq!(
            sup.mediate_syscall(ServiceId::Sql, SvcSyscall::Exec, &mut audit),
            Err(ServiceError::SeccompDenied)
        );

        // svc-sh is denied raw network socket IO and SQL block storage IO:
        assert_eq!(
            sup.mediate_syscall(ServiceId::Shell, SvcSyscall::NetIo, &mut audit),
            Err(ServiceError::SeccompDenied)
        );
        assert_eq!(
            sup.mediate_syscall(ServiceId::Shell, SvcSyscall::StorageIo, &mut audit),
            Err(ServiceError::SeccompDenied)
        );
    }

    #[test]
    fn standing_credential_gate_refuses_every_protected_endpoint_without_session() {
        let mut sup = ServiceSupervisor::empty();
        let mut audit: AuditLogImpl<32> = AuditLogImpl::new();
        sup.init_role(NodeRole::Full, 77);

        let protected_ops = [
            IpcOp::SessionWhoami,
            IpcOp::SessionLogout,
            IpcOp::SqlMutate,
            IpcOp::ShellExec,
            IpcOp::UserElfExec,
            IpcOp::VfsWrite,
            IpcOp::VfsDelete,
        ];
        for op in protected_ops {
            assert_eq!(
                sup.mediate_endpoint(op, true, false, &mut audit),
                Err(ServiceError::Unauthenticated),
                "protected endpoint {:?} must be refused when session_verified == false",
                op
            );
        }

        // With verified session credentials, all protected endpoints succeed and record IPC:
        for op in protected_ops {
            assert!(
                sup.mediate_endpoint(op, true, true, &mut audit).is_ok(),
                "protected endpoint {:?} must succeed when session_verified == true",
                op
            );
        }
        assert!(sup.ipc_total >= 5);
    }

    #[test]
    fn independent_service_rotation_mutates_elf_digest_and_extends_pcr10() {
        let mut sup = ServiceSupervisor::empty();
        let mut audit: AuditLogImpl<16> = AuditLogImpl::new();
        sup.init_role(NodeRole::Full, 1);

        let dig_http_before = sup.services[ServiceId::Http.index()].elf_sha256;
        let dig_sql_before = sup.services[ServiceId::Sql.index()].elf_sha256;
        let pcr_before = sup.svc_pcr10;
        let meas_before = sup.svc_measurements;

        // Rotate ONLY svc-http with seed 9999:
        let dig_http_after = sup
            .rotate_service(ServiceId::Http, 9999, &mut audit)
            .expect("rotate svc-http");
        assert_ne!(
            dig_http_before, dig_http_after,
            "rotating svc-http must produce a new morphed ELF64 binary digest"
        );
        assert_eq!(
            sup.services[ServiceId::Sql.index()].elf_sha256,
            dig_sql_before,
            "rotating svc-http must not disturb svc-sql"
        );
        assert_eq!(sup.services[ServiceId::Http.index()].rotations, 1);
        assert_ne!(sup.svc_pcr10, pcr_before);
        assert_eq!(sup.svc_measurements, meas_before + 1);

        // Crash svc-sql and verify supervisor automatically restarts it on next SQL request:
        sup.simulate_crash(ServiceId::Sql, &mut audit).unwrap();
        assert_eq!(
            sup.services[ServiceId::Sql.index()].state,
            ServiceState::Faulted
        );
        assert!(sup
            .mediate_endpoint(IpcOp::SqlQuery, true, false, &mut audit)
            .is_ok());
        assert_eq!(
            sup.services[ServiceId::Sql.index()].state,
            ServiceState::Running
        );
        assert_eq!(sup.services[ServiceId::Sql.index()].restarts, 1);
    }

    #[test]
    fn distinct_device_keys_boot_distinct_service_variants_and_live_kpti_catches_corruption() {
        let mut audit: AuditLogImpl<16> = AuditLogImpl::new();
        let key_a = [0x11u8; DURABLE_DIGEST_LEN];
        let key_b = [0x22u8; DURABLE_DIGEST_LEN];
        let seed_a = derive_service_base_seed(&key_a);
        let seed_b = derive_service_base_seed(&key_b);
        assert_ne!(seed_a, seed_b);

        let mut sup_a = ServiceSupervisor::empty();
        let mut sup_b = ServiceSupervisor::empty();
        sup_a.init_role(NodeRole::Full, seed_a);
        sup_b.init_role(NodeRole::Full, seed_b);

        for i in 0..SERVICE_COUNT {
            assert_ne!(
                sup_a.services[i].elf_sha256, sup_b.services[i].elf_sha256,
                "nodes with distinct device keys must boot distinct service ELF variants"
            );
        }

        // Verify that corrupting a service's live `user_l4` page table (mapping KERNEL_SECRET_VA
        // or a peer service's VA) is immediately caught by `verify_all_kpti_isolated` and `mediate_syscall`:
        assert!(sup_a.verify_all_kpti_isolated());
        let _ = sup_a.services[ServiceId::Http.index()]
            .user_l4
            .map(KERNEL_SECRET_VA, PTE_PRESENT | PTE_USER);
        assert!(!sup_a.verify_all_kpti_isolated());
        assert_eq!(
            sup_a.mediate_syscall(ServiceId::Http, SvcSyscall::NetIo, &mut audit),
            Err(ServiceError::KptiIsolationFailed)
        );

        // Verify that an eBPF instruction that clobbers the stack canary slot `[r10 - 8]` inside `ctx.stack`
        // is caught by `StackCanaryImpl::verify` with `Err(ServiceError::SandboxTrap)`:
        let sql_idx = ServiceId::Sql.index();
        let header_len = ELF_EHDR_LEN + ELF_PHDR_LEN;
        let smash_insn = BpfInstr::new(bpf_op::BPF_CLASS_ST | bpf_op::BPF_SIZE_W, 10, 0, -8, 0x1337);
        let off = header_len + 3 * 8;
        sup_b.services[sql_idx].elf_image[off] = smash_insn.opcode;
        sup_b.services[sql_idx].elf_image[off + 1] = smash_insn.regs;
        sup_b.services[sql_idx].elf_image[off + 2..off + 4]
            .copy_from_slice(&smash_insn.offset.to_le_bytes());
        sup_b.services[sql_idx].elf_image[off + 4..off + 8]
            .copy_from_slice(&smash_insn.imm.to_le_bytes());
        let elf_len = sup_b.services[sql_idx].elf_len;
        let mut new_dig = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes(&sup_b.services[sql_idx].elf_image[..elf_len], &mut new_dig);
        sup_b.services[sql_idx].elf_sha256 = new_dig;
        assert_eq!(
            sup_b.mediate_endpoint(IpcOp::SqlQuery, true, false, &mut audit),
            Err(ServiceError::SandboxTrap)
        );
    }

    #[test]
    fn role_disabled_refusal_precedes_unauthenticated_across_all_roles() {
        let mut sup = ServiceSupervisor::empty();
        let mut audit: AuditLogImpl<32> = AuditLogImpl::new();

        // On a WFE node, unauthenticated calls to SQL or Shell return RoleDisabled (503),
        // while unauthenticated calls to protected HTTP session ops return Unauthenticated (401).
        sup.init_role(NodeRole::Wfe, 500);
        assert_eq!(
            sup.mediate_endpoint(IpcOp::SqlMutate, true, false, &mut audit),
            Err(ServiceError::RoleDisabled)
        );
        assert_eq!(
            sup.mediate_endpoint(IpcOp::ShellExec, true, false, &mut audit),
            Err(ServiceError::RoleDisabled)
        );
        assert_eq!(
            sup.mediate_endpoint(IpcOp::SessionWhoami, true, false, &mut audit),
            Err(ServiceError::Unauthenticated)
        );

        // On a SQL node, any HTTP gateway call returns RoleDisabled (503), and direct
        // unauthenticated SQL mutations return Unauthenticated (401).
        sup.set_role(NodeRole::Sql, &mut audit);
        assert_eq!(
            sup.mediate_endpoint(IpcOp::ShellExec, true, false, &mut audit),
            Err(ServiceError::RoleDisabled)
        );
        assert_eq!(
            sup.mediate_endpoint(IpcOp::SqlMutate, false, false, &mut audit),
            Err(ServiceError::Unauthenticated)
        );
    }

    #[test]
    fn per_boot_seed_rotation_and_ring3_stub_mailbox_tracking() {
        let mut audit: AuditLogImpl<16> = AuditLogImpl::new();
        let same_key = [0x42u8; DURABLE_DIGEST_LEN];
        let seed_boot1 = derive_service_base_seed_for_boot(&same_key, 1);
        let seed_boot2 = derive_service_base_seed_for_boot(&same_key, 2);
        assert_ne!(
            seed_boot1, seed_boot2,
            "rebooting a node with the same seal_key must mix boot_gen into a fresh service seed"
        );

        let mut sup1 = ServiceSupervisor::empty();
        let mut sup2 = ServiceSupervisor::empty();
        sup1.init_role(NodeRole::Full, seed_boot1);
        sup2.init_role(NodeRole::Full, seed_boot2);
        for i in 0..SERVICE_COUNT {
            assert_ne!(
                sup1.services[i].elf_sha256, sup2.services[i].elf_sha256,
                "consecutive boots on the same node must start with distinct service ELF variants"
            );
            assert_ne!(
                sup1.services[i].ring3_code, sup2.services[i].ring3_code,
                "consecutive boots must also diversify the CPL=3 x86-64 machine-code stub"
            );
            assert_eq!(sup1.services[i].mailbox.pml4_entries, 2);
        }

        let tag = sup1
            .mediate_endpoint(IpcOp::SqlQuery, true, false, &mut audit)
            .expect("mediate SqlQuery");
        let sql_mb = sup1.services[ServiceId::Sql.index()].mailbox;
        assert_eq!(sql_mb.req_seq, 1);
        assert_eq!(sql_mb.last_op, IpcOp::SqlQuery as u8);
        assert_eq!(sql_mb.resp_tag, tag);
    }
}
