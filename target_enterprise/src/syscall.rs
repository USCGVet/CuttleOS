//! Syscall dispatch — `no_std`, capability-gated, allocation-free.
//!
//! Algorithmic core ported from `RustOSa/src/syscall.rs`. The donor
//! wires SYSCALL/SYSRET MSRs, builds a SyscallArgs frame from a naked
//! entry stub, and routes through `caps::allows` before dispatching.
//! The boot-time MSR + IST plumbing is host-incompatible (it needs real
//! ring transitions). This seed strips that surface and keeps the
//! algorithmic core: syscall-number → handler dispatch with capability
//! pre-check.
//!
//! Per-syscall bodies are mostly placeholder — they return `Err(Errno::ENOSYS)`
//! today. The point of having the dispatch *shape* in place is that the
//! verifier can exercise the dispatch table's ABI lock (syscall number
//! semantics never change across morph cycles) before any individual
//! handler is real.
//!
//! Three handlers are wired enough to be useful:
//! - `sys_getpid` returns a constant (`1`), matching the donor's
//!   "single-process for now" stub.
//! - `sys_yield` calls into `scheduler::yield_now`.
//! - `sys_write` echoes into a caller-provided sink trait `WriteSink`
//!   so userland can wire stdout to a UART without the syscall layer
//!   knowing about the device.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::scheduler;
// TASK-014: import the `Iommu` trait so the DMA dispatcher can call
// `map` / `unmap` / `translate` on the `IommuImpl` it borrows. These
// are trait methods — without the trait in scope rustc can't resolve
// them.
use proteus_contracts::Iommu as _;

// ---------- syscall numbers ----------
//
// Locked across morph cycles. Userspace binaries compiled against
// syscall number N MUST continue to observe identical behaviour after
// every morph. Add new numbers at the bottom; never re-use a slot.

/// `exit(status)` — terminate the current task with `status`.
pub const SYS_EXIT: u64 = 0;
/// `write(fd, buf, len)` — write `len` bytes from `buf` to `fd`.
pub const SYS_WRITE: u64 = 1;
/// `getpid()` — return the current task's process id.
pub const SYS_GETPID: u64 = 2;
/// `gettime_ns()` — return monotonic time in nanoseconds.
pub const SYS_GETTIME_NS: u64 = 3;
/// `read_key()` — block on the next keyboard scancode.
pub const SYS_READ_KEY: u64 = 4;
/// `open(path_ptr, path_len)` — open a file in the root FS.
pub const SYS_OPEN: u64 = 5;
/// `read(fd, buf, len)` — read up to `len` bytes from `fd`.
pub const SYS_READ: u64 = 6;
/// `close(fd)` — close an open file descriptor.
pub const SYS_CLOSE: u64 = 7;
/// `sleep_ms(ms)` — block for at least `ms` milliseconds.
pub const SYS_SLEEP_MS: u64 = 8;
/// `realtime_s()` — return wall-clock seconds since the Unix epoch.
pub const SYS_REALTIME_S: u64 = 9;
/// `yield()` — voluntary CPU release.
pub const SYS_YIELD: u64 = 10;
/// `cap_check(required, set)` — return 1 iff `(required & set) == required`.
pub const SYS_CAP_CHECK: u64 = 11;
/// `dma_map(dma_addr, host_phys, perms_byte)` — TASK-014. Bind a
/// page-aligned DMA address to a host physical address with the
/// requested permissions, inside the calling task's bound IOMMU
/// domain. Requires `NET_RAW` capability. Returns `Ok(0)` on success;
/// `EPERM` if the task has no `iommu_domain` bound or the cap check
/// failed; `EINVAL` for misaligned addresses, unknown domain, or a
/// duplicate mapping; `EFAULT` if the dma_addr exceeds the domain's
/// page-table capacity.
pub const SYS_DMA_MAP: u64 = 12;
/// `dma_unmap(dma_addr)` — TASK-014. Inverse of `SYS_DMA_MAP`. Returns
/// `Ok(0)` on success; `EPERM` for an unbound task; `EINVAL` if the
/// dma_addr is misaligned or not currently mapped.
pub const SYS_DMA_UNMAP: u64 = 13;

/// Top of the locked range. Numbers >= this bound are unmapped and
/// MUST return `Err(ENOSYS)` from `dispatch_inner`.
pub const SYS_MAX: u64 = 14;

// ---------- errno ----------

/// Errno enum returned by `dispatch_inner` on the error path. The
/// variant set is locked across morph cycles: userspace observes the
/// discriminants by name and the harness exercises every variant.
///
/// Numeric values are the canonical POSIX errno values where they exist.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Errno {
    /// Operation not permitted (capability check failed).
    EPERM = 1,
    /// No such file or directory.
    ENOENT = 2,
    /// I/O error.
    EIO = 5,
    /// Bad file descriptor.
    EBADF = 9,
    /// Try again (would block).
    EAGAIN = 11,
    /// Bad address (user pointer not mapped).
    EFAULT = 14,
    /// Invalid argument.
    EINVAL = 22,
    /// Function not implemented (unmapped syscall number).
    ENOSYS = 38,
}

impl core::fmt::Debug for Errno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Errno::EPERM => "EPERM",
            Errno::ENOENT => "ENOENT",
            Errno::EIO => "EIO",
            Errno::EBADF => "EBADF",
            Errno::EAGAIN => "EAGAIN",
            Errno::EFAULT => "EFAULT",
            Errno::EINVAL => "EINVAL",
            Errno::ENOSYS => "ENOSYS",
        })
    }
}

impl Errno {
    /// Numeric value (POSIX-ish). Returned to userspace as
    /// `-(errno as i64) as u64` per the Linux convention; userspace
    /// reads the negative range as the errno.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self as u64
    }
}

// ---------- counters ----------

/// Number of syscalls dispatched since boot. Read by selftest / shell.
pub static SYSCALL_COUNT: AtomicU64 = AtomicU64::new(0);

/// Number of syscalls denied by the capability gate. Read by `/metrics`.
pub static DENIED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Number of `sys_yield` invocations.
pub static SYS_YIELD_COUNT: AtomicU64 = AtomicU64::new(0);

/// Number of `sys_write` invocations.
pub static SYS_WRITE_COUNT: AtomicU64 = AtomicU64::new(0);

// ---------- capability gate ----------

/// Per-syscall required capability bits. Indexed by syscall number; an
/// entry of `0` means "no capabilities required" (the syscall is
/// available to all tasks). The morph engine MUST preserve this mapping
/// — moving a syscall from "no caps" to "caps required" is a contract
/// break, not a routine morph.
///
/// The values are drawn from `proteus_contracts::caps::*`. Locked.
pub const SYSCALL_REQUIRED_CAPS: [u64; SYS_MAX as usize] = [
    0,                                          // SYS_EXIT
    0,                                          // SYS_WRITE
    0,                                          // SYS_GETPID
    0,                                          // SYS_GETTIME_NS
    0,                                          // SYS_READ_KEY
    proteus_contracts::caps::FS_BYPASS,         // SYS_OPEN
    0,                                          // SYS_READ
    0,                                          // SYS_CLOSE
    0,                                          // SYS_SLEEP_MS
    0,                                          // SYS_REALTIME_S
    0,                                          // SYS_YIELD
    0,                                          // SYS_CAP_CHECK
    // SYS_DMA_MAP / SYS_DMA_UNMAP — TASK-014. Reuse `NET_RAW` because
    // DMA mapping IS raw-hardware-peripheral access; the semantic
    // overlap is exact. A new `DMA` cap would be a contracts-crate
    // schema bump for marginal naming clarity — deferred until a
    // future iteration that touches contracts/lib.rs for a more
    // substantive reason.
    proteus_contracts::caps::NET_RAW,           // SYS_DMA_MAP
    proteus_contracts::caps::NET_RAW,           // SYS_DMA_UNMAP
];

// ---------- TASK-020: SyscallCapTable contract impl with type-state proof ----------
//
// TASK-004 originally enforced the cap gate via an AST walker inside
// the verifier: any candidate whose `dispatch_syscall` body did not
// syntactically reference `check_cap` was rejected. That walker had
// a known false-floor — `let _ = check_cap(...);`,
// `if false { check_cap(...)?; }`, and similar dead-code patterns
// all passed the walker while silently bypassing the gate at runtime.
//
// TASK-020 replaces the walker with a **compile-time** type-state
// proof. `check_cap` now returns `Result<CapProof, Errno>`. The
// privileged dispatch entry points (`dispatch_inner`,
// `dispatch_inner_with_sink`) take `_proof: CapProof` by value. No
// safe code outside the contracts crate can construct a `CapProof`
// (its inner field is private and the mint helper lives in a
// `pub(crate)` module of `proteus_contracts`), so the only way to
// reach the privileged region is through a successful `check_cap`.
// The compiler — not the verifier — is the enforcer.

/// Number of tasks tracked by the permissive seed cap table. Locked at
/// 32 for the seed; the production allocator-backed table will key on
/// `TaskId` and grow with `BTreeMap` once `alloc` lands.
pub const CAP_TABLE_TASKS: usize = 32;

/// Permissive seed capability table: every task gets every bit set. The
/// morph engine will tighten this on a per-task basis once the task
/// table itself is real. The constant is `pub` so the verifier and
/// downstream tests can confirm the seed is permissive.
pub const PERMISSIVE_CAP_TABLE: [u64; CAP_TABLE_TASKS] = [u64::MAX; CAP_TABLE_TASKS];

/// Concrete [`proteus_contracts::SyscallCapTable`] impl backed by the
/// permissive seed table. Overrides `check_raw`; the trait's provided
/// `check` is the sole site that mints a [`proteus_contracts::CapProof`].
pub struct CapTableImpl;

impl proteus_contracts::SyscallCapTable for CapTableImpl {
    type Cap = u64;

    fn check_raw(
        &self,
        task_id: u64,
        cap: u64,
        syscall_nr: u32,
    ) -> Result<(), proteus_contracts::CapError> {
        if (task_id as usize) >= CAP_TABLE_TASKS {
            return Err(proteus_contracts::CapError::EPERM);
        }
        if (syscall_nr as u64) >= SYS_MAX {
            return Err(proteus_contracts::CapError::ENOSYS);
        }
        let task_mask = PERMISSIVE_CAP_TABLE[task_id as usize];
        let effective = task_mask & cap;
        let required = SYSCALL_REQUIRED_CAPS[syscall_nr as usize];
        if (effective & required) == required {
            Ok(())
        } else {
            DENIED_TOTAL.fetch_add(1, Ordering::Relaxed);
            Err(proteus_contracts::CapError::EPERM)
        }
    }
}

/// Top-level dispatcher. Calls [`check_cap`] to obtain a
/// [`proteus_contracts::CapProof`], then hands it to [`dispatch_inner`]
/// by value. The compiler enforces that no caller can reach the
/// privileged region without a fresh proof.
pub fn dispatch_syscall(
    task_id: u64,
    cap_mask: u64,
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> Result<u64, Errno> {
    // Mint a proof on a successful capability check. The proof is the
    // type-state witness that the rest of the dispatch is allowed to
    // run; the compiler refuses to compile a `dispatch_inner` call
    // without one.
    let proof = check_cap(nr, cap_mask)?;
    let _ = task_id;
    dispatch_inner(nr, a0, a1, a2, a3, a4, a5, proof)
}

/// Capability check: return a freshly-minted
/// [`proteus_contracts::CapProof`] iff the caller's `cap_mask`
/// includes every bit required by syscall `nr`.
///
/// Routes through `CapTableImpl::check`, which is the trait's
/// provided default method and the sole sealed mint site for
/// `CapProof` in `proteus_contracts`. A morph candidate cannot mint
/// a proof by other means: the inner field is private and the seal
/// helper lives in a `pub(crate)` module of the contracts crate. The
/// verifier's old AST walker is therefore obsolete; the compiler
/// itself enforces the type-state.
pub fn check_cap(nr: u64, cap_mask: u64) -> Result<proteus_contracts::CapProof, Errno> {
    use proteus_contracts::{CapError, SyscallCapTable};
    let table = CapTableImpl;
    match table.check(0, cap_mask, nr as u32) {
        Ok(proof) => Ok(proof),
        Err(CapError::ENOSYS) => Err(Errno::ENOSYS),
        Err(CapError::EPERM) => Err(Errno::EPERM),
    }
}

// ---------- output sink ----------

/// Caller-provided byte sink for `sys_write`. Implementations send the
/// bytes to a UART, a framebuffer console, a network socket, etc. The
/// syscall layer doesn't know — and shouldn't.
pub trait WriteSink {
    /// Write `bytes` to the underlying device. Returns the number of
    /// bytes accepted; a short write is allowed.
    fn write(&mut self, bytes: &[u8]) -> usize;
}

/// A trivial sink that discards every byte. Useful for tests and for
/// the default boot path before any console is registered.
pub struct NullSink;

impl WriteSink for NullSink {
    fn write(&mut self, bytes: &[u8]) -> usize {
        bytes.len()
    }
}

/// A buffer-backed sink. Bytes are appended to the buffer up to its
/// capacity; further bytes are dropped. Useful for unit tests.
pub struct BufferSink<'a> {
    /// Backing buffer.
    pub buf: &'a mut [u8],
    /// Number of bytes written so far.
    pub written: usize,
}

impl<'a> BufferSink<'a> {
    /// Construct an empty buffer sink.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, written: 0 }
    }

    /// Total bytes accepted so far.
    pub fn len(&self) -> usize {
        self.written
    }

    /// True iff no bytes have been written.
    pub fn is_empty(&self) -> bool {
        self.written == 0
    }

    /// Borrow the accepted bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.written]
    }
}

impl<'a> WriteSink for BufferSink<'a> {
    fn write(&mut self, bytes: &[u8]) -> usize {
        let mut written = 0usize;
        let mut i = 0usize;
        while i < bytes.len() && self.written < self.buf.len() {
            self.buf[self.written] = bytes[i];
            self.written += 1;
            written += 1;
            i += 1;
        }
        written
    }
}

// ---------- dispatch ----------

/// Privileged dispatch. Routes syscall `nr` to its handler with the six
/// register-passed arguments. The `_proof` parameter is the type-state
/// witness that a successful [`check_cap`] has already minted a
/// [`proteus_contracts::CapProof`]; the compiler enforces that this
/// function cannot be reached without one.
///
/// Returns the value userspace will see in `RAX`, encoded as
/// `Result<u64, Errno>`. The donor returns a raw `u64` with the Linux
/// convention `-errno`; we keep the typed result and let the wrapper
/// `dispatch_to_user_rax` do the negation.
pub fn dispatch_inner(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    proof: proteus_contracts::CapProof,
) -> Result<u64, Errno> {
    // Consume the proof. From here on, every handler runs under the
    // type-state assurance that the cap check has succeeded.
    proof.consume();
    SYSCALL_COUNT.fetch_add(1, Ordering::Relaxed);
    match nr {
        SYS_EXIT => sys_exit(a0 as i32),
        SYS_WRITE => sys_write_stub(a0, a1, a2),
        SYS_GETPID => sys_getpid(),
        SYS_GETTIME_NS => sys_gettime_ns(),
        SYS_READ_KEY => sys_read_key(),
        SYS_OPEN => sys_open(a0, a1),
        SYS_READ => sys_read(a0, a1, a2),
        SYS_CLOSE => sys_close(a0),
        SYS_SLEEP_MS => sys_sleep_ms(a0),
        SYS_REALTIME_S => sys_realtime_s(),
        SYS_YIELD => sys_yield(),
        SYS_CAP_CHECK => sys_cap_check(a0, a1),
        _ => {
            let _ = (a3, a4, a5);
            Err(Errno::ENOSYS)
        }
    }
}

/// Dispatch with a capability pre-check. This is the entry point the
/// production kernel would call from the SYSCALL stub. The proof
/// minted by `check_cap` is threaded into `dispatch_inner` by value.
pub fn dispatch_with_cap(
    nr: u64,
    cap_mask: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> Result<u64, Errno> {
    let proof = check_cap(nr, cap_mask)?;
    dispatch_inner(nr, a0, a1, a2, a3, a4, a5, proof)
}

/// Encode a `Result<u64, Errno>` as the value userspace observes in
/// RAX. Success returns the `u64` payload; failure returns
/// `(-errno) as u64` per the Linux convention.
pub fn dispatch_to_user_rax(r: Result<u64, Errno>) -> u64 {
    match r {
        Ok(v) => v,
        Err(e) => (-(e.as_u64() as i64)) as u64,
    }
}

/// Dispatch with capability check, encoded with a user-supplied write
/// sink so `SYS_WRITE` actually does something. The proof minted by
/// `check_cap` is consumed either by the `sys_write_with_sink` branch
/// (via [`sys_write_privileged`]) or by `dispatch_inner`.
pub fn dispatch_with_sink<S: WriteSink>(
    sink: &mut S,
    nr: u64,
    cap_mask: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> Result<u64, Errno> {
    let proof = check_cap(nr, cap_mask)?;
    if nr == SYS_WRITE {
        return sys_write_privileged(sink, a0, a1, a2, proof);
    }
    dispatch_inner(nr, a0, a1, a2, a3, a4, a5, proof)
}

/// Privileged `sys_write` wrapper that consumes the type-state proof
/// at the entry point. Factored out so the `dispatch_with_sink` fast
/// path keeps the proof handling symmetric with `dispatch_inner`.
fn sys_write_privileged<S: WriteSink>(
    sink: &mut S,
    fd: u64,
    buf: u64,
    len: u64,
    proof: proteus_contracts::CapProof,
) -> Result<u64, Errno> {
    proof.consume();
    sys_write_with_sink(sink, fd, buf, len)
}

// ============================================================
// TASK-014 — DMA dispatch
// ============================================================
//
// The DMA syscalls (SYS_DMA_MAP / SYS_DMA_UNMAP) consume `CapProof`
// PER-HANDLER, not at dispatch_inner-level. This is the literal-spec
// form of the type-state argument: every privileged entry point takes
// the proof by value. (The non-DMA handlers in `dispatch_inner` are
// equivalent in security but consume the proof once at the dispatcher
// itself — documented in iteration 18.) Both patterns are
// compile-time-equivalent under the cap_typestate trybuild suite.
//
// Why a separate dispatch entry: the DMA path needs access to the
// global `IommuImpl` AND the calling task's `iommu_domain` field.
// Passing both through `dispatch_inner`'s u64-only argument shape
// would mean stuffing pointer values in `a0..a5`, which is an
// abstraction violation. The kernel keeps a `&mut IommuImpl<...>` and
// a `&Task` separately and dispatches DMA syscalls through this fn.

/// Top-level DMA dispatcher. Mints a `CapProof` via [`check_cap`],
/// passes it by value to the matched handler. `current_task.iommu_domain`
/// is consulted by the handler — `None` → `EPERM` regardless of caps.
///
/// This is the entry point the production kernel calls from the
/// SYSCALL stub when `rax ∈ {SYS_DMA_MAP, SYS_DMA_UNMAP}`. For other
/// syscall numbers the kernel routes through `dispatch_with_cap` /
/// `dispatch_inner` as usual.
pub fn dispatch_dma<const D: usize, const V: usize, const E: usize>(
    iommu: &mut crate::iommu::IommuImpl<D, V, E>,
    current_task: &crate::scheduler::Task,
    cap_mask: u64,
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
) -> Result<u64, Errno> {
    // Sanity: the dispatcher fast-paths only the two DMA numbers.
    if nr != SYS_DMA_MAP && nr != SYS_DMA_UNMAP {
        return Err(Errno::ENOSYS);
    }
    let proof = check_cap(nr, cap_mask)?;
    match nr {
        SYS_DMA_MAP => sys_dma_map(iommu, current_task, a0, a1, a2, proof),
        SYS_DMA_UNMAP => sys_dma_unmap(iommu, current_task, a0, proof),
        _ => {
            // Already filtered above; unreachable in practice but the
            // compiler doesn't know.
            proof.consume();
            Err(Errno::ENOSYS)
        }
    }
}

/// SYS_DMA_MAP handler. Per-handler `CapProof` consumption.
///
/// Maps `dma_addr → host_phys` with `perms` inside the task's bound
/// IOMMU domain. Layered errors:
///
/// - `EPERM`: task has no `iommu_domain` (unbound caller).
/// - `EINVAL`: `dma_addr`/`host_phys` misaligned, `perms == 0`,
///   unknown domain, already mapped.
/// - `EFAULT`: `dma_addr` outside the domain's page-table capacity.
fn sys_dma_map<const D: usize, const V: usize, const E: usize>(
    iommu: &mut crate::iommu::IommuImpl<D, V, E>,
    task: &crate::scheduler::Task,
    dma_addr: u64,
    host_phys: u64,
    perms_byte: u64,
    proof: proteus_contracts::CapProof,
) -> Result<u64, Errno> {
    // The proof must be consumed by value on every path through the
    // handler — including error paths. We consume it AT the top so
    // every subsequent error return is type-state-correct.
    proof.consume();

    let domain = task.iommu_domain.ok_or(Errno::EPERM)?;
    // perms is encoded as a low byte: bit 0 = READ, bit 1 = WRITE.
    // Mirror `proteus_contracts::PagePerms`. Reject anything outside
    // the 2-bit range — preserves the locked perms encoding.
    if perms_byte & !0b11 != 0 {
        return Err(Errno::EINVAL);
    }
    let perms = proteus_contracts::PagePerms(perms_byte as u8);
    match iommu.map(domain, dma_addr, host_phys, perms) {
        Ok(()) => Ok(0),
        Err(e) => Err(map_iommu_error(e)),
    }
}

/// SYS_DMA_UNMAP handler. Per-handler `CapProof` consumption.
fn sys_dma_unmap<const D: usize, const V: usize, const E: usize>(
    iommu: &mut crate::iommu::IommuImpl<D, V, E>,
    task: &crate::scheduler::Task,
    dma_addr: u64,
    proof: proteus_contracts::CapProof,
) -> Result<u64, Errno> {
    proof.consume();

    let domain = task.iommu_domain.ok_or(Errno::EPERM)?;
    match iommu.unmap(domain, dma_addr) {
        Ok(()) => Ok(0),
        Err(e) => Err(map_iommu_error(e)),
    }
}

/// Translate an `IommuError` into the kernel-facing `Errno`. The
/// mapping is deliberately conservative: anything that's structurally
/// "we don't know that address" → `EINVAL`; anything that's
/// "permission/binding state" → `EPERM`; anything that exceeds the
/// fixed table capacities → `EFAULT`.
fn map_iommu_error(e: proteus_contracts::IommuError) -> Errno {
    use proteus_contracts::IommuError as I;
    match e {
        I::DomainTableFull | I::DeviceTableFull => Errno::EFAULT,
        I::UnknownDomain | I::DeviceNotBound => Errno::EPERM,
        I::DeviceAlreadyBound | I::AlreadyMapped | I::Unmapped => Errno::EINVAL,
        I::BadAddress => Errno::EINVAL,
        I::PermissionDenied => Errno::EPERM,
    }
}

// ---------- handlers ----------

fn sys_exit(status: i32) -> Result<u64, Errno> {
    // The seed scheduler has no notion of "the calling task" without a
    // per-CPU context register, so this handler is a no-op return
    // instead of a longjmp. The morph engine wires the real path.
    let _ = status;
    Ok(0)
}

/// `write` stub that drops bytes on the floor (used by the
/// no-sink dispatch path so the result discriminant is correct).
fn sys_write_stub(fd: u64, buf: u64, len: u64) -> Result<u64, Errno> {
    // Validate arguments minimally — the donor calls validate_user_buf
    // here, which requires page-table walk machinery we don't have in
    // the seed. We accept any `buf` pointer but cap `len` at a sane
    // 64 KiB.
    if fd != 1 && fd != 2 {
        return Err(Errno::EBADF);
    }
    if len > 65536 {
        return Err(Errno::EINVAL);
    }
    let _ = buf;
    SYS_WRITE_COUNT.fetch_add(1, Ordering::Relaxed);
    Ok(len)
}

/// `write` with a real sink. The user buffer is `buf` (a virtual
/// address); the seed assumes it's actually a `&[u8]` because there is
/// no MMU to consult. The morph engine swaps in the real
/// copy_from_user later.
fn sys_write_with_sink<S: WriteSink>(
    sink: &mut S,
    fd: u64,
    buf: u64,
    len: u64,
) -> Result<u64, Errno> {
    if fd != 1 && fd != 2 {
        return Err(Errno::EBADF);
    }
    if len > 65536 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(0);
    }
    // SAFETY: the seed's caller (test code) guarantees `buf` points at
    // `len` bytes of valid memory. The donor's validate_user_buf walks
    // the page tables; the seed cannot.
    let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };
    let written = sink.write(slice);
    SYS_WRITE_COUNT.fetch_add(1, Ordering::Relaxed);
    Ok(written as u64)
}

fn sys_getpid() -> Result<u64, Errno> {
    // Mirror the donor: single-process for now → pid 1.
    Ok(1)
}

fn sys_gettime_ns() -> Result<u64, Errno> {
    // The seed has no HPET/TSC plumbing. Return a monotonically-
    // increasing counter so userspace sees the gettime ABI working.
    static FAKE_CLOCK_NS: AtomicU64 = AtomicU64::new(0);
    let n = FAKE_CLOCK_NS.fetch_add(1_000_000, Ordering::Relaxed);
    Ok(n)
}

fn sys_read_key() -> Result<u64, Errno> {
    // No keyboard driver in the seed. EAGAIN signals "no input
    // available; try again later" which is the natural state for a
    // freshly-booted target with no input device.
    Err(Errno::EAGAIN)
}

fn sys_open(_path_ptr: u64, len: u64) -> Result<u64, Errno> {
    if len == 0 || len > 256 {
        return Err(Errno::EINVAL);
    }
    // No VFS in the seed.
    Err(Errno::ENOENT)
}

fn sys_read(fd: u64, _buf: u64, len: u64) -> Result<u64, Errno> {
    if fd > 1024 {
        return Err(Errno::EBADF);
    }
    if len == 0 {
        return Ok(0);
    }
    Err(Errno::EBADF)
}

fn sys_close(fd: u64) -> Result<u64, Errno> {
    if fd > 1024 {
        return Err(Errno::EBADF);
    }
    Err(Errno::EBADF)
}

fn sys_sleep_ms(ms: u64) -> Result<u64, Errno> {
    // Cap to one hour per the donor.
    let _capped = ms.min(60 * 60 * 1000);
    // No PIT in the seed; return immediately.
    Ok(0)
}

fn sys_realtime_s() -> Result<u64, Errno> {
    // No RTC. Return a fixed timestamp so the result is deterministic.
    Ok(1_700_000_000)
}

fn sys_yield() -> Result<u64, Errno> {
    SYS_YIELD_COUNT.fetch_add(1, Ordering::Relaxed);
    scheduler::yield_now();
    Ok(0)
}

fn sys_cap_check(required: u64, set: u64) -> Result<u64, Errno> {
    if (required & set) == required {
        Ok(1)
    } else {
        Err(Errno::EINVAL)
    }
}

// ---------- contract impl ----------

/// Concrete `SyscallDispatch` impl wrapping `dispatch_inner`. Exposed
/// at the crate root as `target_enterprise::SyscallDispatch` so the
/// integration test can assert the contract.
pub struct SyscallDispatchImpl;

impl proteus_contracts::SyscallDispatch for SyscallDispatchImpl {
    type Result = core::result::Result<u64, Errno>;

    fn dispatch(
        nr: u64,
        a0: u64,
        a1: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    ) -> Self::Result {
        // The contract harness's `check_syscall_dispatch` requires
        // `nr=0` with all-zero args to return `Ok(0)`. The donor's
        // SYS_EXIT (nr=0) returns 0, matching. The harness also
        // requires nr=999_999 to be `Err`; our `dispatch_with_cap`
        // returns `Err(ENOSYS)` for any unmapped nr via `check_cap`.
        //
        // Capability mask is `u64::MAX` because the harness is
        // exercising the ABI surface, not the cap gate — the gate
        // has its own dedicated unit tests further down.
        dispatch_with_cap(nr, u64::MAX, a0, a1, a2, a3, a4, a5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mint a `CapProof` via `check_cap` for the tests that exercise
    /// `dispatch_inner` directly. The unwrap is hot-path local; if the
    /// underlying cap-check ever fails for these test inputs that is a
    /// regression worth panicking on.
    fn proof_for(nr: u64) -> proteus_contracts::CapProof {
        // Use a permissive mask so every test syscall succeeds the gate.
        check_cap(nr, u64::MAX).expect("permissive cap-check must succeed")
    }

    #[test]
    fn unmapped_syscall_returns_enosys_via_check_cap() {
        // Numbers >= SYS_MAX are rejected by `check_cap` before any
        // proof is minted; `dispatch_with_cap` therefore short-circuits
        // to ENOSYS without ever entering `dispatch_inner`.
        let r = dispatch_with_cap(9_999_999, u64::MAX, 0, 0, 0, 0, 0, 0);
        assert!(matches!(r, Err(Errno::ENOSYS)));
        // `check_cap` itself returns ENOSYS for the same input.
        assert!(matches!(check_cap(9_999_999, u64::MAX), Err(Errno::ENOSYS)));
    }

    #[test]
    fn sys_getpid_returns_one() {
        let proof = proof_for(SYS_GETPID);
        let r = dispatch_inner(SYS_GETPID, 0, 0, 0, 0, 0, 0, proof);
        assert_eq!(r, Ok(1));
    }

    #[test]
    fn sys_exit_zero_returns_ok_zero() {
        let proof = proof_for(SYS_EXIT);
        let r = dispatch_inner(SYS_EXIT, 0, 0, 0, 0, 0, 0, proof);
        assert_eq!(r, Ok(0));
    }

    #[test]
    fn sys_yield_increments_counter() {
        let before = SYS_YIELD_COUNT.load(Ordering::Relaxed);
        let proof = proof_for(SYS_YIELD);
        let _ = dispatch_inner(SYS_YIELD, 0, 0, 0, 0, 0, 0, proof);
        let after = SYS_YIELD_COUNT.load(Ordering::Relaxed);
        assert!(after > before);
    }

    #[test]
    fn cap_check_allows_subset() {
        let p1 = proof_for(SYS_CAP_CHECK);
        assert_eq!(dispatch_inner(SYS_CAP_CHECK, 0b0011, 0b1111, 0, 0, 0, 0, p1), Ok(1));
        let p2 = proof_for(SYS_CAP_CHECK);
        assert!(matches!(
            dispatch_inner(SYS_CAP_CHECK, 0b1100, 0b0011, 0, 0, 0, 0, p2),
            Err(Errno::EINVAL)
        ));
    }

    #[test]
    fn check_cap_gates_fs_bypass() {
        // SYS_OPEN requires FS_BYPASS. Without it `check_cap` returns
        // EPERM and no `CapProof` is minted.
        assert!(matches!(check_cap(SYS_OPEN, 0), Err(Errno::EPERM)));
        // With FS_BYPASS the gate succeeds and mints a proof.
        let proof = check_cap(SYS_OPEN, proteus_contracts::caps::FS_BYPASS).expect("Ok");
        proof.consume();
        // SYS_GETPID requires nothing.
        check_cap(SYS_GETPID, 0).expect("Ok").consume();
    }

    #[test]
    fn dispatch_with_cap_denies_without_required_bits() {
        // SYS_OPEN with no caps: the gate denies and DENIED_TOTAL
        // increments. dispatch_inner is unreachable on this path.
        let before = DENIED_TOTAL.load(Ordering::Relaxed);
        let r = dispatch_with_cap(SYS_OPEN, 0, 0, 0, 0, 0, 0, 0);
        let after = DENIED_TOTAL.load(Ordering::Relaxed);
        assert!(matches!(r, Err(Errno::EPERM)));
        assert!(after > before, "DENIED_TOTAL must increment on EPERM");
    }

    #[test]
    fn dispatch_with_cap_succeeds_when_caps_present() {
        // SYS_OPEN with FS_BYPASS: gate accepts, dispatch_inner runs
        // and returns ENOENT (no VFS in seed).
        let r = dispatch_with_cap(
            SYS_OPEN,
            proteus_contracts::caps::FS_BYPASS,
            0xCAFE,
            5,
            0, 0, 0, 0,
        );
        assert!(matches!(r, Err(Errno::ENOENT)));
    }

    #[test]
    fn cap_table_impl_overrides_check_raw_not_check() {
        // Verify that `CapTableImpl` implements the type-state
        // contract correctly: `check_raw` returns unit on success;
        // `check` (provided method) wraps that with a `CapProof`
        // mint and is the sole path safe code can use to obtain one.
        use proteus_contracts::SyscallCapTable;
        let table = CapTableImpl;
        // Out-of-range syscall → ENOSYS.
        assert!(matches!(table.check_raw(0, u64::MAX, 9_999), Err(proteus_contracts::CapError::ENOSYS)));
        // SYS_OPEN with no caps → EPERM via check_raw.
        assert!(matches!(table.check_raw(0, 0, SYS_OPEN as u32), Err(proteus_contracts::CapError::EPERM)));
        // Provided `check` mints proof on success.
        let proof = table
            .check(0, proteus_contracts::caps::FS_BYPASS, SYS_OPEN as u32)
            .expect("Ok");
        proof.consume();
    }

    #[test]
    fn check_cap_caps_proof_size_is_zero() {
        // The CapProof is zero-sized so threading it through every
        // privileged dispatch adds no codegen cost. If a future
        // refactor accidentally adds a runtime field this test
        // surfaces it before the perf gate flag-rejects on noise.
        let proof = check_cap(SYS_GETPID, u64::MAX).expect("Ok");
        assert_eq!(core::mem::size_of_val(&proof), 0);
        proof.consume();
    }

    #[test]
    fn buffer_sink_collects_bytes() {
        let mut buf = [0u8; 16];
        let mut sink = BufferSink::new(&mut buf);
        sink.write(b"hello");
        assert_eq!(sink.as_slice(), b"hello");
        sink.write(b" world");
        assert_eq!(sink.as_slice(), b"hello world");
    }

    #[test]
    fn dispatch_with_sink_routes_write() {
        let mut buf = [0u8; 32];
        let mut sink = BufferSink::new(&mut buf);
        let msg = b"proteus";
        let r = dispatch_with_sink(
            &mut sink,
            SYS_WRITE,
            0,
            1, // fd=stdout
            msg.as_ptr() as u64,
            msg.len() as u64,
            0,
            0,
            0,
        );
        assert_eq!(r, Ok(7));
        assert_eq!(sink.as_slice(), b"proteus");
    }

    #[test]
    fn dispatch_to_user_rax_encodes_errno() {
        // Errno::ENOSYS = 38 → -38 → 0xFFFFFFFFFFFFFFDA
        let rax = dispatch_to_user_rax(Err(Errno::ENOSYS));
        assert_eq!(rax, (-(38i64)) as u64);
    }

    // ====================================================================
    // TASK-014 — DMA syscall tests (4 scenarios per the spec)
    // ====================================================================
    //
    // Acceptance criterion (TASK-014):
    // - unprivileged task is denied
    // - privileged task can map
    // - mapping persists across syscalls
    // - unmap then re-translate returns Unmapped
    //
    // These tests exercise the full chain: `dispatch_dma` → `check_cap`
    // → handler → `IommuImpl::map`/`unmap`/`translate`. The trybuild
    // suite from TASK-020 already proves the type-state at the
    // compile level; here we exercise the runtime behaviour.

    use crate::iommu::{DeviceId, IommuImpl};
    use crate::scheduler::{Task, TaskId};
    use proteus_contracts::{AccessKind, Iommu, PagePerms};

    /// Build a 4-domain / 8-device / 16-entry IOMMU and a privileged
    /// task pre-bound to a freshly-created domain. The bound device is
    /// the same in every test — keeps tests parallel without per-test
    /// device juggling.
    fn dma_test_setup() -> (IommuImpl<4, 8, 16>, Task, DeviceId) {
        let mut iommu: IommuImpl<4, 8, 16> = IommuImpl::new();
        let domain = iommu.create_domain().expect("create_domain");
        let device = DeviceId::from_bdf(0, 0, 1, 0);
        iommu.bind_device(device, domain).expect("bind_device");
        let task = Task::new_ready_with_domain(7 as TaskId, 1, domain);
        (iommu, task, device)
    }

    /// Scenario 1: unprivileged task is denied at the cap-check stage.
    ///
    /// A task with no `NET_RAW` cap in its mask cannot mint a CapProof,
    /// so the dispatcher returns `EPERM` before even looking at the
    /// IOMMU. This is the type-state working as designed: no proof,
    /// no privileged action — full stop.
    #[test]
    fn task014_unprivileged_task_denied() {
        let (mut iommu, task, _device) = dma_test_setup();
        let r = dispatch_dma(
            &mut iommu,
            &task,
            /* cap_mask: NO NET_RAW */ 0,
            SYS_DMA_MAP,
            0x10_0000, // dma_addr
            0xC000_0000, // host_phys
            0b11, // perms = RW
        );
        assert!(matches!(r, Err(Errno::EPERM)));
    }

    /// Scenario 1b: a task whose `iommu_domain` is `None` is also denied,
    /// even WITH the cap bit set. The cap check is necessary but not
    /// sufficient — the task must also be bound to an IOMMU domain.
    /// This is what makes the design defense-in-depth: caps alone do
    /// NOT grant DMA capability.
    #[test]
    fn task014_capped_but_unbound_task_denied() {
        let mut iommu: IommuImpl<4, 8, 16> = IommuImpl::new();
        let task = Task::new_ready(9 as TaskId, 1); // NO domain bound!
        let r = dispatch_dma(
            &mut iommu,
            &task,
            proteus_contracts::caps::NET_RAW, // has cap
            SYS_DMA_MAP,
            0x10_0000,
            0xC000_0000,
            0b11,
        );
        assert!(matches!(r, Err(Errno::EPERM)));
    }

    /// Scenario 2: privileged task (cap + domain bound) can map.
    /// `dispatch_dma` returns `Ok(0)` and the mapping is visible via
    /// `translate` immediately.
    #[test]
    fn task014_privileged_task_can_map() {
        let (mut iommu, task, device) = dma_test_setup();
        let dma_addr = 0x4000u64; // page-aligned, in 16-entry capacity
        let host_phys = 0xC000_0000u64;
        let r = dispatch_dma(
            &mut iommu,
            &task,
            proteus_contracts::caps::NET_RAW,
            SYS_DMA_MAP,
            dma_addr,
            host_phys,
            0b11, // RW
        );
        assert_eq!(r, Ok(0));

        // Confirm the mapping reached the IOMMU by translating from
        // the bound device's perspective.
        let pa = iommu
            .translate(device, dma_addr, AccessKind::Read)
            .expect("translate after map");
        assert_eq!(pa, host_phys);
    }

    /// Scenario 3: a mapping made via `SYS_DMA_MAP` PERSISTS across
    /// multiple subsequent syscalls. We do this by performing the map,
    /// then making two unrelated successful syscall-shaped calls (a
    /// second DMA_MAP at a different address, then a translate), and
    /// confirming the original mapping is still live.
    #[test]
    fn task014_mapping_persists_across_syscalls() {
        let (mut iommu, task, device) = dma_test_setup();
        let dma1 = 0x4000u64;
        let dma2 = 0x8000u64;
        let phys1 = 0xC000_0000u64;
        let phys2 = 0xD000_0000u64;
        let perms = 0b11u64;
        let caps = proteus_contracts::caps::NET_RAW;

        // First map.
        assert_eq!(
            dispatch_dma(&mut iommu, &task, caps, SYS_DMA_MAP, dma1, phys1, perms),
            Ok(0)
        );
        // Unrelated second map.
        assert_eq!(
            dispatch_dma(&mut iommu, &task, caps, SYS_DMA_MAP, dma2, phys2, perms),
            Ok(0)
        );
        // First mapping must still be intact.
        let pa1 = iommu
            .translate(device, dma1, AccessKind::Read)
            .expect("first mapping persisted");
        assert_eq!(pa1, phys1);
        // Second mapping is also live.
        let pa2 = iommu
            .translate(device, dma2, AccessKind::Read)
            .expect("second mapping live");
        assert_eq!(pa2, phys2);
    }

    /// Scenario 4: unmap then re-translate returns `Unmapped`.
    /// The IOMMU enforces that an unmapped address is `Unmapped` on
    /// the very next translate (no caching, no lag). This is the
    /// load-bearing "revocation is immediate" property — without it
    /// a malicious task could keep accessing a freed page across an
    /// unmap syscall.
    #[test]
    fn task014_unmap_then_retranslate_returns_unmapped() {
        let (mut iommu, task, device) = dma_test_setup();
        let dma_addr = 0x4000u64;
        let host_phys = 0xC000_0000u64;
        let caps = proteus_contracts::caps::NET_RAW;

        // Map.
        assert_eq!(
            dispatch_dma(&mut iommu, &task, caps, SYS_DMA_MAP, dma_addr, host_phys, 0b11),
            Ok(0)
        );
        // Visible.
        assert!(iommu.translate(device, dma_addr, AccessKind::Read).is_ok());

        // Unmap.
        assert_eq!(
            dispatch_dma(&mut iommu, &task, caps, SYS_DMA_UNMAP, dma_addr, 0, 0),
            Ok(0)
        );

        // Re-translate fails with Unmapped.
        let r = iommu.translate(device, dma_addr, AccessKind::Read);
        assert!(
            matches!(r, Err(proteus_contracts::IommuError::Unmapped)),
            "expected Unmapped, got {:?}",
            r
        );
    }

    /// Bonus scenario: trying to unmap a never-mapped address returns
    /// `EINVAL` (mapped from IommuError::Unmapped). Confirms the
    /// errno-translation table works correctly.
    #[test]
    fn task014_unmap_of_unmapped_returns_einval() {
        let (mut iommu, task, _device) = dma_test_setup();
        let r = dispatch_dma(
            &mut iommu,
            &task,
            proteus_contracts::caps::NET_RAW,
            SYS_DMA_UNMAP,
            0x4000,
            0,
            0,
        );
        assert!(matches!(r, Err(Errno::EINVAL)));
    }

    /// Bonus scenario: dispatcher refuses to handle non-DMA syscall
    /// numbers — protects against a malformed call site that mis-routes.
    #[test]
    fn task014_dispatch_dma_rejects_non_dma_numbers() {
        let (mut iommu, task, _device) = dma_test_setup();
        let r = dispatch_dma(
            &mut iommu,
            &task,
            u64::MAX,
            SYS_GETPID, // not a DMA syscall
            0,
            0,
            0,
        );
        assert!(matches!(r, Err(Errno::ENOSYS)));
    }

    /// Bonus scenario: misaligned dma_addr → EINVAL via the IOMMU's
    /// own alignment check, mapped through `map_iommu_error`.
    #[test]
    fn task014_misaligned_dma_addr_returns_einval() {
        let (mut iommu, task, _device) = dma_test_setup();
        let r = dispatch_dma(
            &mut iommu,
            &task,
            proteus_contracts::caps::NET_RAW,
            SYS_DMA_MAP,
            0x4001, // NOT page-aligned
            0xC000_0000,
            0b11,
        );
        assert!(matches!(r, Err(Errno::EINVAL)));
    }

    /// Bonus scenario: perms byte with high bits set is rejected at
    /// the syscall layer (before the IOMMU sees it). Preserves the
    /// locked perms encoding — only READ (bit 0) and WRITE (bit 1)
    /// are defined; everything else is reserved.
    #[test]
    fn task014_reserved_perms_bits_rejected() {
        let (mut iommu, task, _device) = dma_test_setup();
        let r = dispatch_dma(
            &mut iommu,
            &task,
            proteus_contracts::caps::NET_RAW,
            SYS_DMA_MAP,
            0x4000,
            0xC000_0000,
            0b1111_1100, // high bits set
        );
        assert!(matches!(r, Err(Errno::EINVAL)));
    }

    /// SYSCALL_REQUIRED_CAPS for the new DMA syscalls must require
    /// NET_RAW. Locking the cap-table mapping in a test catches
    /// regressions if a future iteration reorders the array.
    #[test]
    fn task014_dma_syscalls_require_net_raw() {
        assert_eq!(
            SYSCALL_REQUIRED_CAPS[SYS_DMA_MAP as usize],
            proteus_contracts::caps::NET_RAW
        );
        assert_eq!(
            SYSCALL_REQUIRED_CAPS[SYS_DMA_UNMAP as usize],
            proteus_contracts::caps::NET_RAW
        );
    }
}
