//! Round-robin task scheduler — `no_std`, fixed-capacity, allocation-free.
//!
//! Algorithmic core lifted from `RustOSa/src/scheduler.rs`. The donor
//! is multi-CPU with per-CPU `spin::Mutex<Vec<fn()>>` queues, APIC IPI
//! wake-ups, and `alloc::Vec` storage. That whole surface is host-
//! incompatible because it requires real LAPIC hardware and a heap.
//!
//! This seed exposes the **algorithmic core** of a single-CPU round-
//! robin scheduler over a caller-supplied `[Task; N]` slot pool, where
//! `N` is a const generic. Every queue operation is O(N) in the worst
//! case but constant-time amortised; no allocation occurs. The morph
//! engine will later layer the per-CPU multi-queue + IPI wake path on
//! top of this surface.
//!
//! Invariants the verifier checks (matched against the donor's behaviour
//! at the single-task level):
//! - A `TaskId` that is `enqueue`d is observed by `pick_next` at least
//!   once before any later-enqueued task is observed (FIFO).
//! - `pick_next` only returns a task whose state is `Ready` or `Running`.
//! - `yield_now` causes the current task's state to transition from
//!   `Running` to `Ready` before the next pick.
//! - The scheduler's `executed` counter is monotonic.

use core::sync::atomic::{AtomicU64, Ordering};

/// Maximum task slot pool size accepted by the canonical entrypoints
/// below. The const-generic `RoundRobin<N>` accepts any `N`; this
/// constant exists so external callers have a stable upper bound to
/// build buffers against.
pub const MAX_TASKS: usize = 32;

/// Stable identifier for a scheduled task. Locked at `u32` to match the
/// donor's process-id width.
pub type TaskId = u32;

/// Reserved `TaskId` meaning "no task". Used in the queue as the
/// sentinel for an empty slot.
pub const TASK_ID_NONE: TaskId = u32::MAX;

/// Lifecycle states a task moves through. Mirrors the donor's
/// `TaskState` enum but with the heap-bound `Blocked(Reason)` variant
/// flattened to a single `Blocked` discriminant (the reason payload
/// requires an allocator).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TaskState {
    /// Slot is unused. The TaskId in this slot is meaningless.
    Empty,
    /// Task is on the ready queue, waiting for CPU.
    Ready,
    /// Task is currently executing on the CPU.
    Running,
    /// Task is blocked (I/O, sleep, semaphore). Excluded from `pick_next`.
    Blocked,
    /// Task has exited; the slot is awaiting reaper.
    Exited,
}

/// Task control block — the per-task scheduler view. Real per-task data
/// (open file table, page tables, etc.) lives in the donor's `Task`
/// struct; here we keep only what the scheduler reads/writes plus the
/// IOMMU-domain handle the DMA syscalls (TASK-014) consult.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Task {
    /// Stable identifier.
    pub id: TaskId,
    /// Lifecycle state.
    pub state: TaskState,
    /// Scheduling priority (higher = preferred). The round-robin
    /// algorithm here does not consult priority — a later "tiered RR"
    /// morph cycle adds priority-aware queue selection on top.
    pub priority: u8,
    /// Number of times this task has been picked. Used by the verifier
    /// to confirm round-robin fairness in random-workload tests.
    pub picked: u32,
    /// Exit status if `state == Exited`. Meaningless otherwise.
    pub exit_status: i32,
    /// IOMMU domain bound to this task, or `None` if the task is not
    /// allowed to issue DMA-mapping syscalls. Set at task creation by
    /// the kernel (via [`Task::new_ready_with_domain`]); not mutable
    /// post-creation. `SYS_DMA_MAP` / `SYS_DMA_UNMAP` consult this
    /// field — a `None` task that calls a DMA syscall sees `EPERM`
    /// regardless of its capability mask.
    pub iommu_domain: Option<crate::iommu::DomainId>,
}

impl Task {
    /// The empty / unused slot. `state = Empty`.
    pub const EMPTY: Self = Self {
        id: TASK_ID_NONE,
        state: TaskState::Empty,
        priority: 0,
        picked: 0,
        exit_status: 0,
        iommu_domain: None,
    };

    /// Build a fresh `Ready` task with the given id and priority. All
    /// counters start at zero; `iommu_domain` is `None` (no DMA
    /// capability). Use [`Task::new_ready_with_domain`] for a task
    /// the kernel has already bound to an IOMMU domain.
    pub const fn new_ready(id: TaskId, priority: u8) -> Self {
        Self {
            id,
            state: TaskState::Ready,
            priority,
            picked: 0,
            exit_status: 0,
            iommu_domain: None,
        }
    }

    /// Build a fresh `Ready` task pre-bound to an IOMMU domain. Used
    /// at kernel boot for tasks that are allowed to perform DMA
    /// (TASK-014 path). The domain is opaque to the scheduler — it's
    /// only stored here and read by the DMA syscall handlers.
    pub const fn new_ready_with_domain(
        id: TaskId,
        priority: u8,
        domain: crate::iommu::DomainId,
    ) -> Self {
        Self {
            id,
            state: TaskState::Ready,
            priority,
            picked: 0,
            exit_status: 0,
            iommu_domain: Some(domain),
        }
    }
}

/// Number of times any `RoundRobin` instance has dispatched a task.
/// Mirrors the donor's per-CPU `EXECUTED` array but folds the per-CPU
/// dimension into a single global counter — the seed scheduler is
/// single-CPU.
pub static EXECUTED: AtomicU64 = AtomicU64::new(0);

/// Number of times `yield_now` has been called. Mirrors the donor's
/// `SYS_YIELD_COUNT`.
pub static YIELD_COUNT: AtomicU64 = AtomicU64::new(0);

/// Round-robin scheduler over a fixed `[Task; N]` slot pool.
///
/// The slot pool is allocated inline (no heap). A ring-buffer ready
/// queue indexes into the pool. `pick_next` advances a cursor through
/// the ready queue in FIFO order; the picked slot's state transitions
/// to `Running` and the previously-running slot transitions back to
/// `Ready`.
pub struct RoundRobin<const N: usize> {
    /// The task slot pool. Slot index is NOT the same as `TaskId` —
    /// see `find_slot`.
    tasks: [Task; N],
    /// Ring-buffer of slot indices that are currently `Ready`. The
    /// queue is small and bounded so a linear-search dedup is cheap.
    queue: [usize; N],
    /// Head of the ring buffer (next pick).
    head: usize,
    /// Tail of the ring buffer (next enqueue).
    tail: usize,
    /// Number of slot indices currently in `queue`.
    queue_len: usize,
    /// Slot index of the currently-running task, or `usize::MAX`
    /// when no task is running.
    running: usize,
    /// Monotonically-increasing dispatch counter. Useful for the
    /// fairness property check.
    dispatched: u64,
}

impl<const N: usize> RoundRobin<N> {
    /// Build an empty scheduler. All slots are `Task::EMPTY`; the
    /// ready queue is empty; no task is running.
    pub const fn new() -> Self {
        Self {
            tasks: [Task::EMPTY; N],
            queue: [0usize; N],
            head: 0,
            tail: 0,
            queue_len: 0,
            running: usize::MAX,
            dispatched: 0,
        }
    }

    /// Total slot count (== `N`). The number of tasks the scheduler
    /// can hold simultaneously.
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Number of currently-enqueued ready tasks.
    #[inline]
    pub fn ready_len(&self) -> usize {
        self.queue_len
    }

    /// Total dispatches recorded by this instance.
    #[inline]
    pub fn dispatched_count(&self) -> u64 {
        self.dispatched
    }

    /// Find the slot index for `id`. Returns `None` if no slot holds
    /// that id with a non-empty state.
    fn find_slot(&self, id: TaskId) -> Option<usize> {
        let mut i = 0;
        while i < N {
            if self.tasks[i].state != TaskState::Empty && self.tasks[i].id == id {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Allocate a free slot (the lowest-index `Empty` slot). Returns
    /// `None` if the pool is full.
    fn alloc_slot(&self) -> Option<usize> {
        let mut i = 0;
        while i < N {
            if self.tasks[i].state == TaskState::Empty {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Add a brand-new task with priority 0. Returns `false` if the
    /// task already exists or the pool is full.
    pub fn enqueue(&mut self, id: TaskId) -> bool {
        self.enqueue_with_priority(id, 0)
    }

    /// Add a brand-new task with an explicit priority. Returns `false`
    /// if the task already exists or the pool is full.
    pub fn enqueue_with_priority(&mut self, id: TaskId, priority: u8) -> bool {
        if id == TASK_ID_NONE {
            return false;
        }
        if self.find_slot(id).is_some() {
            return false;
        }
        let slot = match self.alloc_slot() {
            Some(s) => s,
            None => return false,
        };
        self.tasks[slot] = Task::new_ready(id, priority);
        self.push_ready_slot(slot);
        true
    }

    /// Push a slot index onto the ready queue. Internal — callers must
    /// have transitioned the task to `Ready` first.
    fn push_ready_slot(&mut self, slot: usize) {
        if self.queue_len >= N {
            // The ready queue is the same size as the slot pool, so
            // this branch is reachable only on a logic error.
            return;
        }
        self.queue[self.tail] = slot;
        self.tail = (self.tail + 1) % N;
        self.queue_len += 1;
    }

    /// Pop a slot index from the front of the ready queue.
    fn pop_ready_slot(&mut self) -> Option<usize> {
        if self.queue_len == 0 {
            return None;
        }
        let slot = self.queue[self.head];
        self.head = (self.head + 1) % N;
        self.queue_len -= 1;
        Some(slot)
    }

    /// Pick the next task to run. The previously-running task (if any)
    /// is moved back onto the ready queue with state `Ready`. Returns
    /// `None` if no task is ready.
    pub fn pick_next(&mut self) -> Option<TaskId> {
        // Demote the currently-running task.
        if self.running != usize::MAX {
            let prev = self.running;
            // Only re-queue if still in `Running` (not `Exited` /
            // `Blocked`). A task that called sys_exit will have
            // transitioned to `Exited` between dispatch and now.
            if self.tasks[prev].state == TaskState::Running {
                self.tasks[prev].state = TaskState::Ready;
                self.push_ready_slot(prev);
            }
            self.running = usize::MAX;
        }
        let next = self.pop_ready_slot()?;
        self.tasks[next].state = TaskState::Running;
        self.tasks[next].picked = self.tasks[next].picked.wrapping_add(1);
        self.running = next;
        self.dispatched = self.dispatched.wrapping_add(1);
        EXECUTED.fetch_add(1, Ordering::Relaxed);
        Some(self.tasks[next].id)
    }

    /// Voluntarily release the CPU. The currently-running task is
    /// demoted to `Ready` and the next ready task is dispatched.
    /// Returns the id of the newly-running task, or `None` if no
    /// other task is ready (the original task continues).
    pub fn yield_now(&mut self) -> Option<TaskId> {
        YIELD_COUNT.fetch_add(1, Ordering::Relaxed);
        // If nothing else is ready and a task is running, keep running it.
        if self.queue_len == 0 {
            return None;
        }
        self.pick_next()
    }

    /// Mark a task as `Blocked`. The blocked task is removed from the
    /// ready queue (if present) and excluded from future picks until
    /// `unblock` is called. Returns `false` if no such task.
    pub fn block(&mut self, id: TaskId) -> bool {
        let slot = match self.find_slot(id) {
            Some(s) => s,
            None => return false,
        };
        self.tasks[slot].state = TaskState::Blocked;
        // Remove the slot from the ready queue if it is present. We
        // walk the queue manually since direct indexing into a ring
        // buffer is awkward.
        self.remove_from_ready_queue(slot);
        if self.running == slot {
            self.running = usize::MAX;
        }
        true
    }

    /// Move a `Blocked` task back to `Ready`. Returns `false` if the
    /// task is not in the blocked state.
    pub fn unblock(&mut self, id: TaskId) -> bool {
        let slot = match self.find_slot(id) {
            Some(s) => s,
            None => return false,
        };
        if self.tasks[slot].state != TaskState::Blocked {
            return false;
        }
        self.tasks[slot].state = TaskState::Ready;
        self.push_ready_slot(slot);
        true
    }

    /// Mark a task as `Exited` with the given status. The slot remains
    /// occupied (state `Exited`) until `reap` is called; this matches
    /// the donor's convention so a parent can collect the exit code.
    pub fn exit(&mut self, id: TaskId, status: i32) -> bool {
        let slot = match self.find_slot(id) {
            Some(s) => s,
            None => return false,
        };
        self.tasks[slot].state = TaskState::Exited;
        self.tasks[slot].exit_status = status;
        self.remove_from_ready_queue(slot);
        if self.running == slot {
            self.running = usize::MAX;
        }
        true
    }

    /// Reap an `Exited` task. Returns the exit status and frees the
    /// slot. Returns `None` if the task is not in the `Exited` state.
    pub fn reap(&mut self, id: TaskId) -> Option<i32> {
        let slot = self.find_slot(id)?;
        if self.tasks[slot].state != TaskState::Exited {
            return None;
        }
        let status = self.tasks[slot].exit_status;
        self.tasks[slot] = Task::EMPTY;
        Some(status)
    }

    /// Currently-running task id, or `None` if no task is running.
    pub fn current(&self) -> Option<TaskId> {
        if self.running == usize::MAX {
            None
        } else {
            Some(self.tasks[self.running].id)
        }
    }

    /// Read-only snapshot of a task by id.
    pub fn task(&self, id: TaskId) -> Option<&Task> {
        let slot = self.find_slot(id)?;
        Some(&self.tasks[slot])
    }

    /// Read-only snapshot of a task slot by index (`0..N`) if occupied.
    pub fn slot(&self, idx: usize) -> Option<&Task> {
        if idx >= N || self.tasks[idx].state == TaskState::Empty {
            None
        } else {
            Some(&self.tasks[idx])
        }
    }

    /// Internal: linearly walk the ready queue and remove the first
    /// occurrence of `slot`. The queue is bounded by `N` so this is
    /// O(N) and allocation-free.
    fn remove_from_ready_queue(&mut self, slot: usize) {
        if self.queue_len == 0 {
            return;
        }
        // Read each ring-buffer entry and rebuild the queue without
        // the target. Bounded scan of at most `N` entries.
        let mut new_queue = [0usize; N];
        let mut new_len = 0usize;
        let mut i = 0usize;
        while i < self.queue_len {
            let idx = (self.head + i) % N;
            let entry = self.queue[idx];
            if entry != slot {
                new_queue[new_len] = entry;
                new_len += 1;
            }
            i += 1;
        }
        // Copy back. We use a manual loop to stay const-generic-safe
        // (no slice::copy_from_slice which is fine here but the manual
        // form makes the no-alloc story obvious).
        let mut j = 0usize;
        while j < new_len {
            self.queue[j] = new_queue[j];
            j += 1;
        }
        self.head = 0;
        self.tail = new_len % N;
        self.queue_len = new_len;
    }
}

impl<const N: usize> Default for RoundRobin<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience: invoke `yield_now` on a thread-local default scheduler.
/// In the seed crate there is no thread-local — this function is the
/// hook the syscall layer calls into. The morph engine wires it to a
/// real per-CPU scheduler instance later.
///
/// Today it just bumps `YIELD_COUNT` so the syscall ABI observable side
/// effect is in place.
pub fn yield_now() {
    YIELD_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_scheduler_is_empty() {
        let s: RoundRobin<8> = RoundRobin::new();
        assert_eq!(s.ready_len(), 0);
        assert_eq!(s.dispatched_count(), 0);
        assert_eq!(s.current(), None);
    }

    #[test]
    fn enqueue_then_pick_returns_in_fifo_order() {
        let mut s: RoundRobin<4> = RoundRobin::new();
        assert!(s.enqueue(10));
        assert!(s.enqueue(20));
        assert!(s.enqueue(30));
        assert_eq!(s.pick_next(), Some(10));
        assert_eq!(s.pick_next(), Some(20));
        assert_eq!(s.pick_next(), Some(30));
        // After the third pick, slot 10 and 20 are back on ready;
        // next pick rotates back to 10.
        assert_eq!(s.pick_next(), Some(10));
    }

    #[test]
    fn duplicate_enqueue_is_rejected() {
        let mut s: RoundRobin<4> = RoundRobin::new();
        assert!(s.enqueue(7));
        assert!(!s.enqueue(7));
    }

    #[test]
    fn pool_exhaustion() {
        let mut s: RoundRobin<2> = RoundRobin::new();
        assert!(s.enqueue(1));
        assert!(s.enqueue(2));
        assert!(!s.enqueue(3));
    }

    #[test]
    fn block_removes_from_ready_queue() {
        let mut s: RoundRobin<4> = RoundRobin::new();
        s.enqueue(1);
        s.enqueue(2);
        s.enqueue(3);
        s.block(2);
        assert_eq!(s.pick_next(), Some(1));
        assert_eq!(s.pick_next(), Some(3));
        // 2 is blocked; the rotation picks 1 again.
        assert_eq!(s.pick_next(), Some(1));
    }

    #[test]
    fn unblock_returns_task_to_ready() {
        let mut s: RoundRobin<4> = RoundRobin::new();
        s.enqueue(1);
        s.enqueue(2);
        s.block(2);
        s.unblock(2);
        assert_eq!(s.pick_next(), Some(1));
        assert_eq!(s.pick_next(), Some(2));
    }

    #[test]
    fn exit_then_reap() {
        let mut s: RoundRobin<4> = RoundRobin::new();
        s.enqueue(42);
        assert_eq!(s.pick_next(), Some(42));
        s.exit(42, -1);
        assert_eq!(s.pick_next(), None);
        assert_eq!(s.reap(42), Some(-1));
        assert_eq!(s.reap(42), None);
    }

    #[test]
    fn yield_rotates_when_other_tasks_ready() {
        let mut s: RoundRobin<4> = RoundRobin::new();
        s.enqueue(1);
        s.enqueue(2);
        assert_eq!(s.pick_next(), Some(1));
        // Now 1 is running, 2 is ready.
        assert_eq!(s.yield_now(), Some(2));
    }

    #[test]
    fn yield_with_no_other_ready_returns_none() {
        let mut s: RoundRobin<4> = RoundRobin::new();
        s.enqueue(1);
        s.pick_next();
        // Only task running; yield finds nothing on the ready queue.
        assert_eq!(s.yield_now(), None);
    }
}
