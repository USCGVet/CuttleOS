//! Cuttle contracts — the immutable kernel API and wire-format surface.
//!
//! Every morph candidate produced by the factory must satisfy the traits and
//! invariants defined in this crate. This crate is locked by
//! `locked_modules.toml` and is never modified by the diversifier.
//!
//! ## Module Layout
//! - [`arch_and_platform`]: `Smp`, `ApicWriter`, `Pci`, `PciConfigBus`, `XhciTrb`,
//!   `UefiGop`, `IoApic`, `LapicIcr`, `Multiboot2`, `AcpiRsdp`, `Serial16550`,
//!   `TickSource`, `Watchdog`, `Power`, `Elf64`, `Hpet`, `Keyboard`, `IoPort`,
//!   `PicTimer`, `Rtc`, and `CONTRACTS_SCHEMA_VERSION`.
//! - [`core_primitives`]: `Hash`, `Aead`, `SignatureVerify`, `SyscallDispatch`,
//!   `SyscallCapTable`, `CapProof`, `caps`, `BlockDevice`, `Allocator`, and
//!   `property_tests`.
//! - [`mm_and_isolation`]: `Iommu`, `Kpti`, and `FrameBitmap`.
//! - [`net_protocols`]: `NetStack`, `Tcp`, `Http`, `Dns`, `DnsName`, `Eth`,
//!   `Arp`, `Dhcp`, `Icmp`, `Sntp`, and `Tftp`.
//! - [`security_and_diag`]: `PacketFilter`, `Tpm`, `AuditLog`, `EBpf`,
//!   `StackCanary`, `CrashDump`, `SymbolResolve`, and `GdbStub`.
//! - [`storage_and_fs`]: `WriteAheadLog`, `Filesystem`, `Vfs`, `JournalFs`,
//!   `Fat32`, `Quota`, `Gpt`, `AhciFis`, and `AhciCmd`.
//! - [`tls_and_crypto`]: `Tls13Server`, `Tls13Client`, `X509`, `HmacDrbg`,
//!   `KatRunner`, `SigKat`, `Random`, `AttestTlv`, `Base64`, and `Crc32c`.
//! - [`virtio_and_nic`]: `MmioBus`, `NetDevice`, `BlockDeviceVirtio`,
//!   `VirtioPciCaps`, `MmioRegBus`, and `EthernetController`.

#![cfg_attr(not(feature = "property_tests"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

pub mod arch_and_platform;
pub mod core_primitives;
pub mod mm_and_isolation;
pub mod net_protocols;
pub mod security_and_diag;
pub mod storage_and_fs;
pub mod tls_and_crypto;
pub mod virtio_and_nic;

pub use arch_and_platform::*;
pub use core_primitives::*;
pub use mm_and_isolation::*;
pub use net_protocols::*;
pub use security_and_diag::*;
pub use storage_and_fs::*;
pub use tls_and_crypto::*;
pub use virtio_and_nic::*;

#[cfg(test)]
mod cap_proof_tests {
    //! Unit tests for the type-state `CapProof` (TASK-020). These run
    //! under `cargo test -p cuttle-contracts` with the
    //! `property_tests` feature enabled (which switches the crate to
    //! `std` mode); the type-state behaviour itself is independent of
    //! that feature.
    //!
    //! The negative cases that prove "external code cannot mint a
    //! `CapProof`" live in the verifier's trybuild suite at
    //! `verifier/tests/cap_typestate/`. Here we exercise the positive
    //! shape: a successful `check` mints a proof; a failed `check`
    //! does not; a custom impl that overrides `check_raw` is the
    //! sole route to the mint.
    use super::*;

    /// A test-only implementor of `SyscallCapTable` whose `check_raw`
    /// is parameterised at construction so individual cases can hit
    /// every arm of the trait's behaviour.
    struct StubTable {
        /// Closure returning the result of `check_raw`. Boxed so a
        /// single test can hold multiple stubs with different
        /// behaviour without committing to a const generic.
        verdict: fn(u64, u64, u32) -> Result<(), CapError>,
    }

    impl SyscallCapTable for StubTable {
        type Cap = u64;
        fn check_raw(&self, task_id: u64, cap: u64, syscall_nr: u32) -> Result<(), CapError> {
            (self.verdict)(task_id, cap, syscall_nr)
        }
    }

    #[test]
    fn check_mints_proof_on_success() {
        let table = StubTable { verdict: |_, _, _| Ok(()) };
        let result: Result<CapProof, CapError> = table.check(0, 0, 0);
        assert!(result.is_ok(), "check should succeed when check_raw returns Ok");
        // Consume the proof; this is the type-state happy path.
        result.unwrap().consume();
    }

    #[test]
    fn check_does_not_mint_on_failure() {
        let table = StubTable { verdict: |_, _, _| Err(CapError::EPERM) };
        let result = table.check(0, 0, 0);
        assert!(matches!(result, Err(CapError::EPERM)));
    }

    #[test]
    fn check_passes_through_enosys() {
        let table = StubTable { verdict: |_, _, _| Err(CapError::ENOSYS) };
        let result = table.check(0, 0, 0);
        assert!(matches!(result, Err(CapError::ENOSYS)));
    }

    #[test]
    fn cap_proof_is_zero_sized() {
        assert_eq!(core::mem::size_of::<CapProof>(), 0);
    }

    #[test]
    fn cap_proof_is_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<CapProof>();
        assert_sync::<CapProof>();
    }

    #[test]
    fn durable_cap_bits_kat_task_159() {
        use super::caps::*;
        assert_eq!(DURABLE_WAL_WRITE, 1 << 10);
        assert_eq!(DURABLE_FS_WRITE, 1 << 11);
        assert_eq!(DURABLE_AUDIT_PERSIST, 1 << 12);
        assert_eq!(ALLOCATED_BITS, 13);
        assert_eq!(RESERVED_MASK, !((1u64 << 13) - 1));
        assert!(mask_is_valid(ALL_NAMED));
        assert!(!mask_is_valid(1u64 << 13), "bit 13 must be reserved");
        assert!(!mask_is_valid(1u64 << 63));

        let unprivileged: u64 = 0;
        assert!(!allows(unprivileged, DURABLE_WAL_WRITE));
        assert!(!allows(AUDIT_WRITE, DURABLE_AUDIT_PERSIST));
        assert!(!allows(BLOCK_WRITE, DURABLE_WAL_WRITE));
        assert!(allows(ALL_NAMED, DURABLE_WAL_WRITE));
        assert!(allows(ALL_NAMED, DURABLE_FS_WRITE));
        assert!(allows(ALL_NAMED, DURABLE_AUDIT_PERSIST));
        assert!(allows(DURABLE_WAL_WRITE, DURABLE_WAL_WRITE));
        assert!(!allows(DURABLE_WAL_WRITE, DURABLE_FS_WRITE));

        let table = StubTable {
            verdict: |_, held, _| {
                if allows(held, DURABLE_WAL_WRITE) {
                    Ok(())
                } else {
                    Err(CapError::EPERM)
                }
            },
        };
        assert!(matches!(
            table.check(0, unprivileged, 0),
            Err(CapError::EPERM)
        ));
        let proof = table
            .check(0, DURABLE_WAL_WRITE, 0)
            .expect("WAL durable bit must mint proof");
        proof.consume();
    }

    #[test]
    fn consume_is_value_move_not_borrow() {
        let table = StubTable { verdict: |_, _, _| Ok(()) };
        let proof = table.check(0, 0, 0).expect("Ok");
        proof.consume();
        let proof2 = table.check(0, 0, 0).expect("Ok");
        proof2.consume();
    }

    #[test]
    fn cap_proof_implements_debug_trait() {
        fn assert_debug<T: core::fmt::Debug>() {}
        assert_debug::<CapProof>();
    }

    #[test]
    fn schema_version_bumped_for_task_020_through_070_hpet_canary_kbd_fat() {
        assert_eq!(CONTRACTS_SCHEMA_VERSION, 58);
    }
}
