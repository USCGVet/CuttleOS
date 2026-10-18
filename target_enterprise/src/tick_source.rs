//! PIT / HPET tick source mux — TASK-076.

#![allow(missing_docs)]

use cuttle_contracts::{TickKind, TickSource};

/// Dual-counter tick mux for tests / watchdog composition.
pub struct TickSourceImpl {
    kind: TickKind,
    pit_ticks: u64,
    hpet_ticks: u64,
}

impl Default for TickSourceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl TickSourceImpl {
    pub const fn new() -> Self {
        Self {
            kind: TickKind::Pit,
            pit_ticks: 0,
            hpet_ticks: 0,
        }
    }
}

impl TickSource for TickSourceImpl {
    fn select(&mut self, kind: TickKind) {
        self.kind = kind;
    }
    fn kind(&self) -> TickKind {
        self.kind
    }
    fn advance(&mut self, delta: u64) {
        match self.kind {
            TickKind::Pit => self.pit_ticks = self.pit_ticks.wrapping_add(delta),
            TickKind::Hpet => self.hpet_ticks = self.hpet_ticks.wrapping_add(delta),
        }
    }
    fn now_ticks(&self) -> u64 {
        match self.kind {
            TickKind::Pit => self.pit_ticks,
            TickKind::Hpet => self.hpet_ticks,
        }
    }
    fn until(&self, deadline: u64) -> u64 {
        let now = self.now_ticks();
        deadline.saturating_sub(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::TickSource;

    #[test]
    fn default_pit() {
        assert_eq!(TickSourceImpl::new().kind(), TickKind::Pit);
    }

    #[test]
    fn select_hpet() {
        let mut t = TickSourceImpl::new();
        t.select(TickKind::Hpet);
        assert_eq!(t.kind(), TickKind::Hpet);
    }

    #[test]
    fn advance_pit_only() {
        let mut t = TickSourceImpl::new();
        t.advance(5);
        assert_eq!(t.now_ticks(), 5);
        t.select(TickKind::Hpet);
        assert_eq!(t.now_ticks(), 0);
    }

    #[test]
    fn independent_counters() {
        let mut t = TickSourceImpl::new();
        t.advance(10);
        t.select(TickKind::Hpet);
        t.advance(3);
        assert_eq!(t.now_ticks(), 3);
        t.select(TickKind::Pit);
        assert_eq!(t.now_ticks(), 10);
    }

    #[test]
    fn until_basic() {
        let mut t = TickSourceImpl::new();
        t.advance(4);
        assert_eq!(t.until(10), 6);
        assert_eq!(t.until(2), 0);
    }

    #[test]
    fn banner_hpet() {
        let mut t = TickSourceImpl::new();
        t.select(TickKind::Hpet);
        t.advance(1);
        assert_eq!(t.kind(), TickKind::Hpet);
        assert_eq!(t.now_ticks(), 1);
    }

    #[test]
    fn wrap_add() {
        let mut t = TickSourceImpl::new();
        t.pit_ticks = u64::MAX;
        t.advance(1);
        assert_eq!(t.now_ticks(), 0);
    }

    #[test]
    fn default_trait() {
        let t = TickSourceImpl::default();
        assert_eq!(t.now_ticks(), 0);
    }

    #[test]
    fn kind_discriminants() {
        assert_eq!(TickKind::Pit as u8, 0);
        assert_eq!(TickKind::Hpet as u8, 1);
    }

    #[test]
    fn many_advances() {
        let mut t = TickSourceImpl::new();
        for _ in 0..100 {
            t.advance(1);
        }
        assert_eq!(t.now_ticks(), 100);
    }

    #[test]
    fn switch_preserves() {
        let mut t = TickSourceImpl::new();
        t.select(TickKind::Hpet);
        t.advance(7);
        t.select(TickKind::Pit);
        t.select(TickKind::Hpet);
        assert_eq!(t.now_ticks(), 7);
    }

    #[test]
    fn until_equal() {
        let mut t = TickSourceImpl::new();
        t.advance(5);
        assert_eq!(t.until(5), 0);
    }

    #[test]
    fn zero_advance() {
        let mut t = TickSourceImpl::new();
        t.advance(0);
        assert_eq!(t.now_ticks(), 0);
    }

    #[test]
    fn large_delta() {
        let mut t = TickSourceImpl::new();
        t.advance(1_000_000);
        assert_eq!(t.now_ticks(), 1_000_000);
    }

    #[test]
    fn end_to_end() {
        let mut t = TickSourceImpl::new();
        t.select(TickKind::Hpet);
        assert_eq!(t.kind(), TickKind::Hpet);
    }

    #[test]
    fn pit_then_hpet_until() {
        let mut t = TickSourceImpl::new();
        t.advance(2);
        t.select(TickKind::Hpet);
        t.advance(9);
        assert_eq!(t.until(20), 11);
    }

    #[test]
    fn reselect_pit() {
        let mut t = TickSourceImpl::new();
        t.select(TickKind::Hpet);
        t.select(TickKind::Pit);
        assert_eq!(t.kind(), TickKind::Pit);
    }

    #[test]
    fn now_after_select_without_advance() {
        let mut t = TickSourceImpl::new();
        t.select(TickKind::Hpet);
        assert_eq!(t.now_ticks(), 0);
    }

    #[test]
    fn double_advance() {
        let mut t = TickSourceImpl::new();
        t.advance(3);
        t.advance(4);
        assert_eq!(t.now_ticks(), 7);
    }

    #[test]
    fn until_max() {
        let t = TickSourceImpl::new();
        assert_eq!(t.until(u64::MAX), u64::MAX);
    }

    #[test]
    fn banner_kind_hpet_str() {
        // documents banner text
        assert_eq!(TickKind::Hpet as u8, 1);
    }
}
