//! Software watchdog — TASK-071.
//!
//! Arm / pet / tick / check against an injected tick counter.
//! No IRQ wiring — the kernel composes this with PIT/HPET ticks.

#![allow(missing_docs)]

#[cfg(test)]
use proteus_contracts::WATCHDOG_DEFAULT_DEADLINE_TICKS;
use proteus_contracts::{Watchdog, WatchdogError};

/// Software watchdog state.
pub struct WatchdogImpl {
    deadline: u32,
    remaining: u32,
    armed: bool,
    fired: bool,
}

impl Default for WatchdogImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchdogImpl {
    pub const fn new() -> Self {
        Self {
            deadline: 0,
            remaining: 0,
            armed: false,
            fired: false,
        }
    }
}

impl Watchdog for WatchdogImpl {
    fn arm(&mut self, deadline_ticks: u32) -> Result<(), WatchdogError> {
        arm_impl(self, deadline_ticks)
    }
    fn pet(&mut self) -> Result<(), WatchdogError> {
        pet_impl(self)
    }
    fn tick(&mut self) -> Result<(), WatchdogError> {
        tick_impl(self)
    }
    fn check(&self) -> Result<(), WatchdogError> {
        check_impl(self)
    }
    fn remaining(&self) -> u32 {
        if self.fired || !self.armed {
            0
        } else {
            self.remaining
        }
    }
    fn deadline(&self) -> u32 {
        self.deadline
    }
    fn is_armed(&self) -> bool {
        self.armed && !self.fired
    }
}

pub fn arm_impl(w: &mut WatchdogImpl, deadline_ticks: u32) -> Result<(), WatchdogError> {
    if deadline_ticks == 0 {
        return Err(WatchdogError::ZeroDeadline);
    }
    w.deadline = deadline_ticks;
    w.remaining = deadline_ticks;
    w.armed = true;
    w.fired = false;
    Ok(())
}

pub fn pet_impl(w: &mut WatchdogImpl) -> Result<(), WatchdogError> {
    if !w.armed {
        return Err(WatchdogError::NotArmed);
    }
    if w.fired {
        return Err(WatchdogError::Fired);
    }
    w.remaining = w.deadline;
    Ok(())
}

pub fn tick_impl(w: &mut WatchdogImpl) -> Result<(), WatchdogError> {
    if !w.armed {
        return Err(WatchdogError::NotArmed);
    }
    if w.fired {
        return Err(WatchdogError::Fired);
    }
    if w.remaining <= 1 {
        w.remaining = 0;
        w.fired = true;
        return Err(WatchdogError::Fired);
    }
    w.remaining -= 1;
    Ok(())
}

pub fn check_impl(w: &WatchdogImpl) -> Result<(), WatchdogError> {
    if w.fired {
        Err(WatchdogError::Fired)
    } else if !w.armed {
        Err(WatchdogError::NotArmed)
    } else {
        Ok(())
    }
}

/// Banner deadline (small for host tests; banner uses same).
pub const BANNER_DEADLINE: u32 = 5;

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::Watchdog;

    #[test]
    fn default_deadline_constant() {
        assert_eq!(WATCHDOG_DEFAULT_DEADLINE_TICKS, 300);
    }

    #[test]
    fn arm_sets_remaining() {
        let mut w = WatchdogImpl::new();
        w.arm(10).unwrap();
        assert_eq!(w.remaining(), 10);
        assert_eq!(w.deadline(), 10);
        assert!(w.is_armed());
    }

    #[test]
    fn arm_zero_rejected() {
        let mut w = WatchdogImpl::new();
        assert_eq!(w.arm(0), Err(WatchdogError::ZeroDeadline));
    }

    #[test]
    fn pet_resets() {
        let mut w = WatchdogImpl::new();
        w.arm(10).unwrap();
        w.tick().unwrap();
        w.tick().unwrap();
        assert_eq!(w.remaining(), 8);
        w.pet().unwrap();
        assert_eq!(w.remaining(), 10);
    }

    #[test]
    fn pet_not_armed() {
        let mut w = WatchdogImpl::new();
        assert_eq!(w.pet(), Err(WatchdogError::NotArmed));
    }

    #[test]
    fn tick_fires_at_zero() {
        let mut w = WatchdogImpl::new();
        w.arm(2).unwrap();
        assert!(w.tick().is_ok());
        assert_eq!(w.tick(), Err(WatchdogError::Fired));
        assert_eq!(w.check(), Err(WatchdogError::Fired));
        assert!(!w.is_armed());
        assert_eq!(w.remaining(), 0);
    }

    #[test]
    fn tick_not_armed() {
        let mut w = WatchdogImpl::new();
        assert_eq!(w.tick(), Err(WatchdogError::NotArmed));
    }

    #[test]
    fn check_ok_when_armed() {
        let mut w = WatchdogImpl::new();
        w.arm(5).unwrap();
        assert!(w.check().is_ok());
    }

    #[test]
    fn check_not_armed() {
        let w = WatchdogImpl::new();
        assert_eq!(w.check(), Err(WatchdogError::NotArmed));
    }

    #[test]
    fn pet_after_fire_fails() {
        let mut w = WatchdogImpl::new();
        w.arm(1).unwrap();
        let _ = w.tick();
        assert_eq!(w.pet(), Err(WatchdogError::Fired));
    }

    #[test]
    fn rearm_clears_fired() {
        let mut w = WatchdogImpl::new();
        w.arm(1).unwrap();
        let _ = w.tick();
        w.arm(3).unwrap();
        assert!(w.is_armed());
        assert_eq!(w.remaining(), 3);
    }

    #[test]
    fn banner_pet_ok_deadline() {
        let mut w = WatchdogImpl::new();
        w.arm(BANNER_DEADLINE).unwrap();
        w.tick().unwrap();
        w.pet().unwrap();
        assert_eq!(w.deadline(), BANNER_DEADLINE);
        assert_eq!(w.remaining(), BANNER_DEADLINE);
    }

    #[test]
    fn banner_fire_timeout() {
        let mut w = WatchdogImpl::new();
        w.arm(2).unwrap();
        w.tick().unwrap();
        assert_eq!(w.tick(), Err(WatchdogError::Fired));
    }

    #[test]
    fn many_ticks() {
        let mut w = WatchdogImpl::new();
        w.arm(100).unwrap();
        for _ in 0..99 {
            w.tick().unwrap();
        }
        assert_eq!(w.remaining(), 1);
        assert_eq!(w.tick(), Err(WatchdogError::Fired));
    }

    #[test]
    fn free_fns_match() {
        let mut w = WatchdogImpl::new();
        arm_impl(&mut w, 7).unwrap();
        assert_eq!(w.remaining(), 7);
    }

    #[test]
    fn default_new() {
        let w = WatchdogImpl::default();
        assert!(!w.is_armed());
    }

    #[test]
    fn deadline_stable_across_ticks() {
        let mut w = WatchdogImpl::new();
        w.arm(50).unwrap();
        w.tick().unwrap();
        assert_eq!(w.deadline(), 50);
    }

    #[test]
    fn remaining_zero_when_not_armed() {
        assert_eq!(WatchdogImpl::new().remaining(), 0);
    }

    #[test]
    fn tick_after_fire_stays_fired() {
        let mut w = WatchdogImpl::new();
        w.arm(1).unwrap();
        let _ = w.tick();
        assert_eq!(w.tick(), Err(WatchdogError::Fired));
    }

    #[test]
    fn arm_one_fires_on_first_tick() {
        let mut w = WatchdogImpl::new();
        w.arm(1).unwrap();
        assert_eq!(w.tick(), Err(WatchdogError::Fired));
    }

    #[test]
    fn pet_keeps_alive() {
        let mut w = WatchdogImpl::new();
        w.arm(3).unwrap();
        for _ in 0..10 {
            w.tick().unwrap();
            w.pet().unwrap();
        }
        assert!(w.is_armed());
    }

    #[test]
    fn check_after_partial_ticks() {
        let mut w = WatchdogImpl::new();
        w.arm(10).unwrap();
        w.tick().unwrap();
        assert!(w.check().is_ok());
    }

    #[test]
    fn errors_distinct() {
        assert_ne!(WatchdogError::Fired, WatchdogError::NotArmed);
        assert_ne!(WatchdogError::ZeroDeadline, WatchdogError::Fired);
    }

    #[test]
    fn large_deadline() {
        let mut w = WatchdogImpl::new();
        w.arm(u32::MAX).unwrap();
        assert_eq!(w.remaining(), u32::MAX);
    }

    #[test]
    fn end_to_end() {
        let mut w = WatchdogImpl::new();
        w.arm(BANNER_DEADLINE).unwrap();
        w.pet().unwrap();
        for _ in 0..BANNER_DEADLINE - 1 {
            w.tick().unwrap();
        }
        assert_eq!(w.tick(), Err(WatchdogError::Fired));
        assert_eq!(w.check(), Err(WatchdogError::Fired));
    }
}
