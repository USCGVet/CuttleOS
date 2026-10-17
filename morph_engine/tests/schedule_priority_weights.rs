//! Verify that with two modules sharing a max_age but different
//! priorities, the higher-priority module becomes due first.
//!
//! Formula: `(now - last_morph_unix) * priority >= max_age_secs`.
//! With max_age = 3600:
//!   priority 1  → due after 3600s
//!   priority 10 → due after 360s
//! So at elapsed = 400s, the priority-10 module is due and the
//! priority-1 module is not.

use proteus_morph_engine::scheduler::{
    pick_next_at, ModuleConfig, ModuleState, SchedulerConfig, SchedulerState,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn priority_weights_make_higher_priority_due_first() {
    let mut modules = BTreeMap::new();
    modules.insert(
        "slow".to_string(),
        ModuleConfig {
            priority: 1,
            max_age_secs: 3600,
            target_dir: PathBuf::from("/tmp/slow"),
            manifest: None,
        },
    );
    modules.insert(
        "fast".to_string(),
        ModuleConfig {
            priority: 10,
            max_age_secs: 3600,
            target_dir: PathBuf::from("/tmp/fast"),
            manifest: None,
        },
    );
    let cfg = SchedulerConfig {
        modules,
        ..Default::default()
    };

    // Both modules last morphed at t=0; now = 400. Only `fast` is due.
    let mut state = SchedulerState {
        global_cycle: 0,
        modules: BTreeMap::new(),
        ..Default::default()
    };
    state.modules.insert(
        "slow".to_string(),
        ModuleState {
            last_cycle: 0,
            last_morph_unix: 0,
        },
    );
    state.modules.insert(
        "fast".to_string(),
        ModuleState {
            last_cycle: 0,
            last_morph_unix: 0,
        },
    );

    let pick = pick_next_at(&cfg, &state, 400).expect("fast module is due");
    assert_eq!(pick.module, "fast");

    // Sanity: at now=3600 both are due, but priority 10 still wins.
    let pick2 = pick_next_at(&cfg, &state, 3600).expect("both are due");
    assert_eq!(pick2.module, "fast");

    // And before fast is due (now=300), nothing is due.
    let pick3 = pick_next_at(&cfg, &state, 300);
    assert!(pick3.is_none(), "no module should be due at now=300");
}
