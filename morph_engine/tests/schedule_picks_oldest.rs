//! Verify the scheduler picks the module with the oldest `last_morph_unix`
//! when two equally-prioritised modules are both due.

use proteus_morph_engine::scheduler::{
    pick_next_at, ModuleConfig, ModuleState, SchedulerConfig, SchedulerState,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn picks_oldest_when_priority_ties() {
    let mut modules = BTreeMap::new();
    modules.insert(
        "alpha".to_string(),
        ModuleConfig {
            priority: 1,
            max_age_secs: 100,
            target_dir: PathBuf::from("/tmp/alpha"),
            manifest: None,
        },
    );
    modules.insert(
        "bravo".to_string(),
        ModuleConfig {
            priority: 1,
            max_age_secs: 100,
            target_dir: PathBuf::from("/tmp/bravo"),
            manifest: None,
        },
    );
    let cfg = SchedulerConfig {
        modules,
        ..Default::default()
    };

    // alpha morphed at t=500, bravo morphed at t=600 (more recent).
    // At now=1000 both have elapsed >= 100 with priority 1.
    // Oldest is alpha, so alpha must win.
    let mut state = SchedulerState {
        global_cycle: 7,
        modules: BTreeMap::new(),
        ..Default::default()
    };
    state.modules.insert(
        "alpha".to_string(),
        ModuleState {
            last_cycle: 5,
            last_morph_unix: 500,
        },
    );
    state.modules.insert(
        "bravo".to_string(),
        ModuleState {
            last_cycle: 7,
            last_morph_unix: 600,
        },
    );

    let pick = pick_next_at(&cfg, &state, 1000).expect("a module is due");
    assert_eq!(pick.module, "alpha");
    assert_eq!(pick.next_cycle, 8);
}
