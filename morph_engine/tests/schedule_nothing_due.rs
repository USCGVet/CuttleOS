//! With both modules recently morphed (well inside their max_age
//! window), the scheduler must return None so `morph next` exits with
//! EX_NOINPUT (64). This is the "factory should sit idle" path.

use cuttle_morph_engine::scheduler::{
    pick_next_at, ModuleConfig, ModuleState, SchedulerConfig, SchedulerState, EX_NOINPUT,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn returns_none_when_all_modules_recently_morphed() {
    let mut modules = BTreeMap::new();
    modules.insert(
        "alpha".to_string(),
        ModuleConfig {
            priority: 10,
            max_age_secs: 3600,
            target_dir: PathBuf::from("/tmp/alpha"),
            manifest: None,
        },
    );
    modules.insert(
        "bravo".to_string(),
        ModuleConfig {
            priority: 1,
            max_age_secs: 3600,
            target_dir: PathBuf::from("/tmp/bravo"),
            manifest: None,
        },
    );
    let cfg = SchedulerConfig {
        modules,
        ..Default::default()
    };

    // Both morphed at t=10000, now = 10010. Elapsed = 10s.
    //   alpha: 10 * 10 = 100  < 3600  → not due
    //   bravo: 10 * 1  =  10  < 3600  → not due
    let mut state = SchedulerState {
        global_cycle: 4,
        modules: BTreeMap::new(),
        ..Default::default()
    };
    state.modules.insert(
        "alpha".to_string(),
        ModuleState {
            last_cycle: 3,
            last_morph_unix: 10000,
        },
    );
    state.modules.insert(
        "bravo".to_string(),
        ModuleState {
            last_cycle: 4,
            last_morph_unix: 10000,
        },
    );

    let pick = pick_next_at(&cfg, &state, 10010);
    assert!(pick.is_none(), "nothing should be due yet");

    // Document the contract: the CLI exit code for "nothing due" is the
    // EX_NOINPUT sysexits.h constant (64), not a generic error.
    assert_eq!(EX_NOINPUT, 64);
}
