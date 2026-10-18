//! With the state file absent, every module is treated as
//! never-morphed (`last_morph_unix = 0`) and is therefore due. The
//! highest-priority module wins. This is the "first ever boot" path.

use cuttle_morph_engine::scheduler::{
    load_state, pick_next_at, ModuleConfig, SchedulerConfig,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn missing_state_file_means_all_modules_due() {
    // Point load_state at a path that does not exist.
    let tmp = std::env::temp_dir().join(format!(
        "cuttle_morph_missing_state_{}.json",
        std::process::id()
    ));
    if tmp.exists() {
        std::fs::remove_file(&tmp).unwrap();
    }
    let state = load_state(&tmp).expect("missing state must not be an error");
    assert_eq!(state.global_cycle, 0);
    assert!(state.modules.is_empty());

    // Now run the picker. Highest priority should win.
    let mut modules = BTreeMap::new();
    modules.insert(
        "boring".to_string(),
        ModuleConfig {
            priority: 1,
            max_age_secs: 3600,
            target_dir: PathBuf::from("/tmp/boring"),
            manifest: None,
        },
    );
    modules.insert(
        "spicy".to_string(),
        ModuleConfig {
            priority: 100,
            max_age_secs: 3600,
            target_dir: PathBuf::from("/tmp/spicy"),
            manifest: None,
        },
    );
    let cfg = SchedulerConfig {
        modules,
        ..Default::default()
    };

    // last_morph_unix defaults to 0, now = 1000 → elapsed = 1000.
    //   boring: 1000 * 1   = 1000   < 3600 → not due
    //   spicy : 1000 * 100 = 100000 >= 3600 → due
    let pick = pick_next_at(&cfg, &state, 1000).expect("spicy is due");
    assert_eq!(pick.module, "spicy");
    assert_eq!(pick.next_cycle, 1);

    // At a sufficiently large `now`, both are due — highest priority
    // still wins, confirming "treated as oldest possible" implies "all
    // due once enough wall time has passed".
    let pick2 = pick_next_at(&cfg, &state, 10_000).expect("both due");
    assert_eq!(pick2.module, "spicy");
}
