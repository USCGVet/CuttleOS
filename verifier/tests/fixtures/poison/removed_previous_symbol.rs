//! Poison: candidate that *drops* a public symbol the previous cycle
//! exposed. Previous-surface anti-regression must reject.
//!
//! Pair with `previous_full_surface.rs` as `--previous`.

#![no_std]

pub fn keep_me() {}
// deliberately missing: pub fn drop_me()
