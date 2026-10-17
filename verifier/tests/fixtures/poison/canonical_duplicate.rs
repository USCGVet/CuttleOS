//! Poison: when used as both candidate and previous (or any whitespace-
//! only reformat of the same AST), the canonical-hash dedup stage must
//! reject with "no diversity".

#![no_std]

pub fn morph_me() {
    let x = 1;
    let _ = x;
}
