pub fn add_pair(a: u64, b: u64) -> u64 {
    let sum = a.wrapping_add(b);
    if sum > 10 {
        sum.wrapping_mul(3)
    } else {
        sum ^ 0x55
    }
}
