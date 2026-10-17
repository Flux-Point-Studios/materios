use sp_arithmetic::{helpers_128bit::multiply_by_rational_with_rounding, Rounding};
use sp_runtime::Perbill;

const SCALE: u128 = 1_000_000_000_000_000_000_000_000_000;
const BILLION: u128 = 1_000_000_000;

fn mul_div(a: u128, b: u128, denominator: u128, rounding: Rounding) -> u128 {
    // The SDK uses a 256-bit intermediate; only an out-of-range quotient saturates.
    multiply_by_rational_with_rounding(a, b, denominator, rounding).unwrap_or(u128::MAX)
}

/// At most 64 square-and-multiply rounds, including a u64::MAX interval.
pub(crate) fn accrue(balance: u128, per_block: u128, rate: Perbill, elapsed: u64) -> (u128, u128) {
    if elapsed == 0 {
        return (balance, 0);
    }
    if elapsed == 1 {
        // Preserve the established NearestPrefDown one-block step exactly.
        return (rate * balance, per_block);
    }
    if rate == Perbill::one() {
        return (balance, per_block.saturating_mul(u128::from(elapsed)));
    }

    let mut lower = SCALE;
    let mut upper = SCALE;
    let mut power_lower = u128::from(rate.deconstruct()) * (SCALE / BILLION);
    let mut power_upper = power_lower;
    let mut remaining = elapsed;
    while remaining > 0 {
        if remaining & 1 != 0 {
            lower = mul_div(lower, power_lower, SCALE, Rounding::Down);
            upper = mul_div(upper, power_upper, SCALE, Rounding::Up);
        }
        remaining >>= 1;
        if remaining > 0 {
            power_lower = mul_div(power_lower, power_lower, SCALE, Rounding::Down);
            power_upper = mul_div(power_upper, power_upper, SCALE, Rounding::Up);
        }
    }

    let decayed = mul_div(balance, lower, SCALE, Rounding::Down);
    let loss = BILLION - u128::from(rate.deconstruct());
    // Upper r^n bounds make (1-r^n)/(1-r) a LOWER bound on earned generation.
    let sum_lower = (SCALE - upper) * BILLION / loss;
    let sum_upper = ((SCALE - lower) * BILLION).div_ceil(loss);
    let generated = mul_div(per_block, sum_lower, SCALE, Rounding::Down);
    // Each old nearest-integer step can lose 1/2 unit. The first generation step
    // is exact; discount the remaining geometric sum so dormancy never wins.
    let rounding_loss = sum_upper.saturating_sub(SCALE).div_ceil(2 * SCALE);
    (decayed, generated.saturating_sub(rounding_loss))
}
