//! Exact capture-target and engineering-load models.

mod overlay;

pub use overlay::*;

use std::fmt;

use meshmine_hns::derive_capture_parameters;
use meshmine_types::U256;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rational {
    pub numerator: BigUint,
    pub denominator: BigUint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadAssumptions {
    pub hns_block_interval_ms: u64,
    pub encoded_share_bytes: u64,
    pub signature_verifications_per_share: u64,
    pub retained_sessions: u64,
    pub session_duration_ms: u64,
    pub fast_evaluations_per_share: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureLoad {
    pub capture_shares_per_hns_block: Rational,
    pub capture_shares_per_second: Rational,
    pub ingress_bytes_per_second: Rational,
    pub signature_verifications_per_second: Rational,
    pub retained_share_bytes: Rational,
    pub fast_evaluations_per_second: Rational,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureProfile {
    pub bits: u32,
    pub hns_network_target: U256,
    pub leading_zero_bits_p: u16,
    pub leading_zero_prefix_q: u16,
    pub blind_band_bits_d: u16,
    pub capture_target: U256,
    pub load: CaptureLoad,
    pub production_enabled: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SimulationError {
    #[error("compact target is zero, negative, or wider than 256 bits")]
    InvalidTarget,
    #[error("blind bits must be nonzero and strictly smaller than target leading zeros")]
    InvalidBlindBand,
    #[error("block interval must be nonzero")]
    InvalidBlockInterval,
    #[error("production capture profiles remain configuration-gated")]
    ProductionProfileGated,
    #[error("overlay testnet simulation failed: {0}")]
    OverlayFailure(String),
}

impl Rational {
    pub fn new(numerator: BigUint, denominator: BigUint) -> Self {
        assert!(!denominator.is_zero());
        if numerator.is_zero() {
            return Self {
                numerator,
                denominator: BigUint::one(),
            };
        }
        let divisor = numerator.gcd(&denominator);
        Self {
            numerator: numerator / &divisor,
            denominator: denominator / divisor,
        }
    }

    pub fn multiply_integer(&self, value: u64) -> Self {
        Self::new(
            &self.numerator * BigUint::from(value),
            self.denominator.clone(),
        )
    }

    pub fn divide_integer(&self, value: u64) -> Self {
        assert_ne!(value, 0);
        Self::new(
            self.numerator.clone(),
            &self.denominator * BigUint::from(value),
        )
    }

    pub fn decimal(&self, places: usize) -> String {
        let integer = &self.numerator / &self.denominator;
        if places == 0 {
            return integer.to_string();
        }
        let scale = BigUint::from(10u8).pow(places as u32);
        let fraction = ((&self.numerator % &self.denominator) * &scale) / &self.denominator;
        format!("{integer}.{fraction:0>places$}")
    }
}

impl fmt::Display for Rational {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.numerator, self.denominator)
    }
}

pub fn derive_capture_profile(
    bits: u32,
    blind_bits: u16,
    assumptions: LoadAssumptions,
) -> Result<CaptureProfile, SimulationError> {
    if assumptions.hns_block_interval_ms == 0 {
        return Err(SimulationError::InvalidBlockInterval);
    }
    let parameters = derive_capture_parameters(bits, blind_bits).map_err(|error| match error {
        meshmine_hns::CaptureParameterError::InvalidTarget => SimulationError::InvalidTarget,
        meshmine_hns::CaptureParameterError::InvalidBlindBand => SimulationError::InvalidBlindBand,
    })?;
    let network_target = BigUint::from_bytes_be(&parameters.network_target);
    let capture_target = BigUint::from_bytes_be(&parameters.capture_target);
    let captures_per_block = Rational::new(
        &capture_target + BigUint::one(),
        &network_target + BigUint::one(),
    );
    let captures_per_second = captures_per_block
        .multiply_integer(1_000)
        .divide_integer(assumptions.hns_block_interval_ms);
    let retention_ms = assumptions
        .retained_sessions
        .saturating_mul(assumptions.session_duration_ms);
    let load = CaptureLoad {
        capture_shares_per_hns_block: captures_per_block.clone(),
        capture_shares_per_second: captures_per_second.clone(),
        ingress_bytes_per_second: captures_per_second
            .multiply_integer(assumptions.encoded_share_bytes),
        signature_verifications_per_second: captures_per_second
            .multiply_integer(assumptions.signature_verifications_per_share),
        retained_share_bytes: captures_per_second
            .multiply_integer(assumptions.encoded_share_bytes)
            .multiply_integer(retention_ms)
            .divide_integer(1_000),
        fast_evaluations_per_second: captures_per_second
            .multiply_integer(assumptions.fast_evaluations_per_share),
    };
    Ok(CaptureProfile {
        bits,
        hns_network_target: U256(parameters.network_target),
        leading_zero_bits_p: parameters.leading_zero_bits_p,
        leading_zero_prefix_q: parameters.leading_zero_prefix_q,
        blind_band_bits_d: blind_bits,
        capture_target: U256(parameters.capture_target),
        load,
        production_enabled: false,
    })
}

pub fn authorize_production_profile(
    mut profile: CaptureProfile,
    explicit_release_gate: bool,
) -> Result<CaptureProfile, SimulationError> {
    if !explicit_release_gate {
        return Err(SimulationError::ProductionProfileGated);
    }
    profile.production_enabled = true;
    Ok(profile)
}

pub fn default_load_assumptions() -> LoadAssumptions {
    LoadAssumptions {
        hns_block_interval_ms: 600_000,
        encoded_share_bytes: 512,
        signature_verifications_per_share: 2,
        retained_sessions: 1_000,
        session_duration_ms: 10_000,
        fast_evaluations_per_share: 1,
    }
}

#[cfg(test)]
fn to_u256(value: &BigUint) -> U256 {
    let bytes = value.to_bytes_be();
    let mut output = [0; 32];
    output[32 - bytes.len()..].copy_from_slice(&bytes);
    U256(output)
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn profiles_eight_through_sixteen_are_exact_and_gated() {
        for blind_bits in 8..=16 {
            let profile =
                derive_capture_profile(0x1925_ae67, blind_bits, default_load_assumptions())
                    .unwrap();
            assert_eq!(
                profile.leading_zero_prefix_q,
                profile.leading_zero_bits_p - blind_bits
            );
            let capture = BigUint::from_bytes_be(&profile.capture_target.0);
            assert_eq!(
                capture,
                (BigUint::one() << (256 - usize::from(profile.leading_zero_prefix_q)))
                    - BigUint::one()
            );
            assert!(!profile.production_enabled);
            assert_eq!(
                authorize_production_profile(profile, false),
                Err(SimulationError::ProductionProfileGated)
            );
        }
    }

    #[test]
    fn every_generated_network_winner_is_a_capture_share() {
        let profile = derive_capture_profile(0x1925_ae67, 12, default_load_assumptions()).unwrap();
        let target = BigUint::from_bytes_be(&profile.hns_network_target.0);
        let capture = BigUint::from_bytes_be(&profile.capture_target.0);
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        for _ in 0..10_000 {
            let mut pow_bytes = [0; 32];
            rng.fill_bytes(&mut pow_bytes);
            let pow = BigUint::from_bytes_be(&pow_bytes) % (&target + BigUint::one());
            let mut mask = [0; 32];
            rng.fill_bytes(&mut mask);
            for bit in 0..profile.leading_zero_prefix_q {
                let byte = usize::from(bit / 8);
                mask[byte] &= !(1 << (7 - (bit % 8)));
            }
            let pow = to_u256(&pow).0;
            let mut raw = [0; 32];
            for index in 0..32 {
                raw[index] = pow[index] ^ mask[index];
            }
            assert!(BigUint::from_bytes_be(&raw) <= capture);
        }
    }

    #[test]
    fn rate_and_load_relationships_are_exact_rationals() {
        let assumptions = default_load_assumptions();
        let profile = derive_capture_profile(0x1925_ae67, 12, assumptions).unwrap();
        assert_eq!(
            profile.load.ingress_bytes_per_second,
            profile
                .load
                .capture_shares_per_second
                .multiply_integer(assumptions.encoded_share_bytes)
        );
        assert_eq!(
            profile.load.capture_shares_per_second,
            profile
                .load
                .capture_shares_per_hns_block
                .multiply_integer(1_000)
                .divide_integer(assumptions.hns_block_interval_ms)
        );
    }
}
