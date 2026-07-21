use meshmine_types::U256;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetControllerConfig {
    pub desired_submission_interval_ms: u64,
    pub minimum_observations: u32,
    pub maximum_step_numerator: u32,
    pub maximum_step_denominator: u32,
}

impl Default for TargetControllerConfig {
    fn default() -> Self {
        Self {
            desired_submission_interval_ms: 15_000,
            minimum_observations: 4,
            maximum_step_numerator: 4,
            maximum_step_denominator: 1,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TargetControllerError {
    #[error("target controller configuration is invalid")]
    InvalidConfiguration,
    #[error("initial edge target is harder than the capture/device lower bound")]
    InvalidBounds,
}

/// Bounded variable-target controller. The capture target remains the hard
/// forwarding threshold. The edge target may become easier to improve local
/// telemetry, but can never become harder than capture or the device's own
/// minimum accepted target.
pub struct AdaptiveTargetController {
    config: TargetControllerConfig,
    capture_target: U256,
    device_minimum_target: U256,
    maximum_edge_target: U256,
    current_target: U256,
    observed_interval_sum_ms: u128,
    observations: u32,
}

impl AdaptiveTargetController {
    pub fn new(
        config: TargetControllerConfig,
        capture_target: U256,
        device_minimum_target: U256,
        maximum_edge_target: U256,
        initial_target: U256,
    ) -> Result<Self, TargetControllerError> {
        if config.desired_submission_interval_ms == 0
            || config.minimum_observations == 0
            || config.maximum_step_numerator == 0
            || config.maximum_step_denominator == 0
            || config.maximum_step_numerator < config.maximum_step_denominator
        {
            return Err(TargetControllerError::InvalidConfiguration);
        }
        let lower = harder_bound(capture_target, device_minimum_target);
        if maximum_edge_target.0 < lower.0
            || initial_target.0 < lower.0
            || initial_target.0 > maximum_edge_target.0
        {
            return Err(TargetControllerError::InvalidBounds);
        }
        Ok(Self {
            config,
            capture_target,
            device_minimum_target,
            maximum_edge_target,
            current_target: initial_target,
            observed_interval_sum_ms: 0,
            observations: 0,
        })
    }

    pub const fn current_target(&self) -> U256 {
        self.current_target
    }

    pub fn observe_submission(&mut self, interval_ms: u64) -> Option<U256> {
        self.observed_interval_sum_ms = self
            .observed_interval_sum_ms
            .saturating_add(u128::from(interval_ms.max(1)));
        self.observations = self.observations.saturating_add(1);
        if self.observations < self.config.minimum_observations {
            return None;
        }
        let average = self.observed_interval_sum_ms / u128::from(self.observations);
        self.observed_interval_sum_ms = 0;
        self.observations = 0;

        let current = BigUint::from_bytes_be(&self.current_target.0);
        let desired = BigUint::from(self.config.desired_submission_interval_ms);
        let observed = BigUint::from(average.max(1));
        let proposed = (&current * observed) / desired;

        let numerator = BigUint::from(self.config.maximum_step_numerator);
        let denominator = BigUint::from(self.config.maximum_step_denominator);
        let maximum = (&current * &numerator) / &denominator;
        let minimum = (&current * &denominator) / &numerator;
        let bounded_step = proposed.max(minimum).min(maximum);
        let lower = BigUint::from_bytes_be(
            &harder_bound(self.capture_target, self.device_minimum_target).0,
        );
        let protocol_maximum = BigUint::from_bytes_be(&self.maximum_edge_target.0);
        let maximum_u256 = (BigUint::one() << 256usize) - BigUint::one();
        let bounded = bounded_step
            .max(lower)
            .min(protocol_maximum)
            .min(maximum_u256);
        self.current_target = big_to_u256(&bounded);
        Some(self.current_target)
    }
}

fn harder_bound(capture: U256, device_minimum: U256) -> U256 {
    if capture.0 >= device_minimum.0 {
        capture
    } else {
        device_minimum
    }
}

fn big_to_u256(value: &BigUint) -> U256 {
    if value.is_zero() {
        return U256::ZERO;
    }
    let bytes = value.to_bytes_be();
    let mut output = [0; 32];
    let start = 32usize.saturating_sub(bytes.len());
    output[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    U256(output)
}
