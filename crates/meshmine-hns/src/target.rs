use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{ToPrimitive, Zero};
use thiserror::Error;

use crate::Hash256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureParameters {
    pub network_target: Hash256,
    pub leading_zero_bits_p: u16,
    pub leading_zero_prefix_q: u16,
    pub blind_band_bits_d: u16,
    pub capture_target: Hash256,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CaptureParameterError {
    #[error("compact target is zero, negative, or wider than 256 bits")]
    InvalidTarget,
    #[error("blind bits must be nonzero and strictly smaller than target leading zeros")]
    InvalidBlindBand,
}

/// Decode `bits` with the same signed compact-number semantics as `HNS node`.
pub fn compact_to_target(compact: u32) -> BigInt {
    if compact == 0 {
        return BigInt::ZERO;
    }

    let exponent = compact >> 24;
    let negative = ((compact >> 23) & 1) != 0;
    let mut mantissa = compact & 0x007f_ffff;

    let mut target = if exponent <= 3 {
        mantissa >>= 8 * (3 - exponent);
        BigInt::from(mantissa)
    } else {
        BigInt::from(mantissa) << (8 * (exponent - 3))
    };

    if negative {
        target = -target;
    }
    target
}

/// Encode a non-negative target with the same canonical compaction as `HNS node`.
pub fn target_to_compact(target: &BigUint) -> u32 {
    if target.is_zero() {
        return 0;
    }

    let mut exponent = target.to_bytes_be().len() as u32;
    let mut mantissa = if exponent <= 3 {
        target.to_u32().expect("three-byte target fits u32") << (8 * (3 - exponent))
    } else {
        (target >> (8 * (exponent - 3)))
            .to_u32()
            .expect("shifted target fits u32")
    };

    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        exponent += 1;
    }

    (exponent << 24) | mantissa
}

/// Compare an HNS proof hash to the compact target exactly as `HNS node` does.
pub fn verify_pow(hash: &Hash256, bits: u32) -> bool {
    let target = compact_to_target(bits);
    if target.sign() != Sign::Plus || target.bits() > 256 {
        return false;
    }

    BigUint::from_bytes_be(hash) <= target.to_biguint().expect("positive target")
}

/// Derive the public mask-safe target exactly as MM-0001 section 9 requires.
/// Targets are returned as canonical 32-byte big-endian integers so callers
/// can compare them without importing a second target implementation.
pub fn derive_capture_parameters(
    bits: u32,
    blind_band_bits_d: u16,
) -> Result<CaptureParameters, CaptureParameterError> {
    let target = compact_to_target(bits);
    if target.sign() != Sign::Plus || target.bits() > 256 {
        return Err(CaptureParameterError::InvalidTarget);
    }
    let target = target
        .to_biguint()
        .expect("positive compact target converts to BigUint");
    let target_bytes = target.to_bytes_be();
    let mut network_target = [0; 32];
    network_target[32 - target_bytes.len()..].copy_from_slice(&target_bytes);

    let leading_zero_bits_p = count_leading_zero_bits(&network_target);
    if blind_band_bits_d == 0 || blind_band_bits_d >= leading_zero_bits_p {
        return Err(CaptureParameterError::InvalidBlindBand);
    }
    let leading_zero_prefix_q = leading_zero_bits_p - blind_band_bits_d;
    let mut capture_target = [0xff; 32];
    let zero_bytes = usize::from(leading_zero_prefix_q / 8);
    capture_target[..zero_bytes].fill(0);
    let partial_zero_bits = leading_zero_prefix_q % 8;
    if partial_zero_bits != 0 {
        capture_target[zero_bytes] >>= partial_zero_bits;
    }

    Ok(CaptureParameters {
        network_target,
        leading_zero_bits_p,
        leading_zero_prefix_q,
        blind_band_bits_d,
        capture_target,
    })
}

pub fn count_leading_zero_bits(bytes: &Hash256) -> u16 {
    let mut count = 0u16;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as u16;
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_hns_consensus_vector() {
        let hash: Hash256 =
            hex::decode("0000000000000000348f8ef340a84844aaa09b067141ea6742991ab11b3f2b67")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(verify_pow(&hash, 0x1900_896c));
        assert_eq!(
            compact_to_target(0x1900_896c).to_str_radix(16),
            "896c00000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn compact_decode_boundaries_match_hns_consensus() {
        let cases = [
            (0x0000_0000, "0"),
            (0x0100_3456, "0"),
            (0x0112_3456, "12"),
            (0x0200_8000, "80"),
            (0x0500_9234, "92340000"),
            (0x0492_3456, "-12345600"),
            (
                0x2100_ffff,
                "ffff000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                0x2200_ffff,
                "ffff00000000000000000000000000000000000000000000000000000000000000",
            ),
        ];
        for (bits, expected) in cases {
            assert_eq!(compact_to_target(bits).to_str_radix(16), expected);
        }
    }

    #[test]
    fn compact_encode_transitions_match_hns_consensus() {
        let cases = [
            ("0", 0x0000_0000),
            ("1", 0x0101_0000),
            ("7f", 0x017f_0000),
            ("80", 0x0200_8000),
            ("7fff", 0x027f_ff00),
            ("8000", 0x0300_8000),
            ("7fffff", 0x037f_ffff),
            ("800000", 0x0400_8000),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                0x2100_ffff,
            ),
        ];
        for (target, expected) in cases {
            let target = BigUint::parse_bytes(target.as_bytes(), 16).unwrap();
            assert_eq!(target_to_compact(&target), expected);
        }
    }

    #[test]
    fn rejects_zero_negative_and_overflow_targets() {
        assert!(!verify_pow(&[0; 32], 0));
        assert!(!verify_pow(&[0; 32], 0x0492_3456));
        assert!(!verify_pow(&[0; 32], 0x2200_ffff));
    }

    #[test]
    fn capture_parameters_follow_the_exact_zero_prefix_formula() {
        let parameters = derive_capture_parameters(0x1925_ae67, 12).unwrap();
        assert_eq!(parameters.leading_zero_bits_p, 58);
        assert_eq!(parameters.leading_zero_prefix_q, 46);
        assert_eq!(parameters.blind_band_bits_d, 12);
        assert_eq!(&parameters.capture_target[..5], &[0; 5]);
        assert_eq!(parameters.capture_target[5], 0x03);
        assert!(
            parameters.capture_target[6..]
                .iter()
                .all(|byte| *byte == 0xff)
        );

        assert_eq!(
            derive_capture_parameters(0x1925_ae67, 0),
            Err(CaptureParameterError::InvalidBlindBand)
        );
        assert_eq!(
            derive_capture_parameters(0, 1),
            Err(CaptureParameterError::InvalidTarget)
        );
    }
}
