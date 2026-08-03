//! Bounded, canonical binary encoding for MeshMine objects.

use thiserror::Error;

pub const DEFAULT_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_ITEMS: usize = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_object_bytes: usize,
    pub max_vector_items: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_object_bytes: DEFAULT_MAX_BYTES,
            max_vector_items: DEFAULT_MAX_ITEMS,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodecError {
    #[error("object exceeds byte limit: {actual} > {maximum}")]
    ObjectTooLarge { actual: usize, maximum: usize },
    #[error("unexpected end of object at byte {offset}: need {needed} more bytes")]
    UnexpectedEof { offset: usize, needed: usize },
    #[error("noncanonical unsigned varint")]
    NonCanonicalVarint,
    #[error("unsigned varint overflows u64")]
    VarintOverflow,
    #[error("length {actual} exceeds maximum {maximum}")]
    LengthLimit { actual: usize, maximum: usize },
    #[error("invalid option tag {0}")]
    InvalidOption(u8),
    #[error("trailing bytes after canonical object: {0}")]
    TrailingBytes(usize),
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
}

#[derive(Clone, Debug, Default)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub fn varint(&mut self, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.u8(byte);
            if value == 0 {
                break;
            }
        }
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.varint(value.len() as u64);
        self.fixed(value);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    limits: DecodeLimits,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8], limits: DecodeLimits) -> Result<Self, CodecError> {
        if bytes.len() > limits.max_object_bytes {
            return Err(CodecError::ObjectTooLarge {
                actual: bytes.len(),
                maximum: limits.max_object_bytes,
            });
        }
        Ok(Self {
            bytes,
            offset: 0,
            limits,
        })
    }

    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub fn varint(&mut self) -> Result<u64, CodecError> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = self.u8()?;
            let payload = u64::from(byte & 0x7f);
            if index == 9 && (payload > 1 || byte & 0x80 != 0) {
                return Err(CodecError::VarintOverflow);
            }
            value |= payload << (index * 7);
            if byte & 0x80 == 0 {
                if index > 0 && payload == 0 {
                    return Err(CodecError::NonCanonicalVarint);
                }
                return Ok(value);
            }
        }
        Err(CodecError::VarintOverflow)
    }

    pub fn length(&mut self, maximum: usize) -> Result<usize, CodecError> {
        let value = self.varint()?;
        let value = usize::try_from(value).map_err(|_| CodecError::LengthLimit {
            actual: usize::MAX,
            maximum,
        })?;
        if value > maximum || value > self.limits.max_vector_items {
            return Err(CodecError::LengthLimit {
                actual: value,
                maximum: maximum.min(self.limits.max_vector_items),
            });
        }
        Ok(value)
    }

    pub fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, CodecError> {
        let value = self.varint()?;
        let length = usize::try_from(value).map_err(|_| CodecError::LengthLimit {
            actual: usize::MAX,
            maximum,
        })?;
        if length > maximum || length > self.limits.max_object_bytes {
            return Err(CodecError::LengthLimit {
                actual: length,
                maximum: maximum.min(self.limits.max_object_bytes),
            });
        }
        Ok(self.take(length)?.to_vec())
    }

    pub fn fixed_bytes(&mut self, length: usize, maximum: usize) -> Result<Vec<u8>, CodecError> {
        if length > maximum || length > self.limits.max_object_bytes {
            return Err(CodecError::LengthLimit {
                actual: length,
                maximum: maximum.min(self.limits.max_object_bytes),
            });
        }
        Ok(self.take(length)?.to_vec())
    }

    pub fn option<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, CodecError>,
    ) -> Result<Option<T>, CodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => decode(self).map(Some),
            other => Err(CodecError::InvalidOption(other)),
        }
    }

    pub fn finish(self) -> Result<(), CodecError> {
        let remaining = self.bytes.len() - self.offset;
        if remaining != 0 {
            return Err(CodecError::TrailingBytes(remaining));
        }
        Ok(())
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CodecError::UnexpectedEof {
                offset: self.offset,
                needed: length,
            })?;
        if end > self.bytes.len() {
            return Err(CodecError::UnexpectedEof {
                offset: self.offset,
                needed: end - self.bytes.len(),
            });
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }
}

pub trait CanonicalEncode {
    fn encode(&self, encoder: &mut Encoder);

    fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        self.encode(&mut encoder);
        encoder.into_bytes()
    }
}

pub trait CanonicalDecode: Sized {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError>;

    fn from_canonical_bytes(bytes: &[u8], limits: DecodeLimits) -> Result<Self, CodecError> {
        let mut decoder = Decoder::new(bytes, limits)?;
        let value = Self::decode(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_boundaries_round_trip() {
        for value in [0, 1, 0x7f, 0x80, 0x3fff, 0x4000, u32::MAX as u64, u64::MAX] {
            let mut encoder = Encoder::new();
            encoder.varint(value);
            let bytes = encoder.into_bytes();
            let mut decoder = Decoder::new(&bytes, DecodeLimits::default()).unwrap();
            assert_eq!(decoder.varint().unwrap(), value);
            decoder.finish().unwrap();
        }
    }

    #[test]
    fn rejects_redundant_and_overflowing_varints() {
        for bytes in [&[0x80, 0x00][..], &[0x81, 0x00][..], &[0xff; 10][..]] {
            let mut decoder = Decoder::new(bytes, DecodeLimits::default()).unwrap();
            assert!(matches!(
                decoder.varint(),
                Err(CodecError::NonCanonicalVarint | CodecError::VarintOverflow)
            ));
        }
    }

    #[test]
    fn enforces_object_and_field_bounds() {
        assert!(matches!(
            Decoder::new(
                &[0; 5],
                DecodeLimits {
                    max_object_bytes: 4,
                    max_vector_items: 4,
                }
            ),
            Err(CodecError::ObjectTooLarge { .. })
        ));

        let mut decoder = Decoder::new(&[5], DecodeLimits::default()).unwrap();
        assert!(matches!(
            decoder.bytes(4),
            Err(CodecError::LengthLimit { .. })
        ));
    }
}
