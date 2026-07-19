//! Deterministic Boolean circuit for the HNS mask commitment.
//!
//! The circuit has two 256-bit input groups (`parent`, `mask`) and one
//! 256-bit output group. Bits are ordered least-significant bit first within
//! each byte while bytes retain their HNS wire order. Only XOR, AND, and INV
//! gates are emitted, so the result can be consumed by Bristol-Fashion binary
//! MPC runtimes without embedding the clear mask in a helper process.

use std::fmt::{self, Write};

const INPUT_BITS: usize = 512;
const OUTPUT_BITS: usize = 256;

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BooleanGate {
    Xor {
        left: usize,
        right: usize,
        output: usize,
    },
    And {
        left: usize,
        right: usize,
        output: usize,
    },
    Inv {
        input: usize,
        output: usize,
    },
}

#[cfg(test)]
impl BooleanGate {
    const fn output(self) -> usize {
        match self {
            Self::Xor { output, .. } | Self::And { output, .. } | Self::Inv { output, .. } => {
                output
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskHashCircuit {
    gates: Vec<BooleanGate>,
    wire_count: usize,
    output_wires: [usize; OUTPUT_BITS],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitError {
    WrongInputCount,
}

impl fmt::Display for CircuitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongInputCount => formatter.write_str("mask-hash circuit requires 512 wires"),
        }
    }
}

impl std::error::Error for CircuitError {}

impl MaskHashCircuit {
    pub fn build() -> Self {
        let mut builder = CircuitBuilder::new(INPUT_BITS);
        let input_wires: [usize; INPUT_BITS] = std::array::from_fn(|index| index);
        let hash = blake2b_256_one_block(&mut builder, &input_wires);

        // Bristol consumers return the final output-wire suffix. Allocate an
        // explicit copy suffix even where a digest bit already names a wire.
        let zero = builder.constant(false);
        let output_wires = std::array::from_fn(|index| builder.xor(hash[index], zero));
        debug_assert_eq!(output_wires[0] + OUTPUT_BITS, builder.next_wire);
        Self {
            gates: builder.gates,
            wire_count: builder.next_wire,
            output_wires,
        }
    }

    pub const fn input_wire_count(&self) -> usize {
        INPUT_BITS
    }

    pub const fn output_wire_count(&self) -> usize {
        OUTPUT_BITS
    }

    pub fn gate_count(&self) -> usize {
        self.gates.len()
    }

    pub const fn wire_count(&self) -> usize {
        self.wire_count
    }

    /// Evaluate up to 64 independent cases in parallel. Bit `lane` of each
    /// input wire belongs to that case. INV intentionally flips all 64 lanes.
    pub fn evaluate_packed(&self, inputs: &[u64]) -> Result<[u64; OUTPUT_BITS], CircuitError> {
        if inputs.len() != INPUT_BITS {
            return Err(CircuitError::WrongInputCount);
        }
        let mut wires = vec![0u64; self.wire_count];
        wires[..INPUT_BITS].copy_from_slice(inputs);
        for gate in &self.gates {
            match *gate {
                BooleanGate::Xor {
                    left,
                    right,
                    output,
                } => wires[output] = wires[left] ^ wires[right],
                BooleanGate::And {
                    left,
                    right,
                    output,
                } => wires[output] = wires[left] & wires[right],
                BooleanGate::Inv { input, output } => wires[output] = !wires[input],
            }
        }
        Ok(std::array::from_fn(|index| wires[self.output_wires[index]]))
    }

    /// Render the deterministic circuit using the Bristol Fashion accepted by
    /// MP-SPDZ: two 256-wire inputs, one 256-wire output, and XOR/AND/INV only.
    pub fn write_bristol(&self, output: &mut impl Write) -> fmt::Result {
        writeln!(output, "{} {}", self.gate_count(), self.wire_count)?;
        writeln!(output, "2 256 256")?;
        writeln!(output, "1 256")?;
        writeln!(output)?;
        for gate in &self.gates {
            match *gate {
                BooleanGate::Xor {
                    left,
                    right,
                    output: wire,
                } => writeln!(output, "2 1 {left} {right} {wire} XOR")?,
                BooleanGate::And {
                    left,
                    right,
                    output: wire,
                } => writeln!(output, "2 1 {left} {right} {wire} AND")?,
                BooleanGate::Inv {
                    input,
                    output: wire,
                } => writeln!(output, "1 1 {input} {wire} INV")?,
            }
        }
        Ok(())
    }

    pub fn bristol_string(&self) -> String {
        let mut output = String::new();
        self.write_bristol(&mut output)
            .expect("writing to a String cannot fail");
        output
    }
}

struct CircuitBuilder {
    gates: Vec<BooleanGate>,
    next_wire: usize,
    zero: Option<usize>,
    one: Option<usize>,
}

trait BooleanBackend {
    type Wire: Copy;

    fn xor(&mut self, left: Self::Wire, right: Self::Wire) -> Self::Wire;
    fn and(&mut self, left: Self::Wire, right: Self::Wire) -> Self::Wire;
    fn not(&mut self, input: Self::Wire) -> Self::Wire;
    fn constant(&mut self, value: bool) -> Self::Wire;
}

impl CircuitBuilder {
    const fn new(input_wires: usize) -> Self {
        Self {
            gates: Vec::new(),
            next_wire: input_wires,
            zero: None,
            one: None,
        }
    }

    fn allocate(&mut self) -> usize {
        let wire = self.next_wire;
        self.next_wire += 1;
        wire
    }
}

impl BooleanBackend for CircuitBuilder {
    type Wire = usize;

    fn xor(&mut self, left: usize, right: usize) -> usize {
        let output = self.allocate();
        self.gates.push(BooleanGate::Xor {
            left,
            right,
            output,
        });
        output
    }

    fn and(&mut self, left: usize, right: usize) -> usize {
        let output = self.allocate();
        self.gates.push(BooleanGate::And {
            left,
            right,
            output,
        });
        output
    }

    fn not(&mut self, input: usize) -> usize {
        let output = self.allocate();
        self.gates.push(BooleanGate::Inv { input, output });
        output
    }

    fn constant(&mut self, value: bool) -> usize {
        if value {
            if let Some(one) = self.one {
                return one;
            }
            let zero = self.constant(false);
            let one = self.not(zero);
            self.one = Some(one);
            one
        } else {
            if let Some(zero) = self.zero {
                return zero;
            }
            let zero = self.xor(0, 0);
            self.zero = Some(zero);
            zero
        }
    }
}

type Word<W> = [W; 64];

fn constant_word<B: BooleanBackend>(backend: &mut B, value: u64) -> Word<B::Wire> {
    std::array::from_fn(|bit| backend.constant((value >> bit) & 1 == 1))
}

fn xor_word<B: BooleanBackend>(
    backend: &mut B,
    left: Word<B::Wire>,
    right: Word<B::Wire>,
) -> Word<B::Wire> {
    std::array::from_fn(|bit| backend.xor(left[bit], right[bit]))
}

fn add_word<B: BooleanBackend>(
    backend: &mut B,
    left: Word<B::Wire>,
    right: Word<B::Wire>,
) -> Word<B::Wire> {
    let mut carry = backend.constant(false);
    std::array::from_fn(|bit| {
        let pair_xor = backend.xor(left[bit], right[bit]);
        let sum = backend.xor(pair_xor, carry);
        let both = backend.and(left[bit], right[bit]);
        let propagated = backend.and(carry, pair_xor);
        carry = backend.xor(both, propagated);
        sum
    })
}

fn rotate_right<W: Copy>(word: Word<W>, distance: usize) -> Word<W> {
    std::array::from_fn(|bit| word[(bit + distance) % 64])
}

fn g<B: BooleanBackend>(
    backend: &mut B,
    state: &mut [Word<B::Wire>; 16],
    indexes: [usize; 4],
    x: Word<B::Wire>,
    y: Word<B::Wire>,
) {
    let [a, b, c, d] = indexes;
    let a_plus_b = add_word(backend, state[a], state[b]);
    state[a] = add_word(backend, a_plus_b, x);
    state[d] = rotate_right(xor_word(backend, state[d], state[a]), 32);
    state[c] = add_word(backend, state[c], state[d]);
    state[b] = rotate_right(xor_word(backend, state[b], state[c]), 24);
    let a_plus_b = add_word(backend, state[a], state[b]);
    state[a] = add_word(backend, a_plus_b, y);
    state[d] = rotate_right(xor_word(backend, state[d], state[a]), 16);
    state[c] = add_word(backend, state[c], state[d]);
    state[b] = rotate_right(xor_word(backend, state[b], state[c]), 63);
}

fn blake2b_256_one_block<B: BooleanBackend>(
    backend: &mut B,
    input: &[B::Wire; INPUT_BITS],
) -> [B::Wire; OUTPUT_BITS] {
    let message: [Word<B::Wire>; 16] = std::array::from_fn(|word| {
        if word < 8 {
            std::array::from_fn(|bit| input[word * 64 + bit])
        } else {
            constant_word(backend, 0)
        }
    });
    let mut hash: [Word<B::Wire>; 8] = std::array::from_fn(|word| constant_word(backend, IV[word]));
    let parameters = constant_word(backend, 0x0101_0020);
    hash[0] = xor_word(backend, hash[0], parameters);

    let mut state: [Word<B::Wire>; 16] = std::array::from_fn(|word| {
        if word < 8 {
            hash[word]
        } else {
            constant_word(backend, IV[word - 8])
        }
    });
    let input_length = constant_word(backend, 64);
    state[12] = xor_word(backend, state[12], input_length);
    state[14] = std::array::from_fn(|bit| backend.not(state[14][bit]));

    for schedule in SIGMA {
        g(
            backend,
            &mut state,
            [0, 4, 8, 12],
            message[schedule[0]],
            message[schedule[1]],
        );
        g(
            backend,
            &mut state,
            [1, 5, 9, 13],
            message[schedule[2]],
            message[schedule[3]],
        );
        g(
            backend,
            &mut state,
            [2, 6, 10, 14],
            message[schedule[4]],
            message[schedule[5]],
        );
        g(
            backend,
            &mut state,
            [3, 7, 11, 15],
            message[schedule[6]],
            message[schedule[7]],
        );
        g(
            backend,
            &mut state,
            [0, 5, 10, 15],
            message[schedule[8]],
            message[schedule[9]],
        );
        g(
            backend,
            &mut state,
            [1, 6, 11, 12],
            message[schedule[10]],
            message[schedule[11]],
        );
        g(
            backend,
            &mut state,
            [2, 7, 8, 13],
            message[schedule[12]],
            message[schedule[13]],
        );
        g(
            backend,
            &mut state,
            [3, 4, 9, 14],
            message[schedule[14]],
            message[schedule[15]],
        );
    }

    let digest_words: [Word<B::Wire>; 4] = std::array::from_fn(|word| {
        let first = xor_word(backend, hash[word], state[word]);
        xor_word(backend, first, state[word + 8])
    });
    std::array::from_fn(|bit| digest_words[bit / 64][bit % 64])
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshmine_hns::blake2b_256;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn set_lane(inputs: &mut [u64; INPUT_BITS], lane: usize, bytes: &[u8; 64]) {
        for (byte_index, byte) in bytes.iter().enumerate() {
            for bit in 0..8 {
                if byte >> bit & 1 == 1 {
                    inputs[byte_index * 8 + bit] |= 1u64 << lane;
                }
            }
        }
    }

    fn lane_digest(outputs: &[u64; OUTPUT_BITS], lane: usize) -> [u8; 32] {
        std::array::from_fn(|byte| {
            (0..8).fold(0, |value, bit| {
                value | (((outputs[byte * 8 + bit] >> lane) & 1) as u8) << bit
            })
        })
    }

    #[test]
    fn boolean_mask_hash_circuit_matches_ten_thousand_hns_vectors() {
        const CASES: usize = 10_000;
        let circuit = MaskHashCircuit::build();
        let mut rng = ChaCha20Rng::from_seed([0x4d; 32]);
        let mut checked = 0usize;
        while checked < CASES {
            let lanes = (CASES - checked).min(64);
            let mut inputs = [0u64; INPUT_BITS];
            let mut expected = Vec::with_capacity(lanes);
            for lane in 0..lanes {
                let mut parent = [0u8; 32];
                let mut mask = [0u8; 32];
                rng.fill_bytes(&mut parent);
                rng.fill_bytes(&mut mask);
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&parent);
                combined[32..].copy_from_slice(&mask);
                set_lane(&mut inputs, lane, &combined);
                expected.push(blake2b_256(&[&parent, &mask]));
            }
            let outputs = circuit.evaluate_packed(&inputs).unwrap();
            for (lane, expected) in expected.iter().enumerate() {
                assert_eq!(lane_digest(&outputs, lane), *expected);
            }
            checked += lanes;
        }
    }

    #[test]
    fn circuit_is_bounded_deterministic_and_bristol_compatible() {
        let first = MaskHashCircuit::build();
        let second = MaskHashCircuit::build();
        assert_eq!(first, second);
        assert_eq!(first.input_wire_count(), 512);
        assert_eq!(first.output_wire_count(), 256);
        assert!(first.gate_count() < 250_000);
        assert_eq!(first.wire_count(), 512 + first.gate_count());
        assert_eq!(first.output_wires[0] + 256, first.wire_count());
        assert_eq!(first.gates.last().unwrap().output() + 1, first.wire_count());

        let rendered = first.bristol_string();
        let mut lines = rendered.lines();
        assert_eq!(
            lines.next().unwrap(),
            format!("{} {}", first.gate_count(), first.wire_count())
        );
        assert_eq!(lines.next(), Some("2 256 256"));
        assert_eq!(lines.next(), Some("1 256"));
        assert_eq!(lines.next(), Some(""));
        assert_eq!(lines.count(), first.gate_count());
        assert_eq!(
            hex::encode(blake2b_256(&[rendered.as_bytes()])),
            "efcbf93386e192a1147f314375620701f919a25b1b9bb510ee2c78d44847c467"
        );
    }

    #[test]
    fn circuit_rejects_wrong_input_count() {
        assert_eq!(
            MaskHashCircuit::build().evaluate_packed(&[0; 511]),
            Err(CircuitError::WrongInputCount)
        );
    }
}
