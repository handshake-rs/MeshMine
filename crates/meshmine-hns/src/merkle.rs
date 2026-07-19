use crate::{Hash256, blake2b_256};

/// Build the Handshake transaction or witness Merkle root from already-hashed
/// transaction leaves.
///
/// HNS uses bcrypto's domain-separated `mrkl` construction: empty, leaf, and
/// internal hashes are distinct, and an odd node is paired with the empty
/// sentinel rather than duplicated.
pub fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    let sentinel = blake2b_256(&[&[]]);

    if leaves.is_empty() {
        return sentinel;
    }

    let mut level: Vec<Hash256> = leaves
        .iter()
        .map(|leaf| blake2b_256(&[&[0], leaf]))
        .collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&sentinel);
            next.push(blake2b_256(&[&[1], &pair[0], right]));
        }
        level = next;
    }

    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_is_blake2b_empty() {
        assert_eq!(merkle_root(&[]), blake2b_256(&[&[]]));
    }

    #[test]
    fn odd_leaf_is_paired_with_sentinel() {
        let leaves = [[1; 32], [2; 32], [3; 32]];
        let sentinel = blake2b_256(&[&[]]);
        let a = blake2b_256(&[&[0], &leaves[0]]);
        let b = blake2b_256(&[&[0], &leaves[1]]);
        let c = blake2b_256(&[&[0], &leaves[2]]);
        let left = blake2b_256(&[&[1], &a, &b]);
        let right = blake2b_256(&[&[1], &c, &sentinel]);
        assert_eq!(merkle_root(&leaves), blake2b_256(&[&[1], &left, &right]));
    }
}
