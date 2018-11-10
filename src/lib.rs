//! Toy Merkle Tree

#![warn(missing_docs)]
#![warn(warnings)]

extern crate digest;
extern crate rand;
extern crate sha2;

/// Dummy Merkle Tree
///
/// FIXME: Add `merkle_proof`
use digest::generic_array::typenum::U32;
use digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};

type Hash = GenericArray<u8, U32>;

/// Merkle tree
#[derive(Debug, Default)]
pub struct MerkleTree<T: AsRef<[u8]>> {
    blocks: Vec<T>,
}

impl<T: AsRef<[u8]>> MerkleTree<T> {
    /// Insert raw data
    pub fn insert_block(&mut self, block: T)
    where
        T: AsRef<[u8]>,
    {
        self.blocks.push(block);
    }

    /// Check whether any blocks have been added
    pub fn empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Compute the root hash
    pub fn compute_merkle_root(&self) -> Result<Hash, ()> {
        if self.empty() {
            Err(())
        } else {
            let hashes = self
                .blocks
                .iter()
                .rev()
                .map(|block| {
                    let mut hasher = Sha256::default();
                    hasher.input(block.as_ref());
                    hasher.result()
                })
                .collect();
            chain_hashes(hashes)
        }
    }
}

fn chain_hashes(mut hashes: Vec<Hash>) -> Result<Hash, ()> {
    // fill with `dummy data` must be divisable by two
    while hashes.len() % 2 != 0 {
        hashes.push(Hash::default());
    }

    loop {
        hashes = ::std::mem::replace(&mut hashes, Vec::new())
            .chunks(2)
            .filter_map(|chunk| {
                if chunk.len() != 2 {
                    None
                } else {
                    let mut hasher = Sha256::default();
                    let mut concat = chunk[0].to_vec();
                    concat.extend_from_slice(&chunk[1]);
                    hasher.input(&concat);
                    Some(hasher.result())
                }
            })
            .collect();

        if hashes.len() == 1 {
            break;
        }
    }

    assert_eq!(hashes.len(), 1);
    hashes.pop().ok_or(())
}

#[cfg(test)]
mod tests {
    type Bytes = Vec<u8>;
    use super::{Hash, MerkleTree};
    use sha2::{Digest, Sha256};

    #[test]
    fn empty() {
        let tree: MerkleTree<Bytes> = MerkleTree::default();
        assert_eq!(true, tree.empty());
        assert_eq!(Err(()), tree.compute_merkle_root());
    }

    #[test]
    fn simple_merkle() {
        let mut tree = MerkleTree::default();
        let zero = Hash::default();

        let empty = {
            let mut hasher = Sha256::default();
            hasher.input(&zero);
            hasher.result()
        };

        for _ in 0..4 {
            tree.insert_block(zero);
        }

        // hash leaves in to parents
        // H(Parent) = H(H(Leaf1) || H(Leaf2))
        let mut p1 = vec![];
        let mut p2 = vec![];

        p1.extend_from_slice(&empty);
        p1.extend_from_slice(&empty);
        p2.extend_from_slice(&empty);
        p2.extend_from_slice(&empty);

        let mut hasher = Sha256::default();
        hasher.input(&p1);
        let p1_hash = hasher.result();

        let mut hasher = Sha256::default();
        hasher.input(&p2);
        let p2_hash = hasher.result();

        // Hash parents to the root hash
        // H(Root) = H(H(Parent1) || H(Parent2))
        let mut r = vec![];
        r.extend_from_slice(p1_hash.as_slice());
        r.extend_from_slice(p2_hash.as_slice());

        let mut hasher = Sha256::default();
        hasher.input(r.as_slice());
        let root_hash = hasher.result();

        assert_eq!(tree.compute_merkle_root(), Ok(root_hash));
    }

    #[test]
    fn odd_number_blocks_should_be_padded() {
        let mut tree = MerkleTree::default();

        for _ in 0..5 {
            tree.insert_block(Vec::new());
        }
        assert_ne!(Err(()), tree.compute_merkle_root());
    }

    #[test]
    fn test_many_transactions() {
        let mut tree = MerkleTree::default();
        for i in 0..1_000_000 {
            tree.insert_block(format!("foooobar {}", i));
        }
        assert_ne!(Err(()), tree.compute_merkle_root());
    }
}
