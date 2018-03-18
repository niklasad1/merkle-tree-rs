//! Dummy Merkle Tree
//!
// FIXME: Add verify tree and verify transaction

use sha2::{Sha256, Digest};
use std::iter;
use std::collections::VecDeque;
use rand::{Rng, thread_rng};
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::U32;

type HashNode = GenericArray<u8, U32>;

/// Merkle tree
pub struct MerkleTree {
    blocks: Vec<HashNode>,
}

impl MerkleTree {
    /// Create empty merkle tree
    pub fn new() -> Self {
        MerkleTree { blocks: Vec::new() }
    }

    /// Add transaction
    pub fn add_transaction(&mut self) {
        let block = GenericArray::<u8, U32>::default();
        self.blocks.push(block);
    }

    /// Check whether the tree is empty
    pub fn empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Compute the root hash
    pub fn compute_merkle_root(&self) -> Result<HashNode, ()> {
        if self.empty() {
            Err(())
        } else {
            let hashes = self.blocks.iter()
                .rev()
                .map(|b| {
                let mut hasher = Sha256::default();
                hasher.input(b.as_slice());
                hasher.result()
            }).collect();
            Ok(helper(hashes))
        }
    }
} 
fn helper(mut first: Vec<HashNode>) -> HashNode {
    while first.len() % 2 != 0 {
        let last = first.last().unwrap().clone();
        first.push(last);
    }

    let mut second = vec![];

    for chunk in first.chunks(2) {
        let mut hasher = Sha256::default();
        let mut concat = vec![];
        concat.extend_from_slice(chunk[0].as_slice());
        concat.extend_from_slice(chunk[1].as_slice());
        hasher.input(concat.as_slice());
        second.push(hasher.result());
    }
    
    if second.len() == 1 { second[0] } else { helper(second) }
}

// #[derive(Debug, Hash, PartialEq, Eq, Clone)]
// struct Block {
//     data: Vec<u8>,
// }
//
// impl Block {
//     fn new() -> Self {
//         let mut rng = thread_rng();
//         let randomness: Vec<u8> = iter::repeat(()).map(|()| rng.gen()).take(4).collect();
//         Block { data: randomness }
//     }
//
//     fn as_slice(&self) -> &[u8] {
//         self.data.as_slice()
//     }
// }
