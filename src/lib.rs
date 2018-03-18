//! Toy Merkle Tree

#![warn(missing_docs)]
#![warn(warnings)]

extern crate sha2;
extern crate digest;
extern crate rand;

mod merkle_tree;

#[cfg(test)]
mod tests {
    use merkle_tree::MerkleTree;
    use sha2::{Sha256, Digest};
    use digest::generic_array::GenericArray;
    use digest::generic_array::typenum::U32;

    #[test]
    fn empty() {
        let tree = MerkleTree::new();
        assert_eq!(true, tree.empty());
        assert_eq!(Err(()), tree.compute_merkle_root());
    }

    #[test]
    fn simple_merke() {
        let mut tree = MerkleTree::new();
        for _ in 0..4 {
            tree.add_transaction();
        }

        // 32 zeros
        let zeros = GenericArray::<u8, U32>::default();
        let mut hashes = vec![];

        // Hash all `transactions`
        for _ in 0..4 {
            let mut hasher = Sha256::default();
            hasher.input(zeros.as_slice());
            let hash = hasher.result();
            hashes.push(hash);
        }
        
        // hash leaves in to parents
        // H(Parent) = H(H(Leaf1) || H(Leaf2))
        let mut p1 = vec![];
        let mut p2 = vec![];

        p1.extend_from_slice(hashes[0].as_slice());
        p1.extend_from_slice(hashes[1].as_slice());
        p2.extend_from_slice(hashes[2].as_slice());
        p2.extend_from_slice(hashes[3].as_slice());

        let mut hasher = Sha256::default();
        hasher.input(p1.as_slice());
        let p1_hash = hasher.result();
        
        let mut hasher = Sha256::default();
        hasher.input(p2.as_slice());
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
    fn odd_number_shouldnt_return_ok() {
        let mut tree = MerkleTree::new();
        for _ in 0..5 {
            tree.add_transaction();
        }
        assert_ne!(Err(()), tree.compute_merkle_root()); 
    }
    
    #[test]
    fn test_many_transactions() {
        let mut tree = MerkleTree::new();
        for _ in 0..1_000_000 {
            tree.add_transaction();
        }
        assert_ne!(Err(()), tree.compute_merkle_root()); 
    }
}
