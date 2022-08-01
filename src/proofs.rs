use bytes::Bytes;

use crate::{tree_hasher::{Hasher, LEAF_PREFIX}, count_set_bits};
use digest::{Digest, FixedOutputReset};


/// SparseMerkleProof is a Merkle proof for an element in a SparseMerkleTree.
pub struct SparseMerkleProof {
    /// An array of the sibling nodes leading up to the leaf of the proof.
    side_nodes: Vec<Bytes>,

    /// The data of the unrelated leaf at the position
	/// of the key being proven, in the case of a non-membership proof. For
	/// membership proofs, is nil.
    non_membership_leaf_data: Option<Bytes>,

    /// the data of the sibling node to the leaf being proven,
	/// required for updatable proofs. For unupdatable proofs, is nil.
    sibling_data: Option<Bytes>,
}

impl SparseMerkleProof {
    /// Creates a new SparseMerkleProof.
    pub fn new(
        side_nodes: Vec<Bytes>,
        non_membership_leaf_data: Option<Bytes>,
        sibling_data: Option<Bytes>,
    ) -> Self {
        Self {
            side_nodes,
            non_membership_leaf_data,
            sibling_data,
        }
    }

    pub fn verify_proof_with_updates<H>(&self, root: &[u8], key: &[u8], value: &[u8], hash: H) -> Option<Vec<Vec<Bytes>>> 
    where H: Digest + FixedOutputReset
    {
        let mut th = TreeHasher::<H>::new(vec![0; TreeHasher::<H>::path_size()].into());
        let path = th.digest(key);
        todo!()

    }

    fn sanity_check<H: super::Hasher>(&self, th: &mut TreeHasher<H, { H::OUTPUT_SIZE }>) -> bool {
        // Do a basic sanity check on the proof, so that a malicious proof cannot
	    // cause the verifier to fatally exit (e.g. due to an index out-of-range
	    // error) or cause a CPU DoS attack.

	    // Check that the number of supplied sidenodes does not exceed the maximum possible.
        if self.side_nodes.len() > TreeHasher::<H>::path_size() * 8 ||
            // Check that leaf data for non-membership proofs is the correct size.
            self.check_non_membership_proofs_size(th)
        {
            return false;
        }

        // Check that all supplied sidenodes are the correct size.
        for side_node in &self.side_nodes {
            if side_node.len() != <H as digest::Digest>::output_size() {
                return false;
            }
        }

        if self.side_nodes.is_empty() { return true; }

        // Check that the sibling data hashes to the first side node if not nil
        match &self.sibling_data {
            Some(sibling_data) => {
                let sibling_hash = th.digest(sibling_data);
                self.side_nodes[0].eq(sibling_hash.as_slice())
            },
            None => true,
        }
    }

    #[inline]
    fn check_non_membership_proofs_size<H: super::Hasher>(&self, _th: &TreeHasher<H, { H::OUTPUT_SIZE }>) -> bool {
        if let Some(non_membership_proofs) = &self.non_membership_leaf_data {
            non_membership_proofs.len() != LEAF_PREFIX.len() + TreeHasher::<H>::path_size() + <H as digest::Digest>::output_size()
        } else {
            false
        }
    }
}

/// SparseCompactMerkleProof is a compact Merkle proof for an element in a SparseMerkleTree.
pub struct SparseCompactMerkleProof {
    /// An array of the sibling nodes leading up to the leaf of the proof.
    side_nodes: Vec<Bytes>,

    
    /// The data of the unrelated leaf at the position
	/// of the key being proven, in the case of a non-membership proof. For
	/// membership proofs, is nil.
    non_membership_leaf_data: Option<Bytes>,
    

    /// BitMask, in the case of a compact proof, is a bit mask of the sidenodes
	/// of the proof where an on-bit indicates that the sidenode at the bit's
	/// index is a placeholder. This is only set if the proof is compact.
    bitmask: Bytes,

    /// In the case of a compact proof, indicates the number of
	/// sidenodes in the proof when decompacted. This is only set if the proof is compact.
    num_side_nodes: usize,

    // the data of the sibling node to the leaf being proven,
	/// required for updatable proofs. For unupdatable proofs, is nil.
    sibling_data: Option<Bytes>,
}

impl SparseCompactMerkleProof {
    /// Creates a new SparseCompactMerkleProof.
    pub fn new(
        side_nodes: Vec<Bytes>,
        non_membership_leaf_data: Option<Bytes>,
        bitmask: Bytes,
        num_side_nodes: usize,
        sibling_data: Option<Bytes>,
    ) -> Self {
        Self {
            side_nodes,
            non_membership_leaf_data,
            bitmask,
            num_side_nodes,
            sibling_data,
        }
    }

    fn sanity_check<H: super::Hasher>(&self, _th: &mut TreeHasher<H, { H::OUTPUT_SIZE }>) -> bool {
        // Do a basic sanity check on the proof on the fields of the proof specific to
	    // the compact proof only.
	    //
	    // When the proof is de-compacted and verified, the sanity check for the
	    // de-compacted proof should be executed.

	    // Compact proofs: check that NumSideNodes is within the right range.
        if self.num_side_nodes > TreeHasher::<H>::path_size() * 8 ||
            // Compact proofs: check that the length of the bit mask is as expected
		    // according to NumSideNodes.
            self.bitmask.len() != ((self.num_side_nodes as f64 ) / 8f64).ceil() as usize ||
            // Compact proofs: check that the correct number of sidenodes have been
		    // supplied according to the bit mask.
            (self.num_side_nodes > 0 && self.side_nodes.len() != self.num_side_nodes - count_set_bits(&self.bitmask))
        {
            return false;
        }

        true
    }
}

