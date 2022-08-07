#[cfg(test)]
mod tests;

use super::{
    count_set_bits, get_bit_at_from_msb, set_bit_at_from_msb,
    smt::{DEFAULT_VALUE, RIGHT},
    tree_hasher::{TreeHasher, LEAF_PREFIX},
};
use bytes::Bytes;
use core::{marker::PhantomData, ops::Div};
use digest::Digest;

/// Returned when an invalid Merkle proof is supplied.
pub struct BadProof;

impl core::fmt::Debug for BadProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "bad proof")
    }
}

impl core::fmt::Display for BadProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "bad proof")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BadProof {}

/// SparseMerkleProof is a Merkle proof for an element in a SparseMerkleTree.
#[derive(Debug, Clone)]
pub struct SparseMerkleProof<H> {
    /// An array of the sibling nodes leading up to the leaf of the proof.
    pub(crate) side_nodes: Vec<Bytes>,

    /// The data of the unrelated leaf at the position
    /// of the key being proven, in the case of a non-membership proof. For
    /// membership proofs, is nil.
    pub(crate) non_membership_leaf_data: Option<Bytes>,

    /// the data of the sibling node to the leaf being proven,
    /// required for updatable proofs. For unupdatable proofs, is nil.
    pub(crate) sibling_data: Option<Bytes>,
    pub(crate) _marker: PhantomData<H>,
}

impl<H> SparseMerkleProof<H> {
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
            _marker: PhantomData,
        }
    }

    /// Get the sibling data for this proof
    #[inline]
    pub fn sibling_data(&self) -> Option<&Bytes> {
        self.sibling_data.as_ref()
    }

    /// get the non-membership leaf data for this proof
    #[inline]
    pub fn non_membership_leaf_data(&self) -> Option<&Bytes> {
        self.non_membership_leaf_data.as_ref()
    }

    /// get the side nodes for this proof
    #[inline]
    pub fn side_nodes(&self) -> &[Bytes] {
        &self.side_nodes
    }
}

impl<H: digest::Digest> SparseMerkleProof<H> {
    /// Verifies a Merkle proof
    pub fn verify(
        &self,
        root: impl AsRef<[u8]>,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> bool {
        self.verify_proof(root, key, value)
    }

    /// Compacts a proof, to reduce its size.
    pub fn compact(&self) -> Result<SparseCompactMerkleProof<H>, BadProof> {
        let mut th = TreeHasher::<H>::new(vec![0; TreeHasher::<H>::path_size()].into());

        if !self.sanity_check(&mut th) {
            return Err(BadProof);
        }

        let mut bit_mask = vec![0u8; (self.side_nodes.len() as f64).div(8.0).ceil() as usize];

        let compacted_side_nodes = self
            .side_nodes
            .iter()
            .enumerate()
            .filter_map(|(idx, node)| {
                let node = node.slice(..TreeHasher::<H>::path_size());
                if node.eq(th.placeholder_ref()) {
                    set_bit_at_from_msb(bit_mask.as_mut_slice(), idx);
                    None
                } else {
                    Some(node)
                }
            })
            .collect::<Vec<_>>();

        Ok(SparseCompactMerkleProof {
            side_nodes: compacted_side_nodes,
            non_membership_leaf_data: self.non_membership_leaf_data.clone(),
            bitmask: bit_mask.into(),
            num_side_nodes: self.side_nodes.len(),
            sibling_data: self.sibling_data.clone(),
            _marker: PhantomData,
        })
    }

    /// Compacts a proof, to reduce its size.
    pub fn compact_into(self) -> Result<SparseCompactMerkleProof<H>, BadProof> {
        let mut th = TreeHasher::<H>::new(vec![0; TreeHasher::<H>::path_size()].into());

        if !self.sanity_check(&mut th) {
            return Err(BadProof);
        }

        let num_side_nodes = self.side_nodes.len();
        let SparseMerkleProof {
            side_nodes,
            non_membership_leaf_data,
            sibling_data,
            _marker: _,
        } = self;
        let mut bit_mask = vec![0u8; (num_side_nodes as f64).div(8.0).ceil() as usize];

        let compacted_side_nodes = side_nodes
            .into_iter()
            .enumerate()
            .filter_map(|(idx, node)| {
                let node = node.slice(..TreeHasher::<H>::path_size());
                if node.eq(th.placeholder_ref()) {
                    set_bit_at_from_msb(bit_mask.as_mut_slice(), idx);
                    None
                } else {
                    Some(node)
                }
            })
            .collect::<Vec<_>>();

        Ok(SparseCompactMerkleProof {
            side_nodes: compacted_side_nodes,
            non_membership_leaf_data,
            bitmask: bit_mask.into(),
            num_side_nodes,
            sibling_data,
            _marker: PhantomData,
        })
    }

    #[inline]
    fn verify_proof(
        &self,
        root: impl AsRef<[u8]>,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> bool {
        let mut th = TreeHasher::<H>::new(vec![0; TreeHasher::<H>::path_size()].into());
        let path = th.path(key);

        if !self.sanity_check(&mut th) {
            return false;
        }

        let mut current_hash;
        // Determine what the leaf hash should be.
        if value.as_ref().eq(&DEFAULT_VALUE) {
            // Non-membership proof.
            match &self.non_membership_leaf_data {
                Some(data) => {
                    let (actual_path, value_hash) = TreeHasher::<H>::parse_leaf(data);
                    if actual_path.eq(path.as_slice()) {
                        // This is not an unrelated leaf; non-membership proof failed.
                        return false;
                    }

                    current_hash = th.digest_leaf_hash(actual_path, value_hash);
                }
                None => {
                    current_hash = th.placeholder();
                }
            }
        } else {
            let value_hash = th.digest(value);

            current_hash = th.digest_leaf_hash(path, value_hash);
        }
        let num = self.side_nodes.len();
        // Recompute root.
        self.side_nodes.iter().enumerate().for_each(|(idx, path)| {
            let node = path.slice(..TreeHasher::<H>::path_size());
            if get_bit_at_from_msb(path, num - 1 - idx) == RIGHT {
                (current_hash, _) = th.digest_node(node, &current_hash);
            } else {
                (current_hash, _) = th.digest_node(&current_hash, node);
            }
        });

        current_hash.eq(root.as_ref())
    }

    pub(crate) fn verify_proof_with_updates(
        &self,
        root: impl AsRef<[u8]>,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> (bool, Vec<(Bytes, Bytes)>)
    where
        H: Digest,
    {
        let mut th = TreeHasher::<H>::new(vec![0; TreeHasher::<H>::path_size()].into());
        let path = th.path(key);
        if !self.sanity_check(&mut th) {
            return (false, vec![]);
        }

        let mut updates = Vec::with_capacity(self.side_nodes.len() + 1);
        let mut current_hash;
        // Determine what the leaf hash should be.
        if value.as_ref().eq(&DEFAULT_VALUE) {
            // Non-membership proof.
            match &self.non_membership_leaf_data {
                Some(data) => {
                    let (actual_path, value_hash) = TreeHasher::<H>::parse_leaf(data);
                    if actual_path.eq(path.as_slice()) {
                        // This is not an unrelated leaf; non-membership proof failed.
                        return (false, vec![]);
                    }

                    let (hash, data) = th.digest_leaf(actual_path, value_hash);
                    current_hash = hash;
                    updates.push((current_hash.clone(), data));
                }
                None => {
                    current_hash = th.placeholder();
                }
            }
        } else {
            let value_hash = th.digest(value);

            let (hash, data) = th.digest_leaf(path.as_ref(), value_hash);
            current_hash = hash;
            updates.push((current_hash.clone(), data));
        }

        // Recompute root.
        let num = self.side_nodes.len();
        self.side_nodes
            .iter()
            .enumerate()
            .for_each(|(idx, side_node)| {
                let node = side_node.slice(..TreeHasher::<H>::path_size());
                if get_bit_at_from_msb(path.as_ref(), num - 1 - idx) == RIGHT {
                    let (hash, data) = th.digest_node(node, &current_hash);
                    current_hash = hash;
                    updates.push((current_hash.clone(), data));
                } else {
                    let (hash, data) = th.digest_node(&current_hash, node);
                    current_hash = hash;
                    updates.push((current_hash.clone(), data));
                }
            });
        (current_hash.eq(root.as_ref()), updates)
    }

    fn sanity_check(&self, th: &mut TreeHasher<H>) -> bool {
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

        if self.side_nodes.is_empty() {
            return true;
        }

        // Check that the sibling data hashes to the first side node if not nil
        match &self.sibling_data {
            Some(sibling_data) => {
                let sibling_hash = th.digest(sibling_data);
                self.side_nodes[0].eq(sibling_hash.as_slice())
            }
            None => true,
        }
    }

    #[inline]
    fn check_non_membership_proofs_size(&self, _th: &TreeHasher<H>) -> bool {
        if let Some(non_membership_proofs) = &self.non_membership_leaf_data {
            non_membership_proofs.len()
                != LEAF_PREFIX.len()
                    + TreeHasher::<H>::path_size()
                    + <H as digest::Digest>::output_size()
        } else {
            false
        }
    }
}

/// SparseCompactMerkleProof is a compact Merkle proof for an element in a SparseMerkleTree.
#[derive(Debug, Clone)]
pub struct SparseCompactMerkleProof<H> {
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

    _marker: PhantomData<H>,
}

impl<H> SparseCompactMerkleProof<H> {
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
            _marker: PhantomData,
        }
    }

    /// Get the sibility of for this proof
    #[inline]
    pub fn sibling_data(&self) -> Option<&Bytes> {
        self.sibling_data.as_ref()
    }

    /// Get the non-membership leaf data for this proof
    #[inline]
    pub fn non_membership_leaf_data(&self) -> Option<&Bytes> {
        self.non_membership_leaf_data.as_ref()
    }

    /// Get the original number of side nodes
    #[inline]
    pub fn original_side_nodes_len(&self) -> usize {
        self.num_side_nodes
    }

    /// Get the side nodes for this compacted proof
    #[inline]
    pub fn side_nodes(&self) -> &[Bytes] {
        &self.side_nodes
    }
}

impl<H: digest::Digest> SparseCompactMerkleProof<H> {
    fn sanity_check(&self, _th: &mut TreeHasher<H>) -> bool {
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

    /// Verifies a Merkle proof
    pub fn verify(
        &self,
        root: impl AsRef<[u8]>,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> bool {
        self.decompact()
            .map(|proof| proof.verify(root, key, value))
            .unwrap_or(false)
    }

    /// Decompacts a proof, so that it can be used for verify
    pub fn decompact(&self) -> Result<SparseMerkleProof<H>, BadProof> {
        let mut th = TreeHasher::<H>::new(vec![0; TreeHasher::<H>::path_size()].into());

        if !self.sanity_check(&mut th) {
            return Err(BadProof);
        }

        let mut position = 0;
        let nodes = (0..self.num_side_nodes)
            .map(|idx| {
                if get_bit_at_from_msb(&self.bitmask, idx) == 1 {
                    th.placeholder()
                } else {
                    position += 1;
                    self.side_nodes[position - 1].clone()
                }
            })
            .collect::<Vec<_>>();

        Ok(SparseMerkleProof {
            side_nodes: nodes,
            non_membership_leaf_data: self.non_membership_leaf_data.clone(),
            sibling_data: self.sibling_data.clone(),
            _marker: PhantomData,
        })
    }

    /// Decompacts a proof, so that it can be used for verify
    pub fn decompact_into(self) -> Result<SparseMerkleProof<H>, BadProof> {
        let mut th = TreeHasher::<H>::new(vec![0; TreeHasher::<H>::path_size()].into());

        if !self.sanity_check(&mut th) {
            return Err(BadProof);
        }

        let mut position = 0;
        let SparseCompactMerkleProof {
            side_nodes,
            non_membership_leaf_data,
            sibling_data,
            bitmask,
            num_side_nodes,
            _marker,
        } = self;

        let nodes = (0..num_side_nodes)
            .map(|idx| {
                if get_bit_at_from_msb(&bitmask, idx) == 1 {
                    th.placeholder()
                } else {
                    position += 1;
                    side_nodes[position - 1].clone()
                }
            })
            .collect::<Vec<_>>();

        Ok(SparseMerkleProof {
            side_nodes: nodes,
            non_membership_leaf_data,
            sibling_data,
            _marker,
        })
    }
}
