use crate::BadProof;

use super::{
    count_common_prefix, get_bit_at_from_msb, tree_hasher::TreeHasher, KVStore,
    SparseCompactMerkleProof, SparseMerkleProof,
};
use alloc::boxed::Box;
use alloc::{vec, vec::Vec};
use bytes::Bytes;
use core::ops::Deref;
#[cfg(test)]
pub mod tests;

pub(crate) const RIGHT: usize = 1;
pub(crate) const DEFAULT_VALUE: Bytes = Bytes::new();

/// Sparse Merkle tree.
pub struct SparseMerkleTree<S: KVStore> {
    th: TreeHasher<S::Hasher>,
    nodes: S,
    values: S,
    root: Bytes,
}

impl<S: KVStore + core::fmt::Debug> core::fmt::Debug for SparseMerkleTree<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct(core::any::type_name::<Self>())
            .field("nodes", &self.nodes)
            .field("values", &self.values)
            .field("root", &self.root().as_ref())
            .field("tree_hasher", &self.th)
            .finish()
    }
}

impl<S: KVStore + Default> Default for SparseMerkleTree<S> {
    fn default() -> Self {
        let th = TreeHasher::new(vec![0; TreeHasher::<S::Hasher>::path_size()].into());
        let root = th.placeholder();
        Self {
            th,
            nodes: S::default(),
            values: S::default(),
            root,
        }
    }
}

impl<S: KVStore + Clone> Clone for SparseMerkleTree<S> {
    fn clone(&self) -> Self {
        Self {
            th: self.th.clone(),
            nodes: self.nodes.clone(),
            values: self.values.clone(),
            root: self.root.clone(),
        }
    }
}

impl<S: KVStore + Default> SparseMerkleTree<S> {
    /// Create a new sparse merkle tree
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S: KVStore> SparseMerkleTree<S> {
    /// Create a sparse merkle tree based on the given stores
    #[inline]
    pub fn new_with_stores(nodes_store: S, values_store: S) -> Self {
        let th = TreeHasher::new(vec![0; TreeHasher::<S::Hasher>::path_size()].into());
        let root = th.placeholder();
        Self {
            th,
            nodes: nodes_store,
            values: values_store,
            root,
        }
    }

    /// Imports a Sparse Merkle tree from non-empty `KVStore`.
    #[inline]
    pub fn import(nodes_store: S, values_store: S, root: impl Into<Bytes>) -> Self {
        Self {
            th: TreeHasher::new(vec![0; TreeHasher::<S::Hasher>::path_size()].into()),
            nodes: nodes_store,
            values: values_store,
            root: root.into(),
        }
    }

    /// Returns the root of the sparse merkle tree
    #[inline]
    pub fn root(&self) -> Bytes {
        self.root.clone()
    }

    /// Returns the root reference of the sparse merkle tree
    #[inline]
    pub fn root_ref(&self) -> &[u8] {
        &self.root
    }

    /// Set new root for the tree
    #[inline]
    pub fn set_root(&mut self, root: impl Into<Bytes>) {
        self.root = root.into();
    }

    #[inline]
    fn depth(&self) -> usize {
        TreeHasher::<S::Hasher>::path_size() * 8
    }

    /// Gets the value of a key from the tree.
    pub fn get(&self, key: &[u8]) -> Result<Option<Bytes>, <S as KVStore>::Error> {
        if self.root.as_ref().eq(self.th.placeholder_ref()) {
            return Ok(None);
        }

        let path = self.th.path(key);
        match self.values.get(path.as_ref()) {
            Ok(value) => Ok(value),
            Err(e) => Err(e),
        }
    }

    /// Returns true if the value at the given key is non-default, false
    /// otherwise.
    pub fn contains(&self, key: &[u8]) -> Result<bool, <S as KVStore>::Error> {
        if self.root.as_ref().eq(self.th.placeholder_ref()) {
            return Ok(false);
        }
        let path = self.th.path(key);
        self.values.contains(path.as_ref())
    }

    /// Removes a value from tree.
    pub fn remove(&mut self, key: &[u8]) -> Result<(), <S as KVStore>::Error> {
        self.update(key, DEFAULT_VALUE)
    }

    /// Removes a value from tree at a specific root. It returns the new root of the tree.
    pub fn remove_for_root(
        &mut self,
        key: &[u8],
        root: Bytes,
    ) -> Result<Bytes, <S as KVStore>::Error> {
        self.update_for_root(key, DEFAULT_VALUE, root)
    }

    fn remove_with_side_nodes(
        &mut self,
        path: &[u8],
        side_nodes: Vec<Bytes>,
        path_nodes: Vec<Bytes>,
        old_leaf_data: Option<Bytes>,
    ) -> Result<Option<Bytes>, <S as KVStore>::Error> {
        if path_nodes[0].eq(self.th.placeholder_ref()) {
            // This key is already empty as it is a placeholder; return an None.
            return Ok(None);
        }

        let (actual_path, _) = TreeHasher::<S::Hasher>::parse_leaf(old_leaf_data.as_ref().unwrap());
        if path.ne(actual_path) {
            // This key is already empty as a different key was found its place; return an error.
            return Ok(None);
        }

        // All nodes above the deleted leaf are now orphaned
        for node in path_nodes {
            self.nodes.remove(node.as_ref())?;
        }

        let side_nodes_num = side_nodes.len();
        let mut current_data = Bytes::new();
        let mut current_hash = Bytes::new();
        let mut non_placeholder_reached = false;
        for (idx, side_node) in side_nodes.into_iter().enumerate() {
            if current_data.is_empty() {
                let side_node_value = self.nodes.get(side_node.as_ref())?;
                if TreeHasher::<S::Hasher>::is_leaf(&side_node_value) {
                    // This is the leaf sibling that needs to be bubbled up the tree.
                    current_hash = side_node.clone();
                    current_data = side_node.clone();
                    continue;
                } else {
                    // This is the node sibling that needs to be left in its place.
                    current_data = self.th.placeholder();
                    non_placeholder_reached = true;
                }
            }

            if !non_placeholder_reached && side_node.eq(self.th.placeholder_ref()) {
                // We found another placeholder sibling node, keep going up the
                // tree until we find the first sibling that is not a placeholder.
                continue;
            } else if !non_placeholder_reached {
                // We found the first sibling node that is not a placeholder, it is
                // time to insert our leaf sibling node here.
                non_placeholder_reached = true;
            }

            if get_bit_at_from_msb(path, side_nodes_num - idx - 1) == RIGHT {
                (current_hash, current_data) = self.th.digest_node(side_node, &current_data);
            } else {
                (current_hash, current_data) = self.th.digest_node(&current_data, side_node);
            }

            self.nodes.set(current_hash.clone(), current_data.clone())?;

            current_data = current_hash.clone();
        }

        if current_hash.is_empty() {
            // The tree is empty; return placeholder value as root.
            current_hash = self.th.placeholder();
        }
        Ok(Some(current_hash))
    }

    /// Sets a new value for a key in the tree.
    pub fn update(&mut self, key: &[u8], value: Bytes) -> Result<(), <S as KVStore>::Error> {
        let new_root = self.update_for_root(key, value, self.root())?;
        self.set_root(new_root);
        Ok(())
    }

    /// Sets a new value for a key in the tree at a specific root, and returns the new root.
    pub fn update_for_root(
        &mut self,
        key: &[u8],
        value: Bytes,
        root: Bytes,
    ) -> Result<Bytes, <S as KVStore>::Error> {
        let path = {
            let path = self.th.path(key);
            let len = path.len();
            let ptr = Box::into_raw(Box::new(path)) as *mut u8;
            Bytes::from(unsafe { Vec::from_raw_parts(ptr, len, len) })
        };

        let UpdateResult {
            side_nodes,
            path_nodes,
            sibling_data: _,
            current_data: old_leaf_data,
        } = self.side_nodes_for_root(&path, root.clone(), false)?;

        if value.eq(&DEFAULT_VALUE) {
            // Delete operation.
            let new_root =
                self.remove_with_side_nodes(&path, side_nodes, path_nodes, old_leaf_data)?;
            match new_root {
                Some(new_root) => {
                    self.values.remove(&path)?;
                    Ok(new_root)
                }
                // This key is already empty; return the old root.
                None => Ok(root),
            }
        } else {
            // Insert operation.
            self.update_with_side_notes(path, value, side_nodes, path_nodes, old_leaf_data)
        }
    }

    fn update_with_side_notes(
        &mut self,
        path: Bytes,
        value: Bytes,
        side_nodes: Vec<Bytes>,
        path_nodes: Vec<Bytes>,
        old_leaf_data: Option<Bytes>,
    ) -> Result<Bytes, <S as KVStore>::Error> {
        let depth = self.depth();
        let value_hash = self.th.digest(&value);
        let (mut current_hash, mut current_data) = self.th.digest_leaf(&path, &value_hash);
        self.nodes.set(current_hash.clone(), current_data.clone())?;
        current_data = current_hash.clone();

        // If the leaf node that sibling nodes lead to has a different actual path
        // than the leaf node being updated, we need to create an intermediate node
        // with this leaf node and the new leaf node as children.
        //
        // First, get the number of bits that the paths of the two leaf nodes share
        // in common as a prefix.
        let (common_prefix_count, old_value_hash) = if path_nodes[0].eq(self.th.placeholder_ref()) {
            (depth, None)
        } else {
            let (actual_path, value_hash) =
                TreeHasher::<S::Hasher>::parse_leaf(old_leaf_data.as_ref().unwrap());
            (count_common_prefix(&path, actual_path), Some(value_hash))
        };

        if common_prefix_count != depth {
            if get_bit_at_from_msb(&path, common_prefix_count) == RIGHT {
                (current_hash, current_data) = self.th.digest_node(&path_nodes[0], &current_data);
            } else {
                (current_hash, current_data) = self.th.digest_node(&current_data, &path_nodes[0]);
            }

            self.nodes.set(current_hash.clone(), current_data.clone())?;
            current_data = current_hash.clone();
        } else if let Some(old_value_hash) = old_value_hash {
            // Short-circuit if the same value is being set
            if value_hash.deref().eq(old_value_hash) {
                return Ok(self.root());
            }

            // If an old leaf exists, remove it
            self.nodes.remove(&path_nodes[0])?;
            self.values.remove(&path)?;
        }

        // All remaining path nodes are orphaned
        for node in path_nodes.into_iter().skip(1) {
            self.nodes.remove(&node)?;
        }

        // The offset from the bottom of the tree to the start of the side nodes.
        // Note: i-offsetOfSideNodes is the index into sideNodes[]
        let offset_of_side_nodes = depth - side_nodes.len();

        for i in 0..self.depth() {
            match i.checked_sub(offset_of_side_nodes) {
                Some(val) => {
                    if get_bit_at_from_msb(&path, depth - i - 1) == RIGHT {
                        (current_hash, current_data) =
                            self.th.digest_node(&side_nodes[val], &current_data);
                    } else {
                        (current_hash, current_data) =
                            self.th.digest_node(&current_data, &side_nodes[val]);
                    }

                    self.nodes.set(current_hash.clone(), current_data.clone())?;
                    current_data = current_hash.clone();
                }
                None => {
                    if common_prefix_count != depth && common_prefix_count > depth - i - 1 {
                        // If there are no sidenodes at this height, but the number of
                        // bits that the paths of the two leaf nodes share in common is
                        // greater than this depth, then we need to build up the tree
                        // to this depth with placeholder values at siblings.
                        if get_bit_at_from_msb(&path, depth - i - 1) == RIGHT {
                            (current_hash, current_data) = self.th.digest_right_node(&current_data);
                        } else {
                            (current_hash, current_data) = self.th.digest_left_node(&current_data);
                        }

                        self.nodes.set(current_hash.clone(), current_data.clone())?;
                        current_data = current_hash.clone();
                    } else {
                        continue;
                    }
                }
            };
        }

        self.values.set(path, value).map(|_| current_hash)
    }

    /// Gets the value of a key from the tree by descending it.
    /// Use if a key was _not_ previously added with AddBranch, otherwise use Get.
    /// Errors if the key cannot be reached by descending.
    pub fn get_descend(&self, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, S::Error> {
        if self.root.eq(self.th.placeholder_ref()) {
            // The tree is empty
            return Ok(None);
        }

        let path = self.th.path(key);
        let depth = self.depth();

        // avoid call shallow clone on root
        let current_data = self.nodes.get(&self.root)?;
        if TreeHasher::<<S as KVStore>::Hasher>::is_leaf(&current_data) {
            // We've reached the end. Is this the actual leaf?
            let (actual_path, _) =
                TreeHasher::<<S as KVStore>::Hasher>::parse_leaf(current_data.as_ref().unwrap());
            if path.as_ref().ne(actual_path) {
                // Nope. Therefore the key is actually empty.
                return Ok(None);
            }

            // Otherwise, yes. Return the value.
            return self.values.get(path.as_ref());
        }

        let (left, right) = TreeHasher::<<S as KVStore>::Hasher>::parse_node(&current_data);

        let mut current_hash = if get_bit_at_from_msb(path.as_ref(), 0) == RIGHT {
            right
        } else {
            left
        };

        if current_hash.eq(self.th.placeholder_ref()) {
            // We've hit a placeholder value; this is the end.
            return Ok(None);
        }

        for i in 1..depth {
            let current_data = self.nodes.get(&current_hash)?;
            if TreeHasher::<<S as KVStore>::Hasher>::is_leaf(&current_data) {
                // We've reached the end. Is this the actual leaf?
                let (actual_path, _) = TreeHasher::<<S as KVStore>::Hasher>::parse_leaf(
                    current_data.as_ref().unwrap(),
                );
                if path.as_ref().ne(actual_path) {
                    // Nope. Therefore the key is actually empty.
                    return Ok(None);
                }

                // Otherwise, yes. Return the value.
                return self.values.get(path.as_ref());
            }

            let (left, right) = TreeHasher::<<S as KVStore>::Hasher>::parse_node(&current_data);
            if get_bit_at_from_msb(path.as_ref(), i) == RIGHT {
                current_hash = right;
            } else {
                current_hash = left;
            }

            if current_hash.eq(self.th.placeholder_ref()) {
                // We've hit a placeholder value; this is the end.
                return Ok(None);
            }
        }

        // The following lines of code should only be reached if the path is 256
        // nodes high, which should be very unlikely if the underlying hash function
        // is collision-resistant.
        self.values.get(path.as_ref())
    }

    /// Returns true if the value at the given key is non-default, false
    /// otherwise.
    /// Use if a key was _not_ previously added with AddBranch, otherwise use Has.
    /// Errors if the key cannot be reached by descending.
    pub fn has_descend(&self, key: impl AsRef<[u8]>) -> Result<bool, S::Error> {
        self.get_descend(key).map(|v| v.is_some())
    }

    /// Adds a branch to the tree.
    /// These branches are generated by `prove_for_root`.
    /// If the proof is invalid, a ErrBadProof is returned.
    ///
    /// If the leaf may be updated (e.g. during a state transition fraud proof),
    /// an updatable proof should be used. See SparseMerkleTree.ProveUpdatable.
    pub fn add_branch(
        &self,
        proof: SparseMerkleProof<S::Hasher>,
        key: impl AsRef<[u8]>,
        val: impl Into<Bytes> + AsRef<[u8]>,
    ) -> Result<(), S::Error> {
        let val_ref = val.as_ref();
        let (result, updates) = proof.verify_proof_with_updates(&self.root, key.as_ref(), val_ref);
        if !result {
            return Err(BadProof.into());
        }

        if val.as_ref().ne(DEFAULT_VALUE.as_ref()) {
            // Membership proof.
            self.values.set(self.th.path_into(key), val.into())?;
        }

        let SparseMerkleProof {
            side_nodes,
            non_membership_leaf_data: _,
            sibling_data,
            _marker,
        } = proof;

        // Update nodes along branch
        for (hash, data) in updates {
            self.nodes.set(hash, data)?;
        }

        // Update sibling node
        if let Some(sibling) = sibling_data {
            if !side_nodes.is_empty() {
                self.nodes
                    .set(side_nodes.into_iter().take(1).next().unwrap(), sibling)?;
            }
        }

        Ok(())
    }

    /// Generates a Merkle proof for a key against the current root.
    ///
    /// This proof can be used for read-only applications, but should not be used if
    /// the leaf may be updated (e.g. in a state transition fraud proof). For
    /// updatable proofs, see `prove_updatable`.
    pub fn prove(&self, key: impl AsRef<[u8]>) -> Result<SparseMerkleProof<S::Hasher>, S::Error> {
        self.prove_for_root(key, self.root())
    }

    /// ProveForRoot generates a Merkle proof for a key, against a specific node.
    /// This is primarily useful for generating Merkle proofs for subtrees.
    ///
    /// This proof can be used for read-only applications, but should not be used if
    /// the leaf may be updated (e.g. in a state transition fraud proof). For
    /// updatable proofs, see `prove_updatable_for_root`.
    pub fn prove_for_root(
        &self,
        key: impl AsRef<[u8]>,
        root: Bytes,
    ) -> Result<SparseMerkleProof<S::Hasher>, S::Error> {
        self.do_prove_for_root(key, root, false)
    }

    // Generates an updatable Merkle proof for a key against the current root.
    pub fn prove_updatable(
        &self,
        key: impl AsRef<[u8]>,
    ) -> Result<SparseMerkleProof<S::Hasher>, S::Error> {
        self.prove_updatable_for_root(key, self.root())
    }

    // Generates an updatable Merkle proof for a key, against a specific node.
    // This is primarily useful for generating Merkle proofs for subtrees.
    pub fn prove_updatable_for_root(
        &self,
        key: impl AsRef<[u8]>,
        root: Bytes,
    ) -> Result<SparseMerkleProof<S::Hasher>, S::Error> {
        self.do_prove_for_root(key, root, true)
    }

    /// Generates a compacted Merkle proof for a key against the current root.
    pub fn prove_compact(
        &self,
        key: impl AsRef<[u8]>,
    ) -> Result<SparseCompactMerkleProof<S::Hasher>, S::Error> {
        self.prove_compact_for_root(key, self.root())
    }

    /// Generates a compacted Merkle proof for a key, at a specific root.
    pub fn prove_compact_for_root(
        &self,
        key: impl AsRef<[u8]>,
        root: Bytes,
    ) -> Result<SparseCompactMerkleProof<S::Hasher>, S::Error> {
        let proof = self.do_prove_for_root(key, root, false)?;
        proof.compact_into().map_err(Into::into)
    }

    #[inline]
    fn do_prove_for_root(
        &self,
        key: impl AsRef<[u8]>,
        root: Bytes,
        is_updatable: bool,
    ) -> Result<SparseMerkleProof<S::Hasher>, S::Error> {
        let path = self.th.path(key);
        let UpdateResult {
            side_nodes,
            path_nodes,
            sibling_data,
            current_data: leaf_data,
        } = self.side_nodes_for_root(path.as_ref(), root, is_updatable)?;

        let non_empty_side_nodes = side_nodes
            .into_iter()
            .filter(|n| !n.is_empty())
            .collect::<Vec<_>>();

        // Deal with non-membership proofs. If the leaf hash is the placeholder
        // value, we do not need to add anything else to the proof.
        let non_membership_leaf_data = leaf_data.and_then(|leaf_data| {
            if path_nodes[0].ne(self.th.placeholder_ref()) {
                let (actual_path, _) = TreeHasher::<<S as KVStore>::Hasher>::parse_leaf(&leaf_data);
                if actual_path.ne(path.as_ref()) {
                    // This is a non-membership proof that involves showing a different leaf.
                    // Add the leaf data to the proof.
                    return Some(leaf_data);
                }
            }
            None
        });

        Ok(SparseMerkleProof::new(
            non_empty_side_nodes,
            non_membership_leaf_data,
            sibling_data,
        ))
    }

    /// Get all the sibling nodes (sidenodes) for a given path from a given root.
    /// Returns an array of sibling nodes, the leaf hash found at that path, the
    /// leaf data, and the sibling data.
    ///
    /// If the leaf is a placeholder, the leaf data is nil.
    fn side_nodes_for_root(
        &self,
        path: &[u8],
        root: Bytes,
        get_sibling_data: bool,
    ) -> Result<UpdateResult, <S as KVStore>::Error> {
        // Side nodes for the path. Nodes are inserted in reverse order, then the
        // slice is reversed at the end.
        let mut side_nodes = Vec::with_capacity(self.depth());
        let mut path_nodes = Vec::with_capacity(self.depth() + 1);
        path_nodes.push(root.clone());

        if root.eq(self.th.placeholder_ref()) {
            return Ok(UpdateResult {
                side_nodes,
                path_nodes,
                sibling_data: None,
                current_data: None,
            });
        }

        let mut current_data = self.nodes.get(&root)?;
        if TreeHasher::<S::Hasher>::is_leaf(&current_data) {
            // If the root is a leaf, there are also no sidenodes to return.
            return Ok(UpdateResult {
                side_nodes,
                path_nodes,
                sibling_data: None,
                current_data,
            });
        }

        for i in 0..self.depth() {
            let (left_node, right_node) = TreeHasher::<S::Hasher>::parse_node(&current_data);

            // Get sidenode depending on whether the path bit is on or off.
            let (side_node, node_hash) = if get_bit_at_from_msb(path, i) == RIGHT {
                (left_node, right_node)
            } else {
                (right_node, left_node)
            };

            if node_hash.eq(self.th.placeholder_ref()) {
                // If the node is a placeholder, we've reached the end.
                if get_sibling_data {
                    let sibling_data = self.nodes.get(&side_node)?;

                    side_nodes.push(side_node);
                    path_nodes.push(node_hash);
                    side_nodes.reverse();
                    path_nodes.reverse();
                    return Ok(UpdateResult {
                        side_nodes,
                        path_nodes,
                        sibling_data,
                        current_data: None,
                    });
                }

                side_nodes.push(side_node);
                path_nodes.push(node_hash);
                side_nodes.reverse();
                path_nodes.reverse();

                return Ok(UpdateResult {
                    side_nodes,
                    path_nodes,
                    sibling_data: None,
                    current_data: None,
                });
            }

            current_data = self.nodes.get(&node_hash)?;
            if TreeHasher::<S::Hasher>::is_leaf(&current_data) {
                // If the node is a leaf, we've reached the end.
                if get_sibling_data {
                    let sibling_data = self.nodes.get(&side_node)?;

                    side_nodes.push(side_node);
                    path_nodes.push(node_hash);
                    side_nodes.reverse();
                    path_nodes.reverse();
                    return Ok(UpdateResult {
                        side_nodes,
                        path_nodes,
                        sibling_data,
                        current_data,
                    });
                }

                side_nodes.push(side_node);
                path_nodes.push(node_hash);
                side_nodes.reverse();
                path_nodes.reverse();
                return Ok(UpdateResult {
                    side_nodes,
                    path_nodes,
                    sibling_data: None,
                    current_data,
                });
            }

            side_nodes.push(side_node);
            path_nodes.push(node_hash);
        }

        side_nodes.reverse();
        path_nodes.reverse();
        Ok(UpdateResult {
            side_nodes,
            path_nodes,
            sibling_data: None,
            current_data,
        })
    }
}

struct UpdateResult {
    side_nodes: Vec<Bytes>,
    path_nodes: Vec<Bytes>,
    sibling_data: Option<Bytes>,
    current_data: Option<Bytes>,
}
