use alloc::boxed::Box;
use alloc::{vec, vec::Vec};
use core::ops::Deref;

use crate::{count_common_prefix, get_bit_at_from_msb};

use super::{tree_hasher::TreeHasher, KVStore};
use bytes::Bytes;

#[cfg(test)]
pub mod tests;

const RIGHT: usize = 1;
const DEFAULT_VALUE: Bytes = Bytes::new();
const DEFAULT_VALUE_SLICE: [u8; 0] = [];

/// Sparse Merkle tree.
pub struct SparseMerkleTree<NS, VS, H> {
    th: TreeHasher<H>,
    nodes: NS,
    values: VS,
    root: Bytes,
}

impl<NS, VS, H> SparseMerkleTree<NS, VS, H> {
    pub fn nodes(&self) -> &NS {
        &self.nodes
    }

    pub fn values(&self) -> &VS {
        &self.values
    }

    #[inline]
    pub fn root(&self) -> Bytes {
        self.root.clone()
    }

    #[inline]
    pub fn root_ref(&self) -> &[u8] {
        &self.root
    }

    #[inline]
    pub fn set_root(&mut self, root: Bytes) {
        self.root = root;
    }
}

impl<NS, VS, H: digest::Digest + digest::FixedOutputReset> SparseMerkleTree<NS, VS, H> {
    pub fn new(nodes: NS, values: VS, hasher: H) -> Self {
        let th = TreeHasher::new(hasher, vec![0; TreeHasher::<H>::path_size()].into());
        let root = th.placeholder();
        Self {
            th,
            nodes,
            values,
            root,
        }
    }

    /// Imports a Sparse Merkle tree from a non-empty KVStore.
    pub fn import(nodes: NS, values: VS, hasher: H, root: impl Into<Bytes>) -> Self {
        Self {
            th: TreeHasher::new(hasher, vec![0; TreeHasher::<H>::path_size()].into()),
            nodes,
            values,
            root: root.into(),
        }
    }

    #[inline]
    fn depth(&self) -> usize {
        TreeHasher::<H>::path_size() * 8
    }
}

impl<NS, VS: KVStore, H: digest::Digest + digest::FixedOutputReset> SparseMerkleTree<NS, VS, H> {
    /// Gets the value of a key from the tree.
    pub fn get(&self, key: &[u8]) -> Result<Option<Bytes>, <VS as KVStore>::Error> {
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
    pub fn contains(&self, key: &[u8]) -> Result<bool, <VS as KVStore>::Error> {
        if self.root.as_ref().eq(self.th.placeholder_ref()) {
            return Ok(false);
        }
        let path = self.th.path(key);
        self.values.contains(path.as_ref())
    }
}

impl<NS, VS, H> SparseMerkleTree<NS, VS, H>
where
    NS: KVStore,
    NS::Error: core::convert::From<VS::Error>,
    VS: KVStore,
    H: digest::Digest + digest::FixedOutputReset,
{
    /// Removes a value from tree.
    pub fn remove(&mut self, key: &[u8]) -> Result<(), <NS as KVStore>::Error> {
        self.update(key, DEFAULT_VALUE)
    }

    /// Removes a value from tree at a specific root. It returns the new root of the tree.
    pub fn remove_for_root(
        &mut self,
        key: &[u8],
        root: Bytes,
    ) -> Result<Bytes, <NS as KVStore>::Error> {
        self.update_for_root(key, DEFAULT_VALUE, root)
    }

    fn remove_with_side_nodes(
        &mut self,
        path: &[u8],
        side_nodes: Vec<Bytes>,
        path_nodes: Vec<Bytes>,
        old_leaf_data: Option<Bytes>,
    ) -> Result<Option<Bytes>, <NS as KVStore>::Error> {
        if path_nodes[0].eq(self.th.placeholder_ref()) {
            // This key is already empty as it is a placeholder; return an None.
            return Ok(None);
        }

        let (actual_path, _) = TreeHasher::<H>::parse_leaf(old_leaf_data.as_ref().unwrap());
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

                if TreeHasher::<H>::is_leaf(&side_node_value) {
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
    pub fn update(&mut self, key: &[u8], value: Bytes) -> Result<(), <NS as KVStore>::Error> {
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
    ) -> Result<Bytes, <NS as KVStore>::Error> {
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
    ) -> Result<Bytes, <NS as KVStore>::Error> {
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
                TreeHasher::<H>::parse_leaf(old_leaf_data.as_ref().unwrap());
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
        } else if old_value_hash.is_some() {
            // Short-circuit if the same value is being set
            if value_hash.deref().eq(old_value_hash.unwrap()) {
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
            let side_node = match i.checked_sub(offset_of_side_nodes) {
                Some(val) => side_nodes[val].clone(),
                None => {
                    if common_prefix_count != depth && common_prefix_count > depth - i - 1 {
                        // If there are no sidenodes at this height, but the number of
                        // bits that the paths of the two leaf nodes share in common is
                        // greater than this depth, then we need to build up the tree
                        // to this depth with placeholder values at siblings.
                        self.th.placeholder()
                    } else {
                        continue;
                    }
                }
            };

            if get_bit_at_from_msb(&path, depth - i - 1) == RIGHT {
                (current_hash, current_data) = self.th.digest_node(&side_node, &current_data);
            } else {
                (current_hash, current_data) = self.th.digest_node(&current_data, &side_node);
            }

            self.nodes.set(current_hash.clone(), current_data.clone())?;
            current_data = current_hash.clone();
        }

        self.values
            .set(path, value)
            .map(|_| current_hash)
            .map_err(core::convert::Into::into)
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
    ) -> Result<UpdateResult, <NS as KVStore>::Error> {
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
        if TreeHasher::<H>::is_leaf(&current_data) {
            // If the root is a leaf, there are also no sidenodes to return.
            return Ok(UpdateResult {
                side_nodes,
                path_nodes,
                sibling_data: None,
                current_data,
            });
        }

        for i in 0..self.depth() {
            let (left_node, right_node) = TreeHasher::<H>::parse_node(&current_data);

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
            if TreeHasher::<H>::is_leaf(&current_data) {
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
