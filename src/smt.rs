use crate::get_bit_at_from_msb;

use super::{KVStore, tree_hasher::TreeHasher};
use bytes::Bytes;

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
    pub fn import(nodes: NS, values: VS, hasher: H, root: Vec<u8>) -> Self {
        Self { 
            th: TreeHasher::new(hasher, vec![0; TreeHasher::<H>::path_size()].into()), nodes, 
            values, 
            root: root.into(),
        }
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

    #[inline]
    fn depth(&self) -> usize {
        TreeHasher::<H>::path_size() * 8  
    }
}

impl<NS, VS: KVStore, H: digest::Digest + digest::FixedOutputReset> SparseMerkleTree<NS, VS, H> {
    
    /// Gets the value of a key from the tree.
    pub fn get(&self, key: &[u8]) -> Result<&[u8], <VS as KVStore>::Error> {
        if self.root.as_ref().eq(self.th.placeholder_ref()) {
            return Ok(&DEFAULT_VALUE_SLICE);
        }

        let path = self.th.path(key.as_ref());
        match self.values.get(path.as_ref()) {
            Ok(value) => Ok(value),
            Err(e) => Err(e),
        }
    }

    /// Returns true if the value at the given key is non-default, false
    /// otherwise.
    pub fn contains(&self, key: &[u8]) -> Result<bool, <VS as KVStore>::Error> {
        self.get(key).map(|value| DEFAULT_VALUE.ne(value))
    }
}

impl<NS, VS, H> SparseMerkleTree<NS, VS, H> 
where 
    NS: KVStore,
    NS::Error: core::convert::From<VS::Error>,
    VS: KVStore,
    H: digest::Digest + digest::FixedOutputReset
{
    /// Removes a value from tree.
    pub fn remove(&mut self, key: &[u8]) -> Result<(), <NS as KVStore>::Error> {
        self.update(key, DEFAULT_VALUE)
    }

    /// Removes a value from tree at a specific root. It returns the new root of the tree.
    pub fn remove_for_root(&mut self, key: &[u8], root: Bytes) -> Result<Bytes, <NS as KVStore>::Error> {
        self.update_for_root(key, DEFAULT_VALUE, root)
    }


    fn remove_with_side_nodes(&mut self, _path: &[u8], _side_nodes: Vec<Bytes>, _path_nodes: Vec<Bytes>, _old_leaf_data: Option<Bytes>) -> Result<Bytes, <NS as KVStore>::Error> {
        todo!()
    }

    /// Sets a new value for a key in the tree.
    pub fn update(&mut self, key: &[u8], value: Bytes) -> Result<(), <NS as KVStore>::Error> {
        let new_root = self.update_for_root(key, value, self.root())?;
        self.set_root(new_root);
        Ok(())
    }

    /// Sets a new value for a key in the tree at a specific root, and returns the new root.
    pub fn update_for_root(&mut self, key: &[u8], value: Bytes, root: Bytes) -> Result<Bytes, <NS as KVStore>::Error> {
        let path = self.th.path(key);
        let UpdateResult {
            side_nodes,
            path_nodes,
            sibling_data: _,
            current_data: old_leaf_data,
        } = self.side_nodes_for_root(&path, root, false)?;

        if value.eq(&DEFAULT_VALUE) {
            // Delete operation.
            let new_root = self.remove_with_side_nodes(&path, side_nodes, path_nodes, old_leaf_data)?;
            Ok(new_root)
        } else {
            // Insert operation.
            self.update_with_side_notes(&path, value, side_nodes, path_nodes, old_leaf_data)
        }
    }

    fn update_with_side_notes(&mut self, _path: &[u8], _value: Bytes, _side_nodes: Vec<Bytes>, _path_nodes: Vec<Bytes>, _old_leaf_data: Option<Bytes>) -> Result<Bytes, <NS as KVStore>::Error> {
        todo!()
    }

    /// Get all the sibling nodes (sidenodes) for a given path from a given root.
    /// Returns an array of sibling nodes, the leaf hash found at that path, the
    /// leaf data, and the sibling data.
    ///
    /// If the leaf is a placeholder, the leaf data is nil.
    fn side_nodes_for_root(&self, path: &[u8], root: Bytes, get_sibling_data: bool) -> Result<UpdateResult, <NS as KVStore>::Error> {
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
        if TreeHasher::<H>::is_leaf(current_data) {
            // If the root is a leaf, there are also no sidenodes to return.
            return Ok(UpdateResult {
                side_nodes,
                path_nodes,
                sibling_data: None,
                current_data: Some(current_data.clone()),
            });
        }


        for i in 0..self.depth() {
            let (left_node, right_node) = TreeHasher::<H>::parse_node(current_data);

            // Get sidenode depending on whether the path bit is on or off.
            let (side_node, node_hash) =if get_bit_at_from_msb(path, i) == RIGHT {
                (left_node, right_node)
            } else {
                (right_node, left_node)
            };

            if node_hash.eq(self.th.placeholder_ref()) {
                // If the node is a placeholder, we've reached the end.
                if get_sibling_data {
                    let sibling_data = self.nodes.get(&side_node).map(core::clone::Clone::clone)?;

                    side_nodes.push(side_node);
                    path_nodes.push(node_hash);
                    side_nodes.reverse();
                    path_nodes.reverse();
                    return Ok(UpdateResult {
                        side_nodes,
                        path_nodes,
                        sibling_data: Some(sibling_data),
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
            if TreeHasher::<H>::is_leaf(current_data) {
                // If the node is a leaf, we've reached the end.
                if get_sibling_data {
                    let sibling_data = self.nodes.get(&side_node).map(core::clone::Clone::clone)?;

                    side_nodes.push(side_node);
                    path_nodes.push(node_hash);
                    side_nodes.reverse();
                    path_nodes.reverse();
                    return Ok(UpdateResult {
                        side_nodes,
                        path_nodes,
                        sibling_data: Some(sibling_data),
                        current_data: Some(current_data.clone()),
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
                    current_data: Some(current_data.clone()),
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
            current_data: Some(current_data.clone()),
        })
    }
}


struct UpdateResult {
    side_nodes: Vec<Bytes>,
    path_nodes: Vec<Bytes>,
    sibling_data: Option<Bytes>,
    current_data: Option<Bytes>,
}
