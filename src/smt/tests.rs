use digest::generic_array::GenericArray;
use hashbrown::HashMap;

use crate::proofs::BadProof;

use super::*;

#[derive(Debug)]
pub enum Error {
    NotFound,
    BadProof(BadProof),
}

impl From<BadProof> for Error {
    fn from(e: BadProof) -> Self {
        Error::BadProof(e)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[derive(Debug, Clone, Default)]
pub struct SimpleStore {
    data: HashMap<Bytes, Bytes>,
}

impl SimpleStore {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl KVStore for SimpleStore {
    type Error = Error;
    type Hasher = sha2::Sha256;

    fn get(&self, key: &[u8]) -> Result<Option<Bytes>, Self::Error> {
        Ok(self.data.get(key).map(core::clone::Clone::clone))
    }

    fn set(&mut self, key: Bytes, value: Bytes) -> Result<(), Self::Error> {
        self.data.insert(key, value);
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> Result<Bytes, Self::Error> {
        self.data.remove(key).ok_or(Error::NotFound)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error> {
        Ok(self.data.contains_key(key))
    }
}

#[derive(Debug, Clone, Default)]
pub struct DummyStore {
    data: HashMap<Bytes, Bytes>,
}

impl DummyStore {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl KVStore for DummyStore {
    type Error = Error;
    type Hasher = DummyHasher<sha2::Sha256>;

    fn get(&self, key: &[u8]) -> Result<Option<Bytes>, Self::Error> {
        Ok(self.data.get(key).map(core::clone::Clone::clone))
    }

    fn set(&mut self, key: Bytes, value: Bytes) -> Result<(), Self::Error> {
        self.data.insert(key, value);
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> Result<Bytes, Self::Error> {
        self.data.remove(key).ok_or(Error::NotFound)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error> {
        Ok(self.data.contains_key(key))
    }
}

pub fn new_sparse_merkle_tree() -> SparseMerkleTree<SimpleStore> {
    let (smn, smv) = (SimpleStore::new(), SimpleStore::new());
    SparseMerkleTree::<SimpleStore>::new_with_stores(smn, smv)
}

pub struct DummyHasher<D: digest::Digest + digest::OutputSizeUser> {
    base_hasher: D,
    data: Vec<u8>,
}

impl<D: digest::Digest> DummyHasher<D> {
    fn new() -> Self {
        Self {
            base_hasher: D::new(),
            data: Vec::new(),
        }
    }
}

impl<D: digest::Digest + digest::OutputSizeUser> digest::OutputSizeUser for DummyHasher<D> {
    type OutputSize = D::OutputSize;
}

impl<D: digest::Digest + digest::OutputSizeUser> digest::Digest for DummyHasher<D> {
    fn new() -> Self {
        Self {
            base_hasher: D::new(),
            data: Vec::new(),
        }
    }

    fn new_with_prefix(_data: impl AsRef<[u8]>) -> Self {
        todo!()
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.data.extend_from_slice(data.as_ref());
    }

    fn chain_update(self, _data: impl AsRef<[u8]>) -> Self {
        todo!()
    }

    fn finalize(mut self) -> digest::Output<Self> {
        let mut prefix = vec![];
        let mut preimage = self.data.clone();
        prefix.extend(preimage.iter());
        preimage = prefix;

        if preimage.len() >= 4
            && preimage[..4].eq(&[0, 0, 0, 0])
            && preimage.len() == <D as digest::Digest>::output_size() + 4
        {
            let digest = preimage[4..].to_vec();
            GenericArray::from_iter(digest)
        } else {
            self.base_hasher.update(preimage);
            self.base_hasher.finalize()
        }
    }

    fn finalize_into(self, _out: &mut digest::Output<Self>) {
        todo!()
    }

    fn finalize_reset(&mut self) -> digest::Output<Self>
    where
        Self: digest::FixedOutputReset,
    {
        todo!()
    }

    fn finalize_into_reset(&mut self, _out: &mut digest::Output<Self>)
    where
        Self: digest::FixedOutputReset,
    {
        todo!()
    }

    fn reset(&mut self)
    where
        Self: digest::Reset,
    {
        todo!()
    }

    fn output_size() -> usize {
        <D as digest::Digest>::output_size()
    }

    fn digest(data: impl AsRef<[u8]>) -> digest::Output<Self> {
        let mut x = Self::new();
        x.update(data);
        x.finalize()
    }
}

#[test]
fn test_smt_update_basic() {
    let mut smt = new_sparse_merkle_tree();

    // Test getting an empty key.
    assert!(smt.get(&Bytes::from("testKey")).unwrap().is_none());

    assert!(!smt.contains(&Bytes::from("testKey")).unwrap());

    // Test updating the empty key.
    smt.update(&Bytes::from("testKey"), Bytes::from("testValue"))
        .unwrap();

    assert_eq!(
        smt.get(&Bytes::from("testKey")).unwrap(),
        Some(Bytes::from("testValue"))
    );
    assert!(smt.contains(&Bytes::from("testKey")).unwrap());

    // Test updating the non-empty key.
    smt.update(&Bytes::from("testKey"), Bytes::from("testValue2"))
        .unwrap();
    assert_eq!(
        smt.get(&Bytes::from("testKey")).unwrap(),
        Some(Bytes::from("testValue2"))
    );

    // Test updating a second empty key where the path for both keys share the
    // first 2 bits (when using SHA256).
    smt.update(b"foo", Bytes::from("testValue")).unwrap();
    assert_eq!(smt.get(b"foo").unwrap(), Some(Bytes::from("testValue")));

    // Test updating a third empty key.
    smt.update(b"testKey2", Bytes::from("testValue")).unwrap();
    assert_eq!(
        smt.get(b"testKey2").unwrap(),
        Some(Bytes::from("testValue"))
    );
    assert_eq!(
        smt.get(b"testKey").unwrap(),
        Some(Bytes::from("testValue2"))
    );

    // Test that a tree can be imported from a KVStore.
    let smt2 =
        SparseMerkleTree::<SimpleStore>::import(smt.nodes.clone(), smt.values.clone(), smt.root());
    assert_eq!(
        smt2.get(b"testKey").unwrap(),
        Some(Bytes::from("testValue2"))
    );
}

#[test]
fn test_smt_remove_basic() {
    let mut smt = new_sparse_merkle_tree();

    // Testing inserting, deleting a key, and inserting it again.
    smt.update(b"testKey", Bytes::from("testValue")).unwrap();

    let root1 = smt.root();
    smt.update(b"testKey", Bytes::new()).unwrap();
    assert!(smt.get(b"testKey").unwrap().is_none());
    assert!(!smt.contains(b"testKey").unwrap());

    smt.update(b"testKey", Bytes::from("testValue")).unwrap();
    assert_eq!(smt.get(b"testKey").unwrap(), Some(Bytes::from("testValue")));
    assert_eq!(smt.root(), root1);

    // Test inserting and deleting a second key.
    smt.update(b"testKey2", Bytes::from("testValue")).unwrap();
    smt.remove(b"testKey2").unwrap();
    assert!(smt.get(b"testKey2").unwrap().is_none());
    assert_eq!(smt.get(b"testKey").unwrap(), Some(Bytes::from("testValue")));
    assert_eq!(root1, smt.root());

    // Test inserting and deleting a different second key, when the the first 2
    // bits of the path for the two keys in the tree are the same (when using SHA256).

    smt.update(b"foo", Bytes::from("testValue")).unwrap();
    assert_eq!(smt.get(b"foo").unwrap(), Some(Bytes::from("testValue")));
    smt.remove(b"foo").unwrap();
    assert!(smt.get(b"foo").unwrap().is_none());
    assert_eq!(smt.get(b"testKey").unwrap(), Some(Bytes::from("testValue")));
    assert_eq!(root1, smt.root());

    // Testing inserting, deleting a key, and inserting it again, using Delete
    smt.update(b"testKey", Bytes::from("testValue")).unwrap();
    let root1 = smt.root();
    smt.remove(b"testKey").unwrap();
    assert!(smt.get(b"testKey").unwrap().is_none());
    assert!(!smt.contains(b"testKey").unwrap());
    smt.update(b"testKey", Bytes::from("testValue")).unwrap();
    assert_eq!(smt.get(b"testKey").unwrap(), Some(Bytes::from("testValue")));
    assert_eq!(smt.root(), root1);
}

#[test]
fn test_sparse_merkle_tree_known() {
    let (smn, smv) = (DummyStore::new(), DummyStore::new());
    let mut smt = SparseMerkleTree::<DummyStore>::new_with_stores(smn, smv);

    const SIZE: usize = 36;

    let key1: Bytes = vec![0; SIZE].into();

    let key2: Bytes = {
        let mut key2 = vec![0; SIZE];
        key2[4] = 0b0100_0000;
        key2.into()
    };

    let key3 = {
        let mut key3 = vec![0; SIZE];
        key3[4] = 0b1000_0000;
        Bytes::from(key3)
    };
    let key4 = {
        let mut key4 = vec![0; SIZE];
        key4[4] = 0b1100_0000;
        Bytes::from(key4)
    };
    let key5 = {
        let mut key5 = vec![0; SIZE];
        key5[4] = 0b1101_0000;
        Bytes::from(key5)
    };

    smt.update(&key1, Bytes::from("testValue1")).unwrap();
    smt.update(&key2, Bytes::from("testValue2")).unwrap();
    smt.update(&key3, Bytes::from("testValue3")).unwrap();
    smt.update(&key4, Bytes::from("testValue4")).unwrap();
    smt.update(&key5, Bytes::from("testValue5")).unwrap();

    assert_eq!(smt.get(&key1).unwrap(), Some(Bytes::from("testValue1")));
    assert_eq!(smt.get(&key2).unwrap(), Some(Bytes::from("testValue2")));
    assert_eq!(smt.get(&key3).unwrap(), Some(Bytes::from("testValue3")));
    assert_eq!(smt.get(&key4).unwrap(), Some(Bytes::from("testValue4")));
    assert_eq!(smt.get(&key5).unwrap(), Some(Bytes::from("testValue5")));

    let proof1 = smt.prove(&key1).unwrap();
    let proof2 = smt.prove(&key2).unwrap();
    let proof3 = smt.prove(&key3).unwrap();
    let proof4 = smt.prove(&key4).unwrap();
    let proof5 = smt.prove(&key5).unwrap();

    let mut dsmst =
        SparseMerkleTree::<DummyStore>::import(DummyStore::new(), DummyStore::new(), smt.root());
    dsmst
        .add_branch(proof1, &key1, Bytes::from("testValue1"))
        .unwrap();
    dsmst
        .add_branch(proof2, &key2, Bytes::from("testValue2"))
        .unwrap();
    dsmst
        .add_branch(proof3, &key3, Bytes::from("testValue3"))
        .unwrap();
    dsmst
        .add_branch(proof4, &key4, Bytes::from("testValue4"))
        .unwrap();
    dsmst
        .add_branch(proof5, &key5, Bytes::from("testValue5"))
        .unwrap();
}

#[test]
fn test_sparse_merkle_tree_max_height_case() {
    const SIZE: usize = 36;

    let (smn, smv) = (DummyStore::new(), DummyStore::new());
    let mut smt = SparseMerkleTree::<DummyStore>::new_with_stores(smn, smv);

    // Make two neighboring keys.
    //
    // The dummy hash function expects keys to prefixed with four bytes of 0,
    // which will cause it to return the preimage itself as the digest, without
    // the first four bytes.
    let key1 = Bytes::from(vec![0; SIZE]);
    let key2: Bytes = {
        let mut key2 = vec![0; SIZE];
        // We make key2's least significant bit different than key1's
        key2[SIZE - 1] = 1;
        key2.into()
    };

    smt.update(&key1, Bytes::from("testValue1")).unwrap();
    smt.update(&key2, Bytes::from("testValue2")).unwrap();

    assert_eq!(smt.get(&key1).unwrap(), Some(Bytes::from("testValue1")));
    assert_eq!(smt.get(&key2).unwrap(), Some(Bytes::from("testValue2")));

    let proof1 = smt.prove(&key1).unwrap();
    assert_eq!(proof1.side_nodes().len(), 256);
}

#[test]
fn test_deep_sparse_merkle_sub_tree_basic() {
    let mut smt = new_sparse_merkle_tree();

    smt.update(b"testKey1", Bytes::from("testValue1")).unwrap();
    smt.update(b"testKey2", Bytes::from("testValue2")).unwrap();
    smt.update(b"testKey3", Bytes::from("testValue3")).unwrap();
    smt.update(b"testKey4", Bytes::from("testValue4")).unwrap();
    smt.update(b"testKey6", Bytes::from("testValue6")).unwrap();

    let original_root = smt.root();

    let proof1 = smt.prove_updatable(b"testKey1").unwrap();
    let proof2 = smt.prove_updatable(b"testKey2").unwrap();
    let proof5 = smt.prove_updatable(b"testKey5").unwrap();

    let mut dsmst = SparseMerkleTree::import(SimpleStore::new(), SimpleStore::new(), smt.root());
    dsmst
        .add_branch(proof1, b"testKey1", Bytes::from("testValue1"))
        .unwrap();

    dsmst
        .add_branch(proof2, b"testKey2", Bytes::from("testValue2"))
        .unwrap();
    dsmst
        .add_branch(proof5, b"testKey5", DEFAULT_VALUE)
        .unwrap();

    let val = dsmst.get(b"testKey1").unwrap().unwrap();
    assert_eq!(val, Bytes::from("testValue1"));

    let val = dsmst.get_descend(b"testKey1").unwrap().unwrap();
    assert_eq!(val, Bytes::from("testValue1"));

    let val = dsmst.get(b"testKey2").unwrap().unwrap();
    assert_eq!(val, Bytes::from("testValue2"));

    let val = dsmst.get_descend(b"testKey2").unwrap().unwrap();
    assert_eq!(val, Bytes::from("testValue2"));

    let val = dsmst.get(b"testKey5").unwrap();
    assert!(val.is_none());

    let val = dsmst.get_descend(b"testKey5").unwrap();
    assert!(val.is_none());

    assert!(dsmst.get_descend(b"testKey6").unwrap().is_none());

    dsmst
        .update(b"testKey1", Bytes::from("testValue3"))
        .unwrap();
    dsmst.update(b"testKey2", Bytes::new()).unwrap();
    dsmst
        .update(b"testKey5", Bytes::from("testValue5"))
        .unwrap();

    let val = dsmst.get(b"testKey1").unwrap().unwrap();
    assert_eq!(val, Bytes::from("testValue3"));

    let val = dsmst.get(b"testKey2").unwrap();
    assert!(val.is_none());

    let val = dsmst.get(b"testKey5").unwrap().unwrap();
    assert_eq!(val, Bytes::from("testValue5"));

    smt.update(b"testKey1", Bytes::from("testValue3")).unwrap();
    smt.update(b"testKey2", DEFAULT_VALUE).unwrap();
    smt.update(b"testKey5", Bytes::from("testValue5")).unwrap();
    assert_eq!(smt.root(), dsmst.root());
    assert_ne!(smt.root(), original_root);
}

#[test]
fn test_deep_sparse_merkle_sub_tree_bad_input() {
    let mut smt = new_sparse_merkle_tree();

    smt.update(b"testKey1", Bytes::from("testValue1")).unwrap();
    smt.update(b"testKey2", Bytes::from("testValue2")).unwrap();
    smt.update(b"testKey3", Bytes::from("testValue3")).unwrap();
    smt.update(b"testKey4", Bytes::from("testValue4")).unwrap();

    let mut bad_proof = smt.prove(b"testKey1").unwrap();
    let mut vec = vec![0; bad_proof.side_nodes[0].len()];
    vec[1..].copy_from_slice(bad_proof.side_nodes[0][1..].as_ref());
    bad_proof.side_nodes[0] = vec.into();

    let mut dsmst = SparseMerkleTree::import(SimpleStore::new(), SimpleStore::new(), smt.root());
    dsmst
        .add_branch(bad_proof, b"testKey1", Bytes::from("testValue1"))
        .unwrap_err();
}

// TODO: implement this test
#[test]
fn test_orphan_removal() {}

// // Test all tree operations in bulk.
// #[test]
// fn test_sparse_merkle_tree() {
//     for i in 0..5 {
//         eprintln!("{}: {} {} {} {}", i, 200, 100, 100, 50);
//         bulk_operations(200, 100, 100, 50);
//     }

//     for i in 0..5 {
//         eprintln!("{}: {} {} {} {}", i, 200, 100, 100, 500);
//         bulk_operations(200, 100, 100, 500);
//     }
// }

// fn bulk_operations(operations: usize, insert: usize, update: usize, remove: usize) {
//     let mut smt = new_sparse_merkle_tree();
//     let max = insert + update + remove;

//     let mut kv = hashbrown::HashMap::new();
//     let mut rng = rand::thread_rng();
//     for _ in 0..operations {
//         let n = rng.gen_range(0..max);
//         if n < insert {
//             // insert
//             let key_len = 16 + rng.gen_range(0..32);
//             let mut key = vec![0; key_len];
//             rng.fill_bytes(key.as_mut_slice());

//             let val_len = 1 + rng.gen_range(0..64);
//             let mut val = vec![0; val_len];
//             rng.fill_bytes(val.as_mut_slice());
//             let val = Bytes::from(val);
//             smt.update(key.as_slice(), val.clone()).unwrap();

//             kv.insert(Bytes::from(key), val);
//         } else if n > insert && n < insert + update {
//             // update
//             let keys = kv.keys().cloned().collect::<Vec<_>>();
//             if keys.is_empty() {
//                 continue;
//             }

//             let key = keys[rng.gen_range(0..keys.len())].clone();
//             let val_len = 1 + rng.gen_range(0..64);
//             let mut val = vec![0; val_len];
//             rng.fill_bytes(val.as_mut_slice());

//             let val = Bytes::from(val);

//             smt.update(&key, val.clone()).unwrap();
//             kv.insert(key, val);
//         } else {
//             // delete
//             let keys = kv.keys().cloned().collect::<Vec<_>>();
//             if keys.is_empty() {
//                 continue;
//             }
//             let key = keys[rng.gen_range(0..keys.len())].clone();
//             smt.update(&key, DEFAULT_VALUE).unwrap();
//             kv.insert(key, DEFAULT_VALUE);
//         }

//         bulk_check_all(&smt, &kv);
//     }
// }

// fn bulk_check_all<S: KVStore>(smt: &SparseMerkleTree<S>, kv: &hashbrown::HashMap<Bytes, Bytes>) {
//     for (k, v) in kv {
//         assert!(smt.get(k).unwrap().unwrap_or(DEFAULT_VALUE).eq(v));

//         // Generate and verify a Merkle proof for this key.
//         let proof = smt.prove(k).unwrap();
//         assert!(proof.verify(smt.root(), k, v));
//         let compact = smt.prove_compact(k).unwrap();
//         assert!(compact.verify(smt.root(), k, v));

//         if v.eq(&DEFAULT_VALUE) {
//             continue;
//         }

//         // Check that the key is at the correct height in the tree.
//         let mut largest_common_prefix = 0;
//         for (k2, v2) in kv {
//             if v2.eq(&DEFAULT_VALUE) {
//                 continue;
//             }

//             let common_prefix =
//                 count_common_prefix(smt.th.path(k).as_ref(), smt.th.path(k2).as_ref());
//             if common_prefix == smt.depth() && common_prefix > largest_common_prefix {
//                 largest_common_prefix = common_prefix;
//             }
//         }

//         let UpdateResult {
//             side_nodes,
//             path_nodes: _,
//             sibling_data: _,
//             current_data: _,
//         } = smt
//             .side_nodes_for_root(smt.th.path(k).as_ref(), smt.root(), false)
//             .unwrap();

//         let mut num_side_nodes = 0;
//         for node in side_nodes {
//             if !node.is_empty() {
//                 num_side_nodes += 1;
//             }
//         }

//         if num_side_nodes != largest_common_prefix + 1
//             && (num_side_nodes != 0 && largest_common_prefix != 0)
//         {
//             panic!("leaf is at unexpected height");
//         }
//     }
// }
