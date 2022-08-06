use alloc::sync::Arc;
use hashbrown::HashMap;

use crate::proofs::BadProof;

use super::*;
use parking_lot::Mutex;

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

impl std::error::Error for Error {}

#[derive(Debug, Clone, Default)]
pub struct SimpleStore {
    data: Arc<Mutex<HashMap<Bytes, Bytes>>>,
}

impl core::fmt::Display for SimpleStore {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let data = self.data.lock();
        writeln!(f, "length: {}", data.len());
        for (key, value) in data.iter() {
            writeln!(f, "{:?} => {:?}", key.as_ref(), value.as_ref())?;
            writeln!(f, "")?;
        }
        Ok(())
    }
}

impl SimpleStore {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl KVStore for SimpleStore {
    type Error = Error;
    type Hasher = sha2::Sha256;

    fn get(&self, key: &[u8]) -> Result<Option<Bytes>, Self::Error> {
        let data = self.data.lock();
        Ok(data.get(key).map(core::clone::Clone::clone))
    }

    fn set(&self, key: Bytes, value: Bytes) -> Result<(), Self::Error> {
        let mut data = self.data.lock();
        data.insert(key, value);
        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<Bytes, Self::Error> {
        let mut data = self.data.lock();
        data.remove(key).ok_or(Error::NotFound)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error> {
        Ok(self.data.lock().contains_key(key))
    }
}

pub fn new_sparse_merkle_tree() -> SparseMerkleTree<SimpleStore> {
    let (smn, smv) = (SimpleStore::new(), SimpleStore::new());
    SparseMerkleTree::<SimpleStore>::new(smn, smv)
}

struct DummyHasher<D: digest::Digest + digest::OutputSizeUser> {
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

    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
        todo!()
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.data.extend(data.as_ref());
    }

    fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
        todo!()
    }

    fn finalize(self) -> digest::Output<Self> {
        todo!()
    }

    fn finalize_into(self, out: &mut digest::Output<Self>) {
        todo!()
    }

    fn finalize_reset(&mut self) -> digest::Output<Self>
    where
        Self: digest::FixedOutputReset,
    {
        todo!()
    }

    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>)
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
        todo!()
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
fn test_sparse_merkle_tree_known() {}

#[test]
fn test_sparse_merkle_tree_max_height_case() {
    let _smt = new_sparse_merkle_tree();
    // Make two neighboring keys.
    //
    // The dummy hash function expects keys to prefixed with four bytes of 0,
    // which will cause it to return the preimage itself as the digest, without
    // the first four bytes.
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

    let dsmst = SparseMerkleTree::import(SimpleStore::new(), SimpleStore::new(), smt.root());
    dsmst
        .add_branch(bad_proof, b"testKey1", Bytes::from("testValue1"))
        .unwrap_err();
}
