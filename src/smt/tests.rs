use alloc::sync::Arc;
use hashbrown::HashMap;

use super::*;
use parking_lot::Mutex;

#[derive(Debug)]
pub enum Error {
    NotFound,
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

    fn set(&mut self, key: Bytes, value: Bytes) -> Result<(), Self::Error> {
        let mut data = self.data.lock();
        data.insert(key, value);
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> Result<Bytes, Self::Error> {
        let mut data = self.data.lock();
        data.remove(key).ok_or(Error::NotFound)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error> {
        Ok(self.data.lock().contains_key(key))
    }
}

fn new_sparse_merkle_tree() -> SparseMerkleTree<SimpleStore> {
    let (smn, smv) = (SimpleStore::new(), SimpleStore::new());
    SparseMerkleTree::<SimpleStore>::new(smn, smv)
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
    let smt2 = SparseMerkleTree::<SimpleStore>::import(
        smt.nodes.clone(),
        smt.values.clone(),
        smt.root(),
    );
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
fn test_sparse_merkle_tree_max_height_case() {
    let _smt = new_sparse_merkle_tree();
    // Make two neighboring keys.
    //
    // The dummy hash function expects keys to prefixed with four bytes of 0,
    // which will cause it to return the preimage itself as the digest, without
    // the first four bytes.
}
