use lsmtree::{bytes::Bytes, BadProof, KVStore, SparseMerkleTree};
use sha2::Sha256;
use std::collections::HashMap;

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
    type Hasher = Sha256;

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

fn main() {
    let mut smt = SparseMerkleTree::<SimpleStore>::new();

    // insert
    smt.update(b"key1", Bytes::from("val1")).unwrap();

    // get
    assert_eq!(smt.get(b"key1").unwrap(), Some(Bytes::from("val1")));

    // prove
    let proof = smt.prove(b"key1").unwrap();
    assert!(proof.verify(smt.root_ref(), b"key1", b"val1"));
}
