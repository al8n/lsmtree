use std::sync::Arc;

use bytes::Bytes;
use criterion::*;
use hashbrown::HashMap;
use lsmtree::{BadProof, KVStore, SparseMerkleTree};
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

fn bench_update(c: &mut Criterion) {
    let (smn, smv) = (SimpleStore::new(), SimpleStore::new());
    let mut smt = SparseMerkleTree::<SimpleStore>::new_with_stores(smn, smv);
    let mut count = 0;
    c.bench_function("smt update", |b| {
        b.iter_batched(
            || {
                let c = count;
                count += 1;
                let s = Bytes::from(c.to_string());
                (s.clone(), s)
            },
            |s| {
                let _ = smt.update(&s.0, s.1);
            },
            BatchSize::NumIterations(150_000),
        )
    });
}

fn bench_remove(c: &mut Criterion) {
    let (smn, smv) = (SimpleStore::new(), SimpleStore::new());
    let mut smt = SparseMerkleTree::<SimpleStore>::new_with_stores(smn, smv);

    for i in 0..100_000 {
        let s = Bytes::from(i.to_string());
        let _ = smt.update(&s, s.clone());
    }
    let mut count = 0;
    c.bench_function("smt remove", |b| {
        b.iter_batched(
            || {
                let c = count;
                count += 1;
                c
            },
            |s| {
                let s = s.to_string();
                let _ = smt.remove(s.as_bytes());
            },
            BatchSize::NumIterations(150_000),
        )
    });
}

criterion_group! {
    benches,
    bench_update,
    bench_remove,
}

criterion_main!(benches);
