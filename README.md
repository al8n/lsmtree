<div align="center">
<h1>LSMTree</h1>
</div>
<div align="center">

A Rust library that implements a Sparse Merkle tree for a key-value store. The tree implements the same optimisations specified in the [Libra whitepaper][libra whitepaper], to reduce the number of hash operations required per tree operation to O(k) where k is the number of non-empty elements in the tree.

[<img alt="github" src="https://img.shields.io/badge/github-lsmtree-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
[<img alt="Build" src="https://img.shields.io/github/workflow/status/al8n/lsmtree/CI/main?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/lsmtree?style=for-the-badge&token=VlQMUT0YD5&logo=codecov" height="22">][codecov-url]

[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-lsmtree-66c2a5?style=for-the-badge&labelColor=555555&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/lsmtree?style=for-the-badge&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iaXNvLTg4NTktMSI/Pg0KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDE5LjAuMCwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPg0KPHN2ZyB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB4PSIwcHgiIHk9IjBweCINCgkgdmlld0JveD0iMCAwIDUxMiA1MTIiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KPGc+DQoJPGc+DQoJCTxwYXRoIGQ9Ik0yNTYsMEwzMS41MjgsMTEyLjIzNnYyODcuNTI4TDI1Niw1MTJsMjI0LjQ3Mi0xMTIuMjM2VjExMi4yMzZMMjU2LDB6IE0yMzQuMjc3LDQ1Mi41NjRMNzQuOTc0LDM3Mi45MTNWMTYwLjgxDQoJCQlsMTU5LjMwMyw3OS42NTFWNDUyLjU2NHogTTEwMS44MjYsMTI1LjY2MkwyNTYsNDguNTc2bDE1NC4xNzQsNzcuMDg3TDI1NiwyMDIuNzQ5TDEwMS44MjYsMTI1LjY2MnogTTQzNy4wMjYsMzcyLjkxMw0KCQkJbC0xNTkuMzAzLDc5LjY1MVYyNDAuNDYxbDE1OS4zMDMtNzkuNjUxVjM3Mi45MTN6IiBmaWxsPSIjRkZGIi8+DQoJPC9nPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPC9zdmc+DQo=" height="22">][crates-url]
[<img alt="rustc" src="https://img.shields.io/badge/MSRV-1.62.0-fc8d62.svg?style=for-the-badge&logo=Rust" height="22">][rustc-url]

[<img alt="license-apache" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge&logo=Apache" height="22">][license-apache-url]
[<img alt="license-mit" src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge&fontColor=white&logoColor=f5c076&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIGhlaWdodD0iMzZweCIgdmlld0JveD0iMCAwIDI0IDI0IiB3aWR0aD0iMzZweCIgZmlsbD0iI2Y1YzA3NiI+PHBhdGggZD0iTTAgMGgyNHYyNEgwVjB6IiBmaWxsPSJub25lIi8+PHBhdGggZD0iTTEwLjA4IDEwLjg2Yy4wNS0uMzMuMTYtLjYyLjMtLjg3cy4zNC0uNDYuNTktLjYyYy4yNC0uMTUuNTQtLjIyLjkxLS4yMy4yMy4wMS40NC4wNS42My4xMy4yLjA5LjM4LjIxLjUyLjM2cy4yNS4zMy4zNC41My4xMy40Mi4xNC42NGgxLjc5Yy0uMDItLjQ3LS4xMS0uOS0uMjgtMS4yOXMtLjQtLjczLS43LTEuMDEtLjY2LS41LTEuMDgtLjY2LS44OC0uMjMtMS4zOS0uMjNjLS42NSAwLTEuMjIuMTEtMS43LjM0cy0uODguNTMtMS4yLjkyLS41Ni44NC0uNzEgMS4zNlM4IDExLjI5IDggMTEuODd2LjI3YzAgLjU4LjA4IDEuMTIuMjMgMS42NHMuMzkuOTcuNzEgMS4zNS43Mi42OSAxLjIuOTFjLjQ4LjIyIDEuMDUuMzQgMS43LjM0LjQ3IDAgLjkxLS4wOCAxLjMyLS4yM3MuNzctLjM2IDEuMDgtLjYzLjU2LS41OC43NC0uOTQuMjktLjc0LjMtMS4xNWgtMS43OWMtLjAxLjIxLS4wNi40LS4xNS41OHMtLjIxLjMzLS4zNi40Ni0uMzIuMjMtLjUyLjNjLS4xOS4wNy0uMzkuMDktLjYuMS0uMzYtLjAxLS42Ni0uMDgtLjg5LS4yMy0uMjUtLjE2LS40NS0uMzctLjU5LS42MnMtLjI1LS41NS0uMy0uODgtLjA4LS42Ny0uMDgtMXYtLjI3YzAtLjM1LjAzLS42OC4wOC0xLjAxek0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQxIDAtOC0zLjU5LTgtOHMzLjU5LTggOC04IDggMy41OSA4IDgtMy41OSA4LTggOHoiLz48L3N2Zz4=" height="22">][license-mit-url]

English | [简体中文][zh-cn-url]

</div>


## Features

- `no_std` supports, but needs `alloc`.
- Reduce the number of hash operations required per tree operation to O(k) where k is the number of non-empty elements in the tree.
- Internal implementation uses shallow copy, which powered by [`bytes::Bytes`](https://crates.io/crates/bytes).
- Performance almost depends on the cryptographic crate, e.g. `sha2`.
- Adaptable with [RustCrypto's crates](https://github.com/RustCrypto). All cryptographic structs which implement [`digest::Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html) trait are adaptable with this crate.
- Easily compactable with any other cryptographic crates. When you want to use a cryptographic crate which does not implement [`digest::Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html) trait, you actually do not need to fully implement [`digest::Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html) trait.
  
    e.g. only need to implement 5 methods (`new`, `update`, `digest`, `output_size`, `finalize`, actually only 3 methods) and just leave other methods `unreachable!()`.
    
    ```rust
    pub struct DummyHasher { 
        data: Vec<u8>,
    }

    impl digest::OutputSizeUser for DummyHasher {
        type OutputSize = digest::typenum::U32;
    }

    impl digest::Digest for DummyHasher {
        fn new() -> Self {
            // your implementation here
        }

        fn finalize(mut self) -> digest::Output<Self> {
            // your implementation here
        }

        fn update(&mut self, data: impl AsRef<[u8]>) {
            // your implementation here
        }

        fn output_size() -> usize {
            <Self as OutputSizeUser>::output_size()
        }

        fn digest(data: impl AsRef<[u8]>) -> digest::Output<Self> {
            let mut h = Self::new();
            h.update(data);
            h.finalize()
        }

        fn new_with_prefix(_data: impl AsRef<[u8]>) -> Self {
            unreachable!()
        }

        fn chain_update(self, _data: impl AsRef<[u8]>) -> Self {
            unreachable!() 
        }

        fn finalize_into(self, _out: &mut digest::Output<Self>) {
            unreachable!()
        }

        fn finalize_reset(&mut self) -> digest::Output<Self> {
            unreachable!()
        }

        fn finalize_into_reset(&mut self, _out: &mut digest::Output<Self>) {
            unreachable!()
        }

        fn reset(&mut self) {
            unreachable!()
        }
    }
    ```

## Installation
```toml
[dependencies]
lsmtree = "0.1"
```

## Example
```rust
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
```

## Acknowledge
- Thanks celestiaorg's developers for providing amazing Go version [smt](https://github.com/celestiaorg/smt) implementation.


#### License

`lsmtree` is under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2022 Al Liu.

[Github-url]: https://github.com/al8n/lsmtree/
[CI-url]: https://github.com/al8n/lsmtree/actions/workflows/ci.yml
[doc-url]: https://docs.rs/lsmtree
[crates-url]: https://crates.io/crates/lsmtree
[codecov-url]: https://app.codecov.io/gh/al8n/lsmtree/
[license-url]: https://opensource.org/licenses/Apache-2.0
[rustc-url]: https://github.com/rust-lang/rust/blob/master/RELEASES.md
[license-apache-url]: https://opensource.org/licenses/Apache-2.0
[license-mit-url]: https://opensource.org/licenses/MIT
[zh-cn-url]: https://github.com/al8n/lsmtree/tree/main/README-zh_CN.md
[libra whitepaper]: https://diem-developers-components.netlify.app/papers/the-diem-blockchain/2020-05-26.pdf
