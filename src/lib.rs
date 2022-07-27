#![cfg_attr(not(feature="std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::borrow_interior_mutable_const)]
mod tree_hasher;
mod error;
mod smt;
pub mod hashes;

pub use digest;
pub use bytes;
use bytes::Bytes;

/// Key-Value store 
pub trait KVStore {

    type Error: core::fmt::Debug + core::fmt::Display;

    /// Gets the value for a key.
    fn get(&self, key: &[u8]) -> Result<&Bytes, Self::Error>;
    /// Updates the value for a key.
    fn set(&self, key: Bytes, value: Bytes) -> Result<(), Self::Error>;
    /// Remove a key.
    fn remove(&self, key: &[u8]) -> Result<Bytes, Self::Error>;

    fn contains(&self, key: &[u8]) -> bool;
}

pub trait Hasher: digest::Digest {
    /// Returns the hash's underlying block size.
	/// The Write method must be able to accept any amount
	/// of data, but it may operate more efficiently if all writes
	/// are a multiple of the block size.
    fn block_size(&self) -> usize;
}

/// Gets the bit at an offset from the most significant bit
#[inline]
fn get_bit_at_from_msb(data: &[u8], position: usize) -> usize {
    if (data[position / 8] as usize) & (1 << (8-1- (position % 8))) > 0 {
        return 1;
    }
    0
}

/// Sets the bit at an offset from the most significant bit
#[inline]
fn set_bit_at_from_msb(data: &mut [u8], position: usize) {
    let mut n = data[position / 8] as usize;
    n |= 1 << (8-1- (position % 8));
    data[position / 8] = n as u8;
}

#[inline]
fn count_set_bits(data: &[u8]) -> usize {
    let mut count = 0;
    for i in 0..data.len() * 8 {
        if get_bit_at_from_msb(data, i) == 1 {
            count += 1;
        }
    }
    count
}

#[inline]
fn count_common_prefix(a: &[u8], b: &[u8]) -> usize {
    let mut cnt = 0;
    for i in 0..a.len() * 8 {
        if get_bit_at_from_msb(a, i) == get_bit_at_from_msb(b, i) {
            cnt += 1;
            continue;
        }
        break;
    }
    cnt
}