use alloc::boxed::Box;
use alloc::vec::Vec;
use bytes::Bytes;
use digest::{generic_array::GenericArray, Digest, FixedOutputReset, OutputSizeUser};

const LEAF_PREFIX: [u8; 1] = [0];
const NODE_PREFIX: [u8; 1] = [1];

pub(crate) struct TreeHasher<H> {
    hasher: H,
    zero_value: Bytes,
}

impl<H: Digest + FixedOutputReset> TreeHasher<H> {
    pub fn new(hasher: H, zero_value: Bytes) -> Self {
        Self { hasher, zero_value }
    }

    pub(crate) fn digest(
        &mut self,
        data: impl AsRef<[u8]>,
    ) -> GenericArray<u8, <H as OutputSizeUser>::OutputSize> {
        <H as Digest>::update(&mut self.hasher, data);
        self.hasher.finalize_reset()
    }

    pub(crate) fn digest_leaf(
        &mut self,
        path: impl AsRef<[u8]>,
        leaf_data: impl AsRef<[u8]>,
    ) -> (Bytes, Bytes) {
        let path = path.as_ref();
        let leaf_data = leaf_data.as_ref();
        let mut value = Vec::with_capacity(1 + path.len() + leaf_data.len());
        value.push(LEAF_PREFIX[0]);
        value.extend_from_slice(path);
        value.extend_from_slice(leaf_data);
        <H as Digest>::update(&mut self.hasher, &value);
        let ptr = Box::into_raw(Box::new(self.hasher.finalize_reset())) as *mut u8;
        let size = <H as OutputSizeUser>::output_size();
        let sum = Bytes::from(unsafe { Vec::from_raw_parts(ptr, size, size) });
        (sum, value.into())
    }

    pub(crate) fn digest_node(
        &mut self,
        left_data: impl AsRef<[u8]>,
        right_data: impl AsRef<[u8]>,
    ) -> (Bytes, Bytes) {
        let left_data = left_data.as_ref();
        let right_data = right_data.as_ref();
        let mut value = Vec::with_capacity(1 + left_data.len() + right_data.len());
        value.push(NODE_PREFIX[0]);
        value.extend_from_slice(left_data);
        value.extend_from_slice(right_data);
        <H as Digest>::update(&mut self.hasher, &value);
        let ptr = Box::into_raw(Box::new(self.hasher.finalize_reset())) as *mut u8;
        let size = <H as OutputSizeUser>::output_size();
        let sum = Bytes::from(unsafe { Vec::from_raw_parts(ptr, size, size) });
        (sum, value.into())
    }

    pub(crate) fn parse_leaf(data: &[u8]) -> (&[u8], &[u8]) {
        let leaf_prefix_len = LEAF_PREFIX.len();
        let path_size = Self::path_size();
        (
            &data[leaf_prefix_len..path_size + leaf_prefix_len],
            &data[leaf_prefix_len + path_size..],
        )
    }

    pub(crate) fn parse_node(data: &Option<Bytes>) -> (Bytes, Bytes) {
        match data {
            Some(data) => {
                let node_prefix_len = NODE_PREFIX.len();
                let left_size = Self::path_size();
                let right_size = Self::path_size();
                (
                    data.slice(node_prefix_len..left_size + node_prefix_len),
                    data.slice(
                        node_prefix_len + left_size..node_prefix_len + left_size + right_size,
                    ),
                )
            }
            None => (Bytes::new(), Bytes::new()),
        }
    }

    pub(crate) fn is_leaf(data: &Option<impl AsRef<[u8]>>) -> bool {
        match data {
            Some(data) => {
                let data = data.as_ref();
                let leaf_prefix_len = LEAF_PREFIX.len();
                data[..leaf_prefix_len].eq(&LEAF_PREFIX)
            }
            None => false,
        }
    }

    pub(crate) fn path(
        &self,
        key: impl AsRef<[u8]>,
    ) -> GenericArray<u8, <H as OutputSizeUser>::OutputSize> {
        <H as Digest>::digest(key)
    }

    pub(crate) fn path_size() -> usize {
        <H as digest::Digest>::output_size()
    }

    pub(crate) fn placeholder(&self) -> Bytes {
        self.zero_value.clone()
    }

    pub(crate) fn placeholder_ref(&self) -> &[u8] {
        &self.zero_value
    }
}
