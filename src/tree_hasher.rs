use alloc::boxed::Box;
use alloc::vec::Vec;
use bytes::Bytes;
use digest::{generic_array::GenericArray, Digest, OutputSizeUser};

pub(crate) const LEAF_PREFIX: [u8; 1] = [0];
const NODE_PREFIX: [u8; 1] = [1];

pub(crate) struct TreeHasher<H> {
    zero_value: Bytes,
    _marker: core::marker::PhantomData<H>,
}

impl<H> Clone for TreeHasher<H> {
    fn clone(&self) -> Self {
        Self {
            zero_value: self.zero_value.clone(),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<H> core::fmt::Debug for TreeHasher<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(core::any::type_name::<Self>())
            .field("zero_value", &self.zero_value)
            .finish()
    }
}

impl<H: Digest + OutputSizeUser> Default for TreeHasher<H> {
    fn default() -> Self {
        Self {
            zero_value: vec![0; <H as Digest>::output_size()].into(),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<H: Digest + OutputSizeUser> TreeHasher<H> {
    pub(crate) fn new(zero_value: Bytes) -> Self {
        Self {
            _marker: Default::default(),
            zero_value,
        }
    }

    pub(crate) fn digest(
        &self,
        data: impl AsRef<[u8]>,
    ) -> GenericArray<u8, <H as OutputSizeUser>::OutputSize> {
        <H as Digest>::digest(data)
    }

    pub(crate) fn digest_leaf_hash(
        &self,
        path: impl AsRef<[u8]>,
        leaf_data: impl AsRef<[u8]>,
    ) -> Bytes {
        let path = path.as_ref();
        let leaf_data = leaf_data.as_ref();
        let mut value = Vec::with_capacity(1 + path.len() + leaf_data.len());
        value.push(LEAF_PREFIX[0]);
        value.extend_from_slice(path);
        value.extend_from_slice(leaf_data);
        let ptr = Box::into_raw(Box::new(<H as Digest>::digest(&value))) as *mut u8;
        let size = <H as OutputSizeUser>::output_size();
        Bytes::from(unsafe { Vec::from_raw_parts(ptr, size, size) })
    }

    pub(crate) fn digest_leaf(
        &self,
        path: impl AsRef<[u8]>,
        leaf_data: impl AsRef<[u8]>,
    ) -> (Bytes, Bytes) {
        let path = path.as_ref();
        let leaf_data = leaf_data.as_ref();
        let mut value = Vec::with_capacity(1 + path.len() + leaf_data.len());
        value.push(LEAF_PREFIX[0]);
        value.extend_from_slice(path);
        value.extend_from_slice(leaf_data);
        let ptr = Box::into_raw(Box::new(<H as Digest>::digest(&value))) as *mut u8;
        let size = <H as OutputSizeUser>::output_size();
        let sum = Bytes::from(unsafe { Vec::from_raw_parts(ptr, size, size) });
        (sum, value.into())
    }

    pub(crate) fn digest_node(
        &self,
        left_data: impl AsRef<[u8]>,
        right_data: impl AsRef<[u8]>,
    ) -> (Bytes, Bytes) {
        let left_data = left_data.as_ref();
        let right_data = right_data.as_ref();
        self.digest_node_helper(left_data, right_data)
    }

    #[inline]
    fn digest_node_helper(&self, left_data: &[u8], right_data: &[u8]) -> (Bytes, Bytes) {
        let mut value = Vec::with_capacity(1 + left_data.len() + right_data.len());
        value.push(NODE_PREFIX[0]);
        value.extend_from_slice(left_data);
        value.extend_from_slice(right_data);
        let ptr = Box::into_raw(Box::new(<H as Digest>::digest(&value))) as *mut u8;
        let size = <H as OutputSizeUser>::output_size();
        let sum = Bytes::from(unsafe { Vec::from_raw_parts(ptr, size, size) });
        (sum, value.into())
    }

    pub(crate) fn digest_left_node(&self, left_data: impl AsRef<[u8]>) -> (Bytes, Bytes) {
        let left_data = left_data.as_ref();
        let right_data = self.placeholder_ref();
        self.digest_node_helper(left_data, right_data)
    }

    pub(crate) fn digest_right_node(&self, right_data: impl AsRef<[u8]>) -> (Bytes, Bytes) {
        let left_data = self.placeholder_ref();
        let right_data = right_data.as_ref();
        self.digest_node_helper(left_data, right_data)
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

    pub(crate) fn path_into(&self, key: impl AsRef<[u8]>) -> Bytes {
        let ptr = Box::into_raw(Box::new(<H as Digest>::digest(key))) as *mut u8;
        let size = <H as OutputSizeUser>::output_size();
        Bytes::from(unsafe { Vec::from_raw_parts(ptr, size, size) })
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
