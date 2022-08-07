use super::*;
use bytes::Bytes;
use rand::RngCore;

use crate::{
    new_sparse_merkle_tree, smt::DEFAULT_VALUE, tree_hasher::TreeHasher, SparseCompactMerkleProof,
    SparseMerkleProof,
};

// Test base case Merkle proof operations.
#[test]
fn test_proofs_basic() {
    let mut smt = new_sparse_merkle_tree();

    // Generate and verify a proof on an empty key.
    let proof = smt.prove(b"testKey3").unwrap();
    check_compact_equivalence(&proof);

    assert!(proof.verify(
        vec![0; <sha2::Sha256 as digest::Digest>::output_size()],
        b"testKey3",
        DEFAULT_VALUE
    ));

    assert!(!proof.verify(vec![], b"testKey3", b"badValue"));

    // Add a key, generate and verify a Merkle proof.
    smt.update(b"testKey", Bytes::from("testValue")).unwrap();
    let root = smt.root();
    let proof = smt.prove(b"testKey").unwrap();
    check_compact_equivalence(&proof);

    assert!(proof.verify(root.clone(), b"testKey", b"testValue"));

    assert!(!proof.verify(root, b"testKey", b"badValue"));

    // Add a key, generate and verify both Merkle proofs.
    smt.update(b"testKey2", Bytes::from("testValue")).unwrap();
    let root = smt.root();
    let proof = smt.prove(b"testKey2").unwrap();
    check_compact_equivalence(&proof);
    assert!(proof.verify(root.clone(), b"testKey2", b"testValue"));
    assert!(!proof.verify(root.clone(), b"testKey2", b"badValue"));

    assert!(!randomise_proof(&proof).verify(root.clone(), b"testKey2", b"testValue"));

    // Try proving a default value for a non-default leaf.
    let th = TreeHasher::<sha2::Sha256>::default();
    let (_, leaf_data) = th.digest_leaf(th.path(b"testKey2"), th.digest(b"testValue"));
    let proof = SparseMerkleProof::<sha2::Sha256>::new(proof.side_nodes, Some(leaf_data), None);

    assert!(!proof.verify(root.clone(), b"testKey2", DEFAULT_VALUE));

    // Generate and verify a proof on an empty key.
    let proof = smt.prove(b"testKey3").unwrap();
    check_compact_equivalence(&proof);
    assert!(proof.verify(root.clone(), b"testKey3", DEFAULT_VALUE));
    assert!(!proof.verify(root.clone(), b"testKey3", b"badValue"));
    assert!(!randomise_proof(&proof).verify(root, b"testKey3", DEFAULT_VALUE));
}

// Test sanity check cases for non-compact proofs.
#[test]
fn test_proofs_sanity_check() {
    let mut smt = new_sparse_merkle_tree();

    smt.update(b"testKey1", Bytes::from("testValue1")).unwrap();
    smt.update(b"testKey2", Bytes::from("testValue2")).unwrap();
    smt.update(b"testKey3", Bytes::from("testValue3")).unwrap();

    smt.update(b"testKey4", Bytes::from("testValue4")).unwrap();
    let root = smt.root();
    let mut th = TreeHasher::<sha2::Sha256>::default();

    // Case: invalid number of sidenodes.
    let mut proof = smt.prove(b"testKey1").unwrap();
    let side_nodes = (0..TreeHasher::<sha2::Sha256>::path_size() * 8 + 1)
        .map(|_| proof.side_nodes[0].clone())
        .collect();

    proof.side_nodes = side_nodes;
    assert!(!proof.sanity_check(&mut th));
    assert!(!proof.verify(root.clone(), b"testKey1", b"testValue1"));
    assert!(proof.compact().is_err());

    // Case: incorrect size for NonMembershipLeafData.
    let mut proof = smt.prove(b"testKey1").unwrap();
    proof.non_membership_leaf_data = Some(Bytes::from(vec![0; 1]));
    assert!(!proof.sanity_check(&mut th));
    assert!(!proof.verify(root.clone(), b"testKey1", b"testValue1"));
    assert!(proof.compact().is_err());

    // Case: unexpected sidenode size.
    let mut proof = smt.prove(b"testKey1").unwrap();
    proof.side_nodes[0] = Bytes::from(vec![0; 1]);
    assert!(!proof.sanity_check(&mut th));
    assert!(!proof.verify(root.clone(), b"testKey1", b"testValue1"));
    assert!(proof.compact().is_err());

    // Case: incorrect non-nil sibling data
    let mut proof = smt.prove(b"testKey1").unwrap();
    proof.sibling_data = Some(
        th.digest(proof.sibling_data.unwrap_or_default())
            .as_slice()
            .to_vec()
            .into(),
    );
    assert!(!proof.sanity_check(&mut th));
    assert!(!proof.verify(root, b"testKey1", b"testValue1"));
    assert!(proof.compact().is_err());
}

// Test sanity check cases for compact proofs.
#[test]
fn test_compact_proofs_sanity_check() {
    let mut smt = new_sparse_merkle_tree();

    smt.update(b"testKey1", Bytes::from("testValue1")).unwrap();
    smt.update(b"testKey2", Bytes::from("testValue2")).unwrap();
    smt.update(b"testKey3", Bytes::from("testValue3")).unwrap();

    smt.update(b"testKey4", Bytes::from("testValue4")).unwrap();
    let root = smt.root();

    // Case (compact proofs): NumSideNodes out of range.
    let mut proof = smt.prove_compact(b"testKey1").unwrap();
    proof.num_side_nodes = 0;
    let mut th = TreeHasher::<sha2::Sha256>::default();
    assert!(!proof.sanity_check(&mut th));

    proof.num_side_nodes = TreeHasher::<sha2::Sha256>::path_size() * 8 + 1;
    assert!(!proof.sanity_check(&mut th));

    assert!(!proof.verify(root.clone(), b"testKey1", b"testValue1"));

    // Case (compact proofs): unexpected bit mask length.
    let mut proof = smt.prove_compact(b"testKey1").unwrap();
    proof.num_side_nodes = 10;
    assert!(!proof.verify(root.clone(), b"testKey1", b"testValue1"));

    // Case (compact proofs): unexpected number of sidenodes for number of side nodes.
    let mut proof = smt.prove_compact(b"testKey1").unwrap();
    proof.side_nodes.extend(proof.side_nodes.clone());
    assert!(!proof.sanity_check(&mut th));
    assert!(!proof.verify(root, b"testKey1", b"testValue1"));
}

fn check_compact_equivalence<H: digest::Digest>(proof: &SparseMerkleProof<H>) {
    let compact = proof.compact().unwrap();
    let decompact = SparseCompactMerkleProof::<H>::decompact(&compact).unwrap();

    proof.side_nodes.iter().enumerate().for_each(|(idx, node)| {
        assert_eq!(node, &decompact.side_nodes[idx]);
    });

    assert_eq!(
        proof.non_membership_leaf_data,
        decompact.non_membership_leaf_data
    );
}

fn randomise_proof<H: digest::Digest>(proof: &SparseMerkleProof<H>) -> SparseMerkleProof<H> {
    let mut rng = rand::thread_rng();
    let nodes = (0..proof.side_nodes.len())
        .map(|i| {
            let mut node = vec![0; proof.side_nodes[i].len()];
            rng.fill_bytes(node.as_mut_slice());
            Bytes::from(node)
        })
        .collect::<Vec<_>>();

    SparseMerkleProof::new(nodes, proof.non_membership_leaf_data.clone(), None)
}
