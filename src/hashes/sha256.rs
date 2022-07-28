use sha2::Sha256;

#[cfg(test)]
mod tests {
    use super::*;
    use digest::Digest;

    #[test]
    fn test_sha2() {
        let mut hasher = Sha256::new();
        hasher.update(vec![0; 0]);
        let hash = hasher.finalize_reset();
        eprintln!("{:?}", hash);
        println!("{}", <Sha256 as Digest>::output_size());
    }
}
