//! Behaviour checks for maintained replacements in legacy dependency paths.

#[cfg(test)]
mod tests {
    use ark_ff::{Fp64, MontBackend, MontConfig};

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    struct FieldConfig;
    type Field = Fp64<MontBackend<FieldConfig, 1>>;

    #[test]
    fn generic_field_derives_do_not_require_traits_on_the_configuration() {
        // FieldConfig deliberately does not implement Clone, Copy, Eq, Hash or
        // Default. These traits belong to the field element, not its marker.
        let a = Field::from(16u64);
        let b = a;
        assert_eq!(a + Field::from(2u64), Field::from(1u64));
        assert_eq!(a, b);
        assert_eq!(Field::default(), Field::from(0u64));
        let mut set = std::collections::HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn database_records_survive_reopening_with_the_replaced_hash_and_clock() {
        let base = std::env::temp_dir().join(format!("n42-sled-compat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        {
            let db = sled::open(&base).unwrap();
            let tree = db.open_tree(b"validator-history").unwrap();
            for height in 0..1024u64 {
                tree.insert(height.to_be_bytes(), &height.to_le_bytes())
                    .unwrap();
            }
            tree.flush().unwrap();
        }
        {
            let db = sled::open(&base).unwrap();
            let tree = db.open_tree(b"validator-history").unwrap();
            assert_eq!(tree.len(), 1024);
            for height in 0..1024u64 {
                assert_eq!(
                    tree.get(height.to_be_bytes()).unwrap().unwrap().as_ref(),
                    height.to_le_bytes()
                );
            }
        }
        std::fs::remove_dir_all(base).unwrap();
    }
}
