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
        const WRITER_PATH: &str = "N42_SLED_COMPAT_WRITER_PATH";
        if let Some(path) = std::env::var_os(WRITER_PATH) {
            let base = std::path::PathBuf::from(path);
            {
                let db = sled::open(&base).unwrap();
                let tree = db.open_tree(b"validator-history").unwrap();
                for height in 0..1024u64 {
                    tree.insert(height.to_be_bytes(), &height.to_le_bytes())
                        .unwrap();
                }
                tree.flush().unwrap();
            }
            return;
        }
        let base = std::env::temp_dir().join(format!("n42-sled-compat-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        // Sled's background workers can retain the file lock after Db/Tree drop.
        // A separate writer process makes this a real persistence/reopen check:
        // its successful exit releases every worker and database handle.
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::database_records_survive_reopening_with_the_replaced_hash_and_clock",
                "--nocapture",
            ])
            .env(WRITER_PATH, &base)
            .status()
            .unwrap();
        assert!(status.success(), "database writer subprocess failed");
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
