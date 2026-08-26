// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generate BLS validator keys and the validator list a fleet is configured with.
//!
//! ```text
//! cargo run -p n42-h2-node --example h2_keygen -- --count 4 --out-dir ./fleet
//! ```
//!
//! Writes `validators.json` (public, shared by every member) and one
//! `validator-N.key` per validator (secret, one per member).
//!
//! **Order is part of the protocol.** A QC's signer bitmap indexes into this
//! array, so every member must load the identical file in the identical order or
//! they will disagree about who signed what. Generate it once and distribute it;
//! do not let each node build its own.

use std::path::PathBuf;

use alloy_primitives::Address;
use n42_h2_consensus::ValidatorInfo;
use n42_h2_primitives::bls::BlsSecretKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut count: usize = 4;
    let mut out_dir = PathBuf::from(".");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--count" => count = args.next().ok_or("--count needs a value")?.parse()?,
            "--out-dir" => out_dir = PathBuf::from(args.next().ok_or("--out-dir needs a path")?),
            "--help" | "-h" => {
                eprintln!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unknown argument {other}\n\n{USAGE}").into()),
        }
    }
    if count == 0 {
        return Err("--count must be at least 1".into());
    }

    std::fs::create_dir_all(&out_dir)?;

    let mut validators = Vec::with_capacity(count);
    for index in 0..count {
        let secret = BlsSecretKey::random()?;
        let key_path = out_dir.join(format!("validator-{index}.key"));
        std::fs::write(&key_path, format!("0x{}\n", hex::encode(secret.to_bytes())))?;
        // The secret is the whole identity of a validator; leaving it
        // world-readable in a shared directory is how a fleet gets equivocated.
        restrict(&key_path)?;

        validators.push(ValidatorInfo {
            // A placeholder: HotStuff-2 identifies validators by BLS key, and
            // this address is only the fee recipient a proposing node uses.
            address: Address::with_last_byte(index as u8 + 1),
            bls_public_key: secret.public_key(),
            p2p_peer_id: None,
        });
        println!("validator {index}: {}", key_path.display());
    }

    let list_path = out_dir.join("validators.json");
    std::fs::write(&list_path, serde_json::to_string_pretty(&validators)?)?;
    println!("\nvalidator list: {}", list_path.display());
    println!("f = {} (quorum {})", (count - 1) / 3, count - (count - 1) / 3);
    println!("\nEvery member must load this exact file: a QC's signer bitmap indexes into it.");
    Ok(())
}

#[cfg(unix)]
fn restrict(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
const fn restrict(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

const USAGE: &str = "\
h2_keygen — generate BLS validator keys and a fleet's validator list

  --count <n>       how many validators to generate (default 4)
  --out-dir <path>  where to write them (default .)
";
