use banana_palm::{
    CHUNK_SIZE, HEADER_SIZE, Metadata, generate_keys, open, read_key, reconstruct_file, seal,
    split_file,
};
use ring::{
    digest,
    signature::{Ed25519KeyPair, KeyPair},
};
use std::{
    fs,
    io::{self, Cursor},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

fn signer() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
}
fn sender() -> [u8; 32] {
    signer().public_key().as_ref().try_into().unwrap()
}
fn metadata(size: u64) -> Metadata {
    Metadata {
        file_id: [9; 32],
        index: 0,
        count: size.div_ceil(CHUNK_SIZE as u64).max(1) as u32,
        original_size: size,
    }
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "palm-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn wire_layout_and_short_reads() {
    let bytes = seal(b"hello", &metadata(5), &[3; 32], &signer()).unwrap();
    assert_eq!(bytes.len(), HEADER_SIZE + 5 + 16);
    assert_eq!(&bytes[..5], b"PALM\x01");
    assert_eq!(&bytes[5..37], &[9; 32]);
    assert_eq!(&bytes[37..41], &0u32.to_le_bytes());
    assert_eq!(&bytes[41..45], &1u32.to_le_bytes());
    assert_eq!(&bytes[45..53], &5u64.to_le_bytes());
    assert_eq!(&bytes[53..57], &5u32.to_le_bytes());
    assert_eq!(&bytes[69..101], &sender());
    assert_eq!(
        &bytes[101..133],
        digest::digest(&digest::SHA256, &bytes[HEADER_SIZE..]).as_ref()
    );
    struct ShortRead(Cursor<Vec<u8>>);
    impl io::Read for ShortRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let length = buf.len().min(3);
            io::Read::read(&mut self.0, &mut buf[..length])
        }
    }
    let (meta, plain) = open(ShortRead(Cursor::new(bytes)), &[3; 32], &sender()).unwrap();
    assert_eq!(meta, metadata(5));
    assert_eq!(plain, b"hello");
}

#[test]
fn rejects_tampering_truncation_and_trailing_bytes() {
    let bytes = seal(b"hello", &metadata(5), &[3; 32], &signer()).unwrap();
    for offset in [0, 4, 5, 37, 41, 45, 53, 57, 69, 101, 133, HEADER_SIZE] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            open(changed.as_slice(), &[3; 32], &sender()).is_err(),
            "offset {offset}"
        );
    }
    for length in [0, 4, HEADER_SIZE - 1, bytes.len() - 1] {
        assert!(open(&bytes[..length], &[3; 32], &sender()).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(open(trailing.as_slice(), &[3; 32], &sender()).is_err());
    assert!(open(bytes.as_slice(), &[4; 32], &sender()).is_err());
    assert!(open(bytes.as_slice(), &[3; 32], &[0; 32]).is_err());
    // Recomputing the checksum cannot bypass the sender signature.
    let mut forged = bytes;
    forged[HEADER_SIZE] ^= 1;
    let hash = digest::digest(&digest::SHA256, &forged[HEADER_SIZE..]);
    forged[101..133].copy_from_slice(hash.as_ref());
    assert!(open(forged.as_slice(), &[3; 32], &sender()).is_err());
}

#[test]
fn bounds_lengths_before_allocation_and_checks_metadata() {
    assert!(seal(&[], &metadata(1), &[3; 32], &signer()).is_err());
    let mut bytes = seal(b"hello", &metadata(5), &[3; 32], &signer()).unwrap();
    bytes[53..57].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(open(bytes.as_slice(), &[3; 32], &sender()).is_err());
    let invalid = Metadata {
        index: 1,
        ..metadata(5)
    };
    assert!(seal(b"hello", &invalid, &[3; 32], &signer()).is_err());
}

#[test]
fn encryption_uses_fresh_nonces_and_hides_plaintext() {
    let first = seal(
        b"private original content",
        &metadata(24),
        &[3; 32],
        &signer(),
    )
    .unwrap();
    let second = seal(
        b"private original content",
        &metadata(24),
        &[3; 32],
        &signer(),
    )
    .unwrap();
    assert_ne!(&first[57..69], &second[57..69]);
    assert!(
        !first
            .windows(24)
            .any(|window| window == b"private original content")
    );
}

#[test]
fn file_round_trips_include_empty_exact_and_partial_chunks() {
    for size in [0, 1, CHUNK_SIZE, CHUNK_SIZE + 17, CHUNK_SIZE * 2] {
        let temp = Directory::new();
        let source = temp.0.join("original.bin");
        let parts = temp.0.join("parts");
        let restored = temp.0.join("restored.bin");
        let bytes = (0..size).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        fs::write(&source, &bytes).unwrap();
        let count = split_file(&source, &parts, &[3; 32], &signer()).unwrap();
        assert_eq!(count as usize, size.div_ceil(CHUNK_SIZE).max(1));
        reconstruct_file(&parts, &restored, &[3; 32], &sender()).unwrap();
        assert_eq!(fs::read(&restored).unwrap(), bytes);
        assert!(split_file(&source, &parts, &[3; 32], &signer()).is_err());
        assert!(reconstruct_file(&parts, &restored, &[3; 32], &sender()).is_err());
        assert_eq!(fs::read(&restored).unwrap(), bytes);
        assert!(!fs::read_dir(&temp.0).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }
}

#[test]
fn missing_mixed_and_swapped_fragments_never_publish_output() {
    let temp = Directory::new();
    let source = temp.0.join("input");
    fs::write(&source, vec![5; CHUNK_SIZE + 1]).unwrap();
    let parts = temp.0.join("parts");
    split_file(&source, &parts, &[3; 32], &signer()).unwrap();
    let chunk = parts.join("00000001.palm");
    let original = fs::read(&chunk).unwrap();
    fs::remove_file(&chunk).unwrap();
    let output = temp.0.join("output");
    assert!(reconstruct_file(&parts, &output, &[3; 32], &sender()).is_err());
    assert!(!output.exists());
    let other = temp.0.join("other");
    split_file(&source, &other, &[3; 32], &signer()).unwrap();
    fs::copy(other.join("00000001.palm"), &chunk).unwrap();
    assert!(reconstruct_file(&parts, &output, &[3; 32], &sender()).is_err());
    fs::write(&chunk, &original).unwrap();
    fs::copy(&chunk, parts.join("00000000.palm")).unwrap();
    assert!(reconstruct_file(&parts, &output, &[3; 32], &sender()).is_err());
    assert!(!output.exists());
}

#[test]
fn key_files_have_exact_lengths_and_private_permissions() {
    let temp = Directory::new();
    let keys = temp.0.join("keys");
    generate_keys(&keys).unwrap();
    let seed = read_key(keys.join("signing.seed")).unwrap();
    let signer = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    assert_eq!(
        read_key(keys.join("sender.pub")).unwrap().as_slice(),
        signer.public_key().as_ref()
    );
    read_key(keys.join("encryption.key")).unwrap();
    assert!(generate_keys(&keys).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(keys.join("signing.seed"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&keys).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    let bad = temp.0.join("bad.key");
    for length in [0, 31, 33, 4096] {
        fs::write(&bad, vec![0; length]).unwrap();
        assert!(read_key(&bad).is_err());
    }
}

#[test]
fn cli_splits_restores_and_returns_failure_without_overwriting() {
    use std::process::Command;
    let temp = Directory::new();
    let binary = env!("CARGO_BIN_EXE_banana-palm");
    let keys = temp.0.join("keys");
    assert!(
        Command::new(binary)
            .arg("keygen")
            .arg(&keys)
            .status()
            .unwrap()
            .success()
    );
    let source = temp.0.join("original.jpg");
    let parts = temp.0.join("parts");
    let restored = temp.0.join("restored.jpg");
    let data = vec![42; CHUNK_SIZE + 3];
    fs::write(&source, &data).unwrap();
    assert!(
        Command::new(binary)
            .arg("split")
            .arg(&source)
            .arg(&parts)
            .arg("--key")
            .arg(keys.join("encryption.key"))
            .arg("--signing-seed")
            .arg(keys.join("signing.seed"))
            .status()
            .unwrap()
            .success()
    );
    let restore = || {
        Command::new(binary)
            .arg("restore")
            .arg(&parts)
            .arg(&restored)
            .arg("--key")
            .arg(keys.join("encryption.key"))
            .arg("--sender")
            .arg(keys.join("sender.pub"))
            .output()
            .unwrap()
    };
    assert!(restore().status.success());
    assert_eq!(fs::read(&restored).unwrap(), data);
    assert!(!restore().status.success());
    assert_eq!(fs::read(&restored).unwrap(), data);
}
