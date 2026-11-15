//! Experimental PALM v1: bounded, encrypted and authenticated file fragments.
use ring::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair, KeyPair},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

pub const CHUNK_SIZE: usize = 1024 * 1024;
pub const HEADER_SIZE: usize = 197;
const AAD_SIZE: usize = 101;
const SIGNED_HEADER_SIZE: usize = 133;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("secure random generation failed"))?;
    Ok(bytes)
}

fn cipher(key: &[u8; 32]) -> io::Result<aead::LessSafeKey> {
    aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map(aead::LessSafeKey::new)
        .map_err(|_| invalid("invalid encryption key"))
}

/// Metadata authenticated by both the signature and encryption tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub file_id: [u8; 32],
    pub index: u32,
    pub count: u32,
    pub original_size: u64,
}

impl Metadata {
    fn payload_len(&self) -> io::Result<usize> {
        // Even an empty file has one authenticated empty fragment.
        let count = self.original_size.div_ceil(CHUNK_SIZE as u64).max(1);
        if count != u64::from(self.count) || self.index >= self.count {
            return Err(invalid("invalid fragment count or index"));
        }
        Ok(
            (self.original_size - u64::from(self.index) * CHUNK_SIZE as u64).min(CHUNK_SIZE as u64)
                as usize,
        )
    }
}

/// Encode one chunk. The caller supplies the trusted sender's signing key.
pub fn seal(
    payload: &[u8],
    metadata: &Metadata,
    key: &[u8; 32],
    signer: &Ed25519KeyPair,
) -> io::Result<Vec<u8>> {
    if payload.len() != metadata.payload_len()? {
        return Err(invalid("payload length does not match file metadata"));
    }
    let nonce = random::<12>()?;
    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(b"PALM");
    header.push(1);
    header.extend_from_slice(&metadata.file_id);
    header.extend_from_slice(&metadata.index.to_le_bytes());
    header.extend_from_slice(&metadata.count.to_le_bytes());
    header.extend_from_slice(&metadata.original_size.to_le_bytes());
    header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    header.extend_from_slice(&nonce);
    header.extend_from_slice(signer.public_key().as_ref());

    let mut ciphertext = payload.to_vec();
    cipher(key)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(header.as_slice()),
            &mut ciphertext,
        )
        .map_err(|_| invalid("encryption failed"))?;
    header.extend_from_slice(digest::digest(&digest::SHA256, &ciphertext).as_ref());
    let mut signed = header.clone();
    signed.extend_from_slice(&ciphertext);
    header.extend_from_slice(signer.sign(&signed).as_ref());
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

/// Read a standalone fragment, verify its trusted sender, then decrypt it.
/// A public key embedded in a file is never treated as its own trust anchor.
pub fn open(
    mut reader: impl Read,
    key: &[u8; 32],
    trusted_sender: &[u8; 32],
) -> io::Result<(Metadata, Vec<u8>)> {
    let mut header = [0; HEADER_SIZE];
    reader.read_exact(&mut header)?;
    if &header[..4] != b"PALM" || header[4] != 1 {
        return Err(invalid("unsupported PALM magic or version"));
    }
    let metadata = Metadata {
        file_id: header[5..37].try_into().unwrap(),
        index: u32::from_le_bytes(header[37..41].try_into().unwrap()),
        count: u32::from_le_bytes(header[41..45].try_into().unwrap()),
        original_size: u64::from_le_bytes(header[45..53].try_into().unwrap()),
    };
    let length = u32::from_le_bytes(header[53..57].try_into().unwrap()) as usize;
    if length != metadata.payload_len()? || &header[69..101] != trusted_sender {
        return Err(invalid("invalid length or untrusted sender"));
    }
    // The fixed chunk limit is checked before allocating from untrusted input.
    let mut ciphertext = vec![0; length + aead::AES_256_GCM.tag_len()];
    reader.read_exact(&mut ciphertext)?;
    let mut extra = [0];
    if reader.read(&mut extra)? != 0 {
        return Err(invalid("trailing bytes after fragment"));
    }
    if digest::digest(&digest::SHA256, &ciphertext).as_ref() != &header[101..133] {
        return Err(invalid("fragment checksum mismatch"));
    }
    let mut signed = header[..SIGNED_HEADER_SIZE].to_vec();
    signed.extend_from_slice(&ciphertext);
    signature::UnparsedPublicKey::new(&signature::ED25519, trusted_sender)
        .verify(&signed, &header[133..197])
        .map_err(|_| invalid("invalid fragment signature"))?;
    let nonce = aead::Nonce::assume_unique_for_key(header[57..69].try_into().unwrap());
    let plaintext = cipher(key)?
        .open_in_place(nonce, aead::Aad::from(&header[..AAD_SIZE]), &mut ciphertext)
        .map_err(|_| invalid("decryption failed"))?;
    Ok((metadata, plaintext.to_vec()))
}

fn fragment_name(index: u32) -> String {
    format!("{index:08}.palm")
}

fn temporary_path(parent: &Path) -> io::Result<PathBuf> {
    let id = random::<16>()?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(parent.join(format!(".palm-{id}.tmp")))
}

fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

// Publish a complete file without overwriting any existing destination. A same-
// directory hard link provides no-clobber publication; unsupported filesystems
// return an error rather than falling back to an unsafe overwrite.
fn publish(path: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = temporary_path(parent)?;
    let mut file = create_private(&temporary)?;
    let result = write(&mut file).and_then(|()| file.sync_all());
    drop(file);
    let result = result.and_then(|()| fs::hard_link(&temporary, path));
    let cleanup = fs::remove_file(&temporary);
    result.and(cleanup)
}

/// Generate raw AES-256 key, Ed25519 seed, and public key in a fresh directory.
/// Keep encryption.key and signing.seed secret; distribute sender.pub separately.
pub fn generate_keys(directory: impl AsRef<Path>) -> io::Result<()> {
    let directory = directory.as_ref();
    fs::create_dir(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let key = random::<32>()?;
    let seed = random::<32>()?;
    let signer =
        Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| invalid("invalid signing seed"))?;
    for (name, bytes) in [
        ("encryption.key", key.as_slice()),
        ("signing.seed", seed.as_slice()),
        ("sender.pub", signer.public_key().as_ref()),
    ] {
        publish(&directory.join(name), |file| file.write_all(bytes))?;
    }
    Ok(())
}

/// Read a raw 32-byte key without accepting trailing data or unbounded files.
pub fn read_key(path: impl AsRef<Path>) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut key = [0; 32];
    file.read_exact(&mut key)?;
    if file.read(&mut [0])? != 0 {
        return Err(invalid("key must contain exactly 32 bytes"));
    }
    Ok(key)
}

/// Split a stable source into signed encrypted chunks in a fresh directory.
/// Failed splits can leave a partial directory; restore rejects missing chunks.
pub fn split_file(
    source: impl AsRef<Path>,
    directory: impl AsRef<Path>,
    key: &[u8; 32],
    signer: &Ed25519KeyPair,
) -> io::Result<u32> {
    let mut source = File::open(source)?;
    let original_size = source.metadata()?.len();
    let count = u32::try_from(original_size.div_ceil(CHUNK_SIZE as u64).max(1))
        .map_err(|_| invalid("file is too large"))?;
    let file_id = random::<32>()?;
    let directory = directory.as_ref();
    fs::create_dir(directory)?;
    for index in 0..count {
        let metadata = Metadata {
            file_id,
            index,
            count,
            original_size,
        };
        let mut payload = vec![0; metadata.payload_len()?];
        source.read_exact(&mut payload)?;
        let encoded = seal(&payload, &metadata, key, signer)?;
        publish(&directory.join(fragment_name(index)), |file| {
            file.write_all(&encoded)
        })?;
    }
    if source.read(&mut [0])? != 0 {
        return Err(invalid("source grew during splitting"));
    }
    Ok(count)
}

/// Reconstruct exactly one signed file set. All chunks are required (no erasure coding).
/// No plaintext destination is published unless every fragment validates.
pub fn reconstruct_file(
    directory: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    key: &[u8; 32],
    trusted_sender: &[u8; 32],
) -> io::Result<()> {
    let directory = directory.as_ref();
    let (first, payload) = open(
        File::open(directory.join(fragment_name(0)))?,
        key,
        trusted_sender,
    )?;
    if first.index != 0 {
        return Err(invalid("first fragment has the wrong index"));
    }
    publish(destination.as_ref(), |output| {
        output.write_all(&payload)?;
        for index in 1..first.count {
            let (metadata, payload) = open(
                File::open(directory.join(fragment_name(index)))?,
                key,
                trusted_sender,
            )?;
            let expected = Metadata {
                index,
                ..first.clone()
            };
            if metadata != expected {
                return Err(invalid("fragment belongs to a different file or index"));
            }
            output.write_all(&payload)?;
        }
        Ok(())
    })
}
