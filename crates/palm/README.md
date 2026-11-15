# PALM v1 fragment format (experimental)

This standalone Rust crate implements issue #8's `.palm` container: encrypted
fragment bytes, a ciphertext hash, and a sender signature. It also provides a
local file splitter and restorer. It does not yet integrate storage with pool
networking, implement Reed–Solomon recovery (#7), or provide persistent node
identity/key distribution (#19). Timestamp/replay policy remains in #11.

## Try it

From the repository root (the key and parts directories must not already exist):

```sh
cargo run --manifest-path crates/palm/Cargo.toml -- keygen ./palm-keys
cargo run --manifest-path crates/palm/Cargo.toml -- split ./photo.jpg ./photo-parts \
  --key ./palm-keys/encryption.key --signing-seed ./palm-keys/signing.seed
cargo run --manifest-path crates/palm/Cargo.toml -- restore ./photo-parts ./restored.jpg \
  --key ./palm-keys/encryption.key --sender ./palm-keys/sender.pub
cmp ./photo.jpg ./restored.jpg
cargo test --manifest-path crates/palm/Cargo.toml
```

The source can be any file type. Keep it unchanged during splitting. Payloads
are at most 1 MiB; the final payload can be shorter. Empty files have one signed,
encrypted empty fragment. Every fragment is required for reconstruction.
The caller selects the output filename; original filenames are not exposed in
fragment headers. No separate manifest is needed for this simple sequential
format: every signed header carries the set ID, count, index, and original size.
A later erasure-coding format must use a new version with explicit coding metadata.

`encryption.key` is a raw 32-byte AES key; `signing.seed` is a raw 32-byte Ed25519
seed; `sender.pub` is its raw 32-byte public key. Keep the first two secret and
backed up. Recipients need the encryption key and a sender public key obtained
through a trusted channel. Never trust the public key merely because it appears
inside a fragment. Key files are unencrypted at rest. Unix key directories use
0700 and created files use 0600; other platforms require appropriate filesystem
access controls. This is an experimental file format, not a reviewed key vault.

## Exact byte layout

All integers are unsigned little-endian. There is no padding or optional field.
Offsets below are zero-based with exclusive end positions.

| Range | Size | Field |
| --- | --- | --- |
| 0..4 | 4 | ASCII `PALM` magic |
| 4..5 | 1 | Version, exactly 1 |
| 5..37 | 32 | Random file-set ID, shared by all fragments of one split |
| 37..41 | 4 | Zero-based fragment index |
| 41..45 | 4 | Fragment count |
| 45..53 | 8 | Original file length |
| 53..57 | 4 | Plaintext payload length |
| 57..69 | 12 | Random AES-GCM nonce |
| 69..101 | 32 | Ed25519 sender public key |
| 101..133 | 32 | SHA-256 of ciphertext including the authentication tag |
| 133..197 | 64 | Ed25519 signature |
| 197..EOF | payload length + 16 | AES-256-GCM ciphertext and 16-byte tag |

Encryption uses AES-256-GCM with bytes `0..101` as additional authenticated data.
The Ed25519 signature covers the concatenation `bytes[0..133] || bytes[197..EOF]`.
Thus file ID, order, count, size, sender, nonce, hash, and ciphertext are all bound
to the signature. The hash is an integrity checksum, not a substitute for trust.
Nonces are generated with the OS CSPRNG for each sealing operation. Rotate keys
for large deployments and define system-wide per-key usage limits before using
this format at production scale; never replace random nonces with chunk indices
when a key can be reused for multiple files.

For size S, count MUST equal `max(1, ceil(S / 1048576))` and fit in u32. Index MUST
be less than count. Payload length MUST equal `min(1048576, S - index * 1048576)`.
Readers MUST reject unknown magic/version, invalid size/count/index, untrusted
sender, truncation, trailing bytes, hash/signature mismatch, or failed decryption.
The length limit MUST be checked before allocating a payload buffer.

Files are named `00000000.palm`, `00000001.palm`, etc. Readers validate content,
not just extensions. Restoration expects these names and rejects missing,
reordered, or mixed file-set fragments. Unrelated files in the directory are
ignored. The signed header is authoritative, not directory enumeration order.

## Failure and storage behavior

Writes use private temporary files in the destination directory, sync their
contents, then hard-link them to the final name without replacing existing files.
Filesystems without hard-link support return an error. Restore publishes no
plaintext output until every chunk validates. Temporary files are removed on
ordinary failures; abrupt termination may leave private `.palm-*.tmp` files.
Directory entries are not fsynced, so power-loss durability is not guaranteed.

Split requires a fresh directory; a failed or interrupted split may leave a partial
set that must be removed or completed separately. Key generation likewise requires
a fresh directory and may leave partial keys on failure. The library never silently
overwrites existing chunks, keys, or restored files. Keep destination directories
under your control; this helper is not an adversarial multi-user storage service.

The algorithm encrypts each plaintext chunk independently before wrapping it. This
is ordinary chunking, not the future encrypt-then-erasure-code pipeline. Any future
encoding integration must specify and test the ordering explicitly.
