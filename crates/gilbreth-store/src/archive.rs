//! Durable, streaming encryption for cold Gilbreth database archives.
//!
//! The on-disk format is deliberately independent of SQLite. A fixed prefix
//! identifies the file and version, a length-delimited JSON header records
//! provenance and key wrapping, and length-delimited AES-256-GCM STREAM
//! segments carry the database bytes. The complete prefix and header are
//! authenticated as associated data on the first segment.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use aead::{
    rand_core::RngCore,
    stream::{DecryptorBE32, EncryptorBE32, Nonce as StreamNonce, StreamBE32},
    Aead, KeyInit, OsRng, Payload,
};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ARCHIVE_EXTENSION: &str = "gla";
pub const ARCHIVE_MAGIC: [u8; 8] = *b"GBRTHARC";
pub const ARCHIVE_FORMAT_VERSION: u16 = 1;
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

pub const DPAPI_ARCHIVE_RECEIPT: &str = "archive created, encrypted to this Windows account (this user, this machine). A portable copy is a separate explicit export.";
pub const DPAPI_DURABILITY_NOTICE: &str = "if this Windows profile is lost, encrypted archives are not recoverable; make a portable export for anything that must outlive it.";

const FIXED_PREFIX_LEN: usize = ARCHIVE_MAGIC.len() + 2 + 4;
const MAX_HEADER_LEN: usize = 1024 * 1024;
const AES_GCM_TAG_LEN: usize = 16;
const STREAM_NONCE_LEN: usize = 7;
const WRAP_NONCE_LEN: usize = 12;
const CONTENT_KEY_LEN: usize = 32;
const PASSPHRASE_SALT_LEN: usize = 16;
const KEY_WRAP_AAD: &[u8] = b"Gilbreth archive content key v1";
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("archive I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("archive header JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid archive format: {0}")]
    InvalidFormat(String),
    #[error("archive authentication failed; the file is damaged, incomplete, reordered, or was opened with the wrong key")]
    AuthenticationFailed,
    #[error("archive key is not available to this Windows account")]
    DpapiKeyUnavailable,
    #[error("DPAPI user encryption is available only on Windows")]
    DpapiUnsupported,
    #[error("the portable archive passphrase must not be empty")]
    EmptyPassphrase,
    #[error("passphrase key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("archive output already exists: {0}")]
    OutputExists(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveProvenance {
    pub db_uuid: String,
    pub host: Option<String>,
    pub schema_version: u32,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "kebab-case")]
pub enum ArchiveKeyWrap {
    DpapiUser {
        wrapped_key: Vec<u8>,
    },
    Passphrase {
        wrapped_key: Vec<u8>,
        salt: [u8; PASSPHRASE_SALT_LEN],
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        wrap_nonce: [u8; WRAP_NONCE_LEN],
    },
}

impl ArchiveKeyWrap {
    pub fn method_name(&self) -> &'static str {
        match self {
            Self::DpapiUser { .. } => "dpapi-user",
            Self::Passphrase { .. } => "passphrase",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveHeader {
    pub provenance: ArchiveProvenance,
    pub key_wrap: ArchiveKeyWrap,
    pub chunk_size: u32,
    pub stream_nonce: [u8; STREAM_NONCE_LEN],
}

#[derive(Clone, Copy, Debug)]
pub enum ArchiveCredential<'a> {
    DpapiUser,
    Passphrase(&'a str),
}

#[derive(Clone, Copy, Debug)]
pub enum ArchiveSealKey<'a> {
    DpapiUser,
    Passphrase(&'a str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveProtection {
    DpapiUser,
    Passphrase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveEncryptionReceipt {
    pub protection: ArchiveProtection,
    pub summary: &'static str,
    pub durability_notice: &'static str,
}

impl ArchiveEncryptionReceipt {
    pub fn dpapi_user() -> Self {
        Self {
            protection: ArchiveProtection::DpapiUser,
            summary: DPAPI_ARCHIVE_RECEIPT,
            durability_notice: DPAPI_DURABILITY_NOTICE,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArchiveInventory {
    pub encrypted: Vec<PathBuf>,
    pub plaintext_legacy: Vec<PathBuf>,
}

/// Token required by the plaintext export API. The UI must collect the
/// user's explicit acknowledgement before it can obtain this token.
#[derive(Clone, Copy, Debug)]
pub struct PlaintextExportAcknowledgement(());

impl PlaintextExportAcknowledgement {
    pub fn after_explicit_warning(understood: bool) -> Option<Self> {
        understood.then_some(Self(()))
    }
}

/// Return encrypted and plaintext-era archive files in stable filename order.
/// Unknown files are ignored; existing plaintext archives are never modified.
pub fn inventory_archives(directory: &Path) -> Result<ArchiveInventory, ArchiveError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ArchiveInventory::default())
        }
        Err(error) => return Err(error.into()),
    };
    let mut inventory = ArchiveInventory::default();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("gilbreth-archive-") {
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) == Some(ARCHIVE_EXTENSION) {
            if read_archive_header(&path).is_ok() {
                inventory.encrypted.push(path);
            }
        } else if path.extension().and_then(|value| value.to_str()) == Some("db")
            && has_sqlite_magic(&path)?
        {
            inventory.plaintext_legacy.push(path);
        }
    }
    inventory.encrypted.sort();
    inventory.plaintext_legacy.sort();
    Ok(inventory)
}

pub fn read_archive_header(path: &Path) -> Result<ArchiveHeader, ArchiveError> {
    let mut file = File::open(path)?;
    let (header, _) = read_header(&mut file)?;
    Ok(header)
}

pub fn verify_archive(
    path: &Path,
    credential: ArchiveCredential<'_>,
) -> Result<ArchiveHeader, ArchiveError> {
    let mut input = File::open(path)?;
    let mut sink = io::sink();
    unseal_reader(&mut input, &mut sink, credential)
}

pub fn unseal_archive_to(
    source: &Path,
    destination: &Path,
    credential: ArchiveCredential<'_>,
) -> Result<ArchiveHeader, ArchiveError> {
    let mut input = File::open(source)?;
    let mut output = create_new(destination)?;
    let result = unseal_reader(&mut input, &mut output, credential).and_then(|header| {
        output.flush()?;
        output.sync_all()?;
        Ok(header)
    });
    if result.is_err() {
        drop(output);
        remove_if_present(destination);
    }
    result
}

pub fn seal_archive_file(
    source: &Path,
    destination: &Path,
    provenance: ArchiveProvenance,
    key: ArchiveSealKey<'_>,
) -> Result<ArchiveHeader, ArchiveError> {
    let mut input = File::open(source)?;
    let mut output = create_new(destination)?;
    let result = seal_reader(&mut input, &mut output, provenance, key).and_then(|header| {
        output.flush()?;
        output.sync_all()?;
        Ok(header)
    });
    if result.is_err() {
        drop(output);
        remove_if_present(destination);
    }
    result
}

/// Rewrap and stream an archive into a passphrase-protected portable copy.
/// Plaintext is never materialized on disk.
pub fn export_passphrase_archive(
    source: &Path,
    destination: &Path,
    source_credential: ArchiveCredential<'_>,
    passphrase: &str,
) -> Result<ArchiveHeader, ArchiveError> {
    if passphrase.is_empty() {
        return Err(ArchiveError::EmptyPassphrase);
    }
    let mut input = File::open(source)?;
    let mut output = create_new(destination)?;
    let result = transcode_reader(
        &mut input,
        &mut output,
        source_credential,
        ArchiveSealKey::Passphrase(passphrase),
    )
    .and_then(|header| {
        output.flush()?;
        output.sync_all()?;
        Ok(header)
    });
    if result.is_err() {
        drop(output);
        remove_if_present(destination);
    }
    result
}

/// Write a deliberate plaintext export. Callers cannot reach this API without
/// first converting an explicit user acknowledgement into the token.
pub fn export_plaintext_archive(
    source: &Path,
    destination: &Path,
    source_credential: ArchiveCredential<'_>,
    _acknowledgement: PlaintextExportAcknowledgement,
) -> Result<ArchiveHeader, ArchiveError> {
    unseal_archive_to(source, destination, source_credential)
}

fn seal_reader<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    provenance: ArchiveProvenance,
    key: ArchiveSealKey<'_>,
) -> Result<ArchiveHeader, ArchiveError> {
    let mut content_key = [0_u8; CONTENT_KEY_LEN];
    OsRng.fill_bytes(&mut content_key);
    let key_wrap = wrap_content_key(&content_key, key)?;
    let mut stream_nonce = [0_u8; STREAM_NONCE_LEN];
    OsRng.fill_bytes(&mut stream_nonce);
    let header = ArchiveHeader {
        provenance,
        key_wrap,
        chunk_size: DEFAULT_CHUNK_SIZE,
        stream_nonce,
    };
    let authenticated_header = write_header(output, &header)?;
    let cipher = Aes256Gcm::new_from_slice(&content_key)
        .map_err(|_| ArchiveError::InvalidFormat("invalid content-key length".to_string()))?;
    let nonce = StreamNonce::<Aes256Gcm, StreamBE32<Aes256Gcm>>::from_slice(&stream_nonce);
    let mut encryptor = EncryptorBE32::from_aead(cipher, nonce);
    let mut first = true;
    let mut current = read_chunk(input, header.chunk_size as usize)?;
    loop {
        let next = read_chunk(input, header.chunk_size as usize)?;
        let aad = if first {
            authenticated_header.as_slice()
        } else {
            &[]
        };
        let ciphertext = if next.is_empty() {
            encryptor
                .encrypt_last(Payload { msg: &current, aad })
                .map_err(|_| ArchiveError::AuthenticationFailed)?
        } else {
            let ciphertext = encryptor
                .encrypt_next(Payload { msg: &current, aad })
                .map_err(|_| ArchiveError::AuthenticationFailed)?;
            current = next;
            first = false;
            write_frame(output, &ciphertext)?;
            continue;
        };
        write_frame(output, &ciphertext)?;
        break;
    }
    Ok(header)
}

fn unseal_reader<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    credential: ArchiveCredential<'_>,
) -> Result<ArchiveHeader, ArchiveError> {
    let (header, authenticated_header) = read_header(input)?;
    let content_key = unwrap_content_key(&header.key_wrap, credential)?;
    decrypt_chunks(
        input,
        &header,
        &authenticated_header,
        &content_key,
        |plain, _| {
            output.write_all(plain)?;
            Ok(())
        },
    )?;
    Ok(header)
}

fn transcode_reader<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    source_credential: ArchiveCredential<'_>,
    destination_key: ArchiveSealKey<'_>,
) -> Result<ArchiveHeader, ArchiveError> {
    let (source_header, source_aad) = read_header(input)?;
    let source_key = unwrap_content_key(&source_header.key_wrap, source_credential)?;

    let mut destination_content_key = [0_u8; CONTENT_KEY_LEN];
    OsRng.fill_bytes(&mut destination_content_key);
    let mut destination_nonce = [0_u8; STREAM_NONCE_LEN];
    OsRng.fill_bytes(&mut destination_nonce);
    let destination_header = ArchiveHeader {
        provenance: source_header.provenance.clone(),
        key_wrap: wrap_content_key(&destination_content_key, destination_key)?,
        chunk_size: source_header.chunk_size,
        stream_nonce: destination_nonce,
    };
    let destination_aad = write_header(output, &destination_header)?;
    let destination_cipher = Aes256Gcm::new_from_slice(&destination_content_key)
        .map_err(|_| ArchiveError::InvalidFormat("invalid content-key length".to_string()))?;
    let nonce = StreamNonce::<Aes256Gcm, StreamBE32<Aes256Gcm>>::from_slice(&destination_nonce);
    let mut destination_encryptor = Some(EncryptorBE32::from_aead(destination_cipher, nonce));
    let mut first = true;
    decrypt_chunks(
        input,
        &source_header,
        &source_aad,
        &source_key,
        |plain, last| {
            let aad = if first {
                destination_aad.as_slice()
            } else {
                &[]
            };
            let ciphertext = if last {
                destination_encryptor
                    .take()
                    .expect("destination encryptor exists through final chunk")
                    .encrypt_last(Payload { msg: plain, aad })
                    .map_err(|_| ArchiveError::AuthenticationFailed)?
            } else {
                destination_encryptor
                    .as_mut()
                    .expect("destination encryptor exists before final chunk")
                    .encrypt_next(Payload { msg: plain, aad })
                    .map_err(|_| ArchiveError::AuthenticationFailed)?
            };
            write_frame(output, &ciphertext)?;
            first = false;
            Ok(())
        },
    )?;
    Ok(destination_header)
}

fn decrypt_chunks<R, F>(
    input: &mut R,
    header: &ArchiveHeader,
    authenticated_header: &[u8],
    content_key: &[u8; CONTENT_KEY_LEN],
    mut consume: F,
) -> Result<(), ArchiveError>
where
    R: Read,
    F: FnMut(&[u8], bool) -> Result<(), ArchiveError>,
{
    validate_header(header)?;
    let cipher = Aes256Gcm::new_from_slice(content_key)
        .map_err(|_| ArchiveError::InvalidFormat("invalid content-key length".to_string()))?;
    let nonce = StreamNonce::<Aes256Gcm, StreamBE32<Aes256Gcm>>::from_slice(&header.stream_nonce);
    let mut decryptor = Some(DecryptorBE32::from_aead(cipher, nonce));
    let max_frame = header.chunk_size as usize + AES_GCM_TAG_LEN;
    let mut current = read_frame(input, max_frame)?.ok_or_else(|| {
        ArchiveError::InvalidFormat("archive has no authenticated content segment".to_string())
    })?;
    let mut first = true;
    loop {
        let next = read_frame(input, max_frame)?;
        let aad = if first { authenticated_header } else { &[] };
        let last = next.is_none();
        let plaintext = if last {
            decryptor
                .take()
                .expect("decryptor exists through final chunk")
                .decrypt_last(Payload { msg: &current, aad })
                .map_err(|_| ArchiveError::AuthenticationFailed)?
        } else {
            let plaintext = decryptor
                .as_mut()
                .expect("decryptor exists before final chunk")
                .decrypt_next(Payload { msg: &current, aad })
                .map_err(|_| ArchiveError::AuthenticationFailed)?;
            current = next.expect("checked above");
            plaintext
        };
        consume(&plaintext, last)?;
        if last {
            break;
        }
        first = false;
    }
    Ok(())
}

/// Whether this platform can wrap a content key with `key`, checked *before*
/// any plaintext is written.
///
/// Sealing happens after `VACUUM main INTO` has already materialised a
/// complete plaintext copy of the activity database, so discovering that the
/// key is unavailable at wrap time means the copy exists and only a
/// best-effort scrub stands between the user and an unencrypted database on
/// disk — one the archive inventory cannot even report, because it skips the
/// dot-prefixed staging name. On macOS, where `DpapiUser` can never succeed,
/// that was every attempt.
///
/// Callers must run this before computing a staging path. It is a
/// precondition, not a degradation path: it refuses, it does not substitute a
/// weaker mechanism.
pub fn ensure_seal_key_available(key: ArchiveSealKey<'_>) -> Result<(), ArchiveError> {
    match key {
        // Wrapping is a pure DPAPI call with no other failure mode worth
        // predicting here; an empty passphrase is rejected by `wrap_content_key`
        // itself, before any staging path exists.
        ArchiveSealKey::DpapiUser => {
            #[cfg(windows)]
            {
                Ok(())
            }
            #[cfg(not(windows))]
            {
                Err(ArchiveError::DpapiUnsupported)
            }
        }
        ArchiveSealKey::Passphrase(passphrase) => {
            if passphrase.is_empty() {
                return Err(ArchiveError::EmptyPassphrase);
            }
            Ok(())
        }
    }
}

fn wrap_content_key(
    content_key: &[u8; CONTENT_KEY_LEN],
    key: ArchiveSealKey<'_>,
) -> Result<ArchiveKeyWrap, ArchiveError> {
    match key {
        ArchiveSealKey::DpapiUser => Ok(ArchiveKeyWrap::DpapiUser {
            wrapped_key: dpapi_protect(content_key)?,
        }),
        ArchiveSealKey::Passphrase(passphrase) => {
            if passphrase.is_empty() {
                return Err(ArchiveError::EmptyPassphrase);
            }
            let mut salt = [0_u8; PASSPHRASE_SALT_LEN];
            let mut wrap_nonce = [0_u8; WRAP_NONCE_LEN];
            OsRng.fill_bytes(&mut salt);
            OsRng.fill_bytes(&mut wrap_nonce);
            let wrapping_key = derive_passphrase_key(
                passphrase,
                &salt,
                ARGON2_MEMORY_KIB,
                ARGON2_ITERATIONS,
                ARGON2_PARALLELISM,
            )?;
            let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
                .map_err(|_| ArchiveError::InvalidFormat("invalid wrapping-key length".into()))?;
            let wrapped_key = cipher
                .encrypt(
                    Nonce::from_slice(&wrap_nonce),
                    Payload {
                        msg: content_key,
                        aad: KEY_WRAP_AAD,
                    },
                )
                .map_err(|_| ArchiveError::AuthenticationFailed)?;
            Ok(ArchiveKeyWrap::Passphrase {
                wrapped_key,
                salt,
                memory_kib: ARGON2_MEMORY_KIB,
                iterations: ARGON2_ITERATIONS,
                parallelism: ARGON2_PARALLELISM,
                wrap_nonce,
            })
        }
    }
}

fn unwrap_content_key(
    key_wrap: &ArchiveKeyWrap,
    credential: ArchiveCredential<'_>,
) -> Result<[u8; CONTENT_KEY_LEN], ArchiveError> {
    let bytes = match (key_wrap, credential) {
        (ArchiveKeyWrap::DpapiUser { wrapped_key }, ArchiveCredential::DpapiUser) => {
            dpapi_unprotect(wrapped_key)?
        }
        (
            ArchiveKeyWrap::Passphrase {
                wrapped_key,
                salt,
                memory_kib,
                iterations,
                parallelism,
                wrap_nonce,
            },
            ArchiveCredential::Passphrase(passphrase),
        ) => {
            if passphrase.is_empty() {
                return Err(ArchiveError::EmptyPassphrase);
            }
            let wrapping_key =
                derive_passphrase_key(passphrase, salt, *memory_kib, *iterations, *parallelism)?;
            let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
                .map_err(|_| ArchiveError::InvalidFormat("invalid wrapping-key length".into()))?;
            cipher
                .decrypt(
                    Nonce::from_slice(wrap_nonce),
                    Payload {
                        msg: wrapped_key,
                        aad: KEY_WRAP_AAD,
                    },
                )
                .map_err(|_| ArchiveError::AuthenticationFailed)?
        }
        (ArchiveKeyWrap::DpapiUser { .. }, ArchiveCredential::Passphrase(_))
        | (ArchiveKeyWrap::Passphrase { .. }, ArchiveCredential::DpapiUser) => {
            return Err(ArchiveError::AuthenticationFailed)
        }
    };
    bytes
        .try_into()
        .map_err(|_| ArchiveError::InvalidFormat("wrapped content key is not 32 bytes".to_string()))
}

fn derive_passphrase_key(
    passphrase: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<[u8; CONTENT_KEY_LEN], ArchiveError> {
    if !(8 * 1024..=1024 * 1024).contains(&memory_kib)
        || !(1..=10).contains(&iterations)
        || !(1..=16).contains(&parallelism)
    {
        return Err(ArchiveError::InvalidFormat(
            "argon2id parameters are outside supported safety bounds".to_string(),
        ));
    }
    let params = Params::new(memory_kib, iterations, parallelism, Some(CONTENT_KEY_LEN))
        .map_err(|error| ArchiveError::KeyDerivation(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; CONTENT_KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|error| ArchiveError::KeyDerivation(error.to_string()))?;
    Ok(output)
}

fn write_header<W: Write>(output: &mut W, header: &ArchiveHeader) -> Result<Vec<u8>, ArchiveError> {
    validate_header(header)?;
    let json = serde_json::to_vec(header)?;
    if json.len() > MAX_HEADER_LEN {
        return Err(ArchiveError::InvalidFormat(
            "archive header is too large".into(),
        ));
    }
    let mut authenticated = Vec::with_capacity(FIXED_PREFIX_LEN + json.len());
    authenticated.extend_from_slice(&ARCHIVE_MAGIC);
    authenticated.extend_from_slice(&ARCHIVE_FORMAT_VERSION.to_le_bytes());
    authenticated.extend_from_slice(&(json.len() as u32).to_le_bytes());
    authenticated.extend_from_slice(&json);
    output.write_all(&authenticated)?;
    Ok(authenticated)
}

fn read_header<R: Read>(input: &mut R) -> Result<(ArchiveHeader, Vec<u8>), ArchiveError> {
    let mut fixed = [0_u8; FIXED_PREFIX_LEN];
    input.read_exact(&mut fixed)?;
    if fixed[..ARCHIVE_MAGIC.len()] != ARCHIVE_MAGIC {
        return Err(ArchiveError::InvalidFormat(
            "archive magic does not match".to_string(),
        ));
    }
    let version_offset = ARCHIVE_MAGIC.len();
    let version = u16::from_le_bytes(
        fixed[version_offset..version_offset + 2]
            .try_into()
            .expect("fixed version width"),
    );
    if version != ARCHIVE_FORMAT_VERSION {
        return Err(ArchiveError::InvalidFormat(format!(
            "unsupported archive format version {version}"
        )));
    }
    let length_offset = version_offset + 2;
    let length = u32::from_le_bytes(
        fixed[length_offset..length_offset + 4]
            .try_into()
            .expect("fixed length width"),
    ) as usize;
    if length == 0 || length > MAX_HEADER_LEN {
        return Err(ArchiveError::InvalidFormat(
            "archive header length is invalid".to_string(),
        ));
    }
    let mut json = vec![0_u8; length];
    input.read_exact(&mut json)?;
    let header: ArchiveHeader = serde_json::from_slice(&json)?;
    validate_header(&header)?;
    let mut authenticated = fixed.to_vec();
    authenticated.extend_from_slice(&json);
    Ok((header, authenticated))
}

fn validate_header(header: &ArchiveHeader) -> Result<(), ArchiveError> {
    if header.provenance.db_uuid.trim().is_empty() {
        return Err(ArchiveError::InvalidFormat(
            "source db_uuid is missing".to_string(),
        ));
    }
    if !(4 * 1024..=16 * 1024 * 1024).contains(&header.chunk_size) {
        return Err(ArchiveError::InvalidFormat(
            "archive chunk size is outside supported bounds".to_string(),
        ));
    }
    match &header.key_wrap {
        ArchiveKeyWrap::DpapiUser { wrapped_key } if wrapped_key.is_empty() => Err(
            ArchiveError::InvalidFormat("DPAPI-wrapped key is empty".to_string()),
        ),
        ArchiveKeyWrap::Passphrase {
            wrapped_key,
            memory_kib,
            iterations,
            parallelism,
            ..
        } => {
            if wrapped_key.len() != CONTENT_KEY_LEN + AES_GCM_TAG_LEN {
                return Err(ArchiveError::InvalidFormat(
                    "passphrase-wrapped key length is invalid".to_string(),
                ));
            }
            if !(8 * 1024..=1024 * 1024).contains(memory_kib)
                || !(1..=10).contains(iterations)
                || !(1..=16).contains(parallelism)
            {
                return Err(ArchiveError::InvalidFormat(
                    "argon2id parameters are outside supported safety bounds".to_string(),
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn read_chunk<R: Read>(input: &mut R, maximum: usize) -> Result<Vec<u8>, ArchiveError> {
    let mut bytes = vec![0_u8; maximum];
    let mut used = 0;
    while used < maximum {
        match input.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(read) => used += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    bytes.truncate(used);
    Ok(bytes)
}

fn write_frame<W: Write>(output: &mut W, ciphertext: &[u8]) -> Result<(), ArchiveError> {
    let length = u32::try_from(ciphertext.len()).map_err(|_| {
        ArchiveError::InvalidFormat("encrypted archive segment is too large".to_string())
    })?;
    output.write_all(&length.to_le_bytes())?;
    output.write_all(ciphertext)?;
    Ok(())
}

fn read_frame<R: Read>(input: &mut R, maximum: usize) -> Result<Option<Vec<u8>>, ArchiveError> {
    let mut length_bytes = [0_u8; 4];
    match input.read(&mut length_bytes[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("one-byte read returned more than one byte"),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            return read_frame(input, maximum)
        }
        Err(error) => return Err(error.into()),
    }
    input.read_exact(&mut length_bytes[1..])?;
    let length = u32::from_le_bytes(length_bytes) as usize;
    if length < AES_GCM_TAG_LEN || length > maximum {
        return Err(ArchiveError::InvalidFormat(
            "encrypted archive segment length is invalid".to_string(),
        ));
    }
    let mut ciphertext = vec![0_u8; length];
    input.read_exact(&mut ciphertext)?;
    Ok(Some(ciphertext))
}

fn create_new(path: &Path) -> Result<File, ArchiveError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                ArchiveError::OutputExists(path.to_path_buf())
            } else {
                ArchiveError::Io(error)
            }
        })
}

fn remove_if_present(path: &Path) {
    if let Err(error) = fs::remove_file(path) {
        if error.kind() != io::ErrorKind::NotFound {
            tracing::warn!(%error, archive_file = ?path.file_name(), "failed to remove incomplete archive output");
        }
    }
}

fn has_sqlite_magic(path: &Path) -> Result<bool, ArchiveError> {
    let mut file = File::open(path)?;
    let mut magic = [0_u8; 16];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(&magic == b"SQLite format 3\0"),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(windows)]
fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    use windows::{
        core::w,
        Win32::{
            Foundation::{LocalFree, HLOCAL},
            Security::Cryptography::{
                CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
            },
        },
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &input,
            w!("Gilbreth archive content key"),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|_| ArchiveError::DpapiKeyUnavailable)?;
        let protected = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
        Ok(protected)
    }
}

#[cfg(not(windows))]
fn dpapi_protect(_plaintext: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    Err(ArchiveError::DpapiUnsupported)
}

#[cfg(windows)]
fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    use windows::Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|_| ArchiveError::DpapiKeyUnavailable)?;
        let plaintext = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
        Ok(plaintext)
    }
}

#[cfg(not(windows))]
fn dpapi_unprotect(_ciphertext: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    Err(ArchiveError::DpapiUnsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn provenance() -> ArchiveProvenance {
        ArchiveProvenance {
            db_uuid: "12c1a6cc-4654-4db2-92e0-7a2e711d480a".to_string(),
            host: Some("test-host".to_string()),
            schema_version: 6,
            first_ts: Some(10),
            last_ts: Some(20),
            created_at: 30,
        }
    }

    fn portable_archive(plain: &[u8], passphrase: &str) -> Vec<u8> {
        let mut input = Cursor::new(plain);
        let mut output = Vec::new();
        seal_reader(
            &mut input,
            &mut output,
            provenance(),
            ArchiveSealKey::Passphrase(passphrase),
        )
        .expect("seal portable archive");
        output
    }

    fn unseal_portable(archive: &[u8], passphrase: &str) -> Result<Vec<u8>, ArchiveError> {
        let mut input = Cursor::new(archive);
        let mut output = Vec::new();
        unseal_reader(
            &mut input,
            &mut output,
            ArchiveCredential::Passphrase(passphrase),
        )?;
        Ok(output)
    }

    #[test]
    fn round_trip_empty_small_and_chunk_boundary_inputs() {
        for plain in [
            Vec::new(),
            b"small sqlite-shaped payload".to_vec(),
            vec![0x5a; DEFAULT_CHUNK_SIZE as usize * 2 + 137],
        ] {
            let archive = portable_archive(&plain, "correct horse battery staple");
            assert_eq!(
                unseal_portable(&archive, "correct horse battery staple").expect("unseal"),
                plain
            );
        }
    }

    #[test]
    fn wrong_passphrase_fails_without_output() {
        let archive = portable_archive(b"private", "right passphrase");
        assert!(matches!(
            unseal_portable(&archive, "wrong passphrase"),
            Err(ArchiveError::AuthenticationFailed)
        ));
    }

    #[test]
    fn tamper_truncation_and_header_edit_fail_authentication() {
        let archive = portable_archive(
            &vec![0x31; DEFAULT_CHUNK_SIZE as usize + 111],
            "tamper passphrase",
        );

        let mut flipped = archive.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x80;
        assert!(unseal_portable(&flipped, "tamper passphrase").is_err());

        let truncated = &archive[..archive.len() - 8];
        assert!(unseal_portable(truncated, "tamper passphrase").is_err());

        let mut edited_header = archive.clone();
        let needle = b"test-host";
        let offset = edited_header
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("host appears in header");
        edited_header[offset] ^= 1;
        assert!(unseal_portable(&edited_header, "tamper passphrase").is_err());
    }

    #[test]
    fn reordered_and_cross_archive_chunks_fail_authentication() {
        let first = portable_archive(
            &vec![0x41; DEFAULT_CHUNK_SIZE as usize * 2 + 10],
            "stream passphrase",
        );
        let second = portable_archive(
            &vec![0x42; DEFAULT_CHUNK_SIZE as usize * 2 + 10],
            "stream passphrase",
        );
        let ranges = frame_ranges(&first);
        assert!(ranges.len() >= 3);

        let mut reordered = first.clone();
        let a = first[ranges[0].clone()].to_vec();
        let b = first[ranges[1].clone()].to_vec();
        assert_eq!(a.len(), b.len());
        reordered[ranges[0].clone()].copy_from_slice(&b);
        reordered[ranges[1].clone()].copy_from_slice(&a);
        assert!(unseal_portable(&reordered, "stream passphrase").is_err());

        let second_ranges = frame_ranges(&second);
        let mut swapped = first.clone();
        assert_eq!(ranges[1].len(), second_ranges[1].len());
        swapped[ranges[1].clone()].copy_from_slice(&second[second_ranges[1].clone()]);
        assert!(unseal_portable(&swapped, "stream passphrase").is_err());
    }

    #[test]
    fn portable_transcode_and_explicit_plaintext_export_are_streaming() {
        let source_bytes = portable_archive(b"portable contents", "source passphrase");
        let mut source = Cursor::new(source_bytes);
        let mut destination = Vec::new();
        let header = transcode_reader(
            &mut source,
            &mut destination,
            ArchiveCredential::Passphrase("source passphrase"),
            ArchiveSealKey::Passphrase("destination passphrase"),
        )
        .expect("transcode");
        assert_eq!(header.key_wrap.method_name(), "passphrase");
        assert_eq!(
            unseal_portable(&destination, "destination passphrase").expect("unseal destination"),
            b"portable contents"
        );
        assert!(PlaintextExportAcknowledgement::after_explicit_warning(false).is_none());
        assert!(PlaintextExportAcknowledgement::after_explicit_warning(true).is_some());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_user_round_trip_and_bad_blob_message() {
        let mut input = Cursor::new(b"windows account archive".to_vec());
        let mut archive = Vec::new();
        seal_reader(
            &mut input,
            &mut archive,
            provenance(),
            ArchiveSealKey::DpapiUser,
        )
        .expect("DPAPI seal");
        let mut output = Vec::new();
        unseal_reader(
            &mut Cursor::new(&archive),
            &mut output,
            ArchiveCredential::DpapiUser,
        )
        .expect("same-user DPAPI unseal");
        assert_eq!(output, b"windows account archive");

        assert!(matches!(
            dpapi_unprotect(b"not a DPAPI blob"),
            Err(ArchiveError::DpapiKeyUnavailable)
        ));
    }

    #[test]
    fn inventory_surfaces_legacy_plaintext_by_name_without_mutation() {
        let directory = tempfile::tempdir().expect("tempdir");
        let legacy = directory.path().join("gilbreth-archive-old.db");
        let unknown = directory.path().join("other.db");
        fs::write(&legacy, b"SQLite format 3\0legacy").expect("legacy archive");
        fs::write(&unknown, b"SQLite format 3\0unknown").expect("unknown db");
        let sealed = directory.path().join("gilbreth-archive-new.gla");
        seal_archive_file(
            &legacy,
            &sealed,
            provenance(),
            ArchiveSealKey::Passphrase("inventory passphrase"),
        )
        .expect("sealed archive");

        let inventory = inventory_archives(directory.path()).expect("inventory");
        assert_eq!(inventory.plaintext_legacy, vec![legacy.clone()]);
        assert_eq!(inventory.encrypted, vec![sealed]);
        assert_eq!(
            fs::read(legacy).expect("legacy unchanged"),
            b"SQLite format 3\0legacy"
        );
    }

    fn frame_ranges(archive: &[u8]) -> Vec<std::ops::Range<usize>> {
        let header_length = u32::from_le_bytes(
            archive[ARCHIVE_MAGIC.len() + 2..FIXED_PREFIX_LEN]
                .try_into()
                .expect("header length"),
        ) as usize;
        let mut offset = FIXED_PREFIX_LEN + header_length;
        let mut ranges = Vec::new();
        while offset < archive.len() {
            let length = u32::from_le_bytes(
                archive[offset..offset + 4]
                    .try_into()
                    .expect("frame length"),
            ) as usize;
            let start = offset + 4;
            let end = start + length;
            ranges.push(start..end);
            offset = end;
        }
        ranges
    }
}
