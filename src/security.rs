//! Hashing and Ed25519 signatures. All cryptography comes from audited
//! crates (`sha2`, `ed25519-dalek`); nothing is implemented by hand.
//!
//! Key files are plain text: one line of lowercase hex (32 bytes for both
//! public key and secret seed). Signature files hold 64 bytes as hex.

use crate::error::{Error, IoCtx, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

pub fn sha256_bytes(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = File::open(path).ctx("cannot open", path)?;
    sha256_reader(&mut f).ctx("cannot read", path)
}

pub fn sha256_reader(r: &mut impl Read) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// A `Read` adapter that hashes everything passing through it.
pub struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    pub bytes: u64,
}

impl<R: Read> HashingReader<R> {
    pub fn new(inner: R) -> Self {
        HashingReader { inner, hasher: Sha256::new(), bytes: 0 }
    }
    pub fn finish(self) -> (String, u64) {
        (hex::encode(self.hasher.finalize()), self.bytes)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

/// Compare a computed checksum against an expected one (constant-ish
/// behaviour is not needed: checksums are public values).
pub fn check_sha256(what: &str, expected: &str, actual: &str) -> Result<()> {
    if expected.eq_ignore_ascii_case(actual) {
        Ok(())
    } else {
        Err(Error::Verify(format!("checksum mismatch for {what}: expected {expected}, got {actual}")))
    }
}

pub fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ---------------------------------------------------------------- keys

fn decode_hex_key<const N: usize>(what: &str, text: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(text.trim()).map_err(|e| Error::Parse(format!("{what}: not valid hex ({e})")))?;
    bytes
        .try_into()
        .map_err(|_| Error::Parse(format!("{what}: expected {N} bytes of hex")))
}

pub struct PublicKey(VerifyingKey);

impl PublicKey {
    pub fn from_hex(text: &str) -> Result<Self> {
        let raw = decode_hex_key::<32>("public key", text)?;
        VerifyingKey::from_bytes(&raw)
            .map(PublicKey)
            .map_err(|e| Error::Parse(format!("public key is invalid: {e}")))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).ctx("cannot read public key", path)?;
        Self::from_hex(&text).map_err(|e| Error::Config(format!("key {}: {e}", path.display())))
    }

    /// Verify a detached hex signature over `msg`.
    pub fn verify(&self, what: &str, msg: &[u8], sig_hex: &str) -> Result<()> {
        let raw = decode_hex_key::<64>("signature", sig_hex)
            .map_err(|e| Error::Verify(format!("bad signature file for {what}: {e}")))?;
        let sig = Signature::from_bytes(&raw);
        self.0
            .verify_strict(msg, &sig)
            .map_err(|_| Error::Verify(format!("signature of {what} is not valid for the configured repository key")))
    }
}

pub struct SecretKey(SigningKey);

impl SecretKey {
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut seed))
            .map_err(|e| Error::io("cannot read /dev/urandom", e))?;
        Ok(SecretKey(SigningKey::from_bytes(&seed)))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).ctx("cannot read secret key", path)?;
        let raw = decode_hex_key::<32>("secret key", &text)?;
        Ok(SecretKey(SigningKey::from_bytes(&raw)))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.0.verifying_key().to_bytes())
    }

    pub fn sign_hex(&self, msg: &[u8]) -> String {
        hex::encode(self.0.sign(msg).to_bytes())
    }

    /// Write `<name>.key` (mode 0600) and `<name>.pub` into `dir`.
    pub fn write_pair(&self, dir: &Path, name: &str) -> Result<()> {
        std::fs::create_dir_all(dir).ctx("cannot create", dir)?;
        let sec = dir.join(format!("{name}.key"));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&sec).ctx("cannot create", &sec)?;
        writeln!(f, "{}", self.to_hex()).ctx("cannot write", &sec)?;
        let public = dir.join(format!("{name}.pub"));
        std::fs::write(&public, format!("{}\n", self.public_hex())).ctx("cannot write", &public)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = SecretKey::generate().unwrap();
        let pk = PublicKey::from_hex(&sk.public_hex()).unwrap();
        let sig = sk.sign_hex(b"hello");
        pk.verify("test", b"hello", &sig).unwrap();
        assert!(pk.verify("test", b"hellO", &sig).is_err());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        let pk_b = PublicKey::from_hex(&b.public_hex()).unwrap();
        assert!(pk_b.verify("x", b"data", &a.sign_hex(b"data")).is_err());
    }

    #[test]
    fn garbage_signature_is_rejected() {
        let sk = SecretKey::generate().unwrap();
        let pk = PublicKey::from_hex(&sk.public_hex()).unwrap();
        assert!(pk.verify("x", b"d", "zz").is_err());
        assert!(pk.verify("x", b"d", "00").is_err());
    }

    #[test]
    fn checksum_check() {
        let h = sha256_bytes(b"abc");
        assert!(check_sha256("f", &h, &h).is_ok());
        assert!(check_sha256("f", &h, &sha256_bytes(b"abd")).is_err());
    }
}
