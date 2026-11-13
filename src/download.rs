//! Fetching bytes from `file://`, plain paths or `http(s)://`.
//!
//! Downloads go to `<dest>.part`, are size- and hash-checked, and are renamed
//! into place only when complete and correct, so an interrupted or corrupted
//! download never leaves a file that looks valid.

use crate::error::{Error, IoCtx, Result};
use crate::security::HashingReader;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn join_url(base: &str, rel: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), rel.trim_start_matches('/'))
}

enum Location {
    Local(PathBuf),
    Http(String),
}

fn locate(url: &str) -> Result<Location> {
    if let Some(p) = url.strip_prefix("file://") {
        Ok(Location::Local(PathBuf::from(p)))
    } else if url.starts_with("http://") || url.starts_with("https://") {
        Ok(Location::Http(url.to_string()))
    } else if url.starts_with('/') {
        Ok(Location::Local(PathBuf::from(url)))
    } else {
        Err(Error::Config(format!("unsupported URL {url:?} (use https://, http://, file:// or an absolute path)")))
    }
}

fn open(url: &str) -> Result<(Box<dyn Read>, Option<u64>)> {
    match locate(url)? {
        Location::Local(p) => {
            let f = File::open(&p).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Error::NotFound(format!("{} does not exist", p.display()))
                } else {
                    Error::io(format!("cannot open {}", p.display()), e)
                }
            })?;
            let len = f.metadata().ok().map(|m| m.len());
            Ok((Box::new(f), len))
        }
        Location::Http(u) => {
            let agent = ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(15))
                .timeout_read(Duration::from_secs(30))
                .user_agent("ast-pm")
                .build();
            let resp = agent.get(&u).call().map_err(|e| match e {
                ureq::Error::Status(404, _) => Error::NotFound(format!("{u}: HTTP 404 not found")),
                ureq::Error::Status(c, _) => Error::Network(format!("{u}: HTTP status {c}")),
                other => Error::Network(format!("{u}: {other}")),
            })?;
            let len = resp.header("Content-Length").and_then(|v| v.parse().ok());
            Ok((Box::new(resp.into_reader()), len))
        }
    }
}

/// Fetch a small resource fully into memory, refusing more than `max` bytes.
pub fn fetch_bytes(url: &str, max: u64) -> Result<Vec<u8>> {
    let (r, len) = open(url)?;
    if len.is_some_and(|l| l > max) {
        return Err(Error::Verify(format!("{url}: larger than the allowed {max} bytes")));
    }
    let mut buf = Vec::new();
    r.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| Error::Network(format!("{url}: read failed: {e}")))?;
    if buf.len() as u64 > max {
        return Err(Error::Verify(format!("{url}: larger than the allowed {max} bytes")));
    }
    Ok(buf)
}

/// Download `url` to `dest`, at most `max` bytes. When `expected_sha256` is
/// given it must match, otherwise the partial file is deleted and a `Verify`
/// error is returned. On success `dest` is complete and verified.
pub fn download_to(url: &str, dest: &Path, expected_sha256: Option<&str>, max: u64) -> Result<()> {
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir).ctx("cannot create", dir)?;
    }
    let part = PathBuf::from(format!("{}.part", dest.display()));
    let _ = std::fs::remove_file(&part); // stale partial download
    let (r, _) = open(url)?;
    let mut hr = HashingReader::new(r.take(max.saturating_add(1)));
    let res: Result<()> = (|| {
        let mut f = File::create(&part).ctx("cannot create", &part)?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = hr.read(&mut buf).map_err(|e| Error::Network(format!("{url}: download interrupted: {e}")))?;
            if n == 0 {
                break;
            }
            f.write_all(&buf[..n]).ctx("cannot write", &part)?;
        }
        f.sync_all().ctx("cannot sync", &part)?;
        Ok(())
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    let (hash, bytes) = hr.finish();
    let check = (|| {
        if bytes > max {
            return Err(Error::Verify(format!("{url}: larger than the allowed {max} bytes")));
        }
        if let Some(h) = expected_sha256 {
            crate::security::check_sha256(url, h, &hash)?;
        }
        Ok(())
    })();
    if let Err(e) = check {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    std::fs::rename(&part, dest).ctx("cannot move download into place", dest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::sha256_bytes;

    #[test]
    fn download_verifies_and_cleans_up() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src.bin");
        std::fs::write(&src, b"payload bytes").unwrap();
        let url = format!("file://{}", src.display());
        let dest = d.path().join("out/dest.bin");
        download_to(&url, &dest, Some(&sha256_bytes(b"payload bytes")), 1 << 20).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"payload bytes");

        let bad = d.path().join("out/bad.bin");
        let e = download_to(&url, &bad, Some(&sha256_bytes(b"other")), 1 << 20).unwrap_err();
        assert!(matches!(e, Error::Verify(_)));
        assert!(!bad.exists());
        assert!(!PathBuf::from(format!("{}.part", bad.display())).exists());

        let e = download_to(&url, &bad, None, 5).unwrap_err();
        assert!(matches!(e, Error::Verify(_)));
        assert!(!bad.exists());
    }

    #[test]
    fn missing_and_unsupported() {
        let d = tempfile::tempdir().unwrap();
        let e = download_to("file:///nonexistent/zzz", &d.path().join("x"), None, 10).unwrap_err();
        assert!(matches!(e, Error::NotFound(_)));
        assert!(matches!(fetch_bytes("ftp://x/y", 10), Err(Error::Config(_))));
    }

    #[test]
    fn fetch_respects_limit() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, vec![1u8; 100]).unwrap();
        assert!(fetch_bytes(&format!("file://{}", p.display()), 50).is_err());
        assert_eq!(fetch_bytes(&format!("file://{}", p.display()), 100).unwrap().len(), 100);
    }

    #[test]
    fn url_join() {
        assert_eq!(join_url("http://a/b/", "/c.ast"), "http://a/b/c.ast");
    }
}
