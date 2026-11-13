//! `NAME[:REPO][@VERSION]`: the package argument of `ast -i`.

use crate::error::{Error, Result};
use crate::version::{Op, Version};

/// `NAME[:REPO][@VERSION]`: package, optional repository, optional version.
/// `@*` (or no `@`) means the latest version; `@1.2.3` an exact version;
/// `@>=1.2`, `@<2` etc. a constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSpec {
    pub name: String,
    pub repo: Option<String>,
    pub version: Option<(Op, Version)>,
}

pub fn parse_spec(t: &str) -> Result<TargetSpec> {
    let bad = |why: &str| Error::Other(format!("invalid package spec {t:?}: {why} (expected NAME[:REPO][@VERSION])"));
    let (head, ver) = match t.split_once('@') {
        Some((h, v)) => (h, Some(v)),
        None => (t, None),
    };
    let (name, repo) = match head.split_once(':') {
        Some((n, r)) => (n, Some(r)),
        None => (head, None),
    };
    if name.is_empty() {
        return Err(bad("empty package name"));
    }
    if let Some(r) = repo
        && (r.is_empty() || !r.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')) {
            return Err(bad("invalid repository name"));
        }
    let version = match ver {
        None | Some("*") | Some("latest") => None,
        Some("") => return Err(bad("empty version after '@'")),
        Some(v) => {
            let (op, rest) = [(">=", Op::Ge), ("<=", Op::Le), ("==", Op::Eq), ("=", Op::Eq), (">", Op::Gt), ("<", Op::Lt)]
                .iter()
                .find_map(|(p, op)| v.strip_prefix(p).map(|r| (*op, r)))
                .unwrap_or((Op::Eq, v));
            Some((op, Version::new(rest)?))
        }
    };
    Ok(TargetSpec { name: name.to_string(), repo: repo.map(String::from), version })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::Op;

    #[test]
    fn target_spec_syntax() {
        let s = parse_spec("toolbox:extra-edge@*").unwrap();
        assert_eq!((s.name.as_str(), s.repo.as_deref(), s.version.clone()), ("toolbox", Some("extra-edge"), None));
        assert_eq!(parse_spec("nginx").unwrap(), TargetSpec { name: "nginx".into(), repo: None, version: None });
        assert_eq!(parse_spec("nginx:extra").unwrap().repo.as_deref(), Some("extra"));
        assert_eq!(parse_spec("nginx@latest").unwrap().version, None);
        let v = parse_spec("nginx:ast@1.28.0").unwrap().version.unwrap();
        assert_eq!((v.0, v.1.as_str()), (Op::Eq, "1.28.0"));
        let v = parse_spec("nginx@>=1.2").unwrap().version.unwrap();
        assert_eq!((v.0, v.1.as_str()), (Op::Ge, "1.2"));
        assert_eq!(parse_spec("nginx-bin:extra-edge@*").unwrap().name, "nginx-bin");
        for bad in ["", ":repo", "nginx:", "nginx@", "nginx:Bad Repo", "nginx@1/2", "nginx:a:b"] {
            assert!(parse_spec(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
