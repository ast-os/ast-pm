//! Version comparison and dependency constraints.
//!
//! Version strings are split into numeric and alphabetic runs. Numeric runs
//! compare as numbers; a numeric run is newer than an alphabetic one; an
//! alphabetic suffix makes a version older than the same version without it
//! (`1.0rc1 < 1.0`), while extra numeric components make it newer
//! (`1.0.1 > 1.0`). `~` sorts before everything (`1.0~beta < 1.0`).

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

/// A validated package name: `[a-z0-9][a-z0-9+._-]*`. Cannot contain path
/// separators, so it is safe to use as a file name in the database.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PackageName(String);

impl PackageName {
    pub fn new(s: &str) -> Result<Self> {
        let ok = !s.is_empty()
            && s.len() <= 128
            && s.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+._-".contains(c));
        if ok {
            Ok(PackageName(s.to_string()))
        } else {
            Err(Error::Parse(format!(
                "invalid package name {s:?} (allowed: lowercase letters, digits, '+', '.', '_', '-')"
            )))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for PackageName {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        PackageName::new(&s)
    }
}
impl From<PackageName> for String {
    fn from(n: PackageName) -> String {
        n.0
    }
}
impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Version(String);

impl Version {
    pub fn new(s: &str) -> Result<Self> {
        let ok = !s.is_empty()
            && s.len() <= 64
            && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            && s.chars().all(|c| c.is_ascii_alphanumeric() || ".+_~".contains(c));
        if ok {
            Ok(Version(s.to_string()))
        } else {
            Err(Error::Parse(format!("invalid version {s:?} (allowed: letters, digits, '.', '+', '_', '~')")))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for Version {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Version::new(&s)
    }
}
impl From<Version> for String {
    fn from(v: Version) -> String {
        v.0
    }
}
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_versions(&self.0, &other.0)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Tok {
    Tilde,
    Num(String),
    Alpha(String),
}

fn tokenize(s: &str) -> Vec<Tok> {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if c == '~' {
            out.push(Tok::Tilde);
            i += 1;
        } else if c.is_ascii_digit() {
            let st = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let t: String = b[st..i].iter().collect();
            out.push(Tok::Num(t.trim_start_matches('0').to_string()));
        } else if c.is_ascii_alphabetic() {
            let st = i;
            while i < b.len() && b[i].is_ascii_alphabetic() {
                i += 1;
            }
            out.push(Tok::Alpha(b[st..i].iter().collect()));
        } else {
            i += 1; // separators: . _ +
        }
    }
    out
}

pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let (ta, tb) = (tokenize(a), tokenize(b));
    let mut i = 0;
    loop {
        match (ta.get(i), tb.get(i)) {
            (None, None) => return Ordering::Equal,
            (Some(Tok::Tilde), Some(Tok::Tilde)) => {}
            (Some(Tok::Tilde), _) => return Ordering::Less,
            (_, Some(Tok::Tilde)) => return Ordering::Greater,
            // One side ended: alpha suffix = older, numeric continuation = newer.
            (None, Some(Tok::Alpha(_))) => return Ordering::Greater,
            (None, Some(Tok::Num(_))) => return Ordering::Less,
            (Some(Tok::Alpha(_)), None) => return Ordering::Less,
            (Some(Tok::Num(_)), None) => return Ordering::Greater,
            (Some(Tok::Num(x)), Some(Tok::Num(y))) => {
                let o = x.len().cmp(&y.len()).then_with(|| x.cmp(y));
                if o != Ordering::Equal {
                    return o;
                }
            }
            (Some(Tok::Alpha(x)), Some(Tok::Alpha(y))) => {
                let o = x.cmp(y);
                if o != Ordering::Equal {
                    return o;
                }
            }
            (Some(Tok::Num(_)), Some(Tok::Alpha(_))) => return Ordering::Greater,
            (Some(Tok::Alpha(_)), Some(Tok::Num(_))) => return Ordering::Less,
        }
        i += 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Ge => ">=",
            Op::Gt => ">",
            Op::Le => "<=",
            Op::Lt => "<",
        }
    }
}

/// `name`, `name >= 1.0`, `name = 2.1`, ...
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Dependency {
    pub name: PackageName,
    pub constraint: Option<(Op, Version)>,
}

impl Dependency {
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        match parts.as_slice() {
            [n] => Ok(Dependency { name: PackageName::new(n)?, constraint: None }),
            [n, op, v] => {
                let op = match *op {
                    "=" | "==" => Op::Eq,
                    ">=" => Op::Ge,
                    ">" => Op::Gt,
                    "<=" => Op::Le,
                    "<" => Op::Lt,
                    o => return Err(Error::Parse(format!("unknown operator {o:?} in dependency {s:?}"))),
                };
                Ok(Dependency { name: PackageName::new(n)?, constraint: Some((op, Version::new(v)?)) })
            }
            _ => Err(Error::Parse(format!("invalid dependency {s:?} (expected `name` or `name >= 1.0`)"))),
        }
    }

    pub fn matches(&self, name: &PackageName, version: &Version) -> bool {
        if &self.name != name {
            return false;
        }
        match &self.constraint {
            None => true,
            Some((op, v)) => {
                let o = version.cmp(v);
                match op {
                    Op::Eq => o == Ordering::Equal,
                    Op::Ge => o != Ordering::Less,
                    Op::Gt => o == Ordering::Greater,
                    Op::Le => o != Ordering::Greater,
                    Op::Lt => o == Ordering::Less,
                }
            }
        }
    }
}

impl TryFrom<String> for Dependency {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Dependency::parse(&s)
    }
}
impl From<Dependency> for String {
    fn from(d: Dependency) -> String {
        d.to_string()
    }
}
impl fmt::Display for Dependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.constraint {
            None => write!(f, "{}", self.name),
            Some((op, v)) => write!(f, "{} {} {}", self.name, op.as_str(), v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        compare_versions(a, b)
    }

    #[test]
    fn numeric_ordering() {
        assert_eq!(cmp("1.2", "1.10"), Ordering::Less);
        assert_eq!(cmp("1.28.0", "1.28.0"), Ordering::Equal);
        assert_eq!(cmp("10.46", "10.9"), Ordering::Greater);
        assert_eq!(cmp("1.0.1", "1.0"), Ordering::Greater);
        assert_eq!(cmp("1.01", "1.1"), Ordering::Equal);
    }

    #[test]
    fn prerelease_and_tilde() {
        assert_eq!(cmp("1.0rc1", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0~beta", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0a", "1.0b"), Ordering::Less);
        assert_eq!(cmp("1.0", "1.0a"), Ordering::Greater);
        assert_eq!(cmp("2", "1a"), Ordering::Greater);
    }

    #[test]
    fn dependency_parse_and_match() {
        let d = Dependency::parse("zlib >= 1.3").unwrap();
        let n = PackageName::new("zlib").unwrap();
        assert!(d.matches(&n, &Version::new("1.3.1").unwrap()));
        assert!(d.matches(&n, &Version::new("1.3").unwrap()));
        assert!(!d.matches(&n, &Version::new("1.2.13").unwrap()));
        let e = Dependency::parse("zlib = 1.3.1").unwrap();
        assert!(e.matches(&n, &Version::new("1.3.1").unwrap()));
        assert!(!e.matches(&n, &Version::new("1.3.2").unwrap()));
        let l = Dependency::parse("zlib < 2").unwrap();
        assert!(l.matches(&n, &Version::new("1.9").unwrap()));
        assert!(!l.matches(&n, &Version::new("2").unwrap()));
        assert_eq!(d.to_string(), "zlib >= 1.3");
        assert!(Dependency::parse("zlib >=").is_err());
        assert!(Dependency::parse("zlib ?? 1").is_err());
    }

    #[test]
    fn names_are_validated() {
        assert!(PackageName::new("nginx").is_ok());
        assert!(PackageName::new("libstdc++").is_ok());
        assert!(PackageName::new("../etc").is_err());
        assert!(PackageName::new("Nginx").is_err());
        assert!(PackageName::new("").is_err());
        assert!(PackageName::new("a/b").is_err());
    }
}
