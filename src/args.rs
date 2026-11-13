//! Tiny argument parser: `--flag`, `--opt VALUE` / `--opt=VALUE` anywhere on
//! the line, everything else is an operand. No dependencies, no magic.

use crate::error::{Error, Result};

pub struct Args(Vec<String>);

impl Args {
    pub fn from_env() -> Args {
        Args::new(std::env::args().skip(1))
    }

    /// `-ay` is the same as `-a -y`.
    pub fn new<I: IntoIterator<Item = String>>(items: I) -> Args {
        let split = |a: String| match a.strip_prefix('-') {
            Some(c) if c.len() > 1 && c.chars().all(|x| x.is_ascii_alphabetic()) => c.chars().map(|x| format!("-{x}")).collect(),
            _ => vec![a],
        };
        Args(items.into_iter().flat_map(split).collect())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Take a boolean flag out of the line; true if it was there.
    pub fn flag(&mut self, names: &[&str]) -> bool {
        let before = self.0.len();
        self.0.retain(|a| !names.contains(&a.as_str()));
        self.0.len() != before
    }

    /// Take `--opt VALUE` or `--opt=VALUE` out of the line (the last one wins).
    pub fn value(&mut self, names: &[&str]) -> Result<Option<String>> {
        let mut found = None;
        let mut i = 0;
        while i < self.0.len() {
            let a = self.0[i].clone();
            if names.contains(&a.as_str()) {
                if i + 1 >= self.0.len() {
                    return Err(Error::Usage(format!("{a} needs a value")));
                }
                found = Some(self.0.remove(i + 1));
                self.0.remove(i);
            } else if let Some(v) = names.iter().find_map(|n| a.strip_prefix(&format!("{n}="))) {
                found = Some(v.to_string());
                self.0.remove(i);
            } else {
                i += 1;
            }
        }
        Ok(found)
    }

    /// Like `value`, but the option is mandatory.
    pub fn need(&mut self, names: &[&str]) -> Result<String> {
        self.value(names)?.ok_or_else(|| Error::Usage(format!("{} is required", names[names.len() - 1])))
    }

    /// The first operand (the command word).
    pub fn command(&mut self) -> Option<String> {
        let i = self.0.iter().position(|a| !a.starts_with('-'))?;
        Some(self.0.remove(i))
    }

    /// The remaining operands; a leftover `-x` option is a usage error.
    pub fn operands(self) -> Result<Vec<String>> {
        match self.0.iter().find(|a| a.starts_with('-') && a.len() > 1) {
            Some(o) => Err(Error::Usage(format!("unknown option {o}"))),
            None => Ok(self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Args {
        Args::new(s.split_whitespace().map(String::from))
    }

    #[test]
    fn flags_and_values_anywhere() {
        let mut a = args("install -y hello --root /tmp/x --jobs=3 world");
        assert!(a.flag(&["-y", "--yes"]));
        assert!(!a.flag(&["--dry-run"]));
        assert_eq!(a.value(&["--root"]).unwrap().as_deref(), Some("/tmp/x"));
        assert_eq!(a.value(&["-j", "--jobs"]).unwrap().as_deref(), Some("3"));
        assert_eq!(a.command().as_deref(), Some("install"));
        assert_eq!(a.operands().unwrap(), vec!["hello", "world"]);
    }

    #[test]
    fn short_flags_can_be_joined() {
        let mut a = args("update -ay");
        assert!(a.flag(&["-a"]) && a.flag(&["-y"]));
        assert_eq!(a.command().as_deref(), Some("update"));
    }

    #[test]
    fn errors_are_usage_errors() {
        assert!(matches!(args("--root").value(&["--root"]), Err(Error::Usage(_))));
        assert!(matches!(args("install --bogus").operands(), Err(Error::Usage(_))));
        assert!(matches!(args("x").need(&["--out"]), Err(Error::Usage(_))));
        let mut a = args("-y");
        a.flag(&["-y"]);
        assert!(a.command().is_none());
    }
}
