//! `astfstab`: print the fstab lines for what is mounted at and below a directory.

use crate::error::{Error, IoCtx, Result};
use std::path::{Path, PathBuf};

pub const HELP: &str = "astfstab ROOT

print fstab lines for the filesystems mounted at and below ROOT, by UUID
usage: astfstab /mnt >> /mnt/etc/fstab";

struct Mount {
    point: String,
    fstype: String,
    source: String,
    options: String,
}

/// `/proc/self/mountinfo` text -> the real (block device) mounts under `root`, shortest path first.
fn mounts(info: &str, root: &str) -> Vec<Mount> {
    let unescape = |s: &str| {
        let mut out = String::new();
        let mut it = s.chars().peekable();
        while let Some(c) = it.next() {
            let code: String = if c == '\\' { it.clone().take(3).collect() } else { String::new() };
            match u8::from_str_radix(&code, 8) {
                Ok(b) if code.len() == 3 => {
                    out.push(b as char);
                    it.nth(2);
                }
                _ => out.push(c),
            }
        }
        out
    };
    let mut v: Vec<Mount> = info
        .lines()
        .filter_map(|l| {
            let (pre, post) = l.split_once(" - ")?;
            let f: Vec<&str> = pre.split(' ').collect();
            let g: Vec<&str> = post.split(' ').collect();
            let (point, opts, fstype, source, sup) = (unescape(f.get(4)?), *f.get(5)?, *g.first()?, *g.get(1)?, g.get(2).copied().unwrap_or(""));
            let inside = point == root || point.starts_with(&format!("{}/", root.trim_end_matches('/')));
            if !inside || !source.starts_with("/dev/") {
                return None;
            }
            let mut options: Vec<String> = opts.split(',').map(String::from).collect();
            if fstype == "btrfs" {
                options.extend(sup.split(',').filter(|o| o.starts_with("subvol=")).map(String::from));
            }
            Some(Mount { point, fstype: fstype.into(), source: source.into(), options: options.join(",") })
        })
        .collect();
    v.sort_by_key(|m| m.point.len());
    v
}

/// The UUID of a device node, from udev's `/dev/disk/by-uuid` links.
fn uuid_of(dev: &str) -> Option<String> {
    let want = Path::new(dev).canonicalize().ok()?;
    std::fs::read_dir("/dev/disk/by-uuid").ok()?.flatten().find_map(|e| {
        (e.path().canonicalize().ok()? == want).then(|| e.file_name().to_string_lossy().into_owned())
    })
}

fn lines(ms: &[Mount], root: &str, uuid: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let mut out = vec![];
    for m in ms {
        let rel = m.point.strip_prefix(root.trim_end_matches('/')).unwrap_or(&m.point);
        let at = if rel.is_empty() { "/" } else { rel };
        // the kernel mounts the root subvolume (rootflags); a fstab subvol= would only get in the way
        let options = if at == "/" && m.fstype == "btrfs" {
            m.options.split(',').filter(|o| !o.starts_with("subvol=")).collect::<Vec<_>>().join(",")
        } else {
            m.options.clone()
        };
        let id = uuid(&m.source).map(|u| format!("UUID={u}")).unwrap_or_else(|| m.source.clone());
        let pass = match (m.fstype.as_str(), at) {
            ("btrfs", _) => "0",
            (_, "/") => "1",
            _ => "2",
        };
        out.push(format!("# {}", m.source));
        out.push(format!("{id}  {at}  {}  {options}  0  {pass}", m.fstype));
        out.push(String::new());
    }
    out
}

pub fn run(args: Vec<String>) -> Result<i32> {
    let [root] = args.as_slice() else {
        return Err(Error::Usage("astfstab needs one directory".into()));
    };
    let root: PathBuf = Path::new(root).canonicalize().ctx("cannot open", Path::new(root))?;
    let root = root.to_string_lossy().into_owned();
    let info = std::fs::read_to_string("/proc/self/mountinfo").ctx("cannot read", Path::new("/proc/self/mountinfo"))?;
    let ms = mounts(&info, &root);
    if ms.is_empty() {
        return Err(Error::Other(format!("nothing is mounted at {root}")));
    }
    for l in lines(&ms, &root, &uuid_of) {
        println!("{l}");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &str = "\
22 1 0:21 / /proc rw,nosuid - proc proc rw
30 1 8:2 /@ /mnt rw,relatime shared:1 - btrfs /dev/vda2 rw,ssd,subvolid=256,subvol=/@
31 30 8:1 / /mnt/boot rw,relatime - vfat /dev/vda1 rw,fmask=0022
32 30 8:2 /@home /mnt/home rw,relatime - btrfs /dev/vda2 rw,subvolid=257,subvol=/@home
33 30 0:40 / /mnt/dev rw - devtmpfs devtmpfs rw
34 1 8:3 / /mnt2 rw - ext4 /dev/vda3 rw";

    #[test]
    fn only_block_devices_below_the_root() {
        let ms = mounts(INFO, "/mnt");
        let l = lines(&ms, "/mnt", &|d| (d == "/dev/vda1").then(|| "ABCD-1234".to_string()));
        assert_eq!(l[..3], ["# /dev/vda2", "/dev/vda2  /  btrfs  rw,relatime  0  0", ""]);
        assert!(l.contains(&"UUID=ABCD-1234  /boot  vfat  rw,relatime  0  2".to_string()));
        assert!(l.contains(&"/dev/vda2  /home  btrfs  rw,relatime,subvol=/@home  0  0".to_string()));
        assert!(!l.iter().any(|x| x.contains("devtmpfs") || x.contains("vda3")));
    }
}
