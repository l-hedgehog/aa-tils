//! Init / PID1 mode: the boot wrapper.
//!
//! Runs first at VM boot. We mount a cgroup2 view at an existing initfs
//! directory (cgroup2 is global, so the hierarchy object is shared with the
//! real vminitd's later /sys/fs/cgroup mount). We attach the three sockaddr
//! hooks to the ROOT cgroup; descendants (incl. the container cgroup the host
//! creates after boot) inherit them. Finally we exec the real init, replaying
//! the argv[1..] we were launched with.

use std::io::{self, ErrorKind};

use crate::loader;
use crate::sys;

pub struct Ctx {
    pub real_init: String,    // path to the real init, e.g. /sbin/vminitd.real
    pub cgroup_mount: String, // existing initfs dir to mount cgroup2 at, e.g. /mnt
}

/// Run the boot wrapper: mount cgroup2, attach hooks, exec real init.
/// Returns on failure (caller may fall back to a bare exec).
pub fn run(
    cfg: &Ctx,
    rules: &Vec<(u32, loader::Rule)>,
    obj: &[u8],
    passed_args: &[String],
) -> io::Result<()> {
    // 1. mount cgroup2 at the chosen initfs dir.
    match sys::mount("none", &cfg.cgroup_mount, "cgroup2", 0) {
        Ok(_) => println!("dnslink: mounted cgroup2 at {}", cfg.cgroup_mount),
        // EEXIST(17)/EBUSY(16): already mounted by a parent. The hierarchy
        // is shared, so attach onto it regardless. Anything else: continue
        // unhooked rather than hang boot.
        Err(e) if e.kind() == ErrorKind::AlreadyExists || e.kind() == ErrorKind::ResourceBusy => {
            eprintln!("dnslink: cgroup2 at {} already mounted (EEXIST/EBUSY); sharing", cfg.cgroup_mount);
        }
        Err(e) => {
            eprintln!("dnslink: cgroup2 mount {}: {}; continuing unhooked", cfg.cgroup_mount, e);
            return exec_real(cfg.real_init.as_str(), passed_args);
        }
    }

    // 2. attach the three sockaddr hooks to the root cgroup view.
    let want_names: Vec<String> = loader::HOOKS.iter().map(|(sfx, _, _, _)| format!("cgroup/{}", sfx)).collect();
    let want_refs: Vec<&str> = want_names.iter().map(|s| s.as_str()).collect();
    use std::fs::File;

    let cgroup_dir = match File::open(&cfg.cgroup_mount) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("dnslink: open {}: {}; continuing unhooked", cfg.cgroup_mount, e);
            return exec_real(cfg.real_init.as_str(), passed_args);
        }
    };
    match loader::load_and_attach(obj, &cgroup_dir, rules, &want_refs, false) {
        Ok(loaded) => {
            println!("dnslink: attached {} cgroup hook(s) at {}",
                loaded.hooks.len(), cfg.cgroup_mount);
        }
        Err(e) => eprintln!("dnslink: hook attach failed: {}; continuing unhooked", e),
    }

    // 3. hand off to the real init.
    exec_real(&cfg.real_init, passed_args)
}

/// Replay our argv[1..] onto the real init binary via execve (argv[0] is the
/// real init path; the remaining pointers are the args we were launched with,
/// minus our own argv[0]).
pub fn exec_real(path: &str, args: &[String]) -> io::Result<()> {
    let mut argv: Vec<&str> = vec![path];
    argv.extend(args.iter().map(|s| s.as_str()));
    // Keep the path in the error so the caller's fallback message names the
    // binary (io::Error keeps the errno kind).
    sys::execve(path, &argv, &[])
        .map_err(|e| io::Error::new(e.kind(), format!("exec {}: {}", path, e)))
}
