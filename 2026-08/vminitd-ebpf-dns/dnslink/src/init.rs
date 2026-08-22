//! Init / PID1 mode: the boot wrapper.
//!
//! Runs first at VM boot. We mount a cgroup2 view at an existing initfs
//! directory (cgroup2 is global, so the hierarchy object is shared with the
//! real vminitd's later /sys/fs/cgroup mount). We attach the three sockaddr
//! hooks to the ROOT cgroup; descendants (incl. the container cgroup the host
//! creates after boot) inherit them. Finally we exec the real init, replaying
//! the argv[1..] we were launched with.

use crate::bpf;
use crate::loader;

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
    passed_args: &Vec<String>,
) -> Result<(), String> {
    // 1. mount cgroup2 at the chosen initfs dir.
    let mut src = b"none".to_vec();
    let mut fst = b"cgroup2".to_vec();
    let mut mnt = cfg.cgroup_mount.clone().into_bytes();
    mnt.push(0);
    src.push(0);
    fst.push(0);
    match bpf::mount(src.as_ptr(), mnt.as_ptr(), fst.as_ptr(), 0, 0) {
        Ok(_) => println!("dnslink: mounted cgroup2 at {}", cfg.cgroup_mount),
        Err(e) => {
            // EEXIST(17)/EBUSY(16): already mounted by a parent. The hierarchy
            // is shared, so attach onto it regardless. Anything else: continue
            // unhooked rather than hang boot.
            if e != 17 && e != 16 {
                eprintln!("dnslink: cgroup2 mount {}: {}; continuing unhooked", cfg.cgroup_mount, bpf::err_str(e));
                return exec_real(cfg.real_init.as_str(), &passed_args);
            }
            eprintln!("dnslink: cgroup2 at {} already mounted (EEXIST/EBUSY); sharing", cfg.cgroup_mount);
        }
    }

    // 2. attach the three sockaddr hooks to the root cgroup view.
    let want_names: Vec<String> = loader::HOOKS.iter().map(|(sfx, _, _, _)| format!("cgroup/{}", sfx)).collect();
    let want_refs: Vec<&str> = want_names.iter().map(|s| s.as_str()).collect();
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    let cfile = match File::open(&cfg.cgroup_mount) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("dnslink: open {}: {}; continuing unhooked", cfg.cgroup_mount, e);
            return exec_real(&cfg.cgroup_mount, &passed_args);
        }
    };
    let dirfd = cfile.as_raw_fd() as i64;
    match loader::load_and_attach(obj, dirfd, rules, &want_refs, false) {
        Ok(loaded) => {
            println!("dnslink: attached {} cgroup hook(s) at {}",
                loaded.hooks.len(), cfg.cgroup_mount);
        }
        Err(e) => eprintln!("dnslink: hook attach failed: {}; continuing unhooked", e),
    }

    // 3. hand off to the real init.
    exec_real(&cfg.real_init, &passed_args)
}

/// Replay our argv[1..] onto the real init binary via execve (argv[0] is the
/// real init path; the remaining pointers are the args we were launched with,
/// minus our own argv[0]).
pub fn exec_real(path: &str, args: &Vec<String>) -> Result<(), String> {
    let mut bufs: Vec<Vec<u8>> = Vec::new();
    bufs.push(path.bytes().collect());
    for a in args.iter() {
        bufs.push(a.to_owned().into_bytes());
    }
    let mut argv_ptr: Vec<u64> = Vec::new();
    for b in bufs.iter() {
        argv_ptr.push(b.as_ptr() as u64);
    }
    argv_ptr.push(0u64); // NUL terminator
    let env_ptr: Vec<u64> = vec![0u64]; // NULL envp => inherit caller env
    match bpf::execve(path.as_ptr(), &argv_ptr, &env_ptr) {
        Ok(_) => Ok(()),     // unreachable on success
        Err(e) => Err(format!("exec {}: {}", path, bpf::err_str(e))),
    }
}