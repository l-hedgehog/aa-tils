//! dnslink — static eBPF DNS-redirect init/loader.
//!
//! Modes:
//!   attach  — loader mode: attach hooks to a cgroup dir (--cgroup), optional
//!             counter watch.
//!   init    — PID1 boot wrapper: mount cgroup2, attach hooks to the root
//!             cgroup, exec the real init replaying our argv (minus argv[0]).
//!
//! Embeds dns_sockaddr.bpf.o (variant chosen at build: plain `make` =
//! legacy bpf_map_def, `make BTF=1` = BTF-defined maps; overridable at
//! runtime with --obj) and defaults to the rule
//! 127.0.8.6:53 -> 1.1.1.1:53, overridable via --bind-* / --target-*.

use std::fs;
use std::io::{self, ErrorKind};
use std::net::{AddrParseError, Ipv4Addr};
use std::path::{Path, PathBuf};

use aya::maps::{MapData, PerCpuArray};
use procfs::process::Process;

mod init;
mod loader;
mod sys;

/// The embedded BPF object — which variant the bytes are depends on the
/// build (see the module doc + ebpf/Makefile).
const EMBEDDED_OBJ: &[u8] = aya::include_bytes_aligned!("../dns_sockaddr.bpf.o");
const NAMESERVER_PORT: u16 = 53;

fn aton(s: &str) -> Result<u32, AddrParseError> {
    s.parse::<Ipv4Addr>().map(|addr| addr.to_bits())
}

/// Mount procfs at /proc (idempotent; real vminitd does this itself later,
/// but our PID1 wrapper runs before it and needs /proc/cmdline).
fn mount_procfs() {
    let _ = sys::mount("proc", "/proc", "proc", 0);
}

fn is_fs_mounted_at<P: AsRef<Path>>(
    expected_fs: &str,
    target_path: P,
) -> Result<bool, procfs::ProcError> {
    let self_process = Process::myself()?;
    let mount_infos = self_process.mountinfo()?;

    let is_mounted = mount_infos.iter().any(|mount| {
        mount.mount_point.as_path() == target_path.as_ref() && mount.fs_type == expected_fs
    });

    Ok(is_mounted)
}

fn ensure_pin_path(parent: &Path, verbose: bool) -> io::Result<PathBuf> {
    let pin_path = parent.join("dns_sockaddr");
    // Single-level create: the mountpoint is guaranteed here; mode = 0777 &
    // ~umask (0755 at init's default). EEXIST is a normal re-run.
    match fs::create_dir(&pin_path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            if verbose {
                eprintln!("mkdir {}: path already exists", pin_path.display())
            }
        }
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("mkdir {}: {}", pin_path.display(), e),
            ))
        }
    }
    Ok(pin_path)
}

/// Mount bpffs at `target` (idempotent) and create the dns_sockaddr pin
/// directory. Pins live here so the hook links and maps survive
/// process exit and exec of the real init. Non-fatal path — the
/// caller logs and continues; on mount failure pins just won't happen.
fn ensure_bpffs<P: AsRef<Path>>(target: P, verbose: bool) -> io::Result<PathBuf> {
    let bpffs_path = target.as_ref();
    match is_fs_mounted_at("bpf", bpffs_path) {
        Ok(is_mounted) => {
            if is_mounted {
                eprintln!("dnslink: bpffs already mounted at {}", bpffs_path.display());
                return ensure_pin_path(bpffs_path, verbose);
            } else if verbose {
                // Expected pre-state at boot; the mount below follows.
                eprintln!("bpffs not mounted at {}", bpffs_path.display());
            }
        }
        Err(e) => eprintln!(
            "dnslink: bpffs state unknown at {}: {}; attempting mount",
            bpffs_path.display(),
            e
        ),
    }
    // Mountpoint must exist first (create_dir_all tolerates a custom
    // --mount-base whose parents may be missing).
    fs::create_dir_all(bpffs_path)?;
    match sys::mount("bpffs", bpffs_path.to_str().unwrap(), "bpf", 0) {
        Ok(()) => println!("dnslink: mounted bpffs at {}", bpffs_path.display()),
        // EBUSY/EEXIST: bpffs is a single global instance, already mounted.
        Err(e) if e.kind() == ErrorKind::AlreadyExists || e.kind() == ErrorKind::ResourceBusy => {
            eprintln!(
                "dnslink: bpffs already mounted at {}; sharing",
                bpffs_path.display()
            );
        }
        Err(e) => eprintln!(
            "dnslink: mount -t bpf bpffs {}: {}; pins will fail: DNS redirect will not be in effect",
            bpffs_path.display(),
            e
        ),
    }
    ensure_pin_path(bpffs_path, verbose)
}

/// Parse /proc/cmdline for `dnslink.gateway=<ip>`; returns the IP if present.
fn gateway_from_cmdline() -> Option<String> {
    cmdline_value("dnslink.gateway")
}

/// Parse /proc/cmdline for `dnslink.port=<n>`; returns the port if present.
fn port_from_cmdline() -> Option<u16> {
    cmdline_value("dnslink.port").map(|s| s.parse::<u16>().unwrap_or(NAMESERVER_PORT))
}

/// Scan /proc/cmdline for `key=<value>` (space-separated kernel tokens).
fn cmdline_value(key: &str) -> Option<String> {
    let data = match std::fs::read("/proc/cmdline") {
        Ok(d) => d,
        Err(_) => return None,
    };
    let s = String::from_utf8_lossy(&data);
    let prefix = format!("{}=", key);
    for tok in s.split(' ') {
        if let Some(rest) = tok.strip_prefix(prefix.as_str()) {
            return Some(rest.to_owned());
        }
    }
    None
}

fn usage() -> ! {
    eprintln!("usage: dnslink <attach|init> [options]");
    eprintln!("  attach: --cgroup <path> [--watch] [--obj <path>]");
    eprintln!("  init:   [--mount-base <dir>] [--real <path>] [--obj <path>]");
    eprintln!("          (init mounts cgroup2 at <base>/cgroup, bpffs at <base>/bpf)");
    eprintln!("  both:   [--bind-ip <a.b.c.d>] [--bind-port <n>]");
    eprintln!("          [--target-ip <a.b.c.d>] [--target-port <n>]");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // When invoked with argc==1 (PID1: kernel boots with argv = ["/sbin/vminitd"])
    // default to init mode. Otherwise require an explicit attach|init subcommand.
    let mode = if args.len() == 1 {
        "init".to_string()
    } else {
        args[1].as_str().to_string()
    };
    if mode != "attach" && mode != "init" {
        usage();
    }

    let mut cgroup: Option<String> = None;
    let mut mount_base: Option<String> = None;
    let mut real_init = "/sbin/vminitd.real".to_string();
    let mut obj_path: Option<String> = None;
    let mut watch = false;
    let mut bind_ip_str = "127.0.8.6".to_string();
    let mut bind_port: u16 = NAMESERVER_PORT;
    let mut target_ip_str = "1.1.1.1".to_string();
    let mut target_port: u16 = NAMESERVER_PORT;

    let mut i = 2;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--cgroup" => {
                require(i + 1 < args.len(), || usage());
                i += 1;
                cgroup = Some(args[i].clone());
            }
            "--mount-base" => {
                require(i + 1 < args.len(), || usage());
                i += 1;
                mount_base = Some(args[i].clone());
            }
            "--real" => {
                require(i + 1 < args.len(), || usage());
                i += 1;
                real_init = args[i].clone();
            }
            "--obj" => {
                require(i + 1 < args.len(), || usage());
                i += 1;
                obj_path = Some(args[i].clone());
            }
            "--watch" => watch = true,
            "--bind-ip" => {
                require(i + 1 < args.len(), || usage());
                i += 1;
                bind_ip_str = args[i].clone();
            }
            "--bind-port" => {
                require(i + 1 < args.len(), || usage());
                i += 1;
                bind_port = args[i].parse::<u16>().unwrap_or_else(|_| usage());
            }
            "--target-ip" => {
                require(i + 1 < args.len(), || usage());
                i += 1;
                target_ip_str = args[i].clone();
            }
            "--target-port" => {
                require(i + 1 < args.len(), || usage());
                i += 1;
                target_port = args[i].parse::<u16>().unwrap_or_else(|_| usage());
            }
            _ => usage(),
        }
        i += 1;
    }

    // init mode: the upstream may be overridden via a kernel cmdline arg.
    //   dnslink.gateway=<ip>  -> upstream <ip>:53
    //   dnslink.port=<n>      -> port override
    //   (no arg)              -> default 1.1.1.1:53
    // The real vminitd mounts /proc itself — but that hasn't happened yet at
    // PID1, so mount proc now so /proc/cmdline is readable.
    if mode == "init" {
        mount_procfs();
        match gateway_from_cmdline() {
            Some(gw) => {
                let port = port_from_cmdline().unwrap_or(NAMESERVER_PORT);
                eprintln!("dnslink: upstream from /proc/cmdline: {}:{}", gw, port);
                target_ip_str = gw;
                target_port = port;
            }
            None => eprintln!(
                "dnslink: no dnslink.gateway; upstream {}:{}",
                target_ip_str, target_port
            ),
        }
    }

    // object bytes: --obj overrides the embedded copy
    let obj: Vec<u8> = match &obj_path {
        Some(p) => match std::fs::read(p) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("cannot read {}: {}", p, e);
                std::process::exit(1);
            }
        },
        None => EMBEDDED_OBJ.to_vec(),
    };

    let bind_ip = aton(&bind_ip_str).unwrap_or_else(|e| {
        eprintln!("bad IPv4 '{}': {}", bind_ip_str, e);
        std::process::exit(1);
    });
    let target_ip = aton(&target_ip_str).unwrap_or_else(|e| {
        eprintln!("bad IPv4 '{}': {}", target_ip_str, e);
        std::process::exit(1);
    });
    let rules: Vec<(u32, loader::Rule)> = vec![(
        0,
        loader::Rule {
            requested_ip: bind_ip.to_be(),
            actual_ip: target_ip.to_be(),
            requested_port: bind_port.to_be(),
            actual_port: target_port.to_be(),
        },
    )];

    // Resolve where the boot-time mounts hang (init parent dir; both mount
    // points derive from it — a future relayout is a default change).
    let mount_base = mount_base.unwrap_or_else(|| "/mnt".to_string());
    let bpffs_target = if mode == "init" {
        Path::new(&mount_base).join("bpf") // /mnt/bpf
    } else {
        Path::new("/sys/fs/bpf").to_path_buf()
    };

    // bpffs pin dir for links/maps (survive exec). Pins are still attempted
    // if prep failed; each failure below is non-fatal.
    let pin_dir: PathBuf = match ensure_bpffs(&bpffs_target, mode == "attach") {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "dnslink: bpffs prep failed: {}; pins will fail: DNS redirect will not be in effect",
                e
            );
            bpffs_target.join("dns_sockaddr").to_path_buf()
        }
    };

    let ctx = init::Ctx {
        real_init,
        mount_base,
    };

    if mode == "attach" {
        let cgroup = match cgroup {
            Some(c) => c,
            None => usage(),
        };
        attach_mode(&obj, &rules, &cgroup, &pin_dir, watch);
    } else {
        // init mode: replay our argv[1..] onto the real init.
        let init_args: Vec<String> = std::env::args().skip(1).map(|s| s.to_owned()).collect();
        match init::run(&ctx, &rules, &obj, &pin_dir, &init_args) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("dnslink: init failed: {}; falling back to real init", e);
                init::exec_real(&ctx.real_init, &init_args).unwrap_or_else(|e| {
                    eprintln!("dnslink: {}", e);
                    std::process::exit(1);
                });
            }
        }
    }
}

fn require(b: bool, u: fn() -> !) {
    if !b {
        u()
    }
}

/// attach mode entry.
fn attach_mode(
    obj: &[u8],
    rules: &Vec<(u32, loader::Rule)>,
    cgroup: &str,
    pin_dir: &PathBuf,
    watch: bool,
) {
    let cgroup_dir = match std::fs::File::open(cgroup) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cannot open cgroup {}: {}", cgroup, e);
            std::process::exit(1);
        }
    };

    println!(
        "=== dnslink attach: mode={} ===",
        if watch { "watch" } else { "attach" }
    );
    let loaded =
        loader::load_and_attach(obj, &cgroup_dir, rules, pin_dir, true).unwrap_or_else(|e| {
            eprintln!("load failed: {}", e);
            std::process::exit(1);
        });
    println!(
        "dnslink: attached {} cgroup hook(s) at {}",
        loaded.hooks.len(),
        cgroup
    );
    if watch {
        watch_hits(loaded.hit_map);
    }
}

/// Poll the PERCPU hit_cnt map and print on change; keys/labels each come
/// from the matching HOOKS entry.
fn watch_hits(hit_map: PerCpuArray<MapData, u64>) {
    let mut last = String::new();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let mut line = String::new();
        for (_, label, key) in loader::HOOKS {
            let hits = match hit_map.get(key, 0) {
                Ok(vals) => vals.iter().sum::<u64>() as i64,
                Err(_) => 0,
            };
            line = format!("{} {}={}", line, label, hits);
        }
        if line != last {
            println!("[hits]{}", line);
            last = line;
        }
    }
}
