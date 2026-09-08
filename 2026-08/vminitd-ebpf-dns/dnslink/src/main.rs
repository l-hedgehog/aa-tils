//! dnslink — static eBPF DNS-redirect init/loader.
//!
//! Modes:
//!   attach  — loader mode: attach hooks to a cgroup dir (--cgroup), optional
//!             counter watch.
//!   init    — PID1 boot wrapper: mount cgroup2, attach hooks to the root
//!             cgroup, exec the real init replaying our argv (minus argv[0]).
//!
//! Both embed dns_sockaddr.bpf.o and default to the rule
//! 127.0.8.6:53 -> 1.1.1.1:53, overridable via --bind-* / --target-*.

mod bpf;
mod elf;
mod init;
mod loader;
mod sys;

use std::net::{AddrParseError, Ipv4Addr};

/// The embedded BPF object (dns_sockaddr.bpf.o, built by `make`).
const EMBEDDED_OBJ: &[u8] = include_bytes!("../dns_sockaddr.bpf.o");
const NAMESERVER_PORT: u16 = 53;

fn aton(s: &str) -> Result<u32, AddrParseError> {
    s.parse::<Ipv4Addr>().map(|addr| addr.to_bits())
}

/// Mount procfs at /proc (idempotent; real vminitd does this itself later,
/// but our PID1 wrapper runs before it and needs /proc/cmdline).
fn mount_procfs() {
    let _ = sys::mount("proc", "/proc", "proc", 0);
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
    eprintln!("  init:   [--cgroup-mount <dir>] [--real <path>] [--obj <path>]");
    eprintln!("  both:   [--bind-ip <a.b.c.d>] [--bind-port <n>]");
    eprintln!("          [--target-ip <a.b.c.d>] [--target-port <n>]");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // When invoked with argc==1 (PID1: kernel boots with argv = ["/sbin/vminitd"])
    // default to init mode. Otherwise require an explicit attach|init subcommand.
    let mode = if args.len() == 1 { "init".to_string() } else { args[1].as_str().to_string() };
    if mode != "attach" && mode != "init" {
        usage();
    }

    let mut cgroup: Option<String> = None;
    let mut cgroup_mount: Option<String> = None;
    let mut real_init = "/sbin/vminitd.real".to_string();
    let mut obj_path: Option<String> = None;
    let mut watch = false;
    let mut bind_ip_str = "127.0.8.6".to_string();
    let mut bind_port: u16 = NAMESERVER_PORT;
    let mut target_ip_str = "1.1.1.1".to_string();
    let mut target_port: u16 = NAMESERVER_PORT;

    let mut i = 2;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--cgroup" => {
                require(i + 1 < args.len(), || usage());
                i += 1;
                cgroup = Some(args[i].clone());
            }
            "--cgroup-mount" => {
                require(i + 1 < args.len(), || usage());
                i += 1;
                cgroup_mount = Some(args[i].clone());
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
            None => eprintln!("dnslink: no dnslink.gateway; upstream 1.1.1.1:53"),
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

    let cfg = init::Ctx {
        real_init,
        cgroup_mount: cgroup_mount.unwrap_or_else(|| "/mnt".to_string()),
    };

    if mode == "attach" {
        let cgroup = match cgroup {
            Some(c) => c,
            None => usage(),
        };
        attach_mode(&obj, &rules, &cgroup, watch);
    } else {
        // init mode: replay our argv[1..] onto the real init.
        let init_args: Vec<String> = std::env::args().skip(1).map(|s| s.to_owned()).collect();
        match init::run(&cfg, &rules, &obj, &init_args) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("dnslink init failed: {}; falling back to real init", e);
                init::exec_real(&cfg.real_init, &init_args).unwrap_or_else(|e| {
                    eprintln!("{}", e);
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
fn attach_mode(obj: &[u8], rules: &Vec<(u32, loader::Rule)>, cgroup: &str, watch: bool) {
    let cgroup_dir = match std::fs::File::open(cgroup) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cannot open cgroup {}: {}", cgroup, e);
            std::process::exit(1);
        }
    };

    println!("=== dnslink attach: hooks={} ===", if watch { "watch" } else { "attach" });
    let wanted: Vec<String> = loader::HOOKS.iter().map(|(sfx, _, _, _)| format!("cgroup/{}", sfx)).collect();
    let want_refs: Vec<&str> = wanted.iter().map(|s| s.as_str()).collect();
    let loaded = loader::load_and_attach(obj, &cgroup_dir, rules, &want_refs, true)
        .unwrap_or_else(|e| {
            eprintln!("load failed: {}", e);
            std::process::exit(1);
        });
    println!("attached {} cgroup hook(s)", loaded.hooks.len());
    if watch {
        watch_hits(loaded.hit_map_fd);
    }
}

/// Poll the PERCPU hit_cnt map (keys 0..2) and print on change.
fn watch_hits(hit_fd: i64) {
    let mut last: [i64; 3] = [-1; 3];
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let mut cur: [i64; 3] = [0; 3];
        for key in 0..3usize {
            let mut val = [0u8; 4096];
            match bpf::bpf_map_lookup(hit_fd, &(key as u32).to_le_bytes(), &mut val) {
                Ok(_) => {
                    let mut sum: u64 = 0;
                    for slot in 0..128 {
                        sum += u64::from_le_bytes(val[slot * 8..slot * 8 + 8].try_into().unwrap());
                    }
                    cur[key] = sum as i64;
                }
                Err(_) => cur[key] = 0,
            }
        }
        if cur != last {
            println!("[hits] connect4={} sendmsg4={} recvmsg4={}", cur[0], cur[1], cur[2]);
            last = cur;
        }
    }
}
